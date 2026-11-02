package antizapret

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/fsutil"
)

const (
	// UpstreamRepo — репозиторий AntiZapret-VPN.
	UpstreamRepo   = "GubernievS/AntiZapret-VPN"
	upstreamBranch = "main"
	// scriptsPath — каталог скриптов в репозитории; на сервере им соответствует /root/antizapret.
	scriptsPath = "setup/root/antizapret"
	// commitsDepth — сколько последних коммитов main учитывается.
	commitsDepth = 200
	// githubTTL — публичный API пускает 60 запросов в час без токена.
	githubTTL = time.Hour
	// maxCandidates — потолок запросов «содержимое каталога на коммите» за один поиск.
	maxCandidates = 40
	// unknownBehindShown — сколько последних коммитов показывать, когда своя версия неизвестна.
	unknownBehindShown = 20
)

// VersionScripts — скрипты, по которым узнаётся версия установленного AntiZapret.
var VersionScripts = []string{"up.sh", "down.sh", "parse.sh", "update.sh", "doall.sh", "client.sh"}

// Commit — коммит ветки main.
type Commit struct {
	SHA     string    `json:"sha"`
	Message string    `json:"message"` // первая строка
	Date    time.Time `json:"date"`
}

// GitBlobSHA1 — хеш git-blob: sha1("blob <длина>\0" + данные).
func GitBlobSHA1(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// LocalScriptHashes — git-blob хеши скриптов из каталога AntiZapret. Нет
// скрипта — ошибка: версию по неполному набору не определить.
func LocalScriptHashes(dir string) (map[string]string, error) {
	out := make(map[string]string, len(VersionScripts))
	for _, name := range VersionScripts {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out[name] = GitBlobSHA1(data)
	}
	return out, nil
}

// GitHub — чтение публичного API GitHub без токена. Ответы кешируются на час;
// BaseURL и HTTP подменяются в тестах.
type GitHub struct {
	BaseURL string // пусто — https://api.github.com
	Repo    string // пусто — UpstreamRepo
	HTTP    *http.Client
	Now     func() time.Time
	TTL     time.Duration // 0 — час

	mu      sync.Mutex
	commits cacheEntry[[]Commit]
	// Дерево коммита неизменно — кешируется без срока.
	blobs map[string]map[string]string
	// История файла: ключ — имя файла; срок как у списка коммитов.
	history map[string]cacheEntry[[]string]
	// found — результат поиска по хешам; ключ — хеши и вершина main.
	found map[string]cacheEntry[string]
}

type cacheEntry[T any] struct {
	at  time.Time
	val T
	ok  bool
}

func (g *GitHub) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *GitHub) ttl() time.Duration {
	if g.TTL > 0 {
		return g.TTL
	}
	return githubTTL
}

func (g *GitHub) fresh(at time.Time) bool { return g.now().Sub(at) < g.ttl() }

func (g *GitHub) repo() string {
	if g.Repo != "" {
		return g.Repo
	}
	return UpstreamRepo
}

func (g *GitHub) get(ctx context.Context, path string, q url.Values, out any) error {
	base := strings.TrimRight(g.BaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	u := base + "/repos/" + g.repo() + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "azpanel")
	cl := g.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub недоступен: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("GitHub отказал (%d): вероятно, исчерпан предел запросов без токена — повторите позже", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub ответил %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

type ghCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message   string `json:"message"`
		Committer struct {
			Date time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

func (c ghCommit) commit() Commit {
	msg, _, _ := strings.Cut(c.Commit.Message, "\n")
	return Commit{SHA: c.SHA, Message: strings.TrimSpace(msg), Date: c.Commit.Committer.Date}
}

// Commits — последние 200 коммитов main, новые сверху. Кеш на час; если
// GitHub недоступен, а кеш есть — отдаётся он (устаревший лучше пустого).
func (g *GitHub) Commits(ctx context.Context) ([]Commit, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.commits.ok && g.fresh(g.commits.at) {
		return g.commits.val, nil
	}
	var all []Commit
	for page := 1; len(all) < commitsDepth; page++ {
		var raw []ghCommit
		q := url.Values{"sha": {upstreamBranch}, "per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if err := g.get(ctx, "/commits", q, &raw); err != nil {
			if g.commits.ok {
				return g.commits.val, nil
			}
			return nil, err
		}
		for _, c := range raw {
			all = append(all, c.commit())
		}
		if len(raw) < 100 {
			break
		}
	}
	if len(all) > commitsDepth {
		all = all[:commitsDepth]
	}
	g.commits = cacheEntry[[]Commit]{at: g.now(), val: all, ok: true}
	return all, nil
}

// fileHistory — коммиты main, менявшие скрипт, новые сверху.
func (g *GitHub) fileHistory(ctx context.Context, name string) ([]string, error) {
	g.mu.Lock()
	if e, ok := g.history[name]; ok && g.fresh(e.at) {
		g.mu.Unlock()
		return e.val, nil
	}
	g.mu.Unlock()
	var raw []ghCommit
	q := url.Values{"sha": {upstreamBranch}, "path": {scriptsPath + "/" + name}, "per_page": {"100"}}
	if err := g.get(ctx, "/commits", q, &raw); err != nil {
		return nil, err
	}
	shas := make([]string, 0, len(raw))
	for _, c := range raw {
		shas = append(shas, c.SHA)
	}
	g.mu.Lock()
	if g.history == nil {
		g.history = map[string]cacheEntry[[]string]{}
	}
	g.history[name] = cacheEntry[[]string]{at: g.now(), val: shas, ok: true}
	g.mu.Unlock()
	return shas, nil
}

// scriptBlobs — git-blob хеши скриптов на коммите.
func (g *GitHub) scriptBlobs(ctx context.Context, sha string) (map[string]string, error) {
	g.mu.Lock()
	if m, ok := g.blobs[sha]; ok {
		g.mu.Unlock()
		return m, nil
	}
	g.mu.Unlock()
	var entries []struct {
		Name string `json:"name"`
		SHA  string `json:"sha"`
		Type string `json:"type"`
	}
	if err := g.get(ctx, "/contents/"+scriptsPath, url.Values{"ref": {sha}}, &entries); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, e := range entries {
		if e.Type == "file" {
			m[e.Name] = e.SHA
		}
	}
	g.mu.Lock()
	if g.blobs == nil {
		g.blobs = map[string]map[string]string{}
	}
	g.blobs[sha] = m
	g.mu.Unlock()
	return m, nil
}

// FindCommit ищет среди последних 200 коммитов тот, на котором скрипты
// совпадают с локальными по хешам git-blob. Перебор не по всем коммитам, а по
// тем, что меняли скрипты (и по вершине main): между ними скрипты одинаковы, а
// запросов без токена всего 60 в час. Вернётся самый новый из таких
// кандидатов (вершина main, если её скрипты те же). found=false —
// такого набора в истории нет (скрипты правили руками или версия старше).
func (g *GitHub) FindCommit(ctx context.Context, local map[string]string) (sha string, found bool, err error) {
	commits, err := g.Commits(ctx)
	if err != nil {
		return "", false, err
	}
	if len(commits) == 0 {
		return "", false, errors.New("GitHub вернул пустую историю")
	}
	key := commits[0].SHA
	for _, n := range VersionScripts {
		key += "|" + local[n]
	}
	g.mu.Lock()
	if e, ok := g.found[key]; ok && g.fresh(e.at) {
		g.mu.Unlock()
		return e.val, e.val != "", nil
	}
	g.mu.Unlock()

	inRange := map[string]bool{}
	for _, c := range commits {
		inRange[c.SHA] = true
	}
	cand := map[string]bool{commits[0].SHA: true}
	for _, name := range VersionScripts {
		hist, err := g.fileHistory(ctx, name)
		if err != nil {
			return "", false, err
		}
		for _, s := range hist {
			if inRange[s] {
				cand[s] = true
			}
		}
	}
	checked := 0
	for _, c := range commits { // новые сверху
		if !cand[c.SHA] {
			continue
		}
		if checked >= maxCandidates {
			break
		}
		checked++
		blobs, err := g.scriptBlobs(ctx, c.SHA)
		if err != nil {
			return "", false, err
		}
		if sameBlobs(blobs, local) {
			sha = c.SHA
			break
		}
	}
	g.mu.Lock()
	if g.found == nil {
		g.found = map[string]cacheEntry[string]{}
	}
	g.found[key] = cacheEntry[string]{at: g.now(), val: sha, ok: true}
	g.mu.Unlock()
	return sha, sha != "", nil
}

func sameBlobs(remote, local map[string]string) bool {
	for _, n := range VersionScripts {
		if local[n] == "" || remote[n] != local[n] {
			return false
		}
	}
	return true
}

// Installed — запись об установке, сделанной через панель: data/antizapret.json.
// Hashes защищают от устаревшей записи: скрипты поменяли руками или
// переустановили AntiZapret мимо панели — запись больше не верна.
type Installed struct {
	Commit string            `json:"commit"`
	Date   time.Time         `json:"date"`
	Hashes map[string]string `json:"hashes"`
}

// InstalledFile — файл записи об установке.
type InstalledFile struct{ Path string }

// Read читает запись; нет файла — пустая запись без ошибки.
func (f InstalledFile) Read() (Installed, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Installed{}, nil
	}
	if err != nil {
		return Installed{}, err
	}
	var in Installed
	if err := json.Unmarshal(data, &in); err != nil {
		return Installed{}, nil // испорченную запись считаем отсутствующей
	}
	return in, nil
}

// Write записывает коммит и хеши скриптов, какие на диске сейчас.
func (f InstalledFile) Write(dir, commit string, date time.Time) error {
	hashes, err := LocalScriptHashes(dir)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(Installed{Commit: commit, Date: date.UTC(), Hashes: hashes}, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(f.Path, data, 0o640)
}

// Источники текущей версии.
const (
	SourceRecorded = "recorded" // записано при установке через панель
	SourceScripts  = "scripts"  // найдено по хешам скриптов
)

// Version — ответ о версии AntiZapret.
type Version struct {
	// Current — коммит установленной версии; пусто — неизвестна.
	Current       string   `json:"current"`
	CurrentSource string   `json:"current_source,omitempty"`
	Latest        *Commit  `json:"latest,omitempty"`
	UpToDate      bool     `json:"up_to_date"`
	Behind        []Commit `json:"behind"` // новее установленного, новые сверху
	// Truncated — установленная версия старше окна в 200 коммитов: Behind неполон.
	Truncated bool   `json:"truncated,omitempty"`
	Message   string `json:"message,omitempty"`
	// Error — GitHub не ответил; Current при этом может быть известен из записи.
	Error string `json:"error,omitempty"`
}

// VersionService отвечает на вопрос «какой AntiZapret стоит и что новее».
type VersionService struct {
	GitHub *GitHub
	Dir    string // каталог AntiZapret
	Record InstalledFile
}

// Get собирает ответ. Сбой GitHub не ошибка вызова: он в поле Error.
func (s *VersionService) Get(ctx context.Context) Version {
	var v Version
	local, lerr := LocalScriptHashes(s.Dir)
	if rec, err := s.Record.Read(); err == nil && rec.Commit != "" && lerr == nil && hashesEqual(rec.Hashes, local) {
		v.Current, v.CurrentSource = rec.Commit, SourceRecorded
	}
	commits, err := s.GitHub.Commits(ctx)
	if err != nil {
		v.Error = err.Error()
		v.Behind = []Commit{}
		if v.Current == "" {
			v.Message = "версия неизвестна: GitHub недоступен"
		}
		return v
	}
	if len(commits) > 0 {
		latest := commits[0]
		v.Latest = &latest
	}
	if v.Current == "" && lerr == nil {
		sha, found, err := s.GitHub.FindCommit(ctx, local)
		switch {
		case err != nil:
			v.Error = err.Error()
		case found:
			v.Current, v.CurrentSource = sha, SourceScripts
		}
	}
	v.Behind = []Commit{}
	if v.Current == "" {
		if v.Message == "" {
			v.Message = "версия неизвестна, отличается от актуальной"
		}
		n := min(unknownBehindShown, len(commits))
		v.Behind = append(v.Behind, commits[:n]...)
		return v
	}
	idx := -1
	for i, c := range commits {
		if c.SHA == v.Current {
			idx = i
			break
		}
	}
	switch {
	case idx < 0:
		v.Truncated = true
		v.Behind = append(v.Behind, commits...)
	default:
		v.Behind = append(v.Behind, commits[:idx]...)
	}
	v.UpToDate = len(commits) > 0 && commits[0].SHA == v.Current
	return v
}

func hashesEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}
