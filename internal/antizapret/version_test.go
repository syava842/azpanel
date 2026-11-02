package antizapret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitBlobSHA1(t *testing.T) {
	// git hash-object пустого файла и строки «hello\n».
	if got := GitBlobSHA1(nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("пустой blob: %s", got)
	}
	if got := GitBlobSHA1([]byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Fatalf("hello: %s", got)
	}
}

// Скрипты с сервера 94 из testdata совпадают по blob-хешу с main на GitHub
// (сверено 02.11.2026): способ определения версии работает на настоящих файлах.
func TestLocalScriptHashesMatchRealBlobs(t *testing.T) {
	got, err := LocalScriptHashes(filepath.Join("testdata", "scripts"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"doall.sh":  "8cc084147c56a4dfae672954efa2adfe9e5a09c4",
		"update.sh": "9c197d7f7add0235dd7b4db61cb9b0e562bb4a3b",
		"client.sh": "c404e38c81ed4300d7448a0a5750d5279a28cd62",
	} {
		if got[name] != want {
			t.Errorf("%s: %s, ожидалось %s", name, got[name], want)
		}
	}
}

// fakeGitHub — поддельный API: история main (новые сверху) и blob-хеши
// скриптов на каждом коммите. Коммит менял файл, если его хеш отличается от
// хеша у предыдущего коммита.
type fakeGitHub struct {
	commits  []string
	blobs    map[string]map[string]string
	requests atomic.Int32
	fail     atomic.Bool
}

func (f *fakeGitHub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if f.fail.Load() {
			http.Error(w, "boom", http.StatusForbidden)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits"):
			list := f.commits
			if p := r.URL.Query().Get("path"); p != "" {
				name := p[strings.LastIndex(p, "/")+1:]
				list = nil
				for i, c := range f.commits {
					if i == len(f.commits)-1 || f.blobs[c][name] != f.blobs[f.commits[i+1]][name] {
						list = append(list, c)
					}
				}
			}
			out := []map[string]any{}
			for _, c := range list {
				out = append(out, map[string]any{"sha": c, "commit": map[string]any{
					"message":   "Сообщение " + c + "\n\nтело",
					"committer": map[string]any{"date": "2026-11-02T07:30:30Z"},
				}})
			}
			json.NewEncoder(w).Encode(out)
		case strings.Contains(r.URL.Path, "/contents/setup/root/antizapret"):
			ref := r.URL.Query().Get("ref")
			out := []map[string]any{{"name": "config", "sha": "x", "type": "dir"}}
			for n, s := range f.blobs[ref] {
				out = append(out, map[string]any{"name": n, "sha": s, "type": "file"})
			}
			json.NewEncoder(w).Encode(out)
		default:
			http.NotFound(w, r)
		}
	})
}

func newFake(commits ...string) *fakeGitHub {
	return &fakeGitHub{commits: commits, blobs: map[string]map[string]string{}}
}

func (f *fakeGitHub) setBlobs(commit string, m map[string]string) { f.blobs[commit] = m }

func scriptSet(tag string) map[string]string {
	m := map[string]string{}
	for _, n := range VersionScripts {
		m[n] = tag + "-" + n
	}
	return m
}

func with(m map[string]string, name, val string) map[string]string {
	c := map[string]string{}
	for k, v := range m {
		c[k] = v
	}
	c[name] = val
	return c
}

func (f *fakeGitHub) client(t *testing.T) *GitHub {
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return &GitHub{BaseURL: srv.URL}
}

// writeScripts кладёт в dir скрипты и возвращает их blob-хеши.
func writeScripts(t *testing.T, dir string) map[string]string {
	t.Helper()
	hashes := map[string]string{}
	for _, n := range VersionScripts {
		body := "#!/bin/bash\n# " + n + "\n"
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		hashes[n] = GitBlobSHA1([]byte(body))
	}
	return hashes
}

func TestCommitsParsedAndCached(t *testing.T) {
	f := newFake("c3", "c2", "c1")
	gh := f.client(t)
	list, err := gh.Commits(context.Background())
	if err != nil || len(list) != 3 || list[0].SHA != "c3" || list[0].Message != "Сообщение c3" {
		t.Fatalf("список: %+v %v", list, err)
	}
	if list[0].Date.IsZero() {
		t.Fatal("дата не разобрана")
	}
	before := f.requests.Load()
	if _, err := gh.Commits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != before {
		t.Fatal("второй вызов в пределах часа ушёл в сеть")
	}
}

func TestCommitsCacheExpiresAndFallsBackToStale(t *testing.T) {
	f := newFake("c2", "c1")
	gh := f.client(t)
	now := time.Now()
	gh.Now = func() time.Time { return now }
	if _, err := gh.Commits(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * time.Minute)
	f.commits = []string{"c3", "c2", "c1"}
	list, _ := gh.Commits(context.Background())
	if len(list) != 3 {
		t.Fatalf("после часа кеш должен обновиться: %+v", list)
	}
	// GitHub отказал, а кеш есть — отдаётся устаревший.
	now = now.Add(61 * time.Minute)
	f.fail.Store(true)
	list, err := gh.Commits(context.Background())
	if err != nil || len(list) != 3 {
		t.Fatalf("устаревший кеш: %+v %v", list, err)
	}
}

func TestCommitsPaginatesTo200(t *testing.T) {
	var shas []string
	for i := 0; i < 250; i++ {
		shas = append(shas, fmt.Sprintf("%040d", 250-i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		fmt.Sscan(r.URL.Query().Get("page"), &page)
		lo, hi := (page-1)*100, min(page*100, len(shas))
		out := []map[string]any{}
		if lo < len(shas) {
			for _, c := range shas[lo:hi] {
				out = append(out, map[string]any{"sha": c, "commit": map[string]any{"message": "m", "committer": map[string]any{"date": "2026-11-02T07:30:30Z"}}})
			}
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	gh := &GitHub{BaseURL: srv.URL}
	list, err := gh.Commits(context.Background())
	if err != nil || len(list) != 200 {
		t.Fatalf("ожидалось ровно 200 коммитов: %d %v", len(list), err)
	}
}

func TestGitHubRateLimitMessage(t *testing.T) {
	f := newFake("c1")
	f.fail.Store(true)
	_, err := f.client(t).Commits(context.Background())
	if err == nil || !strings.Contains(err.Error(), "предел запросов") {
		t.Fatalf("ошибка лимита: %v", err)
	}
}

func TestFindCommitByScriptHashes(t *testing.T) {
	f := newFake("c4", "c3", "c2", "c1")
	base := scriptSet("a")
	f.setBlobs("c1", base)
	f.setBlobs("c2", with(base, "parse.sh", "p2")) // c2 менял parse.sh
	f.setBlobs("c3", with(base, "parse.sh", "p2")) // c3 скрипты не трогал
	f.setBlobs("c4", with(with(base, "parse.sh", "p2"), "up.sh", "u4"))
	gh := f.client(t)

	// Установлен набор c2 (он же у c3): c3 скрипты не менял и кандидатом не
	// является, поэтому найден c2.
	sha, found, err := gh.FindCommit(context.Background(), with(base, "parse.sh", "p2"))
	if err != nil || !found || sha != "c2" {
		t.Fatalf("c2: %q %v %v", sha, found, err)
	}
	sha, found, _ = gh.FindCommit(context.Background(), base)
	if !found || sha != "c1" {
		t.Fatalf("c1: %q %v", sha, found)
	}
	// Набор, которого в истории не было: не найден.
	sha, found, _ = gh.FindCommit(context.Background(), with(base, "doall.sh", "руками"))
	if found || sha != "" {
		t.Fatalf("чужой набор нашёлся: %q", sha)
	}
}

func TestFindCommitHeadMatches(t *testing.T) {
	f := newFake("c2", "c1")
	base := scriptSet("a")
	f.setBlobs("c1", base)
	f.setBlobs("c2", base)
	sha, found, err := f.client(t).FindCommit(context.Background(), base)
	if err != nil || !found || sha != "c2" {
		t.Fatalf("вершина: %q %v %v", sha, found, err)
	}
}

func versionService(t *testing.T, f *fakeGitHub, dir string) *VersionService {
	return &VersionService{GitHub: f.client(t), Dir: dir, Record: InstalledFile{Path: filepath.Join(t.TempDir(), "antizapret.json")}}
}

func TestVersionRecordedCommit(t *testing.T) {
	f := newFake("c3", "c2", "c1")
	dir := t.TempDir()
	writeScripts(t, dir)
	s := versionService(t, f, dir)
	if err := s.Record.Write(dir, "c2", time.Now()); err != nil {
		t.Fatal(err)
	}
	v := s.Get(context.Background())
	if v.Current != "c2" || v.CurrentSource != SourceRecorded || v.UpToDate || len(v.Behind) != 1 || v.Behind[0].SHA != "c3" {
		t.Fatalf("%+v", v)
	}
	if v.Latest == nil || v.Latest.SHA != "c3" {
		t.Fatalf("последний: %+v", v.Latest)
	}
	if f.requests.Load() != 1 {
		t.Fatalf("запросов %d, нужен один (список коммитов): запись верна, деревья не нужны", f.requests.Load())
	}
}

func TestVersionRecordStaleAfterManualEdit(t *testing.T) {
	f := newFake("c2", "c1")
	dir := t.TempDir()
	writeScripts(t, dir)
	s := versionService(t, f, dir)
	s.Record.Write(dir, "c1", time.Now())
	// Скрипт поменяли руками — запись недействительна, версия неизвестна.
	os.WriteFile(filepath.Join(dir, "up.sh"), []byte("правка\n"), 0o755)
	f.setBlobs("c1", scriptSet("x"))
	f.setBlobs("c2", scriptSet("y"))
	v := s.Get(context.Background())
	if v.Current != "" || !strings.Contains(v.Message, "версия неизвестна") || v.UpToDate {
		t.Fatalf("%+v", v)
	}
	if len(v.Behind) != 2 {
		t.Fatalf("при неизвестной версии показываются последние коммиты: %+v", v.Behind)
	}
}

func TestVersionDetectedByScripts(t *testing.T) {
	f := newFake("c2", "c1")
	dir := t.TempDir()
	h := writeScripts(t, dir)
	f.setBlobs("c1", h)
	f.setBlobs("c2", with(h, "doall.sh", "новый"))
	v := versionService(t, f, dir).Get(context.Background())
	if v.Current != "c1" || v.CurrentSource != SourceScripts || v.UpToDate || len(v.Behind) != 1 {
		t.Fatalf("%+v", v)
	}
}

func TestVersionUpToDate(t *testing.T) {
	f := newFake("c2", "c1")
	dir := t.TempDir()
	h := writeScripts(t, dir)
	f.setBlobs("c1", h)
	f.setBlobs("c2", h)
	v := versionService(t, f, dir).Get(context.Background())
	if !v.UpToDate || v.Current != "c2" || len(v.Behind) != 0 {
		t.Fatalf("%+v", v)
	}
}

func TestVersionGitHubDownKeepsRecordedCurrent(t *testing.T) {
	f := newFake("c1")
	f.fail.Store(true)
	dir := t.TempDir()
	writeScripts(t, dir)
	s := versionService(t, f, dir)
	s.Record.Write(dir, "c1", time.Now())
	v := s.Get(context.Background())
	if v.Current != "c1" || v.Error == "" || v.Latest != nil || v.UpToDate {
		t.Fatalf("%+v", v)
	}
}

func TestVersionMissingScriptsIsUnknown(t *testing.T) {
	f := newFake("c1")
	f.setBlobs("c1", scriptSet("a"))
	v := versionService(t, f, t.TempDir()).Get(context.Background())
	if v.Current != "" || !strings.Contains(v.Message, "неизвестна") {
		t.Fatalf("%+v", v)
	}
}

func TestInstalledFileCorruptIsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	os.WriteFile(p, []byte("{не json"), 0o640)
	in, err := InstalledFile{Path: p}.Read()
	if err != nil || in.Commit != "" {
		t.Fatalf("%+v %v", in, err)
	}
}

// Коммит из форка тянется по тому же адресу архива, что и коммит upstream:
// принадлежность main проверяется через compare, а не по форме sha.
func TestInMain(t *testing.T) {
	inHistory := strings.Repeat("a", 40)
	old := strings.Repeat("b", 40)
	fork := strings.Repeat("c", 40)
	var compares atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits"):
			json.NewEncoder(w).Encode([]map[string]any{{"sha": inHistory, "commit": map[string]any{"message": "x"}}})
		case strings.Contains(r.URL.Path, "/compare/"+old+"..."):
			compares.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"status": "behind"})
		case strings.Contains(r.URL.Path, "/compare/"+fork+"..."):
			compares.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"status": "diverged"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	g := &GitHub{BaseURL: srv.URL}
	ctx := context.Background()
	for sha, want := range map[string]bool{inHistory: true, old: true, fork: false, strings.Repeat("d", 40): false} {
		got, err := g.InMain(ctx, sha)
		if err != nil || got != want {
			t.Errorf("%s: %v %v, ждали %v", sha[:1], got, err, want)
		}
	}
	before := compares.Load()
	g.InMain(ctx, old)
	g.InMain(ctx, fork)
	if compares.Load() != before {
		t.Error("ответ compare не кешируется")
	}
}
