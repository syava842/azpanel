package antizapret

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/syava842/azpanel/internal/fsutil"
)

// Виды списков маршрутизации — по окончанию имени файла.
const (
	KindHosts = "hosts" // *-hosts.txt
	KindIPs   = "ips"   // *-ips.txt
	KindRPZ   = "rpz"   // *-rpz.txt
)

// MaxReplaceBytes — до какого размера файл правится целиком (PUT).
const MaxReplaceBytes = 1 << 20

var (
	ErrNoList   = errors.New("такого списка нет")
	ErrTooLarge = errors.New("файл слишком большой для правки целиком — редактируйте по строкам")
	ErrReadOnly = errors.New("файл не относится к спискам маршрутизации — правка запрещена")
)

var routingNameRe = regexp.MustCompile(`^[a-z0-9-]+\.txt$`)

// routingTitles — описания для интерфейса. Смысл списков — по parse.sh
// (testdata/scripts): какой файл куда попадает. Неизвестное имя — без описания.
var routingTitles = map[string]string{
	"include-hosts.txt":         "Домены через AntiZapret",
	"exclude-hosts.txt":         "Исключить домены из AntiZapret",
	"remove-hosts.txt":          "Несуществующие домены (убираются из списков)",
	"include-warp-hosts.txt":    "Домены через WARP",
	"exclude-warp-hosts.txt":    "Исключить домены из WARP",
	"include-adblock-hosts.txt": "Блокировка рекламы — добавить",
	"exclude-adblock-hosts.txt": "Блокировка рекламы — исключения",
	"include-ips.txt":           "IP через AntiZapret",
	"exclude-ips.txt":           "Исключить IP из маршрутизации",
	"forward-ips.txt":           "Сети, разрешённые для пересылки",
	"drop-ips.txt":              "Сети, которым запрещена пересылка",
	"deny-ips.txt":              "Источники, которым запрещены входящие подключения",
	"allow-ips.txt":             "Разрешённые IP (защита от сканирования)",
	"deny-rpz.txt":              "Правила RPZ: блокировка (AntiZapret)",
	"deny2-rpz.txt":             "Правила RPZ: блокировка (полный VPN)",
	"deny3-rpz.txt":             "Правила RPZ: блокировка (Proxy DNS)",
	"proxy-rpz.txt":             "Правила RPZ: домены через прокси",
	"warp-rpz.txt":              "Правила RPZ: домены через WARP",
}

// KindOf — вид списка по имени файла; пусто — не список маршрутизации.
func KindOf(name string) string {
	switch {
	case strings.HasSuffix(name, "-hosts.txt"):
		return KindHosts
	case strings.HasSuffix(name, "-ips.txt"):
		return KindIPs
	case strings.HasSuffix(name, "-rpz.txt"):
		return KindRPZ
	}
	return ""
}

// RoutingFile — сведения о файле списка.
type RoutingFile struct {
	Name  string
	Kind  string
	Title string
	Lines int // строк-записей, без комментариев и пустых
	Bytes int64
}

// LineError — ошибка строки: Line считается с единицы в присланном списке
// (в PUT — в присланном тексте).
type LineError struct {
	Line   int
	Value  string
	Reason string
}

// PatchResult — итог правки по строкам. Applied=false: файл не менялся
// (есть ошибки или правка ничего не изменила).
type PatchResult struct {
	Applied bool
	Added   int
	Removed int
	Skipped int
	Errors  []LineError
}

// Page — страница строк файла.
type Page struct {
	Lines []string
	Total int // сколько строк подошло под фильтр
}

// Routing правит config/*.txt каталога AntiZapret: проверка строк, копия
// перед записью, атомарная замена с прежними правами и владельцем.
type Routing struct {
	ConfigDir string // /root/antizapret/config
	Backups   *Backups

	mu sync.Mutex
}

// path проверяет имя и находит его среди обычных файлов каталога; путь из
// запроса не собирается — имя берётся из шаблона и найденного списка.
func (r *Routing) path(name string) (string, error) {
	if !routingNameRe.MatchString(name) {
		return "", ErrNoList
	}
	entries, err := os.ReadDir(r.ConfigDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.Name() == name && e.Type().IsRegular() {
			return filepath.Join(r.ConfigDir, name), nil
		}
	}
	return "", ErrNoList
}

// Files — списки каталога config, по имени.
func (r *Routing) Files() ([]RoutingFile, error) {
	entries, err := os.ReadDir(r.ConfigDir)
	if err != nil {
		return nil, err
	}
	out := []RoutingFile{}
	for _, e := range entries {
		if !routingNameRe.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		f, err := r.fileInfo(e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Lines — записи файла (без комментариев и пустых), отфильтрованные
// подстрокой q без учёта регистра; страница с offset, не больше limit.
func (r *Routing) Lines(name, q string, offset, limit int) (Page, error) {
	p, err := r.path(name)
	if err != nil {
		return Page{}, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return Page{}, err
	}
	kind := KindOf(name)
	q = strings.ToLower(strings.TrimSpace(q))
	page := Page{Lines: []string{}}
	for _, line := range splitLines(data) {
		if !isEntry(kind, line) {
			continue
		}
		t := strings.TrimSpace(line)
		if q != "" && !strings.Contains(strings.ToLower(t), q) {
			continue
		}
		if page.Total >= offset && len(page.Lines) < limit {
			page.Lines = append(page.Lines, t)
		}
		page.Total++
	}
	return page, nil
}

func clean(s string) string { return strings.TrimSpace(strings.ReplaceAll(s, "\r", "")) }

// Patch добавляет и удаляет строки. Новые строки проверяются и приводятся к
// каноническому виду; повторы пропускаются; удаляются точные совпадения.
// Комментарии, пустые строки и порядок прочих строк сохраняются. Есть
// ошибка — файл не меняется.
func (r *Routing) Patch(name string, add, remove []string) (PatchResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.path(name)
	if err != nil {
		return PatchResult{}, err
	}
	kind := KindOf(name)
	if kind == "" {
		return PatchResult{}, ErrReadOnly
	}
	var res PatchResult

	// Сначала проверка присланного: ошибки не зависят от содержимого файла.
	adds := make([]string, 0, len(add))
	for i, raw := range add {
		t := clean(raw)
		if t == "" {
			continue
		}
		if !isEntry(kind, t) {
			res.Errors = append(res.Errors, LineError{Line: i + 1, Value: t, Reason: "комментарии не добавляются — только записи"})
			continue
		}
		norm, err := normalizeEntry(kind, name, t)
		if err != nil {
			res.Errors = append(res.Errors, LineError{Line: i + 1, Value: t, Reason: err.Error()})
			continue
		}
		adds = append(adds, norm)
	}
	if len(res.Errors) > 0 {
		return res, nil
	}

	data, err := os.ReadFile(p)
	if err != nil {
		return PatchResult{}, err
	}
	lines := splitLines(data)

	if len(remove) > 0 {
		want := map[string]bool{}
		for _, raw := range remove {
			t := clean(raw)
			if t == "" {
				continue
			}
			want[t] = true
			if norm, err := normalizeEntry(kind, name, t); err == nil {
				want[norm] = true
			}
		}
		matched := map[string]bool{}
		kept := make([]string, 0, len(lines))
		for _, line := range lines {
			if isEntry(kind, line) {
				t := strings.TrimSpace(line)
				hit := ""
				if want[t] {
					hit = t
				} else if norm, err := normalizeEntry(kind, name, t); err == nil && want[norm] {
					hit = norm
				}
				if hit != "" {
					matched[hit] = true
					res.Removed++
					continue
				}
			}
			kept = append(kept, line)
		}
		lines = kept
		for _, raw := range remove {
			t := clean(raw)
			if t == "" {
				continue
			}
			norm, _ := normalizeEntry(kind, name, t)
			if !matched[t] && !(norm != "" && matched[norm]) {
				res.Skipped++
			}
		}
	}

	if len(adds) > 0 {
		have := make(map[string]bool, len(lines))
		for _, line := range lines {
			if !isEntry(kind, line) {
				continue
			}
			t := strings.TrimSpace(line)
			have[t] = true
			if norm, err := normalizeEntry(kind, name, t); err == nil {
				have[norm] = true
			}
		}
		for _, norm := range adds {
			if have[norm] {
				res.Skipped++
				continue
			}
			have[norm] = true
			lines = append(lines, norm)
			res.Added++
		}
	}

	if res.Added == 0 && res.Removed == 0 {
		return res, nil
	}
	if err := r.write(name, p, data, joinLines(lines)); err != nil {
		return PatchResult{}, err
	}
	res.Applied = true
	return res, nil
}

// Replace заменяет файл целиком. Каждая строка проверяется; строки-записи
// приводятся к каноническому виду, \r убирается. Ошибки — построчно, файл
// не меняется. Возвращает число записей в новом файле.
func (r *Routing) Replace(name, content string) (int, []LineError, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.path(name)
	if err != nil {
		return 0, nil, err
	}
	kind := KindOf(name)
	if kind == "" {
		return 0, nil, ErrReadOnly
	}
	if len(content) > MaxReplaceBytes {
		return 0, nil, ErrTooLarge
	}
	old, err := os.ReadFile(p)
	if err != nil {
		return 0, nil, err
	}
	if len(old) > MaxReplaceBytes {
		return 0, nil, ErrTooLarge
	}
	lines := splitLines([]byte(strings.ReplaceAll(content, "\r", "")))
	var errs []LineError
	entries := 0
	for i, line := range lines {
		if !isEntry(kind, line) {
			if strings.TrimSpace(line) == "" {
				lines[i] = ""
			}
			continue
		}
		t := strings.TrimSpace(line)
		norm, err := normalizeEntry(kind, name, t)
		if err != nil {
			errs = append(errs, LineError{Line: i + 1, Value: t, Reason: err.Error()})
			continue
		}
		lines[i] = norm
		entries++
	}
	if len(errs) > 0 {
		return 0, errs, nil
	}
	if err := r.write(name, p, old, joinLines(lines)); err != nil {
		return 0, nil, err
	}
	return entries, nil, nil
}

// BackupList — копии файла, новые сверху.
func (r *Routing) BackupList(name string) ([]BackupInfo, error) {
	if _, err := r.path(name); err != nil {
		return nil, err
	}
	return r.Backups.List(name)
}

// Restore возвращает копию на место файла; текущая версия перед этим
// тоже копируется. Содержимое копии не проверяется — это то, что было записано.
func (r *Routing) Restore(name, stamp string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.path(name)
	if err != nil {
		return err
	}
	saved, err := r.Backups.Read(name, stamp)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoList
	}
	if err != nil {
		return err
	}
	cur, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return r.write(name, p, cur, saved)
}

// write: копия прежнего содержимого, затем атомарная замена.
func (r *Routing) write(name, path string, before, after []byte) error {
	if _, err := r.Backups.Save(name, before); err != nil {
		return fmt.Errorf("копия %s не сохранена: %w", name, err)
	}
	return fsutil.WriteFileKeepMeta(path, after)
}

// --- строки ---

// splitLines режет текст по \n; пустой хвост после финального \n
// отбрасывается. \r остаются в строках: нетронутые строки пишутся как были.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func joinLines(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// isEntry — строка является записью, а не комментарием или пустой.
// parse.sh убирает пробелы и \r; комментарии — «#», у rpz — «;».
func isEntry(kind, line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	if kind == KindRPZ {
		return t[0] != ';'
	}
	return t[0] != '#'
}

// normalizeEntry проверяет строку-запись и возвращает её канонический вид.
// Правила — по parse.sh (testdata/scripts/parse.sh):
//   - hosts: sed обрезает строку с первого из символов ]_~:/?#[@!$&'()*+,;=,
//     приводит её к нижнему регистру и отбрасывает строки, начинающиеся со
//     знака препинания; одиночная «.» пропускается только для include-hosts и
//     include-warp-hosts. Поэтому допустимы только метки [a-z0-9-];
//   - ips: awk берёт только a.b.c.d/N, N от 1 до 32; одиночный адрес без
//     маски awk отбросил бы молча, поэтому он приводится к /32;
//   - rpz: строки идут в зону Knot Resolver как есть (после удаления \r и
//     строк с «;»), поэтому проверяется вид «<домен> CNAME <цель>».
func normalizeEntry(kind, name, s string) (string, error) {
	switch kind {
	case KindHosts:
		return normalizeHost(name, s)
	case KindIPs:
		return normalizeIP(s)
	case KindRPZ:
		return normalizeRPZ(s)
	}
	return "", ErrReadOnly
}

func normalizeHost(name, s string) (string, error) {
	s = strings.ToLower(s)
	if s == "." {
		if name == "include-hosts.txt" || name == "include-warp-hosts.txt" {
			return ".", nil
		}
		return "", errors.New("одиночная точка (все домены) допускается только в include-hosts.txt и include-warp-hosts.txt")
	}
	if err := validateDomain(s); err != nil {
		return "", err
	}
	return s, nil
}

// validateDomain — домен в нижнем регистре: метки [a-z0-9-] длиной 1-63, не
// с дефиса, всего не больше 253, хотя бы одна точка.
func validateDomain(s string) error {
	if s == "" {
		return errors.New("пустой домен")
	}
	if len(s) > 253 {
		return errors.New("домен длиннее 253 символов")
	}
	if s[0] == '.' {
		return errors.New("домен не может начинаться с точки: parse.sh пропустит такую строку")
	}
	if !strings.Contains(s, ".") {
		return errors.New("в домене нужна хотя бы одна точка")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return errors.New("пустая метка домена (две точки подряд или точка на конце)")
		}
		if len(label) > 63 {
			return fmt.Errorf("метка %q длиннее 63 символов", label)
		}
		if label[0] == '-' {
			return fmt.Errorf("метка %q начинается с дефиса", label)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("недопустимый символ %q в домене (разрешены латинские буквы, цифры, дефис и точка)", c)
			}
		}
	}
	return nil
}

func normalizeIP(s string) (string, error) {
	var pfx netip.Prefix
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", errors.New("не IPv4-сеть вида 1.2.3.0/24")
		}
		pfx = p
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "", errors.New("не IPv4-адрес и не сеть вида 1.2.3.0/24")
		}
		pfx = netip.PrefixFrom(a, a.BitLen())
	}
	if !pfx.Addr().Is4() {
		return "", errors.New("нужен IPv4-адрес")
	}
	if pfx.Bits() < 1 {
		return "", errors.New("маска /0 не принимается: parse.sh допускает от /1 до /32")
	}
	return pfx.Masked().String(), nil
}

func normalizeRPZ(s string) (string, error) {
	f := strings.Fields(s)
	if len(f) != 3 || !strings.EqualFold(f[1], "CNAME") {
		return "", errors.New("нужен вид «<домен> CNAME <цель>»")
	}
	owner := strings.ToLower(f[0])
	wild := strings.HasPrefix(owner, "*.")
	if wild {
		owner = owner[2:]
	}
	if err := validateDomain(owner); err != nil {
		return "", fmt.Errorf("домен: %w", err)
	}
	if wild {
		owner = "*." + owner
	}
	target := strings.ToLower(f[2])
	if target != "." && target != "rpz-passthru." {
		if err := validateDomain(strings.TrimSuffix(target, ".")); err != nil {
			return "", fmt.Errorf("цель (., rpz-passthru. или домен): %w", err)
		}
	}
	return owner + " CNAME " + target, nil
}

// File — сведения об одном списке.
func (r *Routing) File(name string) (RoutingFile, error) {
	if _, err := r.path(name); err != nil {
		return RoutingFile{}, err
	}
	return r.fileInfo(name)
}

func (r *Routing) fileInfo(name string) (RoutingFile, error) {
	data, err := os.ReadFile(filepath.Join(r.ConfigDir, name))
	if err != nil {
		return RoutingFile{}, err
	}
	kind := KindOf(name)
	n := 0
	for _, line := range splitLines(data) {
		if isEntry(kind, line) {
			n++
		}
	}
	return RoutingFile{Name: name, Kind: kind, Title: routingTitles[name], Lines: n, Bytes: int64(len(data))}, nil
}
