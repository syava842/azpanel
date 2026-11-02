package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/paths"
)

// Пути и метка, которыми azpanel помечает свои правки в nginx.
const (
	NginxDir        = "/etc/nginx"
	SnippetPath     = "/etc/nginx/snippets/azpanel.conf"
	AcmeSnippetPath = "/etc/nginx/snippets/azpanel-acme.conf"
	IncludeMarker   = "# azpanel"
	ownPortFile     = "sites-available/azpanel"
	ownPortLink     = "sites-enabled/azpanel"
)

// NginxServer — один блок server { … } чужого конфига.
type NginxServer struct {
	File           string
	StartLine      int      // строка слова server (с 1)
	EndLine        int      // строка закрывающей скобки
	Listen         []string // аргументы каждой директивы listen, через пробел
	ServerName     []string
	SSLCertificate string
	// ACMERoot — root из location …acme-challenge… этого блока, если он есть.
	ACMERoot string
	// Redirects — на уровне server есть return: он срабатывает раньше
	// любого location, и вставленный location до запроса не доживёт.
	Redirects bool
}

// Ports — порты, на которых слушает блок.
func (s NginxServer) Ports() []int {
	var ports []int
	for _, l := range s.Listen {
		fields := strings.Fields(l)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "unix:") {
			continue
		}
		addr := fields[0]
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			addr = addr[i+1:]
		}
		if p, err := strconv.Atoi(addr); err == nil {
			ports = append(ports, p)
		}
	}
	return ports
}

// ListensOn — слушает ли блок порт.
func (s NginxServer) ListensOn(port int) bool {
	for _, p := range s.Ports() {
		if p == port {
			return true
		}
	}
	return false
}

// SSL — есть ли у блока listen … ssl.
func (s NginxServer) SSL() bool {
	for _, l := range s.Listen {
		fields := strings.Fields(l)
		for _, w := range fields[min(1, len(fields)):] {
			if w == "ssl" {
				return true
			}
		}
	}
	return false
}

// defaultServer — блок помечен default_server на порту.
func (s NginxServer) defaultServer(port int) bool {
	for _, l := range s.Listen {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		addr := fields[0]
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			addr = addr[i+1:]
		}
		if p, err := strconv.Atoi(addr); err != nil || p != port {
			continue
		}
		for _, w := range fields[1:] {
			if w == "default_server" {
				return true
			}
		}
	}
	return false
}

// NamedFor — упомянут ли домен в server_name.
func (s NginxServer) NamedFor(domain string) bool {
	for _, n := range s.ServerName {
		if strings.EqualFold(n, domain) {
			return true
		}
	}
	return false
}

type token struct {
	kind byte // 'w' слово, '{', '}', ';'
	text string
	off  int
	line int
}

// tokenize режет конфиг nginx на слова и скобки. Комментарии (# до конца
// строки в начале слова) отбрасываются, строки в кавычках — одно слово.
func tokenize(src string) []token {
	var toks []token
	line := 1
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '{' || c == '}' || c == ';':
			toks = append(toks, token{kind: c, text: string(c), off: i, line: line})
			i++
		case c == '"' || c == '\'':
			start, startLine := i, line
			i++
			var b strings.Builder
			for i < len(src) && src[i] != c {
				if src[i] == '\\' && i+1 < len(src) {
					i++
				}
				if src[i] == '\n' {
					line++
				}
				b.WriteByte(src[i])
				i++
			}
			i++ // закрывающая кавычка
			toks = append(toks, token{kind: 'w', text: b.String(), off: start, line: startLine})
		default:
			start := i
			for i < len(src) {
				ch := src[i]
				if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '{' || ch == '}' {
					// «${имя}» — переменная, скобки внутри слова.
					if ch == '{' && i > start && src[i-1] == '$' {
						for i < len(src) && src[i] != '}' {
							i++
						}
						i++
						continue
					}
					break
				}
				i++
			}
			toks = append(toks, token{kind: 'w', text: src[start:min(i, len(src))], off: start, line: line})
		}
	}
	return toks
}

var acmeRootRe = regexp.MustCompile(`location\s+[^{;]*acme-challenge[^{;]*\{\s*root\s+([^;\s]+)\s*;`)

type parsedServer struct {
	NginxServer
	startOff, endOff int // смещение слова server и закрывающей скобки
}

func parseServers(file, src string) []parsedServer {
	var out []parsedServer
	var words []token
	depth, serverDepth := 0, 0
	var cur *parsedServer
	for _, t := range tokenize(src) {
		switch t.kind {
		case 'w':
			words = append(words, t)
		case '{':
			if cur == nil && len(words) == 1 && words[0].text == "server" {
				cur = &parsedServer{startOff: words[0].off}
				cur.File, cur.StartLine = file, words[0].line
				serverDepth = depth + 1
			}
			depth++
			words = nil
		case ';':
			if cur != nil && depth == serverDepth && len(words) > 0 {
				args := make([]string, 0, len(words)-1)
				for _, w := range words[1:] {
					args = append(args, w.text)
				}
				switch words[0].text {
				case "listen":
					cur.Listen = append(cur.Listen, strings.Join(args, " "))
				case "server_name":
					cur.ServerName = append(cur.ServerName, args...)
				case "ssl_certificate":
					if len(args) > 0 {
						cur.SSLCertificate = args[0]
					}
				case "return":
					cur.Redirects = true
				}
			}
			words = nil
		case '}':
			depth--
			if cur != nil && depth == serverDepth-1 {
				cur.endOff, cur.EndLine = t.off, t.line
				if m := acmeRootRe.FindStringSubmatch(src[cur.startOff:cur.endOff]); m != nil {
					cur.ACMERoot = m[1]
				}
				out = append(out, *cur)
				cur = nil
			}
			words = nil
		}
	}
	return out
}

// FindServers разбирает dir/conf.d/*.conf и dir/sites-enabled/* (только
// чтение) в том порядке, в каком их читает nginx: в Debian и Ubuntu
// nginx.conf подключает `include /etc/nginx/conf.d/*.conf;` раньше
// `include /etc/nginx/sites-enabled/*;`. Порядок важен: из блоков с одним
// server_name на порту nginx берёт первый. Отсутствующий каталог — не ошибка.
func FindServers(dir string) ([]NginxServer, error) {
	var files []string
	for _, pat := range []string{"conf.d/*.conf", "sites-enabled/*"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		sort.Strings(m)
		files = append(files, m...)
	}
	var servers []NginxServer
	for _, f := range files {
		if isBackupName(f) {
			continue
		}
		st, err := os.Stat(f)
		if err != nil || st.IsDir() {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("чтение %s: %w", f, err)
		}
		for _, p := range parseServers(f, string(b)) {
			servers = append(servers, p.NginxServer)
		}
	}
	return servers, nil
}

// isBackupName — имя похоже на старую копию .bak-… (прежние версии мастера
// клали их рядом с конфигом, и nginx загружал их как конфиги).
func isBackupName(file string) bool {
	return strings.Contains(path.Base(filepath.ToSlash(file)), ".bak-")
}

func normalizeBase(basePath string) string {
	p := "/" + strings.Trim(basePath, "/")
	if p == "/" {
		return "/"
	}
	return p + "/"
}

// Snippet — фрагмент для чужого server-блока. proxy_pass без пути: nginx
// передаёт URI как есть, префикс снимает сама панель (base_path). Под тем
// же префиксом лежат портал /p/ и скачивания /dl/, отдельных location не нужно.
func Snippet(basePath, upstream string) string {
	loc := normalizeBase(basePath)
	var b strings.Builder
	if loc != "/" {
		fmt.Fprintf(&b, "location = %s { return 301 %s; }\n", strings.TrimSuffix(loc, "/"), loc)
	}
	fmt.Fprintf(&b, "location ^~ %s {\n", loc)
	fmt.Fprintf(&b, "    proxy_pass http://%s;\n", upstream)
	b.WriteString("    proxy_set_header Host $host;\n")
	b.WriteString("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("    proxy_set_header X-Forwarded-Proto $scheme;\n")
	b.WriteString("    proxy_read_timeout 900s;\n")
	b.WriteString("    client_max_body_size 2m;\n")
	b.WriteString("}\n")
	return b.String()
}

// AcmeSnippet — location для проверки домена certbot'ом. Остаётся и после
// выпуска: certbot запоминает webroot и по нему же продлевает сертификат.
func AcmeSnippet(webroot string) string {
	return fmt.Sprintf("location ^~ /.well-known/acme-challenge/ {\n    root %s;\n}\n", webroot)
}

// ServerBlock — отдельный server на своём порту (файл sites-available/azpanel).
func ServerBlock(port int, cert, key, serverName string) string {
	if serverName == "" {
		serverName = "_"
	}
	var b strings.Builder
	b.WriteString("# azpanel: отдельный порт панели\nserver {\n")
	fmt.Fprintf(&b, "    listen %d ssl;\n", port)
	fmt.Fprintf(&b, "    server_name %s;\n\n", serverName)
	fmt.Fprintf(&b, "    ssl_certificate     %s;\n", cert)
	fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", key)
	b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n\n")
	fmt.Fprintf(&b, "    include %s;\n", SnippetPath)
	b.WriteString("}\n")
	return b.String()
}

func includeLine(snippet string) string {
	return "include " + snippet + "; " + IncludeMarker
}

// AddInclude — текст src с одной строкой include перед закрывающей скобкой
// блока server. Повторный вызов текст не меняет. Блок ищется по номеру
// строки server.StartLine.
func AddInclude(file, src string, server NginxServer, snippet string) (string, error) {
	var target *parsedServer
	for _, p := range parseServers(file, src) {
		if p.StartLine == server.StartLine {
			p := p
			target = &p
		}
	}
	if target == nil {
		return "", fmt.Errorf("в %s нет блока server со строки %d: файл изменился", file, server.StartLine)
	}
	line := includeLine(snippet)
	if strings.Contains(src[target.startOff:target.endOff], line) {
		return src, nil
	}
	ls := strings.LastIndex(src[:target.endOff], "\n") + 1
	prefix := src[ls:target.endOff]
	if strings.TrimSpace(prefix) != "" {
		return "", fmt.Errorf("в %s закрывающая скобка блока server не на отдельной строке", file)
	}
	indent := prefix + blockIndent(src[target.startOff:ls])
	return src[:ls] + indent + line + "\n" + src[ls:], nil
}

// blockIndent — отступ внутри блока по ближайшей выше строке с директивой
// (не комментарий); нет такой — четыре пробела.
func blockIndent(head string) string {
	lines := strings.Split(strings.TrimRight(head, "\n"), "\n")
	for i := len(lines) - 1; i > 0; i-- {
		l := lines[i]
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return l[:len(l)-len(strings.TrimLeft(l, " \t"))]
	}
	return "    "
}

// DropInclude — текст src без строки include с меткой azpanel.
func DropInclude(src, snippet string) string {
	line := includeLine(snippet)
	var b strings.Builder
	for _, l := range strings.SplitAfter(src, "\n") {
		if strings.TrimSpace(l) != line {
			b.WriteString(l)
		}
	}
	return b.String()
}

// InsertInclude — AddInclude над файлом на диске.
func InsertInclude(file string, server NginxServer, snippet string) error {
	return editFile(os.ReadFile, writeKeepOrNew, file, func(src string) (string, error) {
		return AddInclude(file, src, server, snippet)
	})
}

// RemoveInclude — DropInclude над файлом на диске; строки нет — не ошибка.
func RemoveInclude(file, snippet string) error {
	return editFile(os.ReadFile, writeKeepOrNew, file, func(src string) (string, error) {
		return DropInclude(src, snippet), nil
	})
}

func editFile(read func(string) ([]byte, error), write func(string, []byte, os.FileMode) error, file string, edit func(string) (string, error)) error {
	b, err := read(file)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", file, err)
	}
	out, err := edit(string(b))
	if err != nil {
		return err
	}
	if out == string(b) {
		return nil
	}
	return write(file, []byte(out), 0o644)
}

// Nginx — применение правок к nginx. Всё, что меняет систему, идёт через
// поля, в тестах они подменяются.
type Nginx struct {
	Dir string // корень конфига, по умолчанию /etc/nginx
	// BackupDir — куда ложатся копии правленых файлов. Только вне каталогов,
	// которые читает nginx: sites-enabled/* подключается целиком, и копия
	// файла стала бы вторым конфигом.
	BackupDir string
	ReadFile  func(path string) ([]byte, error)
	WriteFile func(path string, data []byte, perm os.FileMode) error
	MkdirAll  func(path string, perm os.FileMode) error
	Remove    func(path string) error
	Symlink   func(target, link string) error
	Readlink  func(link string) (string, error)
	Run       func(name string, args ...string) ([]byte, error) // вывод — общий
	Now       func() time.Time
}

func runCombined(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// writeKeepOrNew пишет атомарно, сохраняя владельца и права существующего файла.
// Символьная ссылка (sites-enabled/* -> sites-available/*) не заменяется
// обычным файлом: запись идёт в её цель.
func writeKeepOrNew(p string, data []byte, perm os.FileMode) error {
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	if _, err := os.Stat(p); err == nil {
		return fsutil.WriteFileKeepMeta(p, data)
	}
	return fsutil.WriteFileAtomic(p, data, perm)
}

// NewNginx — рабочий вариант на реальной системе.
func NewNginx() *Nginx {
	return &Nginx{
		Dir:       NginxDir,
		ReadFile:  os.ReadFile,
		WriteFile: writeKeepOrNew,
		MkdirAll:  os.MkdirAll,
		Remove:    os.Remove,
		Symlink:   os.Symlink,
		Readlink:  os.Readlink,
		BackupDir: path.Join(filepath.ToSlash(paths.Backup()), "nginx"),
		Run:       runCombined,
		Now:       time.Now,
	}
}

func (n *Nginx) backupDir() string {
	if n.BackupDir == "" {
		return path.Join(filepath.ToSlash(paths.Backup()), "nginx")
	}
	return n.BackupDir
}

func (n *Nginx) dir() string {
	if n.Dir == "" {
		return NginxDir
	}
	return n.Dir
}

// Apply: копии файлов в BackupDir (<имя>.<UTC-время>), change, nginx -t. Не
// прошёл — все файлы возвращаются (созданные change и копии удаляются), ошибка
// с выводом nginx. Прошёл — systemctl reload nginx.
func (n *Nginx) Apply(files []string, change func() error) error {
	return n.apply(files, nil, change)
}

// apply: links — символьные ссылки, которыми управляет change; их содержимое
// не копируется, откат возвращает прежнюю цель (или удаляет новую ссылку).
func (n *Nginx) apply(files, links []string, change func() error) error {
	type saved struct {
		data    []byte
		existed bool
	}
	before := make(map[string]saved, len(files))
	prevLink := make(map[string]string, len(links))
	stamp := n.Now().UTC().Format("20060102T150405Z")
	var copies []string // копии, созданные этим вызовом
	dropCopies := func() {
		for _, c := range copies {
			_ = n.Remove(c)
		}
	}
	for _, f := range files {
		data, err := n.ReadFile(f)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				before[f] = saved{}
				continue
			}
			dropCopies()
			return fmt.Errorf("чтение %s: %w", f, err)
		}
		before[f] = saved{data: data, existed: true}
		bak := path.Join(n.backupDir(), path.Base(filepath.ToSlash(f))+"."+stamp)
		// Копия в ту же секунду уже есть — она исходная, не затираем.
		if _, err := n.ReadFile(bak); err != nil {
			if err := n.MkdirAll(n.backupDir(), 0o700); err != nil {
				dropCopies()
				return fmt.Errorf("каталог копий %s: %w", n.backupDir(), err)
			}
			if err := n.WriteFile(bak, data, 0o600); err != nil {
				dropCopies()
				return fmt.Errorf("копия %s: %w", bak, err)
			}
			copies = append(copies, bak)
		}
	}
	for _, l := range links {
		if n.Readlink != nil {
			if target, err := n.Readlink(l); err == nil {
				prevLink[l] = target
			}
		}
	}
	rollback := func() error {
		var errs []error
		for _, f := range files {
			s := before[f]
			if s.existed {
				if err := n.WriteFile(f, s.data, 0o644); err != nil {
					errs = append(errs, err)
				}
			} else if err := n.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		for _, l := range links {
			if err := n.Remove(l); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			if target, ok := prevLink[l]; ok {
				if err := n.Symlink(target, l); err != nil {
					errs = append(errs, err)
				}
			}
		}
		return errors.Join(errs...)
	}
	fail := func(cause error) error {
		rerr := rollback()
		dropCopies()
		if rerr != nil {
			return fmt.Errorf("%w; возврат файлов не удался: %v", cause, rerr)
		}
		return cause
	}
	if err := change(); err != nil {
		return fail(err)
	}
	if out, err := n.Run("nginx", "-t"); err != nil {
		return fail(fmt.Errorf("nginx -t не прошёл, файлы возвращены: %w\n%s", err, strings.TrimSpace(string(out))))
	}
	if out, err := n.Run("systemctl", "reload", "nginx"); err != nil {
		return fmt.Errorf("systemctl reload nginx: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// editInclude правит файл через поля Nginx.
func (n *Nginx) editInclude(file string, edit func(string) (string, error)) error {
	return editFile(n.ReadFile, n.WriteFile, file, edit)
}

// Enable вставляет панель в выбранный чужой server-блок.
func (n *Nginx) Enable(server NginxServer, basePath, upstream string) error {
	return n.Apply([]string{server.File, SnippetPath}, func() error {
		if err := n.MkdirAll(path.Dir(SnippetPath), 0o755); err != nil {
			return err
		}
		if err := n.WriteFile(SnippetPath, []byte(Snippet(basePath, upstream)), 0o644); err != nil {
			return err
		}
		return n.editInclude(server.File, func(src string) (string, error) {
			return AddInclude(server.File, src, server, SnippetPath)
		})
	})
}

// EnableOwnPort заводит отдельный server на своём порту.
func (n *Nginx) EnableOwnPort(port int, cert, key, serverName, basePath, upstream string) error {
	avail := path.Join(n.dir(), ownPortFile)
	link := path.Join(n.dir(), ownPortLink)
	return n.apply([]string{SnippetPath, avail}, []string{link}, func() error {
		if err := n.MkdirAll(path.Dir(SnippetPath), 0o755); err != nil {
			return err
		}
		if err := n.WriteFile(SnippetPath, []byte(Snippet(basePath, upstream)), 0o644); err != nil {
			return err
		}
		if err := n.WriteFile(avail, []byte(ServerBlock(port, cert, key, serverName)), 0o644); err != nil {
			return err
		}
		if err := n.Remove(link); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return n.Symlink(avail, link)
	})
}

// UpdateSnippet переписывает фрагмент панели под новый префикс и адрес, если
// фрагмент стоит (done=true). Нет фрагмента — nginx не трогается (done=false).
// Правка идёт через Apply: nginx -t, при отказе файл возвращается.
func (n *Nginx) UpdateSnippet(basePath, upstream string) (done bool, err error) {
	cur, err := n.ReadFile(SnippetPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	want := Snippet(basePath, upstream)
	if string(cur) == want {
		return true, nil
	}
	return true, n.Apply([]string{SnippetPath}, func() error {
		return n.WriteFile(SnippetPath, []byte(want), 0o644)
	})
}

// Disable — обратное Enable/EnableOwnPort: строки include (во всех
// перечисленных файлах разом: пока одна ещё подключает фрагмент, удалять его
// нельзя), фрагменты, файл и ссылка отдельного порта. Пустые имена файлов
// пропускаются.
func (n *Nginx) Disable(includeFiles ...string) error {
	avail := path.Join(n.dir(), ownPortFile)
	link := path.Join(n.dir(), ownPortLink)
	var edit []string
	seen := map[string]bool{}
	for _, f := range includeFiles {
		if f != "" && !seen[f] {
			seen[f] = true
			edit = append(edit, f)
		}
	}
	files := append(append([]string{}, edit...), SnippetPath, AcmeSnippetPath, avail)
	return n.apply(files, []string{link}, func() error {
		for _, f := range edit {
			err := n.editInclude(f, func(src string) (string, error) {
				return DropInclude(DropInclude(src, SnippetPath), AcmeSnippetPath), nil
			})
			if err != nil {
				return err
			}
		}
		for _, f := range []string{link, avail, SnippetPath, AcmeSnippetPath} {
			if err := n.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	})
}
