package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const testNginxDir = "testdata/nginx"

func TestFindServersRealConfigs(t *testing.T) {
	servers, err := FindServers(testNginxDir)
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string][]NginxServer{}
	for _, s := range servers {
		byFile[filepath.Base(s.File)] = append(byFile[filepath.Base(s.File)], s)
	}
	if len(byFile) != 3 || len(byFile["default"]) != 1 || len(byFile["vpn.test"]) != 2 || len(byFile["warper-web"]) != 2 {
		t.Fatalf("файлы/блоки: %v", byFile)
	}
	var s443 *NginxServer
	for i, s := range byFile["vpn.test"] {
		if s.ListensOn(443) {
			s443 = &byFile["vpn.test"][i]
		}
	}
	if s443 == nil {
		t.Fatal("нет блока vpn.test:443")
	}
	if !s443.SSL() || !s443.NamedFor("vpn.test") || s443.SSLCertificate != "/etc/letsencrypt/live/vpn.test/fullchain.pem" {
		t.Fatalf("блок 443: %+v", *s443)
	}
	if s443.StartLine != 8 || s443.EndLine != 29 {
		t.Fatalf("строки блока 443: %d-%d", s443.StartLine, s443.EndLine)
	}
	// 80 с return: редирект; 80 warper-web: location проверки с root.
	for _, s := range byFile["vpn.test"] {
		if s.ListensOn(80) && !s.Redirects {
			t.Fatal("блок 80 vpn.test должен быть редиректом")
		}
	}
	var w80 NginxServer
	for _, s := range byFile["warper-web"] {
		if s.ListensOn(80) {
			w80 = s
		}
	}
	if w80.ACMERoot != "/var/www/html" {
		t.Fatalf("ACMERoot=%q", w80.ACMERoot)
	}
	// default: комментарии не мешают, listen с [::].
	d := byFile["default"][0]
	if len(d.Listen) != 2 || !d.ListensOn(80) || !d.NamedFor("_") {
		t.Fatalf("default: %+v", d)
	}
	for _, s := range byFile["warper-web"] {
		if s.ListensOn(6060) && !s.SSL() {
			t.Fatal("6060 должен быть ssl")
		}
	}
}

func TestTokenizerCommentsAndQuotes(t *testing.T) {
	src := "# server { listen 1;\nserver {\n  server_name \"a;b{c}\" d; # }\n  location / { return 200 '}'; }\n  listen 8443 ssl;\n}\nserver { listen 81; }\n"
	ps := parseServers("x", src)
	if len(ps) != 2 {
		t.Fatalf("блоков %d", len(ps))
	}
	if ps[0].ServerName[0] != "a;b{c}" || !ps[0].ListensOn(8443) || ps[0].EndLine != 6 {
		t.Fatalf("%+v", ps[0])
	}
	if ps[0].Redirects {
		t.Fatal("return внутри location не считается")
	}
}

func copyTestdata(t *testing.T, name string) (string, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testNginxDir, "sites-enabled", name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p, string(b)
}

func server443(t *testing.T, file string) NginxServer {
	t.Helper()
	b, _ := os.ReadFile(file)
	for _, p := range parseServers(file, string(b)) {
		if p.ListensOn(443) {
			return p.NginxServer
		}
	}
	t.Fatal("нет блока 443")
	return NginxServer{}
}

func TestInsertRemoveIncludeRoundTrip(t *testing.T) {
	file, orig := copyTestdata(t, "vpn.test")
	srv := server443(t, file)
	if err := InsertInclude(file, srv, SnippetPath); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(file)
	line := "    include /etc/nginx/snippets/azpanel.conf; # azpanel\n"
	if strings.Count(string(got), "# azpanel") != 1 || !strings.Contains(string(got), line+"}\n") {
		t.Fatalf("вставка:\n%s", got)
	}
	// Повтор не дублирует.
	if err := InsertInclude(file, srv, SnippetPath); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(file)
	if string(again) != string(got) {
		t.Fatal("повторная вставка изменила файл")
	}
	if err := RemoveInclude(file, SnippetPath); err != nil {
		t.Fatal(err)
	}
	back, _ := os.ReadFile(file)
	if string(back) != orig {
		t.Fatalf("после удаления файл не совпал с исходным:\n%s", back)
	}
	if err := RemoveInclude(file, SnippetPath); err != nil {
		t.Fatal("удаление отсутствующей строки — не ошибка:", err)
	}
}

func TestAddIncludeTabIndentAndStale(t *testing.T) {
	file, orig := copyTestdata(t, "default")
	srv := parseServers(file, orig)[0].NginxServer
	out, err := AddInclude(file, orig, srv, SnippetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\n\tinclude /etc/nginx/snippets/azpanel.conf; # azpanel\n}") {
		t.Fatalf("отступ:\n%s", out)
	}
	if DropInclude(out, SnippetPath) != orig {
		t.Fatal("DropInclude не вернул исходник")
	}
	srv.StartLine = 999
	if _, err := AddInclude(file, orig, srv, SnippetPath); err == nil {
		t.Fatal("устаревший номер строки должен давать ошибку")
	}
}

func TestSnippetKeepsPrefix(t *testing.T) {
	s := Snippet("/azpanel", "127.0.0.1:8080")
	for _, want := range []string{
		"location ^~ /azpanel/ {",
		"proxy_pass http://127.0.0.1:8080;\n",
		"proxy_set_header Host $host;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Proto $scheme;",
		"return 301 /azpanel/;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %q:\n%s", want, s)
		}
	}
	// proxy_pass без пути: иначе nginx срежет префикс.
	if strings.Contains(s, "proxy_pass http://127.0.0.1:8080/") {
		t.Fatal("proxy_pass не должен заканчиваться путём")
	}
	if !strings.Contains(Snippet("/", "127.0.0.1:8080"), "location ^~ / {") {
		t.Fatal("корневой префикс")
	}
}

func TestServerBlockParses(t *testing.T) {
	ps := parseServers("x", ServerBlock(8443, "/c.pem", "/k.pem", ""))
	if len(ps) != 1 || !ps[0].ListensOn(8443) || !ps[0].SSL() || ps[0].SSLCertificate != "/c.pem" || !ps[0].NamedFor("_") {
		t.Fatalf("%+v", ps)
	}
}

// fakeSys — подмена файловой системы и команд.
type fakeSys struct {
	files   map[string][]byte
	links   map[string]string
	cmds    []string
	nginxT  error
	reloadE error
	initial map[string]bool // файлы, которые были до правок
	stray   []string        // посторонние файлы в каталогах, которые читает nginx
}

// strayFiles — файлы в sites-enabled, conf.d и snippets, которых не было до
// правок и которые не наши: nginx подключает эти каталоги целиком.
func (f *fakeSys) strayFiles() []string {
	var out []string
	for p := range f.files {
		for _, d := range []string{"/etc/nginx/sites-enabled/", "/etc/nginx/conf.d/", "/etc/nginx/snippets/"} {
			if !strings.HasPrefix(p, d) || f.initial[p] {
				continue
			}
			if p == SnippetPath || p == AcmeSnippetPath {
				continue
			}
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func newFakeNginx(files map[string]string) (*Nginx, *fakeSys) {
	f := &fakeSys{files: map[string][]byte{}, links: map[string]string{}, initial: map[string]bool{}}
	for k, v := range files {
		f.files[k] = []byte(v)
		f.initial[k] = true
	}
	n := &Nginx{
		Dir: "/etc/nginx",
		ReadFile: func(p string) ([]byte, error) {
			if b, ok := f.files[p]; ok {
				return b, nil
			}
			return nil, fs.ErrNotExist
		},
		WriteFile: func(p string, d []byte, _ os.FileMode) error { f.files[p] = append([]byte(nil), d...); return nil },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		Remove: func(p string) error {
			if _, ok := f.files[p]; ok {
				delete(f.files, p)
				return nil
			}
			if _, ok := f.links[p]; ok {
				delete(f.links, p)
				return nil
			}
			return fs.ErrNotExist
		},
		Symlink: func(target, link string) error { f.links[link] = target; return nil },
		Readlink: func(link string) (string, error) {
			if t, ok := f.links[link]; ok {
				return t, nil
			}
			return "", fs.ErrNotExist
		},
		BackupDir: "/opt/azpanel/backup/nginx",
		Run: func(name string, args ...string) ([]byte, error) {
			f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
			if name == "nginx" {
				// Настоящий nginx -t загрузил бы всё, что лежит в этих каталогах.
				f.stray = append(f.stray, f.strayFiles()...)
				if f.nginxT != nil {
					return []byte("unexpected \"}\" in /etc/nginx/x:1"), f.nginxT
				}
			} else if name == "systemctl" && f.reloadE != nil {
				return nil, f.reloadE
			}
			return nil, nil
		},
		Now: func() time.Time { return time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC) },
	}
	return n, f
}

func TestEnableAndDisable(t *testing.T) {
	_, orig := copyTestdata(t, "vpn.test")
	const file = "/etc/nginx/sites-enabled/vpn.test"
	n, f := newFakeNginx(map[string]string{file: orig})
	srv := parseServers(file, orig)[1].NginxServer
	if err := n.Enable(srv, "/azpanel", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.files[file]), "include /etc/nginx/snippets/azpanel.conf; # azpanel") {
		t.Fatal("include не вставлен")
	}
	if !strings.Contains(string(f.files[SnippetPath]), "location ^~ /azpanel/") {
		t.Fatal("фрагмент не записан")
	}
	if string(f.files["/opt/azpanel/backup/nginx/vpn.test.20261102T000000Z"]) != orig {
		t.Fatalf("нет копии в каталоге копий: %v", f.keys())
	}
	if strings.Join(f.cmds, "|") != "nginx -t|systemctl reload nginx" {
		t.Fatalf("команды: %v", f.cmds)
	}
	if err := n.Disable(file); err != nil {
		t.Fatal(err)
	}
	if string(f.files[file]) != orig {
		t.Fatal("после Disable файл не совпал с исходным")
	}
	if len(f.stray) != 0 || len(f.strayFiles()) != 0 {
		t.Fatalf("в каталогах nginx появились посторонние файлы: %v %v", f.stray, f.strayFiles())
	}
	if _, ok := f.files[SnippetPath]; ok {
		t.Fatal("фрагмент остался")
	}
}

func TestEnableNginxTFailureRestores(t *testing.T) {
	_, orig := copyTestdata(t, "vpn.test")
	const file = "/etc/nginx/sites-enabled/vpn.test"
	n, f := newFakeNginx(map[string]string{file: orig})
	f.nginxT = errors.New("exit status 1")
	srv := parseServers(file, orig)[1].NginxServer
	err := n.Enable(srv, "/azpanel", "127.0.0.1:8080")
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("ожидалась ошибка с выводом nginx: %v", err)
	}
	if string(f.files[file]) != orig {
		t.Fatal("файл не восстановлен")
	}
	if _, ok := f.files[SnippetPath]; ok {
		t.Fatal("созданный фрагмент не удалён")
	}
	if len(f.strayFiles()) != 0 || len(f.keysUnder("/opt/azpanel/backup/nginx/")) != 0 {
		t.Fatalf("после отката остались копии: %v", f.keys())
	}
	for _, c := range f.cmds {
		if strings.Contains(c, "reload") {
			t.Fatal("reload после неудачного nginx -t")
		}
	}
}

func TestEnableOwnPort(t *testing.T) {
	n, f := newFakeNginx(nil)
	if err := n.EnableOwnPort(8443, "/c.pem", "/k.pem", "", "/azpanel", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.files["/etc/nginx/sites-available/azpanel"]), "listen 8443 ssl;") {
		t.Fatal("нет server на порту")
	}
	if f.links["/etc/nginx/sites-enabled/azpanel"] != "/etc/nginx/sites-available/azpanel" {
		t.Fatalf("ссылка: %v", f.links)
	}
	if err := n.Disable(""); err != nil {
		t.Fatal(err)
	}
	if len(f.links) != 0 {
		t.Fatalf("ссылка осталась: %v", f.links)
	}
	for _, p := range []string{SnippetPath, "/etc/nginx/sites-available/azpanel"} {
		if _, ok := f.files[p]; ok {
			t.Fatalf("%s остался", p)
		}
	}
}

func TestApplyReloadErrorReported(t *testing.T) {
	n, f := newFakeNginx(nil)
	f.reloadE = errors.New("boom")
	err := n.Apply(nil, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "reload") {
		t.Fatal(err)
	}
}

func (f *fakeSys) keys() []string {
	var out []string
	for p := range f.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (f *fakeSys) keysUnder(prefix string) []string {
	var out []string
	for _, p := range f.keys() {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	return out
}

// Копии лежат вне каталогов nginx: ни uninstall, ни поиск include их не видят,
// и nginx -t не загружает их как конфиги (C1).
func TestBackupsOutsideNginxDirs(t *testing.T) {
	_, orig := copyTestdata(t, "default")
	const file = "/etc/nginx/sites-enabled/default"
	n, f := newFakeNginx(map[string]string{file: orig})
	srv := parseServers(file, orig)[0].NginxServer
	if err := n.Enable(srv, "/azpanel", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if len(f.stray) != 0 || len(f.strayFiles()) != 0 {
		t.Fatalf("посторонние файлы в каталогах nginx: %v %v", f.stray, f.strayFiles())
	}
	if len(f.keysUnder("/opt/azpanel/backup/nginx/")) == 0 {
		t.Fatal("копий нет")
	}
	// Другой момент времени: копии копятся только в каталоге копий.
	n.Now = func() time.Time { return time.Date(2026, 11, 3, 1, 2, 3, 0, time.UTC) }
	if err := n.Disable(file); err != nil {
		t.Fatal(err)
	}
	if len(f.stray) != 0 || len(f.strayFiles()) != 0 {
		t.Fatalf("посторонние файлы после Disable: %v %v", f.stray, f.strayFiles())
	}
	if _, ok := f.files["/opt/azpanel/backup/nginx/default.20261103T010203Z"]; !ok {
		t.Fatalf("копия Disable не там: %v", f.keys())
	}
}

// Старая копия .bak-... в sites-enabled поиском блоков не берётся.
func TestFindServersSkipsOldBackups(t *testing.T) {
	dir := t.TempDir()
	_, orig := copyTestdata(t, "default")
	writeReal(t, filepath.Join(dir, "sites-enabled", "default"), orig)
	writeReal(t, filepath.Join(dir, "sites-enabled", "default.bak-20260101"), orig)
	got, err := FindServers(dir)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %d", err, len(got))
	}
}

// Правка файла по символьной ссылке пишет в цель, ссылка остаётся ссылкой (I1).
func TestWriteKeepOrNewKeepsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sites-available", "x")
	link := filepath.Join(dir, "sites-enabled", "x")
	writeReal(t, target, "старое\n")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("символьные ссылки недоступны:", err)
	}
	if err := writeKeepOrNew(link, []byte("новое\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("ссылка заменена файлом: %v %v", st, err)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "новое\n" {
		t.Fatalf("цель не обновлена: %q", b)
	}
}

// Disable по двум файлам с include — один проход: nginx -t видит оба убранными.
func TestDisableTwoIncludeFilesOneApply(t *testing.T) {
	_, orig := copyTestdata(t, "vpn.test")
	const a, b = "/etc/nginx/sites-enabled/a", "/etc/nginx/sites-enabled/b"
	n, f := newFakeNginx(map[string]string{a: orig, b: orig})
	if err := n.Enable(parseServers(a, orig)[1].NginxServer, "/azpanel", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := n.Enable(parseServers(b, orig)[1].NginxServer, "/azpanel", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	f.cmds = nil
	if err := n.Disable(a, b); err != nil {
		t.Fatal(err)
	}
	if string(f.files[a]) != orig || string(f.files[b]) != orig {
		t.Fatal("include остался")
	}
	if strings.Join(f.cmds, "|") != "nginx -t|systemctl reload nginx" {
		t.Fatalf("ожидался один проход: %v", f.cmds)
	}
}

// nginx читает conf.d/*.conf раньше sites-enabled/*: блок домена из conf.d
// побеждает одноимённый блок из sites-enabled, и проверка домена (PlanACME)
// должна идти через него.
func TestFindServersConfDBeforeSitesEnabled(t *testing.T) {
	dir := t.TempDir()
	site := "server {\n    listen 80;\n    server_name vpn.example.org;\n    location / { root /var/www/a; }\n}\n"
	conf := "server {\n    listen 80;\n    server_name vpn.example.org;\n    location ^~ /.well-known/acme-challenge/ {\n        root /var/www/conf;\n    }\n}\n"
	writeReal(t, filepath.Join(dir, "sites-enabled", "a-site"), site)
	writeReal(t, filepath.Join(dir, "conf.d", "z-conf.conf"), conf)
	got, err := FindServers(dir)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %d", err, len(got))
	}
	if filepath.Base(got[0].File) != "z-conf.conf" || filepath.Base(got[1].File) != "a-site" {
		t.Fatalf("порядок блоков: %s, %s", got[0].File, got[1].File)
	}
	plan, err := PlanACME(got, "vpn.example.org", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != ACMEExisting || plan.Webroot != "/var/www/conf" || filepath.Base(plan.Server.File) != "z-conf.conf" {
		t.Fatalf("план взял не первый блок nginx: %+v", plan)
	}
}
