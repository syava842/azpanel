package install

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/antizapret"
)

type relocEnv struct {
	o     RelocateOptions
	calls []string
	fail  string // команда, которая вернёт ошибку
	nginx string // конфиг nginx с путём сертификата
	out   *bytes.Buffer
}

func newRelocEnv(t *testing.T) *relocEnv {
	t.Helper()
	base := t.TempDir()
	e := &relocEnv{out: &bytes.Buffer{}}
	from, to := filepath.Join(base, "opt", "azpanel"), filepath.Join(base, "root", "azpanel")
	units, scripts, ngx := filepath.Join(base, "units"), filepath.Join(base, "scripts"), filepath.Join(base, "nginx")
	fromS := filepath.ToSlash(from)
	write := func(p, body string, mode os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(from, "bin", "azpanel"), "BINARY", 0o755)
	write(filepath.Join(from, "etc", "config.toml"), "[panel]\nlisten = \"127.0.0.1:8080\"\n", 0o600)
	write(filepath.Join(from, "etc", "install.env"), "BACKUP_DIR="+fromS+"/backup\nMODE=panel+node\n", 0o600)
	write(filepath.Join(from, "data", "tasks.json"), `{"log":"`+fromS+`/log/tasks/a.log"}`, 0o640)
	write(filepath.Join(from, "data", "limits.json"), `{"limits":{}}`, 0o600)
	write(filepath.Join(units, nodeUnitName), "OLD NODE "+fromS+"\n", 0o644)
	write(filepath.Join(units, panelUnitName), "OLD PANEL "+fromS+"\n", 0o644)
	if _, err := (antizapret.HookFiles{ScriptsDir: mkdir(t, scripts), Binary: fromS + "/bin/azpanel"}).Ensure(); err != nil {
		t.Fatal(err)
	}
	e.nginx = filepath.Join(ngx, "sites-available", "azpanel")
	write(e.nginx, "ssl_certificate "+fromS+"/etc/tls/cert.pem;\n", 0o644)
	write(filepath.Join(ngx, "sites-available", "other"), "server_name example.com;\n", 0o644)
	e.o = RelocateOptions{
		From: from, To: to, UnitDir: units, ScriptsDir: scripts,
		HookBinary: filepath.Join(base, "lib", "azpanel", "azpanel"),
		NginxGlobs: []string{filepath.Join(ngx, "sites-available", "*")},
		Out:        e.out,
		Run: func(name string, args ...string) error {
			c := name + " " + strings.Join(args, " ")
			e.calls = append(e.calls, c)
			if e.fail != "" && c == e.fail {
				return errors.New("сбой " + c)
			}
			return nil
		},
		Wait: func() error { e.calls = append(e.calls, "wait"); return nil },
	}
	if runtime.GOOS == "linux" {
		e.o.LinkPath = filepath.Join(base, "bin", "azpanel")
		if err := os.MkdirAll(filepath.Dir(e.o.LinkPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(from, "bin", "azpanel"), e.o.LinkPath); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func mkdir(t *testing.T, d string) string {
	t.Helper()
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRelocate(t *testing.T) {
	e := newRelocEnv(t)
	o := e.o
	fromS, toS := filepath.ToSlash(o.From), filepath.ToSlash(o.To)
	if err := Relocate(o); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if _, err := os.Stat(o.From); !os.IsNotExist(err) {
		t.Fatal("прежний каталог остался")
	}
	if read(t, filepath.Join(o.To, "bin", "azpanel")) != "BINARY" || read(t, filepath.Join(o.To, "data", "limits.json")) != `{"limits":{}}` {
		t.Fatal("содержимое каталога не перенесено")
	}
	for _, rel := range []string{"etc/install.env", "data/tasks.json"} {
		if s := read(t, filepath.Join(o.To, filepath.FromSlash(rel))); strings.Contains(s, fromS) || !strings.Contains(s, toS) {
			t.Errorf("%s: путь не заменён: %s", rel, s)
		}
	}
	if runtime.GOOS == "linux" {
		if st, _ := os.Stat(filepath.Join(o.To, "etc", "install.env")); st.Mode().Perm() != 0o600 {
			t.Errorf("права install.env: %v", st.Mode().Perm())
		}
		if cur, err := os.Readlink(o.LinkPath); err != nil || cur != filepath.Join(o.To, "bin", "azpanel") {
			t.Errorf("ссылка команды: %q %v", cur, err)
		}
	}
	for _, name := range []string{nodeUnitName, panelUnitName} {
		u := read(t, filepath.Join(o.UnitDir, name))
		if !strings.Contains(u, "ExecStart="+toS+"/bin/azpanel ") || strings.Contains(u, fromS) || !strings.Contains(u, "ReadWritePaths="+toS) {
			t.Errorf("%s:\n%s", name, u)
		}
	}
	if u := read(t, filepath.Join(o.UnitDir, nodeUnitName)); !strings.Contains(u, " -"+filepath.ToSlash(filepath.Dir(o.HookBinary))+"\n") {
		t.Errorf("агенту не разрешена запись в копию для хука:\n%s", u)
	}
	if _, err := os.Stat(filepath.Join(o.UnitDir, proxyUnitName)); !os.IsNotExist(err) {
		t.Error("создан юнит прокси, которого не было")
	}
	if read(t, o.HookBinary) != "BINARY" {
		t.Error("копия программы для хука не создана")
	}
	hook := read(t, filepath.Join(o.ScriptsDir, "custom-client-connect.sh"))
	if !strings.Contains(hook, filepath.ToSlash(o.HookBinary)+" hook connect") || strings.Contains(hook, fromS) {
		t.Errorf("хук:\n%s", hook)
	}
	if s := read(t, e.nginx); s != "ssl_certificate "+toS+"/etc/tls/cert.pem;\n" {
		t.Errorf("nginx: %s", s)
	}
	want := "systemctl stop azpanel-panel|systemctl stop azpanel-node|nginx -t|systemctl reload nginx|systemctl daemon-reload|systemctl start azpanel-node|wait|systemctl start azpanel-panel"
	if got := strings.Join(e.calls, "|"); got != want {
		t.Errorf("вызовы:\n%s\nждали:\n%s", got, want)
	}
}

// nginx -t не прошёл: каталог, юниты, хук и конфиг nginx возвращаются, службы
// запускаются из прежнего каталога.
func TestRelocateRollsBack(t *testing.T) {
	e := newRelocEnv(t)
	o := e.o
	fromS := filepath.ToSlash(o.From)
	e.fail = "nginx -t"
	err := Relocate(o)
	if err == nil || !strings.Contains(err.Error(), "всё возвращено") {
		t.Fatalf("ошибка: %v", err)
	}
	if _, serr := os.Stat(o.To); !os.IsNotExist(serr) {
		t.Fatal("новый каталог остался")
	}
	if read(t, filepath.Join(o.From, "bin", "azpanel")) != "BINARY" {
		t.Fatal("прежний каталог не возвращён")
	}
	if s := read(t, filepath.Join(o.From, "etc", "install.env")); !strings.Contains(s, "BACKUP_DIR="+fromS+"/backup") {
		t.Errorf("пути в настройках не возвращены: %s", s)
	}
	if u := read(t, filepath.Join(o.UnitDir, nodeUnitName)); u != "OLD NODE "+fromS+"\n" {
		t.Errorf("юнит агента не возвращён:\n%s", u)
	}
	if s := read(t, e.nginx); s != "ssl_certificate "+fromS+"/etc/tls/cert.pem;\n" {
		t.Errorf("nginx не возвращён: %s", s)
	}
	if hook := read(t, filepath.Join(o.ScriptsDir, "custom-client-connect.sh")); !strings.Contains(hook, fromS+"/bin/azpanel hook connect") {
		t.Errorf("хук не возвращён:\n%s", hook)
	}
	tail := strings.Join(e.calls[len(e.calls)-4:], "|")
	if tail != "systemctl daemon-reload|systemctl start azpanel-node|wait|systemctl start azpanel-panel" {
		t.Errorf("службы после возврата: %s", tail)
	}
}

func TestRelocateRefusals(t *testing.T) {
	e := newRelocEnv(t)
	o := e.o
	mkdir(t, o.To)
	if err := Relocate(o); err == nil || !strings.Contains(err.Error(), "уже существует") {
		t.Fatalf("занятый каталог: %v", err)
	}
	o.To += "-2"
	o.From = filepath.Join(filepath.Dir(o.From), "нет")
	if err := Relocate(o); err == nil || !strings.Contains(err.Error(), "переносить нечего") {
		t.Fatalf("нет установки: %v", err)
	}
	if len(e.calls) != 0 {
		t.Fatalf("при отказе вызваны команды: %v", e.calls)
	}
}

func TestSyncFile(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "lib", "azpanel", "azpanel")
	os.WriteFile(src, []byte("v1"), 0o755)
	for _, want := range []string{"v1", "v1", "v2"} {
		if want == "v2" {
			os.WriteFile(src, []byte("v2"), 0o755)
		}
		if err := syncFile(src, dst); err != nil {
			t.Fatal(err)
		}
		if read(t, dst) != want {
			t.Fatalf("копия: %q, ждали %q", read(t, dst), want)
		}
	}
	if runtime.GOOS == "linux" {
		for p, mode := range map[string]os.FileMode{dst: 0o755, filepath.Dir(dst): 0o755} {
			if st, _ := os.Stat(p); st.Mode().Perm() != mode {
				t.Errorf("%s: %v", p, st.Mode().Perm())
			}
		}
	}
}
