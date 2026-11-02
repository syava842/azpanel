package install

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/config"
)

// useRealNginx направляет мастер на копии конфигов 94.
func (e *wizEnv) useRealNginx() { e.w.Nginx.Dir = testNginxDir }

const fakePassword = "Abcd2345Efgh6789"

// wizEnv — поддельная система: каждое изменение пишется в mut.
type wizEnv struct {
	w       *Wizard
	out     *bytes.Buffer
	mut     []string
	fs      *fakeSys
	files   map[string]string // для Host.ReadFile
	cfg     config.Config
	written config.Config
	admin   struct{ login, pw string }
	envFile []byte
	secrets map[string]string
}

func newWizEnv(t *testing.T, input string, interactive bool, env map[string]string) *wizEnv {
	t.Helper()
	t.Setenv("AZPANEL_ROOT", filepath.Join(t.TempDir(), "opt", "azpanel"))
	e := &wizEnv{out: &bytes.Buffer{}, files: map[string]string{}, cfg: config.Default()}
	n, f := newFakeNginx(nil)
	n.Dir = t.TempDir() // по умолчанию в nginx нет ни одного server
	// Настоящие файлы из testdata видны и nginx через поля.
	filepath.WalkDir(testNginxDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			f.files[p] = b
		}
		return nil
	})
	e.fs = f
	tl := newTestTLS(n, f)
	mark := func(name string) { e.mut = append(e.mut, name) }
	h := Host{
		Geteuid: func() int { return 0 },
		ReadFile: func(p string) ([]byte, error) {
			if p == "/etc/os-release" {
				return []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), nil
			}
			if v, ok := e.files[filepath.Base(p)]; ok {
				return []byte(v), nil
			}
			return nil, fs.ErrNotExist
		},
		Stat:        func(string) (fs.FileInfo, error) { return nil, nil },
		HasSystemd:  func() bool { return true },
		PortBusy:    func(int) bool { return false },
		Port80Owner: func() string { return "nginx" },
		Fetch:       func(string) (string, error) { return "203.0.113.7\n", nil },
		AdminExists: func(string) bool { return false },
		LoadConfig:  func() (config.Config, error) { return e.cfg, nil },

		MkLayout:        func() error { mark("layout"); return nil },
		CopyBinary:      func() error { mark("binary"); return nil },
		WriteConfig:     func(c config.Config) error { mark("config"); e.written = c; return nil },
		EnsureNodeToken: func() error { mark("node-token"); return nil },
		WriteSecrets: func(kv map[string]string) error {
			mark("secrets")
			e.secrets = kv
			return nil
		},
		WriteInstallEnv: func(d []byte) error { mark("install.env"); e.envFile = d; return nil },
		WriteUnit:       func(name, _ string) error { mark("unit " + name); return nil },
		InstallHook:     func() error { mark("hook"); return nil },
		Systemctl:       func(a ...string) error { mark("systemctl " + strings.Join(a, " ")); return nil },
		WaitAgent:       func() error { mark("wait-agent"); return nil },
		WaitPanel:       func(u string) error { mark("wait-panel " + u); return nil },
		CreateAdmin: func(l, p string, _ bool) error {
			mark("admin")
			e.admin.login, e.admin.pw = l, p
			return nil
		},
		OpenFirewall: func(p int) error { mark("firewall"); return nil },
	}
	e.w = &Wizard{
		In: bufio.NewReader(strings.NewReader(input)), Out: e.out, Interactive: interactive,
		Getenv: func(k string) string { return env[k] }, Flags: nil,
		Host: h, Nginx: n, TLS: tl,
		AntiZapretDir: "/root/antizapret", ScriptsDir: "/etc/openvpn/server/scripts",
		NewPassword: func() (string, error) { return fakePassword, nil },
	}
	// Все изменения nginx и системных команд тоже считаются.
	baseRun := n.Run
	n.Run = func(name string, args ...string) ([]byte, error) {
		mark(name + " " + strings.Join(args, " "))
		return baseRun(name, args...)
	}
	return e
}

// Ответы по умолчанию: 11 Enter (вопрос про Telegram не задаётся) и подтверждение.
const defaultScript = "\n\n\n\n\n\n\n\n\n\n"

func TestWizardDefaultsNothingBeforeConfirm(t *testing.T) {
	e := newWizEnv(t, defaultScript+"n\n", true, nil)
	err := e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "отменена") {
		t.Fatalf("ожидалась отмена: %v", err)
	}
	if len(e.mut) != 0 {
		t.Fatalf("до подтверждения вызваны изменения: %v", e.mut)
	}
	out := e.out.String()
	if !strings.Contains(out, "Применить?") || !strings.Contains(out, fakePassword) {
		t.Fatalf("итог не показан или без пароля:\n%s", out)
	}
}

func TestWizardDefaultsApplyOrder(t *testing.T) {
	e := newWizEnv(t, defaultScript+"y\n", true, nil)
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	want := []string{
		"layout", "binary", "config", "node-token",
		"unit azpanel-node.service", "unit azpanel-panel.service", "hook",
		"admin", "install.env",
		"systemctl daemon-reload", "systemctl enable azpanel-node", "systemctl enable azpanel-panel",
		"systemctl restart azpanel-node", "wait-agent", "systemctl restart azpanel-panel",
		"wait-panel http://127.0.0.1:8080/healthz",
	}
	if strings.Join(e.mut, "\n") != strings.Join(want, "\n") {
		t.Fatalf("порядок применения:\n%s\nожидался:\n%s", strings.Join(e.mut, "\n"), strings.Join(want, "\n"))
	}
	if e.admin.login != "admin" || e.admin.pw != fakePassword {
		t.Fatalf("администратор: %+v", e.admin)
	}
	if e.written.Panel.BasePath != "" || e.written.Panel.Listen != "127.0.0.1:8080" {
		t.Fatalf("конфиг: %+v", e.written.Panel)
	}
	// Пароль показан на шаге, в итоге и в конце.
	if n := strings.Count(e.out.String(), fakePassword); n < 2 {
		t.Fatalf("пароль показан %d раз", n)
	}
	if strings.Contains(string(e.envFile), fakePassword) || strings.Contains(string(e.envFile), "PASSWORD") {
		t.Fatalf("секрет попал в install.env:\n%s", e.envFile)
	}
	if !strings.Contains(string(e.envFile), "MODE=panel+node") || !strings.Contains(string(e.envFile), "ACCESS=local") {
		t.Fatalf("install.env:\n%s", e.envFile)
	}
}

func TestWizardOwnPasswordRules(t *testing.T) {
	// Слабый пароль, затем несовпадающее повторение, затем верный.
	in := "\n\n\n\n" + "admin\n" + "short1\n" + "GoodPass12345\nOther12345\n" + "GoodPass12345\nGoodPass12345\n" +
		"\n" + "\n\n\n" + "y\n"
	e := newWizEnv(t, in, true, nil)
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.admin.pw != "GoodPass12345" {
		t.Fatalf("пароль: %q\n%s", e.admin.pw, e.out)
	}
	out := e.out.String()
	if !strings.Contains(out, "короче 10") || !strings.Contains(out, "не совпадают") {
		t.Fatalf("нет сообщений об ошибках:\n%s", out)
	}
}

func TestWizardNotYetModes(t *testing.T) {
	for _, mode := range []string{"node", "proxy", "panel"} {
		e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": mode, "AZPANEL_ACCESS": "local"})
		err := e.w.Run()
		if !errors.Is(err, ErrNotYet) {
			t.Fatalf("%s: %v", mode, err)
		}
		if len(e.mut) != 0 {
			t.Fatalf("%s: изменения %v", mode, e.mut)
		}
	}
	// В диалоге: выбор «только узел» (2) — тот же отказ.
	e := newWizEnv(t, "2\n", true, nil)
	if err := e.w.Run(); !errors.Is(err, ErrNotYet) || len(e.mut) != 0 {
		t.Fatalf("диалог: %v %v", err, e.mut)
	}
}

func TestWizardNonInteractiveMissingList(t *testing.T) {
	e := newWizEnv(t, "", false, nil)
	err := e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "AZPANEL_MODE") || !strings.Contains(err.Error(), "AZPANEL_ACCESS") {
		t.Fatalf("нет списка: %v", err)
	}
	if len(e.mut) != 0 {
		t.Fatalf("изменения: %v", e.mut)
	}
	e = newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "path"})
	err = e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "AZPANEL_DOMAIN") || strings.Contains(err.Error(), "AZPANEL_MODE") {
		t.Fatalf("список для path: %v", err)
	}
	e = newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "port",
		"AZPANEL_DOMAIN": "vpn.example.org", "AZPANEL_TLS": "letsencrypt"})
	err = e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "AZPANEL_EMAIL") {
		t.Fatalf("список для letsencrypt: %v", err)
	}
}

func TestWizardNonInteractiveBadValue(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "wat"})
	err := e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "AZPANEL_ACCESS") {
		t.Fatalf("%v", err)
	}
}

func TestWizardNonInteractivePathInNginx(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "path", "AZPANEL_DOMAIN": "vpn.test",
		"AZPANEL_TLS": "existing", "AZPANEL_ADMIN": "boss",
	})
	e.useRealNginx()
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	file := filepath.Join("testdata", "nginx", "sites-enabled", "vpn.test")
	got := string(e.fs.files[file])
	if strings.Count(got, "include /etc/nginx/snippets/azpanel.conf; # azpanel") != 1 {
		t.Fatalf("include не вставлен ровно один раз:\n%s", got)
	}
	if !strings.Contains(string(e.fs.files[SnippetPath]), "location ^~ /azpanel/") {
		t.Fatal("фрагмент не записан")
	}
	if e.written.Panel.BasePath != "/azpanel/" || e.written.Panel.PublicURL != "https://vpn.test" {
		t.Fatalf("конфиг панели: %+v", e.written.Panel)
	}
	if len(e.written.Panel.TrustedProxies) == 0 {
		t.Fatal("доверенные прокси пропали")
	}
	// nginx трогается после конфига и юнитов, до запуска, с nginx -t и reload.
	joined := strings.Join(e.mut, "|")
	i, j, k := strings.Index(joined, "hook"), strings.Index(joined, "nginx -t"), strings.Index(joined, "systemctl daemon-reload")
	if !(i >= 0 && i < j && j < k) || !strings.Contains(joined, "systemctl reload nginx") {
		t.Fatalf("порядок: %s", joined)
	}
	if !strings.Contains(joined, "wait-panel http://127.0.0.1:8080/azpanel/healthz") {
		t.Fatalf("healthz с префиксом: %s", joined)
	}
	if e.admin.login != "boss" || e.admin.pw != fakePassword {
		t.Fatalf("администратор: %+v", e.admin)
	}
	if !strings.Contains(e.out.String(), "https://vpn.test/azpanel/") {
		t.Fatalf("адрес не показан:\n%s", e.out)
	}
	if !strings.Contains(string(e.envFile), "NGINX_FILE="+file) {
		t.Fatalf("install.env:\n%s", e.envFile)
	}
}

func TestWizardPathNoServerIsRefusedBeforeChanges(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "path", "AZPANEL_DOMAIN": "nowhere.example.org",
	})
	e.useRealNginx()
	err := e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "нет server-блока") || len(e.mut) != 0 {
		t.Fatalf("%v %v", err, e.mut)
	}
}

func TestWizardOwnPortSelfSigned(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "port", "AZPANEL_TLS": "selfsigned",
		"AZPANEL_DOMAIN": "vpn.example.org", "AZPANEL_FIREWALL": "y",
	})
	e.useRealNginx()
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.written.Panel.PublicURL != "https://vpn.example.org:8443" || e.written.Panel.BasePath != "" {
		t.Fatalf("конфиг: %+v", e.written.Panel)
	}
	block := string(e.fs.files[testNginxDir+"/sites-available/azpanel"])
	if !strings.Contains(block, "listen 8443 ssl;") || !strings.Contains(block, "azpanel.crt") {
		t.Fatalf("блок:\n%s", block)
	}
	if !strings.Contains(strings.Join(e.mut, "|"), "firewall") {
		t.Fatal("правило файрвола не добавлено")
	}
}

func TestWizardBusyPortRefused(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "port", "AZPANEL_TLS": "selfsigned", "AZPANEL_PORT": "443",
		"AZPANEL_DOMAIN": "vpn.example.org",
	})
	e.w.Host.PortBusy = func(p int) bool { return p == 443 }
	e.w.Host.Stat = func(p string) (fs.FileInfo, error) {
		if strings.HasSuffix(p, "azpanel") {
			return nil, fs.ErrNotExist
		}
		return nil, nil
	}
	err := e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "занят") || len(e.mut) != 0 {
		t.Fatalf("%v %v", err, e.mut)
	}
}

func TestWizardRerunPicksInstallEnv(t *testing.T) {
	e := newWizEnv(t, "", false, nil)
	e.files["install.env"] = "MODE=panel+node\nACCESS=local\nADMIN=boss\n"
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.admin.login != "boss" {
		t.Fatalf("install.env не подхвачен: %+v", e.admin)
	}
}

func TestWizardRerunInteractiveDefaultsFromInstallEnv(t *testing.T) {
	e := newWizEnv(t, defaultScript+"y\n", true, nil)
	e.files["install.env"] = "MODE=panel+node\nACCESS=local\nADMIN=boss\nTELEGRAM=n\n"
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.admin.login != "boss" || !strings.Contains(e.out.String(), "Логин [boss]") {
		t.Fatalf("умолчания из install.env: %+v\n%s", e.admin, e.out)
	}
}

func TestWizardExistingAdminKept(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local"})
	e.w.Host.AdminExists = func(string) bool { return true }
	if err := e.w.Run(); err != nil {
		t.Fatal(err)
	}
	if e.admin.login != "" || strings.Contains(strings.Join(e.mut, "|"), "admin") {
		t.Fatalf("существующий администратор перезаписан: %v", e.mut)
	}
}

func TestWizardPreflightFailuresNoChanges(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local"})
	e.w.Host.Geteuid = func() int { return 1000 }
	e.w.Host.HasSystemd = func() bool { return false }
	e.w.Host.Stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }
	err := e.w.Run()
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	for _, want := range []string{"root", "systemd", "client.sh"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("нет %q: %v", want, err)
		}
	}
	if len(e.mut) != 0 {
		t.Fatalf("изменения: %v", e.mut)
	}
}

func TestWizardTelegram(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local", "AZPANEL_TELEGRAM": "y",
		"AZPANEL_TELEGRAM_TOKEN": "123:abc", "AZPANEL_TELEGRAM_CHAT": "555",
	})
	e.w.Experimental = true
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !e.written.Telegram.Enabled || e.written.Telegram.NotifyChats[0] != 555 || e.secrets["TELEGRAM_BOT_TOKEN"] != "123:abc" {
		t.Fatalf("telegram: %+v %v", e.written.Telegram, e.secrets)
	}
	if strings.Contains(string(e.envFile), "123:abc") {
		t.Fatal("токен в install.env")
	}
	e = newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local", "AZPANEL_TELEGRAM": "y",
	})
	e.w.Experimental = true
	if err := e.w.Run(); err == nil || len(e.mut) != 0 {
		t.Fatalf("Telegram без токена: %v %v", err, e.mut)
	}
}

func TestExternalIPMajority(t *testing.T) {
	answers := map[string]string{ipSources[0]: "1.2.3.4", ipSources[1]: "9.9.9.9\n", ipSources[2]: "1.2.3.4\n"}
	var asked []string
	ip, err := ExternalIP(func(u string) (string, error) { asked = append(asked, u); return answers[u], nil })
	if err != nil || ip != "1.2.3.4" || len(asked) != 3 {
		t.Fatalf("%q %v %v", ip, err, asked)
	}
	for _, u := range ipSources {
		if !strings.HasPrefix(u, "https://") {
			t.Fatalf("источник не HTTPS: %s", u)
		}
	}
	// Один источник из трёх — не большинство.
	_, err = ExternalIP(func(u string) (string, error) {
		if u == ipSources[0] {
			return "1.2.3.4", nil
		}
		return "", errors.New("нет сети")
	})
	if err == nil {
		t.Fatal("один ответ принят как большинство")
	}
	// Мусор вместо адреса.
	if _, err := ExternalIP(func(string) (string, error) { return "<html>", nil }); err == nil {
		t.Fatal("мусор принят")
	}
}

func TestCheckOS(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"ID=ubuntu\nVERSION_ID=\"24.04\"", true},
		{"ID=ubuntu\nVERSION_ID=\"26.04\"", true},
		{"ID=ubuntu\nVERSION_ID=\"22.04\"", false},
		{"ID=debian\nVERSION_ID=\"13\"", true},
		{"ID=debian\nVERSION_ID=\"12\"", false},
		{"ID=centos\nVERSION_ID=\"9\"", false},
	} {
		if err := CheckOS(c.in); (err == nil) != c.ok {
			t.Errorf("%q: %v", c.in, err)
		}
	}
}

func TestParsePortOwner(t *testing.T) {
	if ParsePortOwner("") != "" {
		t.Fatal("пусто — свободен")
	}
	if got := ParsePortOwner(`LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=812,fd=6))` + "\n"); got != "nginx" {
		t.Fatal(got)
	}
	if got := ParsePortOwner("LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n"); got != "?" {
		t.Fatal(got)
	}
}

func TestInstallEnvKeepsNoSecrets(t *testing.T) {
	a := DefaultAnswers("/opt/azpanel/backup")
	a.Mode, a.Access = ModePanelNode, AccessLocal
	a.AdminPassword, a.TelegramToken = "Secret12345", "999:tok"
	a.Telegram = true
	got := string(a.EnvFile())
	if strings.Contains(got, "Secret12345") || strings.Contains(got, "999:tok") {
		t.Fatalf("секрет в файле:\n%s", got)
	}
	kv, err := ParseEnvFile([]byte(got + "ADMIN_PASSWORD=zzz\n"))
	if err != nil || kv[KeyAdminPass] != "" || kv[KeyMode] != ModePanelNode {
		t.Fatalf("%v %v", kv, err)
	}
}

func TestValidatePassword(t *testing.T) {
	for pw, ok := range map[string]bool{
		"Abcdefgh12": true, "short1": false, "onlyletterslong": false, "12345678901": false,
		"Admin12345": false, // равен логину без учёта регистра — ниже
	} {
		login := "x"
		if pw == "Admin12345" {
			login = "admin12345"
			ok = false
		}
		if err := ValidatePassword(login, pw); (err == nil) != ok {
			t.Errorf("%q: %v", pw, err)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	for i := 0; i < 20; i++ {
		pw, err := GeneratePassword()
		if err != nil || len(pw) != 16 || ValidatePassword("admin", pw) != nil {
			t.Fatalf("%q %v", pw, err)
		}
	}
}

func TestWizardInteractiveDefaultsToFoundNginx(t *testing.T) {
	// mode, адрес, домен, доступ (Enter = путь), server-блок 1, логин, пароль,
	// смена, telegram, три вопроса бэкапов, подтверждение.
	in := "\n\nvpn.test\n\n1\n\n\n\n\n\n\ny\n"
	e := newWizEnv(t, in, true, nil)
	e.useRealNginx()
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.written.Panel.BasePath != "/azpanel/" {
		t.Fatalf("base_path: %q\n%s", e.written.Panel.BasePath, e.out)
	}
	if !strings.Contains(string(e.fs.files[filepath.Join("testdata", "nginx", "sites-enabled", "vpn.test")]), "# azpanel") {
		t.Fatal("include не вставлен")
	}
}

// Свой пароль не печатается нигде (I6): ни в итоге, ни в конце.
func TestWizardOwnPasswordNeverPrinted(t *testing.T) {
	const own = "OwnSecret12345"
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local", "AZPANEL_ADMIN": "boss",
		"AZPANEL_ADMIN_PASSWORD": own,
	})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if strings.Contains(e.out.String(), own) {
		t.Fatalf("свой пароль напечатан:\n%s", e.out)
	}
	if e.admin.pw != own {
		t.Fatalf("пароль не передан в создание администратора: %q", e.admin.pw)
	}
}

// Созданный пароль показан дважды: на шаге вопросов и в конце (не трижды).
func TestWizardGeneratedPasswordShownTwice(t *testing.T) {
	e := newWizEnv(t, defaultScript+"y\n", true, nil)
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if n := strings.Count(e.out.String(), fakePassword); n != 2 {
		t.Fatalf("пароль показан %d раз, нужно 2:\n%s", n, e.out)
	}
	e = newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local", "AZPANEL_ADMIN": "boss",
	})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if n := strings.Count(e.out.String(), fakePassword); n != 2 {
		t.Fatalf("без вопросов пароль показан %d раз, нужно 2:\n%s", n, e.out)
	}
}

// Повторная установка в режиме local не стирает public_url из настроек (M7).
func TestWizardLocalKeepsPublicURL(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local", "AZPANEL_ADMIN": "boss",
	})
	e.cfg.Panel.PublicURL = "https://panel.example"
	e.cfg.Panel.BasePath = "/azpanel/"
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.written.Panel.PublicURL != "https://panel.example" || e.written.Panel.BasePath != "/azpanel/" {
		t.Fatalf("настройки стёрты: %+v", e.written.Panel)
	}
}

// Сбой шага: мастер называет сделанное и подсказывает, что дальше (M6).
func TestWizardStepFailureListsDone(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local", "AZPANEL_ADMIN": "boss",
	})
	e.w.Host.InstallHook = func() error { return errors.New("нет скриптов") }
	err := e.w.Run()
	if err == nil {
		t.Fatal("ожидался сбой")
	}
	out := e.out.String()
	if !strings.Contains(out, "Установка прервана") || !strings.Contains(out, "Уже выполнено") || !strings.Contains(out, "azpanel uninstall") {
		t.Fatalf("нет сводки сделанного:\n%s", out)
	}
}

// Пути сертификата идут в директивы nginx: лишние знаки отвергаются (M10).
func TestCertPathRejectsNginxSyntax(t *testing.T) {
	for _, bad := range []string{"cert.pem", "/etc/x;y", "/etc/x{", "/etc/a b", "/etc/x\ny", "/etc/\"x"} {
		var a Answers
		if err := a.set(KeyCert, bad); err == nil {
			t.Errorf("%q принят", bad)
		}
		if err := a.set(KeyKey, bad); err == nil {
			t.Errorf("ключ %q принят", bad)
		}
	}
	var a Answers
	if err := a.set(KeyCert, "/etc/letsencrypt/live/x.ru/fullchain.pem"); err != nil {
		t.Fatal(err)
	}
}

// bakEnv — nginx во временном каталоге с рабочим конфигом и его копией .bak-.
func bakEnv(t *testing.T, input string, interactive bool) (*wizEnv, string) {
	t.Helper()
	env := map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "path", "AZPANEL_DOMAIN": "vpn.test", "AZPANEL_TLS": "existing",
	}
	e := newWizEnv(t, input, interactive, env)
	dir := t.TempDir()
	e.w.Nginx.Dir = dir
	_, orig := copyTestdata(t, "vpn.test")
	bak := path.Join(dir, "sites-enabled", "vpn.test.bak-20261001")
	main := filepath.Join(dir, "sites-enabled", "vpn.test")
	writeReal(t, main, orig)
	writeReal(t, bak, orig)
	e.fs.files[main], e.fs.files[bak] = []byte(orig), []byte(orig)
	e.fs.initial[main], e.fs.initial[bak] = true, true
	return e, bak
}

func TestWizardBakFilesWarnedNotMovedNonInteractive(t *testing.T) {
	e, bak := bakEnv(t, "", false)
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	out := e.out.String()
	if !strings.Contains(out, "Внимание") || !strings.Contains(out, "vpn.test.bak-20261001") {
		t.Fatalf("нет предупреждения:\n%s", out)
	}
	if _, ok := e.fs.files[bak]; !ok {
		t.Fatal("в неинтерактивном режиме копия не должна переноситься")
	}
}

func TestWizardBakFilesMovedOnAnswerYes(t *testing.T) {
	// Ответы: 1 тип, адрес, домен, доступ, затем вопрос о копиях (Enter = да).
	e, bak := bakEnv(t, "1\n\n\n\n\n\n\n\n\n\n\ny\n", true)
	// Кандидат один и сертификат существующий: диалог проходит на умолчаниях.
	err := e.w.Run()
	if err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !strings.Contains(e.out.String(), "Перенести их в /opt/azpanel/backup/nginx") {
		t.Fatalf("вопроса нет:\n%s", e.out)
	}
	if _, ok := e.fs.files[bak]; ok {
		t.Fatal("копия осталась в sites-enabled")
	}
	if _, ok := e.fs.files["/opt/azpanel/backup/nginx/vpn.test.bak-20261001"]; !ok {
		t.Fatalf("копия не перенесена: %v", e.fs.keys())
	}
}

func TestWizardBakFilesKeptOnAnswerNo(t *testing.T) {
	e, bak := bakEnv(t, "1\n\n\n\nn\n\n\n\n\n\n\n\ny\n", true)
	_ = e.w.Run()
	if !strings.Contains(e.out.String(), "Перенести их в") {
		t.Fatalf("вопроса нет:\n%s", e.out)
	}
	if _, ok := e.fs.files[bak]; !ok {
		t.Fatal("копия перенесена вопреки ответу")
	}
}

// Пока отложенное выключено, вопрос про Telegram не задаётся, а ответы о нём
// (даже из окружения) игнорируются и в install.env не пишутся.
func TestWizardNoTelegramWhileExperimentalOff(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{
		"AZPANEL_MODE": "panel+node", "AZPANEL_ACCESS": "local", "AZPANEL_TELEGRAM": "y",
		"AZPANEL_TELEGRAM_TOKEN": "123:abc", "AZPANEL_TELEGRAM_CHAT": "555",
	})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.written.Telegram.Enabled || e.secrets["TELEGRAM_BOT_TOKEN"] != "" {
		t.Fatalf("telegram записан: %+v %v", e.written.Telegram, e.secrets)
	}
	if strings.Contains(string(e.envFile), "TELEGRAM") || strings.Contains(e.out.String(), "9. Telegram") {
		t.Fatalf("Telegram виден: %s\n%s", e.envFile, e.out)
	}
}
