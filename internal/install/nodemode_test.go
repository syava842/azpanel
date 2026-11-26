package install

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/secrets"
)

const fakeAgentFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testNodeKey(t *testing.T) (nodeapi.NodeKey, string) {
	t.Helper()
	k := nodeapi.NodeKey{PanelIP: "203.0.113.9", Token: strings.Repeat("cd", 32)}
	s, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return k, s
}

func TestWizardNodeWithKey(t *testing.T) {
	k, s := testNodeKey(t)
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "node", nodeapi.NodeKeyEnv: s})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.secrets[secrets.NodeToken] != k.Token || len(e.secrets) != 1 {
		t.Fatalf("секреты: %v", e.secrets)
	}
	n := e.written.Node
	if n.ListenTLS != "0.0.0.0:9100" || !slices.Equal(n.AllowIPs, []string{"203.0.113.9"}) {
		t.Fatalf("TLS-порт: %q %v", n.ListenTLS, n.AllowIPs)
	}
	if n.APIListen != "127.0.0.1:9102" || e.written.Panel.NodeURL != "http://127.0.0.1:9102" {
		t.Fatalf("петлевой API: %q, адрес агента %q", n.APIListen, e.written.Panel.NodeURL)
	}
	if err := e.written.Validate(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(e.mut, "|")
	for _, step := range []string{"layout", "binary", "config", "secrets", "agent-cert", "unit azpanel-node.service", "hook",
		"install.env", "systemctl restart azpanel-node", "wait-agent"} {
		if !strings.Contains(joined, step) {
			t.Errorf("нет шага %q в %s", step, joined)
		}
	}
	for _, bad := range []string{"azpanel-panel", "wait-panel", "admin", "nginx", "node-token"} {
		if strings.Contains(joined, bad) {
			t.Errorf("лишний шаг %q в %s", bad, joined)
		}
	}
	if strings.Index(joined, "agent-cert") > strings.Index(joined, "systemctl restart azpanel-node") {
		t.Fatalf("сертификат после запуска агента: %s", joined)
	}
	if string(e.envFile) != "MODE=node\n" {
		t.Fatalf("install.env: %q", e.envFile)
	}
	out := e.out.String()
	for _, want := range []string{agenttls.FormatFingerprint(fakeAgentFP), "Откройте TCP 9100 для 203.0.113.9", "203.0.113.7:9100"} {
		if !strings.Contains(out, want) {
			t.Errorf("в выводе нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, k.Token) || strings.Contains(out, s) {
		t.Fatalf("токен в выводе:\n%s", out)
	}
}

func TestWizardNodeKeyFile(t *testing.T) {
	k, s := testNodeKey(t)
	file := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(file, []byte(s+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "node", nodeapi.NodeKeyFileEnv: file})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.secrets[secrets.NodeToken] != k.Token {
		t.Fatalf("секреты: %v", e.secrets)
	}
}

func TestWizardNodeBadKeyNothingChanged(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"без ключа":     {"AZPANEL_MODE": "node"},
		"неверный ключ": {"AZPANEL_MODE": "node", nodeapi.NodeKeyEnv: "azn1.мусор"},
		"не ключ":       {"AZPANEL_MODE": "node", nodeapi.NodeKeyEnv: "abc"},
	} {
		e := newWizEnv(t, "", false, env)
		err := e.w.Run()
		if err == nil || !strings.Contains(err.Error(), "Ничего не изменено") {
			t.Fatalf("%s: %v", name, err)
		}
		if len(e.mut) != 0 {
			t.Fatalf("%s: изменения %v", name, e.mut)
		}
	}
}

func TestWizardNodeAsksKeyAgain(t *testing.T) {
	k, s := testNodeKey(t)
	in := "\n" + "azn1.мусор\n" + s + "\n" + "y\n"
	e := newWizEnv(t, in, true, map[string]string{"AZPANEL_MODE": "node"})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	out := e.out.String()
	if strings.Count(out, "Ключ узла (из панели: Узлы → Добавить)") != 3 || !strings.Contains(out, "ключ узла повреждён") {
		t.Fatalf("ключ не переспрошен:\n%s", out)
	}
	if e.secrets[secrets.NodeToken] != k.Token {
		t.Fatalf("секреты: %v", e.secrets)
	}
}

func TestWizardNodeNothingBeforeConfirm(t *testing.T) {
	_, s := testNodeKey(t)
	e := newWizEnv(t, s+"\nn\n", true, map[string]string{"AZPANEL_MODE": "node"})
	err := e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "отменена") {
		t.Fatalf("ожидалась отмена: %v", err)
	}
	if len(e.mut) != 0 {
		t.Fatalf("до подтверждения вызваны изменения: %v", e.mut)
	}
	// Ввод ключа закончился без ключа — тоже ничего не изменено.
	e = newWizEnv(t, "", true, map[string]string{"AZPANEL_MODE": "node"})
	if err := e.w.Run(); err == nil || len(e.mut) != 0 {
		t.Fatalf("без ввода: %v, изменения %v", err, e.mut)
	}
}

func TestWizardNodePortBusy(t *testing.T) {
	_, s := testNodeKey(t)
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "node", nodeapi.NodeKeyEnv: s})
	e.w.Host.Stat = func(p string) (fs.FileInfo, error) {
		if strings.HasSuffix(filepath.ToSlash(p), nodeUnitName) {
			return nil, fs.ErrNotExist // агента ещё нет: порт занят чужим
		}
		return nil, nil
	}
	e.w.Host.PortBusy = func(p int) bool { return p == 9100 }
	if err := e.w.Run(); err == nil || !strings.Contains(err.Error(), "порт 9100 занят") || len(e.mut) != 0 {
		t.Fatalf("занятый порт: %v, изменения %v", err, e.mut)
	}
}

// На сервере с панелью (install.env MODE=panel+node или юнит azpanel-panel)
// узел для другой панели не ставится: отказ до любых изменений.
func TestWizardNodeRefusesOnPanelServer(t *testing.T) {
	_, s := testNodeKey(t)
	for name, file := range map[string][2]string{
		"install.env": {"install.env", "MODE=panel+node\n"},
		"юнит":        {"azpanel-panel.service", "[Unit]\n"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "node", nodeapi.NodeKeyEnv: s})
			e.files[file[0]] = file[1]
			err := e.w.Run()
			if err == nil || !strings.Contains(err.Error(), "На этом сервере стоит панель; узел для другой панели ставится на отдельный сервер") {
				t.Fatalf("ждали отказ: %v\n%s", err, e.out)
			}
			if len(e.mut) != 0 {
				t.Fatalf("изменения до отказа: %v", e.mut)
			}
		})
	}
	// MODE=node от прошлой установки узла — не помеха (переустановка узла).
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "node", nodeapi.NodeKeyEnv: s})
	e.files["install.env"] = "MODE=node\n"
	if err := e.w.Run(); err != nil {
		t.Fatalf("переустановка узла: %v\n%s", err, e.out)
	}
}

// Повторный azpanel install на подключённом узле без ключа: ключ не
// спрашивается, токен и адрес панели — прежние, порт агента — из конфига.
// С ключом — ключ заменяет прежнее; на неподключённом без ключа — ошибка.
func TestWizardNodeReinstallWithoutKey(t *testing.T) {
	oldTok := strings.Repeat("ab", 32)
	connected := func(t *testing.T, env map[string]string) *wizEnv {
		t.Helper()
		e := newWizEnv(t, "", false, env)
		e.files["install.env"] = "MODE=node\n"
		e.files["secrets.env"] = secrets.NodeToken + "=" + oldTok + "\n"
		e.cfg.Node.ListenTLS = "0.0.0.0:9443"
		e.cfg.Node.AllowIPs = []string{"198.51.100.4"}
		return e
	}
	e := connected(t, map[string]string{"AZPANEL_MODE": "node"})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.secrets[secrets.NodeToken] != oldTok {
		t.Fatalf("токен: %v", e.secrets)
	}
	n := e.written.Node
	if n.ListenTLS != "0.0.0.0:9443" || !slices.Equal(n.AllowIPs, []string{"198.51.100.4"}) {
		t.Fatalf("порт и белый список не прежние: %q %v", n.ListenTLS, n.AllowIPs)
	}
	if out := e.out.String(); strings.Contains(out, "Ключ узла (из панели") || strings.Contains(out, oldTok) {
		t.Fatalf("спросил ключ или показал токен:\n%s", out)
	}

	// С ключом — ключ заменяет прежние токен и адрес панели.
	k, s := testNodeKey(t)
	e = connected(t, map[string]string{"AZPANEL_MODE": "node", nodeapi.NodeKeyEnv: s})
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if e.secrets[secrets.NodeToken] != k.Token || !slices.Equal(e.written.Node.AllowIPs, []string{k.PanelIP}) {
		t.Fatalf("ключ не заменил прежнее: %v %v", e.secrets, e.written.Node.AllowIPs)
	}

	// Неподключённый (нет токена или белого списка) без ключа и без терминала — ошибка.
	for name, spoil := range map[string]func(e *wizEnv){
		"нет токена":     func(e *wizEnv) { delete(e.files, "secrets.env") },
		"нет allow_ips":  func(e *wizEnv) { e.cfg.Node.AllowIPs = nil },
		"не режим node":  func(e *wizEnv) { delete(e.files, "install.env") },
		"нет listen_tls": func(e *wizEnv) { e.cfg.Node.ListenTLS = "" },
	} {
		e := connected(t, map[string]string{"AZPANEL_MODE": "node"})
		spoil(e)
		if err := e.w.Run(); err == nil || !strings.Contains(err.Error(), "нужен ключ узла") || len(e.mut) != 0 {
			t.Fatalf("%s: %v, изменения %v", name, err, e.mut)
		}
	}
}

// Переустановка с прежним listen_tls не на 9100: файрвол и итоговые строки —
// с фактическим портом.
func TestWizardNodeReinstallUsesActualPort(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_MODE": "node", "AZPANEL_FIREWALL": "y"})
	e.files["install.env"] = "MODE=node\n"
	e.files["secrets.env"] = secrets.NodeToken + "=" + strings.Repeat("ab", 32) + "\n"
	e.cfg.Node.ListenTLS = "0.0.0.0:9443"
	e.cfg.Node.AllowIPs = []string{"198.51.100.4"}
	opened := 0
	e.w.Host.OpenFirewall = func(p int) error { opened = p; return nil }
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if opened != 9443 {
		t.Fatalf("файрвол открыт для %d", opened)
	}
	out := e.out.String()
	for _, want := range []string{"правило iptables для TCP 9443", "Откройте TCP 9443 для 198.51.100.4", "203.0.113.7:9443"} {
		if !strings.Contains(out, want) {
			t.Errorf("в выводе нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "9100") {
		t.Fatalf("в выводе порт по умолчанию:\n%s", out)
	}
}
