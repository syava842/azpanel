package install

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

const stock = "#!/bin/bash\n\nexit 0"

func setup(t *testing.T) (Options, *[]string) {
	t.Helper()
	base := t.TempDir()
	t.Setenv("AZPANEL_ROOT", filepath.Join(base, "opt", "azpanel"))
	az := filepath.Join(base, "antizapret")
	scripts := filepath.Join(base, "scripts")
	units := filepath.Join(base, "units")
	for _, d := range []string{az, scripts, units} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(az, "client.sh"), []byte("#!/bin/bash\n"), 0o755)
	for _, n := range []string{"custom-client-connect.sh", "custom-client-disconnect.sh"} {
		os.WriteFile(filepath.Join(scripts, n), []byte(stock), 0o755)
	}
	self := filepath.Join(base, "azpanel-new")
	os.WriteFile(self, []byte("BINARY"), 0o755)
	var calls []string
	return Options{
		Yes: true, In: strings.NewReader(""), Out: &bytes.Buffer{},
		Run: func(name string, args ...string) error {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil
		},
		Wait:    func() error { return nil },
		UnitDir: units, AntiZapretDir: az, ScriptsDir: scripts, Self: self,
	}, &calls
}

func TestInstallNode(t *testing.T) {
	o, calls := setup(t)
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(paths.Binary()); string(b) != "BINARY" {
		t.Fatalf("бинарник: %q", b)
	}
	if _, err := os.Stat(paths.ConfigFile()); err != nil {
		t.Fatalf("config.toml: %v", err)
	}
	unit, _ := os.ReadFile(filepath.Join(o.UnitDir, "azpanel-node.service"))
	if !strings.Contains(string(unit), "ExecStart="+paths.Binary()+" node") || !strings.Contains(string(unit), "RuntimeDirectory=azpanel") {
		t.Fatalf("юнит:\n%s", unit)
	}
	want := []string{"systemctl daemon-reload", "systemctl enable azpanel-node", "systemctl restart azpanel-node"}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("вызовы: %v", *calls)
	}
	b, _ := os.ReadFile(filepath.Join(o.ScriptsDir, "custom-client-connect.sh"))
	if !strings.Contains(string(b), "hook connect") {
		t.Fatalf("хук не поставлен:\n%s", b)
	}
	if runtime.GOOS == "linux" {
		for dir, mode := range map[string]os.FileMode{paths.Root(): 0o755, paths.Bin(): 0o755, paths.Etc(): 0o700, paths.Log(): 0o700, paths.Data(): 0o700, paths.Backup(): 0o700} {
			st, _ := os.Stat(dir)
			if st.Mode().Perm() != mode {
				t.Errorf("%s: %v, ждали %v", dir, st.Mode().Perm(), mode)
			}
		}
	}
	sec, err := secrets.Load(paths.SecretsFile())
	if err != nil || len(sec[secrets.NodeToken]) != 64 {
		t.Fatalf("токен узла: %v", err)
	}
	for _, line := range []string{"ProtectSystem=strict", "ReadWritePaths=/opt/azpanel -/etc/openvpn -/etc/wireguard -/root/antizapret", "PrivateTmp=true", "NoNewPrivileges=true"} {
		if !strings.Contains(string(unit), line) {
			t.Fatalf("в юните нет %q:\n%s", line, unit)
		}
	}
}

func TestInstallNodeKeepsToken(t *testing.T) {
	o, _ := setup(t)
	os.MkdirAll(paths.Etc(), 0o700)
	if err := secrets.Set(paths.SecretsFile(), secrets.NodeToken, "OLDTOKEN"); err != nil {
		t.Fatal(err)
	}
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if sec, _ := secrets.Load(paths.SecretsFile()); sec[secrets.NodeToken] != "OLDTOKEN" {
		t.Fatal("токен заменён")
	}
}

func TestInstallNodeKeepsExistingConfig(t *testing.T) {
	o, _ := setup(t)
	os.MkdirAll(paths.Etc(), 0o700)
	os.WriteFile(paths.ConfigFile(), []byte("config_version = 1\n[node]\npoll_seconds = 9\n"), 0o600)
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(paths.ConfigFile()); !strings.Contains(string(b), "poll_seconds = 9") {
		t.Fatalf("конфиг перезаписан:\n%s", b)
	}
}

func TestInstallNodeRequiresAntiZapret(t *testing.T) {
	o, calls := setup(t)
	os.Remove(filepath.Join(o.AntiZapretDir, "client.sh"))
	if err := InstallNode(o); err == nil || !strings.Contains(err.Error(), "AntiZapret") {
		t.Fatalf("ошибка = %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("при отказе вызван systemctl: %v", *calls)
	}
}

func TestInstallNodeAsksWithoutYes(t *testing.T) {
	o, calls := setup(t)
	o.Yes = false
	o.In = strings.NewReader("n\n")
	if err := InstallNode(o); err == nil {
		t.Fatal("ответ «n» — ждали отказ")
	}
	if len(*calls) != 0 {
		t.Fatalf("после отказа вызван systemctl: %v", *calls)
	}
	if _, err := os.Stat(paths.Root()); !os.IsNotExist(err) {
		t.Fatal("после отказа созданы каталоги")
	}
}

func TestPurgeRefusesForeignRoot(t *testing.T) {
	o, _ := setup(t)
	foreign := t.TempDir() // имя каталога — не «azpanel»
	t.Setenv("AZPANEL_ROOT", foreign)
	o.Purge = true
	if err := Uninstall(o); err == nil {
		t.Fatal("--purge чужого каталога: ждали отказ")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("чужой каталог удалён: %v", err)
	}
}

func TestUninstall(t *testing.T) {
	o, calls := setup(t)
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	o.Purge = true
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if (*calls)[0] != "systemctl disable --now azpanel-node" {
		t.Fatalf("сначала должна останавливаться служба: %v", *calls)
	}
	b, _ := os.ReadFile(filepath.Join(o.ScriptsDir, "custom-client-connect.sh"))
	if string(b) != stock {
		t.Fatalf("хук не снят:\n%q", b)
	}
	if _, err := os.Stat(filepath.Join(o.UnitDir, "azpanel-node.service")); !os.IsNotExist(err) {
		t.Fatal("юнит остался")
	}
	if _, err := os.Stat(paths.Root()); !os.IsNotExist(err) {
		t.Fatal("--purge не удалил корень")
	}
}

func TestPanelUnit(t *testing.T) {
	u := PanelUnit("/x")
	for _, s := range []string{"ExecStart=/x panel", "ProtectSystem=strict", "ProtectHome=true", "ReadWritePaths=/opt/azpanel", "After=network-online.target azpanel-node.service", "Description=azpanel: веб-панель", "PrivateTmp=true", "NoNewPrivileges=true",
		"\nCapabilityBoundingSet=\n", "\nAmbientCapabilities=\n", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
		"ProtectKernelTunables=true", "ProtectKernelModules=true", "ProtectControlGroups=true", "RestrictNamespaces=true",
		"LockPersonality=true", "RestrictSUIDSGID=true", "PrivateDevices=true", "SystemCallArchitectures=native"} {
		if !strings.Contains(u, s) {
			t.Errorf("в юните панели нет %q:\n%s", s, u)
		}
	}
	if strings.Contains(u, "RuntimeDirectory") {
		t.Errorf("у панели не должно быть RuntimeDirectory:\n%s", u)
	}
}

func TestInstallNodeWithPanel(t *testing.T) {
	o, calls := setup(t)
	o.Panel = true
	out := &bytes.Buffer{}
	o.Out = out
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(o.UnitDir, "azpanel-panel.service")); !strings.Contains(string(b), "ExecStart="+paths.Binary()+" panel") {
		t.Fatalf("юнит панели:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(o.UnitDir, "azpanel-node.service")); err != nil {
		t.Fatal("юнита агента нет")
	}
	want := []string{"systemctl daemon-reload", "systemctl enable azpanel-node", "systemctl restart azpanel-node", "systemctl enable azpanel-panel", "systemctl restart azpanel-panel"}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("вызовы: %v", *calls)
	}
	if !strings.Contains(out.String(), "azpanel panel passwd") || !strings.Contains(out.String(), "ssh -L") {
		t.Fatalf("нет подсказки про пароль и туннель:\n%s", out)
	}
}

func TestInstallNodeWithoutPanel(t *testing.T) {
	o, calls := setup(t)
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(o.UnitDir, "azpanel-panel.service")); !os.IsNotExist(err) {
		t.Fatal("юнит панели создан без --panel")
	}
	for _, c := range *calls {
		if strings.Contains(c, "azpanel-panel") {
			t.Fatalf("вызов про панель без --panel: %s", c)
		}
	}
}

func TestUninstallRemovesPanelUnit(t *testing.T) {
	o, calls := setup(t)
	o.Panel = true
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	o.Panel = false
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(o.UnitDir, "azpanel-panel.service")); !os.IsNotExist(err) {
		t.Fatal("юнит панели остался")
	}
	if (*calls)[0] != "systemctl disable --now azpanel-panel" || (*calls)[1] != "systemctl disable --now azpanel-node" {
		t.Fatalf("порядок остановки: %v", *calls)
	}
}
