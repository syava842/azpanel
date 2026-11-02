package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMissingGivesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "нет.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, Default()) {
		t.Fatalf("получено %+v", c)
	}
}

func TestLoadPartialKeepsOtherDefaults(t *testing.T) {
	c, err := Load(write(t, "config_version = 1\n[node]\npoll_seconds = 7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Node.PollSeconds != 7 {
		t.Fatalf("poll_seconds = %d", c.Node.PollSeconds)
	}
	if c.Node.OpenVPNSocketDir != "/run/openvpn-server" || c.Log.Keep != 5 {
		t.Fatalf("умолчания потеряны: %+v", c)
	}
}

func TestLoadRejectsNewerVersion(t *testing.T) {
	_, err := Load(write(t, "config_version = 99\n"))
	if err == nil || !strings.Contains(err.Error(), "новее") {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestLoadRejectsBadPoll(t *testing.T) {
	_, err := Load(write(t, "config_version = 1\n[node]\npoll_seconds = 0\n"))
	if err == nil || !strings.Contains(err.Error(), "poll_seconds") {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	c := Default()
	c.Log.Keep = 9
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("получено %+v, ждали %+v", got, c)
	}
}

func TestLoadV1FileGetsV2Defaults(t *testing.T) {
	c, err := Load(write(t, "config_version = 1\n[node]\npoll_seconds = 7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ConfigVersion != CurrentVersion || CurrentVersion != 2 {
		t.Fatalf("config_version = %d, CurrentVersion = %d", c.ConfigVersion, CurrentVersion)
	}
	if c.Node.PollSeconds != 7 {
		t.Fatalf("poll_seconds = %d", c.Node.PollSeconds)
	}
	if c.Node.APIListen != "127.0.0.1:9100" || c.Node.ClientShTimeoutS != 120 {
		t.Fatalf("умолчания узла: %+v", c.Node)
	}
	if c.Panel.Listen != "127.0.0.1:8080" || c.Panel.HistoryDays != 30 {
		t.Fatalf("умолчания панели: %+v", c.Panel)
	}
}

func TestValidateListenAddresses(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
		ok   bool
	}{
		{"api пусто — API выключен", func(c *Config) { c.Node.APIListen = "" }, true},
		{"api ipv6 loopback", func(c *Config) { c.Node.APIListen = "[::1]:9100" }, true},
		{"api наружу", func(c *Config) { c.Node.APIListen = "0.0.0.0:9100" }, false},
		{"api без порта", func(c *Config) { c.Node.APIListen = "127.0.0.1" }, false},
		{"панель наружу", func(c *Config) { c.Panel.Listen = "10.0.0.1:8080" }, false},
		{"адрес агента не http", func(c *Config) { c.Panel.NodeURL = "127.0.0.1:9100" }, false},
		{"тайм-аут client.sh мал", func(c *Config) { c.Node.ClientShTimeoutS = 5 }, false},
		{"история 0 дней", func(c *Config) { c.Panel.HistoryDays = 0 }, false},
		{"public_url пуст", func(c *Config) { c.Panel.PublicURL = "" }, true},
		{"public_url https", func(c *Config) { c.Panel.PublicURL = "https://vpn.example.org" }, true},
		{"public_url http с портом и путём", func(c *Config) { c.Panel.PublicURL = "http://10.0.0.5:8443/panel" }, true},
		{"public_url без схемы", func(c *Config) { c.Panel.PublicURL = "vpn.example.org" }, false},
		{"public_url ftp", func(c *Config) { c.Panel.PublicURL = "ftp://vpn.example.org" }, false},
		{"public_url без хоста", func(c *Config) { c.Panel.PublicURL = "https://" }, false},
		{"public_url с запросом", func(c *Config) { c.Panel.PublicURL = "https://vpn.example.org/?a=1" }, false},
		{"public_url с учёткой", func(c *Config) { c.Panel.PublicURL = "https://u:p@vpn.example.org" }, false},
		{"public_url с пробелом", func(c *Config) { c.Panel.PublicURL = "https://vpn example.org" }, false},
	}
	for _, tc := range cases {
		c := Default()
		tc.edit(&c)
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

func TestRequireAdmin2FA(t *testing.T) {
	if Default().Panel.RequireAdmin2FA {
		t.Fatal("по умолчанию require_admin_2fa должна быть выключена")
	}
	c, err := Load(write(t, "config_version = 2\n[panel]\nrequire_admin_2fa = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Panel.RequireAdmin2FA {
		t.Fatal("require_admin_2fa = true не прочитан")
	}
	if _, err := Load(write(t, "config_version = 2\n[panel]\nrequire_admin_2fa = \"да\"\n")); err == nil {
		t.Fatal("не-bool в require_admin_2fa должен отвергаться")
	}
}

func TestParseAllowIPs(t *testing.T) {
	got, err := ParseAllowIPs([]string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32", " ::1 "})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.7/32", "2001:db8::/32", "::1/128"}
	if len(got) != len(want) {
		t.Fatalf("получено %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("[%d] = %s, ждали %s", i, got[i], want[i])
		}
	}
	if got, err := ParseAllowIPs(nil); err != nil || len(got) != 0 {
		t.Fatalf("пустой список: %v %v", got, err)
	}
	for _, bad := range []string{"", "10.0.0.0/33", "abc", "10.0.0.256", "1.2.3.4/x"} {
		if _, err := ParseAllowIPs([]string{bad}); err == nil {
			t.Errorf("%q: ждали ошибку", bad)
		}
	}
}

func TestValidateAllowIPs(t *testing.T) {
	c := Default()
	c.Panel.AllowIPs = []string{"10.0.0.0/8"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Panel.AllowIPs = []string{"nope"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "panel.allow_ips") {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestParseAllowIPsMappedShortPrefix(t *testing.T) {
	// ::ffff:10.0.0.0/80 не помещается в IPv4: ошибка, а не пустая запись.
	if _, err := ParseAllowIPs([]string{"::ffff:10.0.0.0/80"}); err == nil || !strings.Contains(err.Error(), "/96") {
		t.Fatalf("ждали ошибку про /96, получили %v", err)
	}
	got, err := ParseAllowIPs([]string{"::ffff:10.0.0.0/104"})
	if err != nil || len(got) != 1 || got[0].String() != "10.0.0.0/8" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestTelegramDefaults(t *testing.T) {
	c := Default().Telegram
	if c.Enabled || c.Strangers != "closed" || c.CPUPercent != 90 || c.MemPercent != 90 || c.DiskPercent != 90 ||
		c.LoadMinutes != 5 || c.SummaryAt != "09:00" || c.BackupEveryDays != 0 {
		t.Fatalf("умолчания: %+v", c)
	}
	if len(c.Notify) != len(TelegramNotifyKinds) {
		t.Fatalf("виды по умолчанию: %v", c.Notify)
	}
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTelegramLoadOverrides(t *testing.T) {
	c, err := Load(write(t, `config_version = 2
[telegram]
enabled = true
strangers = "request"
notify_chats = [123, -100456]
notify = ["node_down", "reboot"]
summary_at = ""
backup_every_days = 7
backup_chats = [123]
cpu_percent = 80
`))
	if err != nil {
		t.Fatal(err)
	}
	g := c.Telegram
	if !g.Enabled || g.Strangers != "request" || len(g.NotifyChats) != 2 || g.NotifyChats[1] != -100456 ||
		len(g.Notify) != 2 || g.SummaryAt != "" || g.BackupEveryDays != 7 || g.CPUPercent != 80 || g.MemPercent != 90 {
		t.Fatalf("получено %+v", g)
	}
}

func TestValidateTelegram(t *testing.T) {
	cases := map[string]func(*Telegram){
		"strangers":       func(g *Telegram) { g.Strangers = "open" },
		"неизвестный вид": func(g *Telegram) { g.Notify = []string{"node_down", "boom"} },
		"summary_at":      func(g *Telegram) { g.SummaryAt = "25:00" },
		"summary_at 2":    func(g *Telegram) { g.SummaryAt = "9:00" },
		"summary_at 3":    func(g *Telegram) { g.SummaryAt = "09:60" },
		"cpu":             func(g *Telegram) { g.CPUPercent = 0 },
		"mem":             func(g *Telegram) { g.MemPercent = 101 },
		"disk":            func(g *Telegram) { g.DiskPercent = -1 },
		"minutes":         func(g *Telegram) { g.LoadMinutes = 0 },
		"backup":          func(g *Telegram) { g.BackupEveryDays = -1 },
		"backup 2":        func(g *Telegram) { g.BackupEveryDays = 400 },
		"chat 0":          func(g *Telegram) { g.NotifyChats = []int64{0} },
		"backup chat 0":   func(g *Telegram) { g.BackupChats = []int64{0} },
	}
	for name, mut := range cases {
		c := Default()
		mut(&c.Telegram)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "telegram.") {
			t.Fatalf("%s: ошибка %v", name, err)
		}
	}
	c := Default()
	c.Telegram.SummaryAt = ""
	c.Telegram.Notify = nil
	c.Telegram.BackupEveryDays = 30
	if err := c.Validate(); err != nil {
		t.Fatalf("допустимые значения отвергнуты: %v", err)
	}
	// Загрузка с неверным значением отвергается.
	if _, err := Load(write(t, "[telegram]\nsummary_at = \"7pm\"\n")); err == nil {
		t.Fatal("Load принял неверное время")
	}
}

func TestTelegramSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	c := Default()
	c.Telegram.Enabled = true
	c.Telegram.NotifyChats = []int64{1, -2}
	c.Telegram.Notify = []string{"reboot"}
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("получено %+v, %v", got, err)
	}
}
