package config

import (
	"os"
	"path/filepath"
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
	if c != Default() {
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
	if got != c {
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
	}
	for _, tc := range cases {
		c := Default()
		tc.edit(&c)
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}
