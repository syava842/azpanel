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
