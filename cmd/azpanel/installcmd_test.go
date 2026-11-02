package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/syava842/azpanel/internal/install"
)

func TestParseInstallArgsLegacy(t *testing.T) {
	for _, args := range [][]string{{"--yes"}, {"--yes", "--panel"}, {"--panel"}} {
		a, err := parseInstallArgs(args)
		if err != nil || !a.legacy() {
			t.Fatalf("%v: %+v %v", args, a, err)
		}
	}
	for _, args := range [][]string{{}, {"--non-interactive"}, {"--yes", "--mode", "panel+node"}} {
		a, err := parseInstallArgs(args)
		if err != nil || a.legacy() {
			t.Fatalf("%v: должен быть мастер: %+v %v", args, a, err)
		}
	}
}

func TestParseInstallArgsAnswers(t *testing.T) {
	a, err := parseInstallArgs([]string{"--non-interactive", "--mode=panel+node", "--access", "path", "--domain=vpn.test", "--tls", "existing"})
	if err != nil || !a.NonInteractive {
		t.Fatal(err)
	}
	want := map[string]string{install.KeyMode: "panel+node", install.KeyAccess: "path", install.KeyDomain: "vpn.test", install.KeyTLS: "existing"}
	for k, v := range want {
		if a.Answers[k] != v {
			t.Errorf("%s=%q", k, a.Answers[k])
		}
	}
	if _, err := parseInstallArgs([]string{"--bogus"}); !errors.Is(err, errUsage) {
		t.Fatalf("неизвестный флаг: %v", err)
	}
	if _, err := parseInstallArgs([]string{"--mode"}); err == nil {
		t.Fatal("флаг без значения принят")
	}
	if _, err := parseInstallArgs([]string{"mode"}); !errors.Is(err, errUsage) {
		t.Fatal("слово без -- принято")
	}
}

func TestParseUninstallFlags(t *testing.T) {
	a, err := parseInstallArgs([]string{"--yes", "--purge", "--skip-backup"})
	if err != nil || !a.Yes || !a.Purge || !a.SkipBackup {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestPanelCreateAdmin(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", filepath.Join(t.TempDir(), "azpanel"))
	if err := os.MkdirAll(filepath.Dir(panelDBPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if panelAdminExists("admin") {
		t.Fatal("базы нет, а администратор есть")
	}
	if err := panelCreateAdmin("admin", "short", true); err == nil {
		t.Fatal("слабый пароль принят")
	}
	if err := panelCreateAdmin("admin", "GoodPass12345", true); err != nil {
		t.Fatal(err)
	}
	if !panelAdminExists("admin") {
		t.Fatal("администратор не создан")
	}
	if err := panelCreateAdmin("admin", "GoodPass12345", true); !errors.Is(err, install.ErrAdminExists) {
		t.Fatalf("повтор: %v", err)
	}
}

// Вопрос «есть ли администратор» задаётся до подтверждения: база старой версии
// от него меняться не должна (миграции — только после «да»).
func TestPanelAdminExistsDoesNotMigrate(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", filepath.Join(t.TempDir(), "azpanel"))
	if err := os.MkdirAll(filepath.Dir(panelDBPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := panelCreateAdmin("admin", "GoodPass12345", true); err != nil {
		t.Fatal(err)
	}
	// Делаем базу «старой»: версия схемы ниже текущей.
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(panelDBPath()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE meta SET value = '1' WHERE key = 'schema_version'`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(panelDBPath())
	if err != nil {
		t.Fatal(err)
	}
	if !panelAdminExists("admin") || panelAdminExists("nobody") {
		t.Fatal("проверка логина неверна")
	}
	after, _ := os.ReadFile(panelDBPath())
	if !bytes.Equal(before, after) {
		t.Fatal("файл базы изменился от проверки логина")
	}
	db, err = sql.Open("sqlite", "file:"+filepath.ToSlash(panelDBPath()))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v); err != nil || v != "1" {
		t.Fatalf("версия схемы %q: %v", v, err)
	}
}
