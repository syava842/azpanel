package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

func panelEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AZPANEL_ROOT", filepath.Join(t.TempDir(), "azpanel"))
	os.MkdirAll(paths.Etc(), 0o700)
}

func TestPasswdFromPipe(t *testing.T) {
	panelEnv(t)
	out := &bytes.Buffer{}
	err := cmdPanelPasswd([]string{"--user", "boss"}, strings.NewReader("s3cret-пароль\n"), nil, out)
	if err != nil {
		t.Fatal(err)
	}
	sec, _ := secrets.Load(paths.SecretsFile())
	if sec["PANEL_ADMIN_USER"] != "boss" {
		t.Fatalf("имя: %q", sec["PANEL_ADMIN_USER"])
	}
	if bcrypt.CompareHashAndPassword([]byte(sec["PANEL_ADMIN_HASH"]), []byte("s3cret-пароль")) != nil {
		t.Fatal("хеш не соответствует паролю")
	}
	if !strings.Contains(out.String(), "systemctl restart azpanel-panel") {
		t.Fatalf("вывод: %q", out)
	}
	if strings.Contains(out.String(), "s3cret") || strings.Contains(out.String(), sec["PANEL_ADMIN_HASH"]) {
		t.Fatal("вывод содержит пароль или хеш")
	}
}

func TestPasswdTerminalMismatch(t *testing.T) {
	panelEnv(t)
	answers := []string{"one", "two"}
	read := func() ([]byte, error) {
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	err := cmdPanelPasswd(nil, nil, read, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "не совпадают") {
		t.Fatalf("ошибка = %v", err)
	}
	if sec, _ := secrets.Load(paths.SecretsFile()); sec["PANEL_ADMIN_HASH"] != "" {
		t.Fatal("хеш записан при несовпадении")
	}
}

func TestPasswdTerminalOK(t *testing.T) {
	panelEnv(t)
	read := func() ([]byte, error) { return []byte("pw-long-enough"), nil }
	if err := cmdPanelPasswd(nil, nil, read, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	sec, _ := secrets.Load(paths.SecretsFile())
	if sec["PANEL_ADMIN_HASH"] == "" || sec["PANEL_ADMIN_USER"] != "" {
		t.Fatalf("секреты: %v", sec)
	}
}

func TestPasswdEmptyAndBadFlag(t *testing.T) {
	panelEnv(t)
	if err := cmdPanelPasswd(nil, strings.NewReader("\n"), nil, &bytes.Buffer{}); err == nil {
		t.Fatal("пустой пароль: ждали ошибку")
	}
	if err := cmdPanelPasswd([]string{"--x"}, strings.NewReader("a\n"), nil, &bytes.Buffer{}); !errors.Is(err, errUsage) {
		t.Fatalf("ошибка = %v", err)
	}
}
