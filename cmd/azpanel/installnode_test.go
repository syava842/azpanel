package main

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/nodeapi"
)

// Команда установки узла из панели: переменные окружения, setup.sh и
// аргументы после «--», которые setup.sh передаёт azpanel install как есть.
func TestPanelNodeCommandParses(t *testing.T) {
	want := nodeapi.NodeKey{PanelIP: "203.0.113.9", Token: strings.Repeat("ef", 32)}
	key, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cmd := nodeapi.InstallCommand(key)
	m := regexp.MustCompile(`^((?:[A-Z_]+=\S+ )+)bash -c "\$\(curl -fsSL (\S+)\)" -- (.*)$`).FindStringSubmatch(cmd)
	if m == nil {
		t.Fatalf("команда не той формы: %s", cmd)
	}
	if m[2] != nodeapi.SetupURL {
		t.Fatalf("установщик: %s", m[2])
	}
	env := map[string]string{}
	for _, kv := range strings.Fields(m[1]) {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = strings.Trim(v, "'")
	}
	args := strings.Fields(m[3])
	a, err := parseInstallArgs(args)
	if err != nil || !a.NonInteractive || a.legacy() {
		t.Fatalf("аргументы %v: %+v %v", args, a, err)
	}
	if strings.Contains(m[3], key) {
		t.Fatal("ключ узла попал в аргументы azpanel")
	}
	var ans install.Answers
	if _, err := ans.Overlay(map[string]string{install.KeyMode: env[install.EnvName(install.KeyMode)]}); err != nil || ans.Mode != install.ModeNode {
		t.Fatalf("тип установки: %q %v", ans.Mode, err)
	}
	got, err := nodeapi.ReadNodeKey("", func(k string) string { return env[k] }, nil)
	if err != nil || got != want {
		t.Fatalf("ключ из окружения: %+v %v", got, err)
	}
}

// Прежняя форма команды (переменные аргументами) — ошибка вызова.
func TestOldNodeCommandRejected(t *testing.T) {
	if _, err := parseInstallArgs([]string{"--non-interactive", "AZPANEL_MODE=node"}); !errors.Is(err, errUsage) {
		t.Fatalf("ждали ошибку вызова: %v", err)
	}
}
