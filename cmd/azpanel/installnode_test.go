package main

import (
	"errors"
	"os"
	"path/filepath"
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
	cmd := nodeapi.InstallCommand(key, "1.4.2")
	// Пробел в начале: bash с HISTCONTROL=ignorespace/ignoreboth не пишет
	// команду с ключом в историю.
	m := regexp.MustCompile(`^ ((?:[A-Z_]+=\S+ )+)bash -c "\$\(curl -fsSL (\S+)\)" -- (.*)$`).FindStringSubmatch(cmd)
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
	if env["AZPANEL_VERSION"] != "1.4.2" {
		t.Fatalf("версия узла: %q", env["AZPANEL_VERSION"])
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

// Версия узла — как у панели, если панель из релиза; сборка не из релиза —
// без AZPANEL_VERSION (setup.sh берёт последний релиз).
func TestPanelNodeCommandVersion(t *testing.T) {
	key, err := nodeapi.NodeKey{PanelIP: "203.0.113.9", Token: strings.Repeat("ef", 32)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for ver, want := range map[string]string{
		"1.2.3": "AZPANEL_VERSION=1.2.3 ", "v0.1.7": "AZPANEL_VERSION=0.1.7 ",
		"1.2.3-pre": "", "1.2.3+abc": "", "0.1.7-10-g054b092": "", "dev": "", "": "",
	} {
		cmd := nodeapi.InstallCommand(key, ver)
		if !strings.HasPrefix(cmd, " AZPANEL_MODE=node ") {
			t.Fatalf("%q: команда без пробела в начале: %s", ver, cmd)
		}
		got := ""
		if i := strings.Index(cmd, "AZPANEL_VERSION="); i >= 0 {
			got = cmd[i : i+strings.Index(cmd[i:], " ")+1]
		}
		if got != want {
			t.Errorf("версия %q: в команде %q, ждали %q", ver, got, want)
		}
	}
}

// setup.sh убирает ключ узла из окружения до установщика AntiZapret и
// apt-get и возвращает его только мастеру azpanel install.
func TestSetupShHidesNodeKeyFromChildren(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	unset := strings.Index(s, "\nunset AZPANEL_NODE_KEY\n")
	export := strings.Index(s, `export AZPANEL_NODE_KEY="$node_key"`)
	master := strings.Index(s, `with_tty "$tmp/azpanel" install "$@"`)
	if unset < 0 || export < 0 || master < 0 {
		t.Fatalf("нет unset/export/запуска мастера: %d %d %d", unset, export, master)
	}
	for _, child := range []string{`bash <(curl -fsSL "$AZ_SETUP")`, "apt-get update"} {
		i := strings.Index(s, child)
		if i < 0 || i < unset || i > export {
			t.Fatalf("%s — не между unset и export ключа", child)
		}
	}
	if export > master {
		t.Fatal("ключ возвращается в окружение после запуска мастера")
	}
}
