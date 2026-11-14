package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Бэкапы прежних версий раскладываются по подкаталогам; свежий бэкап идущего
// обновления остаётся на месте, чужое и уже разложенное не трогается.
func TestMigrateBackupLayout(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AZPANEL_ROOT", root)
	if err := MigrateBackupLayout(); err != nil { // установки нет — не ошибка
		t.Fatal(err)
	}
	write := func(rel, body string, age time.Duration) {
		p := filepath.Join(root, "backup", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ts := time.Now().Add(-age)
		if err := os.Chtimes(p, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	write("update-0.1.0-old.tar.gz", "old", 48*time.Hour)
	write("update-0.1.1-now.tar.gz", "now", time.Minute)
	write("backup-azpanel-2026-11-03-063100.tar.gz", "az", time.Minute)
	write("manual.tar.gz", "mine", 48*time.Hour)
	write("antizapret/uninstall-20261103-064018.tar.gz", "un", 48*time.Hour)
	write("antizapret/include-hosts.txt.20261102T065913.781Z", "list", 48*time.Hour)
	write("antizapret/setup.20261102T065924.306Z", "setup", 48*time.Hour)
	write("antizapret/lists/setup.20261102T065924.306Z", "уже здесь", 48*time.Hour)
	for i := 0; i < 2; i++ { // повтор ничего не меняет
		if err := MigrateBackupLayout(); err != nil {
			t.Fatal(err)
		}
	}
	for rel, want := range map[string]string{
		"azpanel/update-0.1.0-old.tar.gz":                             "old",
		"update-0.1.1-now.tar.gz":                                     "now",
		"antizapret/archives/backup-azpanel-2026-11-03-063100.tar.gz": "az",
		"manual.tar.gz":                                               "mine",
		"antizapret/archives/uninstall-20261103-064018.tar.gz":        "un",
		"antizapret/lists/include-hosts.txt.20261102T065913.781Z":     "list",
		"antizapret/lists/setup.20261102T065924.306Z":                 "уже здесь",
		"antizapret/setup.20261102T065924.306Z":                       "setup",
	} {
		b, err := os.ReadFile(filepath.Join(root, "backup", filepath.FromSlash(rel)))
		if err != nil || string(b) != want {
			t.Errorf("%s: %q, %v; ждали %q", rel, b, err, want)
		}
	}
	for _, rel := range []string{"update-0.1.0-old.tar.gz", "backup-azpanel-2026-11-03-063100.tar.gz", "antizapret/include-hosts.txt.20261102T065913.781Z", "antizapret/uninstall-20261103-064018.tar.gz"} {
		if _, err := os.Stat(filepath.Join(root, "backup", filepath.FromSlash(rel))); err == nil {
			t.Errorf("%s остался на старом месте", rel)
		}
	}
	// Всё, что связано с AntiZapret, остаётся под каталогом, закрытым панели.
	for _, d := range []string{BackupAntiZapret(), BackupLists()} {
		if rel, err := filepath.Rel(filepath.Join(root, "backup", "antizapret"), d); err != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("%s вне backup/antizapret", d)
		}
	}
}

func TestRootDefault(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", "")
	old := isDir
	t.Cleanup(func() { isDir = old })
	exists := map[string]bool{}
	isDir = func(p string) bool { return exists[filepath.ToSlash(p)] }

	// Чистый сервер и сервер после переноса — /root/azpanel, копия для хука отдельно.
	for _, have := range [][]string{nil, {"/root/azpanel/etc"}, {"/root/azpanel/etc", "/opt/azpanel/etc"}} {
		exists = map[string]bool{}
		for _, d := range have {
			exists[d] = true
		}
		if got := filepath.ToSlash(Root()); got != "/root/azpanel" || Legacy() {
			t.Fatalf("%v: Root() = %q, Legacy() = %v", have, got, Legacy())
		}
		if got := HookBinary(); got != "/usr/local/lib/azpanel/azpanel" || HookDir() != "/usr/local/lib/azpanel" {
			t.Fatalf("%v: HookBinary() = %q, HookDir() = %q", have, got, HookDir())
		}
	}
	// Прежняя установка, ещё не перенесённая: работаем из /opt/azpanel, хук зовёт сам бинарник.
	exists = map[string]bool{"/opt/azpanel/etc": true}
	if got := filepath.ToSlash(Root()); got != "/opt/azpanel" || !Legacy() {
		t.Fatalf("Root() = %q, Legacy() = %v", got, Legacy())
	}
	if HookBinary() != Binary() || HookDir() != "" {
		t.Fatalf("HookBinary() = %q, HookDir() = %q", HookBinary(), HookDir())
	}
	if got := NodeSocket(); got != "/run/azpanel/node.sock" {
		t.Fatalf("NodeSocket() = %q", got)
	}
}

func TestRootOverride(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AZPANEL_ROOT", root)
	if got, want := LimitsFile(), filepath.Join(root, "data", "limits.json"); got != want {
		t.Fatalf("LimitsFile() = %q, want %q", got, want)
	}
	if got, want := NodeSocket(), filepath.Join(root, "run", "node.sock"); got != want {
		t.Fatalf("NodeSocket() = %q, want %q", got, want)
	}
	// Под AZPANEL_ROOT (тесты) отдельной копии для хука нет.
	if Legacy() || HookBinary() != Binary() || HookDir() != "" {
		t.Fatalf("Legacy() = %v, HookBinary() = %q", Legacy(), HookBinary())
	}
}
