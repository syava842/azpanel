package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// Скрипт AntiZapret, запущенный мимо агента, виден по /proc/<pid>/cmdline.
func TestProcScriptsFindsAntiZapretScripts(t *testing.T) {
	proc := t.TempDir()
	write := func(pid, cmdline string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("1", "/sbin/init\x00")
	write("200", "/usr/bin/vim\x00/root/notes.txt\x00")
	os.MkdirAll(filepath.Join(proc, "self"), 0o755) // не pid
	if got := ProcScripts(proc); got != "" {
		t.Fatalf("без скриптов: %q", got)
	}
	write("301", "bash\x00/root/antizapret/doall.sh\x00")
	if got := ProcScripts(proc); got != "doall.sh" {
		t.Fatalf("doall.sh: %q", got)
	}
	os.RemoveAll(filepath.Join(proc, "301"))
	write("302", "sudo\x00bash\x00./client.sh\x001\x00bob\x00")
	if got := ProcScripts(proc); got != "client.sh" {
		t.Fatalf("client.sh: %q", got)
	}
	// Имя скрипта далеко в аргументах (например, у редактора) — не скрипт.
	os.RemoveAll(filepath.Join(proc, "302"))
	write("303", "python3\x00-m\x00tool\x00--flag\x00--file\x00setup.sh\x00")
	if got := ProcScripts(proc); got != "" {
		t.Fatalf("аргумент чужой программы: %q", got)
	}
	if got := ProcScripts(filepath.Join(proc, "нет")); got != "" {
		t.Fatalf("нет каталога: %q", got)
	}
}

// Пока идёт задача агента или скрипт AntiZapret, манифест — 423, и клиент
// панели видит nodeapi.ErrBusy; освободился — манифест отдаётся.
func TestSyncManifestBusy(t *testing.T) {
	l := newSyncLayout(t)
	script := ""
	l.api.ScriptRunning = func() string { return script }
	if _, err := l.client.SyncManifest(context.Background()); err != nil {
		t.Fatalf("свободный узел: %v", err)
	}

	script = "doall.sh"
	_, err := l.client.SyncManifest(context.Background())
	var ne *nodeapi.Error
	if !errors.Is(err, nodeapi.ErrBusy) || !errors.As(err, &ne) || ne.Status != 423 {
		t.Fatalf("скрипт AntiZapret: %v", err)
	}
	script = ""

	l.roles.Set(nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: "g"})
	inSet := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	if _, err := l.client.SyncApply(context.Background(), buildTar(t, map[string]string{inSet: "b.example\n"}), nodeapi.SyncApplyOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.client.SyncManifest(context.Background()); !errors.Is(err, nodeapi.ErrBusy) {
		t.Fatalf("идёт задача: %v", err)
	}
	l.f.done()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, busy := l.api.Tasks.Running(); !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("задача не завершилась")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := l.client.SyncManifest(context.Background()); err != nil {
		t.Fatalf("после задачи: %v", err)
	}
}
