package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// Скрипт AntiZapret, запущенный мимо агента, виден по /proc/<pid>/cmdline —
// только если его выполняет интерпретатор.
func TestProcScriptsFindsAntiZapretScripts(t *testing.T) {
	proc := t.TempDir()
	write := func(pid string, args ...string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "cmdline"), []byte(strings.Join(args, "\x00")+"\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("1", "/sbin/init")
	write("200", "/usr/bin/vim", "/root/notes.txt")
	os.MkdirAll(filepath.Join(proc, "self"), 0o755) // не pid
	if got := ProcScripts(proc); got != "" {
		t.Fatalf("без скриптов: %q", got)
	}
	write("301", "/bin/bash", "/root/antizapret/doall.sh")
	if got := ProcScripts(proc); got != "doall.sh" {
		t.Fatalf("doall.sh: %q", got)
	}
	os.RemoveAll(filepath.Join(proc, "301"))
	if got := ProcScripts(filepath.Join(proc, "нет")); got != "" {
		t.Fatalf("нет каталога: %q", got)
	}
}

func TestScriptOf(t *testing.T) {
	for want, cases := range map[string][][]string{
		"doall.sh": {
			{"/bin/bash", "/root/antizapret/doall.sh"},
			{"nice", "-n", "19", "bash", "doall.sh"},
			{"ionice", "-c", "3", "nice", "-n", "19", "/usr/bin/bash", "-x", "/root/antizapret/doall.sh", "ip"},
			{"timeout", "1h", "sh", "./doall.sh"},
			{"env", "LANG=C", "dash", "doall.sh"},
		},
		"client.sh": {
			{"sudo", "bash", "./client.sh", "1", "bob"},
			{"bash", "-o", "pipefail", "client.sh", "7"},
		},
		"": {
			{"nano", "/root/antizapret/client.sh"},
			{"less", "doall.sh"},
			{"vi", "setup.sh"},
			{"nice", "-n", "19", "less", "doall.sh"},
			{"bash", "-c", "/root/antizapret/doall.sh"},
			{"bash", "/dev/fd/63"},
			{"bash", "notes.sh", "doall.sh"},
			{"python3", "setup.sh"},
		},
	} {
		for _, args := range cases {
			if got := scriptOf(args); got != want {
				t.Errorf("%q: %q, ждали %q", args, got, want)
			}
		}
	}
}

// Установка AntiZapret («bash <(wget …)» — в /proc только /dev/fd/63) видна
// по каталогу /tmp/antizapret; остаток оборванной установки старше двух
// часов не в счёт.
func TestSetupInProgress(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "antizapret")
	now := time.Now()
	if SetupInProgress(dir, now) {
		t.Fatal("каталога нет, а установка «идёт»")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !SetupInProgress(dir, now) {
		t.Fatal("свежий каталог установки не замечен")
	}
	if SetupInProgress(dir, now.Add(2*time.Hour+time.Minute)) {
		t.Fatal("каталог старше двух часов считается идущей установкой")
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
