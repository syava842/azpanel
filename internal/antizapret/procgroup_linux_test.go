//go:build linux

package antizapret

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecClientShKillsGrandchildren(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\nsleep 300 &\necho $! > \"$(dirname \"$0\")/pid\"\nwait\n"
	if err := os.WriteFile(filepath.Join(dir, "client.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	execClientSh(ctx, dir)
	raw, err := os.ReadFile(filepath.Join(dir, "pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	// Потомок должен быть убит вместе с группой.
	for i := 0; i < 20; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("потомок %d пережил таймаут", pid)
}
