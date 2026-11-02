package node

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPIRebootAndBackupTasks(t *testing.T) {
	cases := []struct {
		name string
		call func(e apiEnv) (string, error)
		kind string
		tail []string
	}{
		{"reboot", func(e apiEnv) (string, error) {
			tk, err := e.client.Reboot(context.Background())
			return tk.Kind, err
		}, TaskReboot, []string{"systemctl", "reboot"}},
		{"backup", func(e apiEnv) (string, error) {
			tk, err := e.client.CreateBackup(context.Background())
			return tk.Kind, err
		}, TaskBackup, []string{"client.sh", "8"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, f, tk := tasksEnv(t)
			kind, err := c.call(e)
			if err != nil || kind != c.kind {
				t.Fatalf("%q, %v", kind, err)
			}
			list, _ := e.client.Tasks(context.Background())
			f.done()
			waitFinished(t, tk, list[0].ID)
			got := f.calls[0]
			n := len(c.tail)
			if filepath.Base(got[len(got)-n]) != c.tail[0] || strings.Join(got[len(got)-n+1:], " ") != strings.Join(c.tail[1:], " ") {
				t.Fatalf("команда: %v", got)
			}
		})
	}
	if DefaultTaskTimeouts[TaskBackup] != 600*time.Second {
		t.Fatalf("предел бэкапа: %v", DefaultTaskTimeouts[TaskBackup])
	}
}

func TestAPIBackupsListAndFetch(t *testing.T) {
	e := newAPI(t)
	dir := t.TempDir()
	e.api.BackupDir = dir
	old := filepath.Join(dir, "backup-old.tar.gz")
	cur := filepath.Join(dir, "backup-1.2.3.4.tar.gz")
	os.WriteFile(old, []byte("OLD"), 0o600)
	os.WriteFile(cur, []byte("NEW-DATA"), 0o600)
	os.Chtimes(old, time.Unix(1000, 0), time.Unix(1000, 0))
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("нельзя"), 0o600)
	os.WriteFile(filepath.Join(dir, "backup-x.txt"), []byte("нельзя"), 0o600)
	ctx := context.Background()

	list, err := e.client.Backups(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "backup-1.2.3.4.tar.gz" || list[0].Size != 8 {
		t.Fatalf("%+v, %v", list, err)
	}
	rc, err := e.client.Backup(ctx, "backup-1.2.3.4.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _ := rc.Read(buf)
	rc.Close()
	if string(buf[:n]) != "NEW-DATA" {
		t.Fatalf("содержимое: %q", buf[:n])
	}
	for _, name := range []string{"secret.txt", "backup-x.txt", "..%2Fetc%2Fpasswd", "backup-nope.tar.gz", "backup-.tar.gz/../secret.txt"} {
		if _, err := e.client.Backup(ctx, name); status(err) != 404 && status(err) != 400 {
			t.Fatalf("имя %q: %v", name, err)
		}
	}
}

func TestAPIBackupsSymlinkIgnored(t *testing.T) {
	e := newAPI(t)
	dir := t.TempDir()
	e.api.BackupDir = dir
	target := filepath.Join(t.TempDir(), "x")
	os.WriteFile(target, []byte("чужое"), 0o600)
	if err := os.Symlink(target, filepath.Join(dir, "backup-link.tar.gz")); err != nil {
		t.Skip("симлинки недоступны")
	}
	list, _ := e.client.Backups(context.Background())
	if len(list) != 0 {
		t.Fatalf("симлинк в списке: %+v", list)
	}
	if _, err := e.client.Backup(context.Background(), "backup-link.tar.gz"); status(err) != 404 {
		t.Fatalf("симлинк выдан: %v", err)
	}
}
