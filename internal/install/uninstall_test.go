package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallCleansNginxAndBacksUpFirst(t *testing.T) {
	o, calls := setup(t)
	_, orig := copyTestdata(t, "vpn.test")
	n, f := newFakeNginx(nil)
	n.Dir = t.TempDir()
	file := filepath.Join(n.Dir, "sites-enabled", "vpn.test")
	f.files[file] = []byte(orig)
	srv := parseServers(file, orig)[1].NginxServer
	if err := n.Enable(srv, "/azpanel", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	// FindServers читает диск, а не поля: кладём файл и туда.
	writeReal(t, file, string(f.files[file]))
	f.cmds = nil
	o.Nginx = n
	var order []string
	o.Backup = func() error { order = append(order, "backup"); return nil }
	o.Run = func(name string, args ...string) error {
		order = append(order, name+" "+strings.Join(args, " "))
		return nil
	}
	_ = calls
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if string(f.files[file]) != orig {
		t.Fatal("файл nginx после uninstall не совпал с исходным")
	}
	if _, ok := f.files[SnippetPath]; ok {
		t.Fatal("фрагмент остался")
	}
	if strings.Join(f.cmds, "|") != "nginx -t|systemctl reload nginx" {
		t.Fatalf("команды nginx: %v", f.cmds)
	}
	if order[0] != "backup" {
		t.Fatalf("бэкап должен быть первым: %v", order)
	}
}

func TestUninstallBackupFailureAborts(t *testing.T) {
	o, calls := setup(t)
	o.Backup = func() error { return errors.New("client.sh 8 упал") }
	err := Uninstall(o)
	if err == nil || !strings.Contains(err.Error(), "ничего не удалено") || len(*calls) != 0 {
		t.Fatalf("%v %v", err, *calls)
	}
	o.SkipBackup = true
	if err := Uninstall(o); err != nil {
		t.Fatalf("--skip-backup: %v", err)
	}
}

func TestUninstallWithoutOurNginxLeavesNginxAlone(t *testing.T) {
	o, _ := setup(t)
	n, f := newFakeNginx(nil)
	n.Dir = t.TempDir()
	o.Nginx = n
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 0 {
		t.Fatalf("nginx тронут: %v", f.cmds)
	}
}

func writeReal(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
