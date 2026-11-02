package store

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var ctx = context.Background()

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenMigratesEmptyAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "azpanel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.SchemaVersion(ctx)
	if err != nil || v != len(migrations) {
		t.Fatalf("версия %d, %v", v, err)
	}
	var name string
	if err := s.db.QueryRow(`SELECT name FROM nodes WHERE id = 1`).Scan(&name); err != nil || name != "local" {
		t.Fatalf("узел 1: %q, %v", name, err)
	}
	if err := s.Audit(ctx, AuditEntry{TS: 1, User: "u", Action: "a", Target: "t"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, _ := s.SchemaVersion(ctx); v != len(migrations) {
		t.Fatalf("после повторного открытия версия %d", v)
	}
	if _, n, _ := s.AuditList(ctx, 10, 0, ""); n != 1 {
		t.Fatalf("данные пропали при повторном открытии: %d", n)
	}
}

func TestOpenPragmas(t *testing.T) {
	s := open(t)
	var mode string
	s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	var fk, busy int
	s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy)
	if mode != "wal" || fk != 1 || busy != 5000 {
		t.Fatalf("journal_mode=%s foreign_keys=%d busy_timeout=%d", mode, fk, busy)
	}
}

func TestOpenNewerSchemaRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "azpanel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE meta SET value = '99' WHERE key = 'schema_version'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = Open(path)
	if err == nil || !strings.Contains(err.Error(), "база версии 99 новее, чем знает эта версия azpanel") {
		t.Fatalf("ошибка: %v", err)
	}
}

func TestOpenFileMode600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права POSIX на Windows не применимы")
	}
	path := filepath.Join(t.TempDir(), "azpanel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fi, err := osStat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("права %v, %v", fi, err)
	}
}
