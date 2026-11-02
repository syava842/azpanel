package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicReplacesContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Fatalf("содержимое %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("остались временные файлы: %v", entries)
	}
}

func TestWriteFileKeepMeta(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileKeepMeta(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	info, _ := os.Stat(p)
	if string(got) != "new" {
		t.Fatalf("%q", got)
	}
	if os.PathSeparator == '/' && info.Mode().Perm() != 0o600 {
		t.Fatalf("права: %v", info.Mode().Perm())
	}
	// Нет файла — ошибка, новый не создаётся.
	missing := filepath.Join(filepath.Dir(p), "nope")
	if err := WriteFileKeepMeta(missing, []byte("x")); !os.IsNotExist(err) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("файл не должен появиться")
	}
}
