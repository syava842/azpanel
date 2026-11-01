package logx

import (
	"os"
	"path/filepath"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<нет>"
	}
	return string(b)
}

func TestRotatorShiftsAndDropsOldest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node.log")
	r, err := Open(p, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"first\n", "second\n", "third\n", "fourth\n"} {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	if got := read(t, p); got != "fourth\n" {
		t.Fatalf("node.log = %q", got)
	}
	if got := read(t, p+".1"); got != "third\n" {
		t.Fatalf("node.log.1 = %q", got)
	}
	if got := read(t, p+".2"); got != "second\n" {
		t.Fatalf("node.log.2 = %q", got)
	}
	if got := read(t, p+".3"); got != "<нет>" {
		t.Fatalf("лишний node.log.3 = %q", got)
	}
}

// Ротация не удалась (каталог пропал) — после его возвращения запись оживает.
func TestRotatorRecoversAfterFailedRotate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	os.MkdirAll(dir, 0o700)
	p := filepath.Join(dir, "node.log")
	r, err := Open(p, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.Write([]byte("first\n"))
	r.f.Close() // на Windows открытый файл не даёт удалить каталог
	os.RemoveAll(dir)
	if _, err := r.Write([]byte("second\n")); err == nil {
		t.Fatal("ждали ошибку записи без каталога")
	}
	os.MkdirAll(dir, 0o700)
	if _, err := r.Write([]byte("third\n")); err != nil {
		t.Fatalf("запись не ожила: %v", err)
	}
	if got := read(t, p); got != "third\n" {
		t.Fatalf("node.log = %q", got)
	}
}

func TestRotatorAppendsToExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node.log")
	os.WriteFile(p, []byte("old\n"), 0o640)
	r, err := Open(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	r.Write([]byte("new\n"))
	r.Close()
	if got := read(t, p); got != "old\nnew\n" {
		t.Fatalf("node.log = %q", got)
	}
}
