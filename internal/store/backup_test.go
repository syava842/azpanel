package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupIsConsistentSnapshot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetMeta(ctx, "k", "до"); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "snap.db")
	if err := st.Backup(ctx, snap); err != nil {
		t.Fatal(err)
	}
	// Запись после снимка в снимок не попадает.
	if err := st.SetMeta(ctx, "k", "после"); err != nil {
		t.Fatal(err)
	}
	cp, err := Open(snap)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if v, ok, _ := cp.Meta(ctx, "k"); !ok || v != "до" {
		t.Fatalf("в снимке %q ok=%v", v, ok)
	}
	if err := st.Backup(ctx, snap); err == nil {
		t.Fatal("снимок поверх существующего файла")
	}
	if _, err := os.Stat(snap); err != nil {
		t.Fatal("существующий снимок пропал после отказа")
	}
}
