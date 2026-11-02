package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMeta(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, ok, err := st.Meta(ctx, "k"); ok || err != nil {
		t.Fatalf("пустой ключ: ok=%v err=%v", ok, err)
	}
	if err := st.SetMeta(ctx, "k", "1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta(ctx, "k", "2"); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := st.Meta(ctx, "k"); !ok || v != "2" {
		t.Fatalf("значение = %q ok=%v", v, ok)
	}
	if err := st.ClearMeta(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.Meta(ctx, "k"); ok {
		t.Fatal("ключ остался после удаления")
	}
	if err := st.ClearMeta(ctx, "k"); err != nil {
		t.Fatalf("повторное удаление: %v", err)
	}
}

func TestMetaPrefixOnlyMatching(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.SetMeta(ctx, "cert_warn:a", "1")
	_ = s.SetMeta(ctx, "cert_warn:б", "2")
	_ = s.SetMeta(ctx, "cert_other", "3")
	got, err := s.MetaPrefix(ctx, "cert_warn:")
	if err != nil || len(got) != 2 || got["cert_warn:a"] != "1" {
		t.Fatalf("получено %v, %v", got, err)
	}
}
