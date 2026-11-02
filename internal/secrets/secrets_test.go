package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadMissingIsEmpty(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "secrets.env"))
	if err != nil || len(m) != 0 {
		t.Fatalf("m = %v, err = %v", m, err)
	}
}

func TestSetKeepsOtherKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := Set(p, "B_KEY", "2"); err != nil {
		t.Fatal(err)
	}
	if err := Set(p, NodeToken, "abc=def"); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if m["B_KEY"] != "2" || m[NodeToken] != "abc=def" {
		t.Fatalf("m = %v", m)
	}
	data, _ := os.ReadFile(p)
	if string(data) != "B_KEY=2\nNODE_TOKEN=abc=def\n" {
		t.Fatalf("файл:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("права %v", st.Mode().Perm())
		}
	}
}

func TestSetRejectsBadInput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := Set(p, "bad key", "x"); err == nil {
		t.Fatal("имя с пробелом принято")
	}
	if err := Set(p, "KEY", "a\nB=c"); err == nil {
		t.Fatal("значение с переводом строки принято")
	}
}

func TestLoadBadLineHidesValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	os.WriteFile(p, []byte("# комментарий\n\nGOOD=1\nsupersecretvalue\n"), 0o600)
	_, err := Load(p)
	if err == nil || strings.Contains(err.Error(), "supersecretvalue") || !strings.Contains(err.Error(), ":4:") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewToken(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if len(a) != 64 || a == b {
		t.Fatalf("a = %q, b = %q", a, b)
	}
}

func TestSetManyAtomicAndKeepsOthers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := Set(p, "KEEP", "1"); err != nil {
		t.Fatal(err)
	}
	if err := SetMany(p, map[string]string{"A_KEY": "x=y", "B_KEY": "2", "KEEP": "3"}); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || m["A_KEY"] != "x=y" || m["B_KEY"] != "2" || m["KEEP"] != "3" {
		t.Fatalf("m = %v", m)
	}
}

func TestSetManyBadInputWritesNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := Set(p, "KEEP", "1"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	if err := SetMany(p, map[string]string{"GOOD": "1", "bad key": "x"}); err == nil {
		t.Fatal("плохой ключ принят")
	}
	if err := SetMany(p, map[string]string{"GOOD": "1", "OTHER": "a\nb"}); err == nil {
		t.Fatal("значение с переводом строки принято")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatalf("файл изменён: %q -> %q", before, after)
	}
}

func TestDeleteAndParse(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secrets.env")
	if err := SetMany(f, map[string]string{"A_KEY": "1", "TELEGRAM_BOT_TOKEN": "x:y", "ZED": "3"}); err != nil {
		t.Fatal(err)
	}
	if err := Delete(f, TelegramBotToken, "НЕТ_ТАКОГО"); err != nil {
		t.Fatal(err)
	}
	m, err := Load(f)
	if err != nil || len(m) != 2 || m["A_KEY"] != "1" || m["ZED"] != "3" {
		t.Fatalf("%v %v", m, err)
	}
	p, err := Parse(Marshal(m))
	if err != nil || p["ZED"] != "3" || len(p) != 2 {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := Parse([]byte("мусор без равно")); err == nil {
		t.Fatal("мусор принят")
	}
}
