package limits

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"alice": true, "a-b_C9": true, "": false, "имя": false,
		"a b": false, "abcdefghijabcdefghijabcdefghijabc": false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v", name, got)
		}
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "limits.json"))
	if err != nil || len(m) != 0 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	if err := Save(p, map[string]int{"alice": 3}); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil || m["alice"] != 3 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"битый JSON": `{`,
		"версия":     `{"version":2,"limits":{}}`,
		"ноль":       `{"version":1,"limits":{"alice":0}}`,
		"кривое имя": `{"version":1,"limits":{"a b":1}}`,
	} {
		p := filepath.Join(dir, "l.json")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: ждали ошибку", name)
		}
	}
}

func TestStoreRereadsOnChange(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	s := NewStore(p)
	if n, err := s.Get("alice"); n != 0 || err != nil {
		t.Fatalf("без файла: n=%d err=%v", n, err)
	}
	Save(p, map[string]int{"alice": 2})
	if n, _ := s.Get("alice"); n != 2 {
		t.Fatalf("после записи n=%d", n)
	}
	Save(p, map[string]int{"alice": 2, "bob": 10})
	if n, _ := s.Get("bob"); n != 10 {
		t.Fatalf("после второй записи n=%d", n)
	}
	os.WriteFile(p, []byte("{"), 0o600)
	if _, err := s.Get("alice"); err == nil {
		t.Fatal("битый файл: ждали ошибку")
	}
}
