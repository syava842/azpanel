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
	d, err := Load(filepath.Join(t.TempDir(), "limits.json"))
	if err != nil || len(d.Limits) != 0 || len(d.Blocked) != 0 || d.Limits == nil || d.Blocked == nil {
		t.Fatalf("d = %+v, err = %v", d, err)
	}
}

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	in := Data{Limits: map[string]int{"alice": 3}, Blocked: map[string]bool{"bob": true, "carol": true, "dave": false}}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	want := "{\n  \"version\": 2,\n  \"limits\": {\n    \"alice\": 3\n  },\n  \"blocked\": [\n    \"bob\",\n    \"carol\"\n  ]\n}\n"
	if string(data) != want {
		t.Fatalf("файл:\n%s", data)
	}
	d, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Limits["alice"] != 3 || !d.Blocked["bob"] || !d.Blocked["carol"] || d.Blocked["dave"] || len(d.Blocked) != 2 {
		t.Fatalf("d = %+v", d)
	}
}

func TestLoadVersion1(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(p, []byte(`{"version":1,"limits":{"alice":2}}`), 0o600)
	d, err := Load(p)
	if err != nil || d.Limits["alice"] != 2 || len(d.Blocked) != 0 {
		t.Fatalf("d = %+v, err = %v", d, err)
	}
}

func TestLoadRejectsBadBlockedName(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(p, []byte(`{"version":2,"limits":{},"blocked":["bad name"]}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("недопустимое имя в blocked принято")
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"битый JSON": `{`,
		"версия":     `{"version":3,"limits":{}}`,
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
	if e, err := s.Get("alice"); e.Limit != 0 || err != nil {
		t.Fatalf("без файла: e=%+v err=%v", e, err)
	}
	Save(p, Data{Limits: map[string]int{"alice": 2}})
	if e, _ := s.Get("alice"); e.Limit != 2 {
		t.Fatalf("после записи e=%+v", e)
	}
	Save(p, Data{Limits: map[string]int{"alice": 2, "bob": 10}})
	if e, _ := s.Get("bob"); e.Limit != 10 {
		t.Fatalf("после второй записи e=%+v", e)
	}
	os.WriteFile(p, []byte("{"), 0o600)
	e, err := s.Get("alice")
	if err == nil {
		t.Fatal("битый файл: ждали ошибку")
	}
	if e.Limit != 2 {
		t.Fatalf("битый файл: действует последний прочитанный лимит, ждали 2, получено %d", e.Limit)
	}
}

func TestStoreBrokenFromStartIsUnlimited(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(p, []byte("{"), 0o600)
	if e, err := NewStore(p).Get("alice"); e.Limit != 0 || e.Blocked || err == nil {
		t.Fatalf("e=%+v err=%v", e, err)
	}
}

func TestStoreReportsBlocked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	Save(p, Data{Limits: map[string]int{"alice": 1}, Blocked: map[string]bool{"bob": true}})
	s := NewStore(p)
	if e, err := s.Get("bob"); err != nil || !e.Blocked || e.Limit != 0 {
		t.Fatalf("bob: %+v, %v", e, err)
	}
	if e, _ := s.Get("alice"); e.Blocked || e.Limit != 1 {
		t.Fatalf("alice: %+v", e)
	}
}
