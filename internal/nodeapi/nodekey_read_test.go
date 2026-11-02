package nodeapi

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testKeyString(t *testing.T) (NodeKey, string) {
	t.Helper()
	k := NodeKey{PanelIP: "203.0.113.9", Token: strings.Repeat("ab", 32)}
	s, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return k, s
}

// M12: ключ узла читается из stdin или файла, а не из аргумента.
func TestReadNodeKeySources(t *testing.T) {
	k, s := testKeyString(t)
	noEnv := func(string) string { return "" }
	got, err := ReadNodeKey("-", noEnv, strings.NewReader(" "+s+"\n"))
	if err != nil || got != k {
		t.Fatalf("stdin: %+v %v", got, err)
	}
	path := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(path, []byte(s+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err = ReadNodeKey(path, noEnv, nil); err != nil || got != k {
		t.Fatalf("файл: %+v %v", got, err)
	}
	env := func(name string) string {
		if name == NodeKeyFileEnv {
			return path
		}
		return ""
	}
	if got, err = ReadNodeKey("", env, nil); err != nil || got != k {
		t.Fatalf("переменная окружения: %+v %v", got, err)
	}
}

func TestReadNodeKeyRefusesArgvAndBadInput(t *testing.T) {
	_, s := testKeyString(t)
	noEnv := func(string) string { return "" }
	if _, err := ReadNodeKey(s, noEnv, nil); err == nil || !strings.Contains(err.Error(), "аргументом") {
		t.Fatalf("ключ в аргументе принят: %v", err)
	}
	if _, err := ReadNodeKey("", noEnv, nil); err == nil {
		t.Fatal("пустой источник принят")
	}
	if _, err := ReadNodeKey("-", noEnv, strings.NewReader("мусор")); err == nil {
		t.Fatal("мусор на stdin принят")
	}
	if _, err := ReadNodeKey("-", noEnv, strings.NewReader(strings.Repeat("x", 10000))); err == nil || !strings.Contains(err.Error(), "длинный") {
		t.Fatalf("огромный ввод: %v", err)
	}
	if _, err := ReadNodeKey(filepath.Join(t.TempDir(), "нет"), noEnv, nil); err == nil {
		t.Fatal("несуществующий файл принят")
	}
}

func TestReadNodeKeyRefusesWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("биты прав POSIX")
	}
	_, s := testKeyString(t)
	path := filepath.Join(t.TempDir(), "node.key")
	os.WriteFile(path, []byte(s), 0o644)
	os.Chmod(path, 0o644)
	if _, err := ReadNodeKey(path, func(string) string { return "" }, nil); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("файл с правами 0644 принят: %v", err)
	}
}
