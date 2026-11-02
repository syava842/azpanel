package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/syava842/azpanel/internal/telemt"
)

func TestReadParamsRemovesFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "params.json")
	os.WriteFile(f, []byte(`{"op":"add","name":"u","secret":"00112233445566778899aabbccddeeff"}`), 0o600)
	var p telemt.ApplyParams
	if err := readParams([]string{"--params", f}, &p); err != nil {
		t.Fatal(err)
	}
	if p.Op != "add" || p.Name != "u" {
		t.Fatalf("%+v", p)
	}
	if _, err := os.Stat(f); err == nil {
		t.Fatal("файл параметров должен быть удалён сразу после чтения")
	}
	if err := readParams([]string{"--params", f}, &p); err == nil {
		t.Fatal("повторное чтение должно проваливаться")
	}
}

func TestReadParamsRejectsUnknownFieldsAndUsage(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(f, []byte(`{"op":"add","лишнее":1}`), 0o600)
	var p telemt.ApplyParams
	if err := readParams([]string{"--params", f}, &p); err == nil {
		t.Fatal("неизвестное поле должно отклоняться")
	}
	if err := readParams([]string{"f"}, &p); err == nil {
		t.Fatal("ждали ошибку аргументов")
	}
}
