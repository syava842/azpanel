package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInternalNginxSnippetRejectsBadParams(t *testing.T) {
	p := filepath.Join(t.TempDir(), "params.json")
	os.WriteFile(p, []byte(`{"base_path":"/x; }","upstream":"127.0.0.1:8080"}`), 0o600)
	err := internalModes["nginx-snippet"](context.Background(), []string{"--params", p}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "base_path") {
		t.Fatalf("%v", err)
	}
	if _, serr := os.Stat(p); serr == nil {
		t.Fatal("файл параметров не удалён")
	}
}
