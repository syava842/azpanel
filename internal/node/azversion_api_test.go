package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

func TestAPIAntizapretVersion(t *testing.T) {
	e := newAPI(t)
	if _, err := e.client.AZVersion(context.Background()); status(err) != http.StatusServiceUnavailable {
		t.Fatalf("без настройки ожидался 503: %v", err)
	}

	dir := t.TempDir()
	hashes := map[string]string{}
	for _, n := range antizapret.VersionScripts {
		body := []byte("#!/bin/bash\n# " + n + "\n")
		os.WriteFile(filepath.Join(dir, n), body, 0o755)
		hashes[n] = antizapret.GitBlobSHA1(body)
	}
	commit := func(sha, msg string) map[string]any {
		return map[string]any{"sha": sha, "commit": map[string]any{"message": msg + "\n\nтело", "committer": map[string]any{"date": "2026-11-02T07:30:30Z"}}}
	}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits") && r.URL.Query().Get("path") == "":
			json.NewEncoder(w).Encode([]any{commit("bbbb", "Update parse.sh"), commit("aaaa", "Update up.sh")})
		case strings.HasSuffix(r.URL.Path, "/commits"):
			json.NewEncoder(w).Encode([]any{commit("aaaa", "Update up.sh")})
		default:
			var out []map[string]any
			for n, h := range hashes {
				out = append(out, map[string]any{"name": n, "sha": h, "type": "file"})
			}
			json.NewEncoder(w).Encode(out)
		}
	}))
	defer gh.Close()
	// Запись об установке: коммит aaaa, на один новее — bbbb.
	rec := antizapret.InstalledFile{Path: filepath.Join(t.TempDir(), "antizapret.json")}
	if err := rec.Write(dir, "aaaa", time.Now()); err != nil {
		t.Fatal(err)
	}
	e.api.AZVersion = &antizapret.VersionService{GitHub: &antizapret.GitHub{BaseURL: gh.URL}, Dir: dir, Record: rec}

	v, err := e.client.AZVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Current != "aaaa" || v.CurrentSource != "recorded" || v.UpToDate || v.Latest == nil || v.Latest.SHA != "bbbb" {
		t.Fatalf("%+v", v)
	}
	if len(v.Behind) != 1 || v.Behind[0].SHA != "bbbb" || v.Behind[0].Message != "Update parse.sh" || v.Behind[0].Date.IsZero() {
		t.Fatalf("коммиты между: %+v", v.Behind)
	}
}
