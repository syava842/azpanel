package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/update"
)

const cliToken = "ghp_CLITOKEN"

// releaseServer — поддельный GitHub с подписанным релизом ver.
func releaseServer(t *testing.T, ver string, priv ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	name := update.ArchiveName(ver, runtime.GOARCH)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	body := "\x7fELF-new"
	tw.WriteHeader(&tar.Header{Name: "azpanel", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	files := map[string][]byte{"1": buf.Bytes(), "2": sums, "3": ed25519.Sign(priv, sums)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/syava842/azpanel/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(update.Release{Tag: "v" + ver, Body: "Новое: быстрее", Assets: []update.Asset{
			{ID: 1, Name: name}, {ID: 2, Name: update.SumsName}, {ID: 3, Name: update.SigName}}})
	})
	mux.HandleFunc("GET /repos/syava842/azpanel/releases/assets/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Write(files[r.PathValue("id")])
	})
	return httptest.NewServer(mux)
}

func withVersion(t *testing.T, v string) {
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

func testDeps(srv *httptest.Server, token string, env func(io.Writer) (*update.Env, error)) updateDeps {
	return updateDeps{
		token:  func() string { return token },
		client: func(tok string) *update.Client { return &update.Client{BaseURL: srv.URL, Token: tok} },
		env:    env,
	}
}

func TestUpdateCheck(t *testing.T) {
	withVersion(t, "0.9.0")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := releaseServer(t, "0.9.1", priv)
	defer srv.Close()
	var out bytes.Buffer
	err := runUpdate([]string{"--check"}, strings.NewReader(""), &out, testDeps(srv, cliToken, nil))
	if err != nil || !strings.Contains(out.String(), "0.9.1") || !strings.Contains(out.String(), "Новое: быстрее") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	withVersion(t, "0.9.1")
	out.Reset()
	if err := runUpdate([]string{"--check"}, strings.NewReader(""), &out, testDeps(srv, cliToken, nil)); err != nil || !strings.Contains(out.String(), "Обновлений нет") {
		t.Fatalf("%v\n%s", err, out.String())
	}
}

func TestUpdateRefusesDevAllowsNoToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := releaseServer(t, "0.9.1", priv)
	defer srv.Close()
	withVersion(t, "dev")
	if err := runUpdate([]string{"--check"}, strings.NewReader(""), io.Discard, testDeps(srv, cliToken, nil)); err == nil {
		t.Fatal("dev-сборка проверила обновления")
	}
	withVersion(t, "0.9.0")
	if err := runUpdate([]string{"--check"}, strings.NewReader(""), io.Discard, testDeps(srv, "", nil)); err != nil {
		t.Fatalf("без токена (публичный репозиторий) проверка отказала: %v", err)
	}
	if err := runUpdate([]string{"--что"}, strings.NewReader(""), io.Discard, testDeps(srv, cliToken, nil)); err == nil {
		t.Fatal("неизвестный флаг принят")
	}
}

// migrateExec подменяет запуск распакованного нового бинарника: отвечает так,
// как `azpanel internal migrate-config` (код 3 и JSON при вопросах).
func migrateExec(migrate func([]byte, map[string]string) ([]byte, []config.Question, error)) update.ExecFunc {
	return func(_ context.Context, _ string, args ...string) (update.ExecResult, error) {
		cfg, _ := os.ReadFile(args[3])
		var answers map[string]string
		ans, _ := os.ReadFile(args[5])
		json.Unmarshal(ans, &answers)
		out, _, err := migrate(cfg, answers)
		var qe *config.QuestionsError
		switch {
		case errors.As(err, &qe):
			var reply update.MigrateReply
			for _, q := range qe.Questions {
				reply.Questions = append(reply.Questions, update.MigrateQuestion{Key: q.Key, Text: q.Text})
			}
			data, _ := json.Marshal(reply)
			return update.ExecResult{Stdout: data, Code: update.MigrateExitQuestions}, nil
		case err != nil:
			return update.ExecResult{Stderr: []byte(err.Error()), Code: 1}, nil
		}
		return update.ExecResult{Stdout: out}, nil
	}
}

func fakeEnv(t *testing.T, pub ed25519.PublicKey, migrate func([]byte, map[string]string) ([]byte, []config.Question, error)) (*update.Env, string) {
	root := t.TempDir()
	for rel, c := range map[string]string{"bin/azpanel": "\x7fELF-old", "etc/config.toml": "a = 1\n"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(c), 0o755)
	}
	if migrate == nil {
		migrate = config.Migrate
	}
	return &update.Env{
		Root: root, Version: "0.9.0", Pub: pub, Arch: runtime.GOARCH, Exec: migrateExec(migrate),
		Checks:     []update.Check{func(context.Context, string) error { return nil }},
		Systemctl:  func(context.Context, ...string) error { return nil },
		HealthWait: time.Second,
	}, root
}

func TestUpdateCancelAtPrompt(t *testing.T) {
	withVersion(t, "0.9.0")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := releaseServer(t, "0.9.1", priv)
	defer srv.Close()
	env, root := fakeEnv(t, pub, nil)
	var out bytes.Buffer
	err := runUpdate(nil, strings.NewReader("n\n"), &out, testDeps(srv, cliToken, func(io.Writer) (*update.Env, error) { return env, nil }))
	if err != nil || !strings.Contains(out.String(), "Отменено") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(root, "bin", "azpanel")); string(b) != "\x7fELF-old" {
		t.Fatal("отмена изменила бинарник")
	}
}

func TestUpdateAsksQuestionThenApplies(t *testing.T) {
	withVersion(t, "0.9.0")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := releaseServer(t, "0.9.1", priv)
	defer srv.Close()
	q := config.Question{Key: "node.x", Text: "Какой x?"}
	env, root := fakeEnv(t, pub, func(data []byte, a map[string]string) ([]byte, []config.Question, error) {
		if a["node.x"] == "" {
			return nil, []config.Question{q}, &config.QuestionsError{Questions: []config.Question{q}}
		}
		return append(data, []byte("x = "+a["node.x"]+"\n")...), nil, nil
	})
	var out bytes.Buffer
	err := runUpdate(nil, strings.NewReader("y\n42\n"), &out, testDeps(srv, cliToken, func(io.Writer) (*update.Env, error) { return env, nil }))
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Какой x?") || !strings.Contains(out.String(), "Обновлено: 0.9.0 -> 0.9.1") {
		t.Fatalf("вывод:\n%s", out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(root, "bin", "azpanel")); string(b) != "\x7fELF-new" {
		t.Fatal("бинарник не заменён")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc", "config.toml")); !strings.Contains(string(b), "x = 42") {
		t.Fatalf("конфиг: %s", b)
	}
}

func TestUpdateYesWithQuestionRefuses(t *testing.T) {
	withVersion(t, "0.9.0")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := releaseServer(t, "0.9.1", priv)
	defer srv.Close()
	q := config.Question{Key: "node.x", Text: "Какой x?"}
	env, root := fakeEnv(t, pub, func([]byte, map[string]string) ([]byte, []config.Question, error) {
		return nil, []config.Question{q}, &config.QuestionsError{Questions: []config.Question{q}}
	})
	err := runUpdate([]string{"--yes"}, strings.NewReader(""), io.Discard, testDeps(srv, cliToken, func(io.Writer) (*update.Env, error) { return env, nil }))
	if err == nil {
		t.Fatal("--yes обошёл вопрос")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "bin", "azpanel")); string(b) != "\x7fELF-old" {
		t.Fatal("отказ изменил бинарник")
	}
	if _, err := os.Stat(filepath.Join(root, "backup")); err == nil {
		t.Fatal("отказ создал бэкап")
	}
}

func TestUpdateWrongSignatureRefuses(t *testing.T) {
	withVersion(t, "0.9.0")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	srv := releaseServer(t, "0.9.1", otherPriv)
	defer srv.Close()
	env, root := fakeEnv(t, pub, nil)
	err := runUpdate([]string{"--yes"}, strings.NewReader(""), io.Discard, testDeps(srv, cliToken, func(io.Writer) (*update.Env, error) { return env, nil }))
	if err == nil || !strings.Contains(err.Error(), "подпись") {
		t.Fatalf("ждали отказ по подписи: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "bin", "azpanel")); string(b) != "\x7fELF-old" {
		t.Fatal("отказ изменил бинарник")
	}
}

func TestHealthChecksAgentVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte("ok"))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"proto": 1, "version": "0.9.0"})
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := config.Default()
	cfg.Panel.Listen, cfg.Node.APIListen = addr, addr
	checks := healthChecks(cfg, "tok", []string{"azpanel-node", "azpanel-panel"})
	if len(checks) != 2 {
		t.Fatalf("проверок %d", len(checks))
	}
	ctx := context.Background()
	if err := checks[0](ctx, "0.9.1"); err != nil {
		t.Fatalf("healthz: %v", err)
	}
	if err := checks[1](ctx, "0.9.1"); err == nil {
		t.Fatal("агент со старой версией признан живым")
	}
	if err := checks[1](ctx, "0.9.0"); err != nil {
		t.Fatalf("агент с нужной версией: %v", err)
	}
}
