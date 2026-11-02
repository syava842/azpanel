package proxy

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
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/update"
	"github.com/syava842/azpanel/internal/updateapi"
)

type updFixture struct {
	t       *testing.T
	root    string
	priv    ed25519.PrivateKey
	client  *nodeapi.HTTPClient
	calls   [][]string
	running bool
}

func newUpdFixture(t *testing.T) *updFixture {
	t.Helper()
	e := newAPI(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "config.toml"), []byte("config_version = 2\n"), 0o600)
	f := &updFixture{t: t, root: root, priv: priv}
	run := func(_ context.Context, name string, args ...string) (int, []byte, error) {
		f.calls = append(f.calls, append([]string{name}, args...))
		if name == "systemctl" && f.running {
			return 0, nil, nil
		}
		if name == "systemctl" {
			return 3, nil, nil
		}
		return 0, nil, nil
	}
	e.api.Update = &updateapi.Service{
		Root: root, Pub: pub, Self: "/opt/azpanel/bin/azpanel", Version: "0.9.0",
		ParamsDir: filepath.Join(root, "data", "params"), StageDir: filepath.Join(root, "data", "update", "stage"),
		Exec: func(_ context.Context, _ string, args ...string) (update.ExecResult, error) {
			cfg, _ := os.ReadFile(args[3])
			out, _, err := config.Migrate(cfg, nil)
			if err != nil {
				return update.ExecResult{Stderr: []byte(err.Error()), Code: 1}, nil
			}
			return update.ExecResult{Stdout: out}, nil
		},
		Log:    e.api.Log,
		Launch: SelfUpdateLauncher(run, filepath.Join(root, "log", "selfupdate.log"), e.api.Log, func() time.Time { return time.Unix(2_000_000_000, 0) }),
	}
	// Маршруты регистрируются в Handler, поэтому сервер поднимается заново.
	srv := httptest.NewServer(e.api.Handler())
	t.Cleanup(srv.Close)
	f.client = nodeapi.New(srv.URL, testToken)
	return f
}

func (f *updFixture) release(ver string, key ed25519.PrivateKey) nodeapi.UpdateRequest {
	name := update.ArchiveName(ver, runtime.GOARCH)
	body := "\x7fELF" + strings.Repeat("x", 200<<10) // больше обычного предела тела (64 КБ)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "azpanel", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	return nodeapi.UpdateRequest{Name: name, Archive: buf.Bytes(), Sums: sums, Sig: ed25519.Sign(key, sums)}
}

// I4: у прокси-агента есть POST /v1/update, как у агента узла.
func TestProxyUpdateAcceptsSignedReleaseAndStartsUnit(t *testing.T) {
	f := newUpdFixture(t)
	task, err := f.client.Update(context.Background(), f.release("0.9.1", f.priv))
	if err != nil {
		t.Fatal(err)
	}
	if task.Kind != "selfupdate" {
		t.Fatalf("%+v", task)
	}
	last := f.calls[len(f.calls)-1]
	joined := strings.Join(last, " ")
	if last[0] != "systemd-run" || !strings.Contains(joined, "--unit="+SelfUpdateUnit) ||
		!strings.Contains(joined, "/opt/azpanel/bin/azpanel internal selfupdate --params ") {
		t.Fatalf("команда: %s", joined)
	}
	files, _ := filepath.Glob(filepath.Join(f.root, "data", "params", "params-*.json"))
	if len(files) != 1 {
		t.Fatalf("файлов параметров %d", len(files))
	}
	var p updateapi.Params
	data, _ := os.ReadFile(files[0])
	if json.Unmarshal(data, &p) != nil || p.Name == "" {
		t.Fatalf("параметры: %s", data)
	}
	if b, _ := os.ReadFile(p.ArchivePath); len(b) == 0 {
		t.Fatal("архив не подготовлен")
	}
}

func TestProxyUpdateRejectsForeignSignatureWithoutTraces(t *testing.T) {
	f := newUpdFixture(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_, err := f.client.Update(context.Background(), f.release("0.9.1", other))
	if err == nil || !strings.Contains(err.Error(), "подпись") {
		t.Fatalf("ждали отказ по подписи: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("юнит запущен: %v", f.calls)
	}
	if m, _ := os.ReadDir(filepath.Join(f.root, "data")); len(m) != 0 {
		t.Fatalf("следы: %v", m)
	}
}

func TestProxyUpdateWhileRunningIs409AndCleansUp(t *testing.T) {
	f := newUpdFixture(t)
	f.running = true
	_, err := f.client.Update(context.Background(), f.release("0.9.1", f.priv))
	var ae *nodeapi.Error
	if !errors.As(err, &ae) || ae.Status != 409 {
		t.Fatalf("ждали 409: %v", err)
	}
	if m, _ := filepath.Glob(filepath.Join(f.root, "data", "params", "*")); len(m) != 0 {
		t.Fatalf("файл параметров остался: %v", m)
	}
	if m, _ := os.ReadDir(filepath.Join(f.root, "data", "update", "stage")); len(m) != 0 {
		t.Fatalf("файлы обновления остались: %v", m)
	}
}

func TestProxyUpdateResult(t *testing.T) {
	f := newUpdFixture(t)
	if res, err := f.client.UpdateResult(context.Background()); err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}
