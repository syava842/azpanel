package panel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
)

func runEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AZPANEL_ROOT", filepath.Join(t.TempDir(), "azpanel"))
	for _, d := range []string{paths.Etc(), paths.Log()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunNoToken(t *testing.T) {
	runEnv(t)
	err := Run(context.Background(), config.Default(), "test")
	if err == nil || !strings.Contains(err.Error(), "нет NODE_TOKEN в secrets.env: переустановите узел") {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestRunServesAndStops(t *testing.T) {
	runEnv(t)
	if err := secrets.Set(paths.SecretsFile(), secrets.NodeToken, strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfg := config.Default()
	cfg.Panel.Listen = addr

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, "test") }()

	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/healthz: %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run после отмены: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run не остановился")
	}
}

func TestRunBusyPort(t *testing.T) {
	runEnv(t)
	secrets.Set(paths.SecretsFile(), secrets.NodeToken, strings.Repeat("ab", 32))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := config.Default()
	cfg.Panel.Listen = ln.Addr().String()
	if err := Run(context.Background(), cfg, "test"); err == nil {
		t.Fatal("занятый порт: ждали ошибку")
	}
}

func TestRunCreatesDBAndCollects(t *testing.T) {
	runEnv(t)
	token := strings.Repeat("cd", 32)
	if err := secrets.Set(paths.SecretsFile(), secrets.NodeToken, token); err != nil {
		t.Fatal(err)
	}
	var good, bad atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			bad.Add(1)
			http.Error(w, `{"error":"нет доступа"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/system":
			good.Add(1)
			w.Write([]byte(`{"resources":{"cpu_percent":7.5}}`))
		case "/v1/sessions", "/v1/clients":
			w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfg := config.Default()
	cfg.Panel.Listen = addr
	cfg.Panel.NodeURL = agent.URL

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, "test") }()

	dbPath := filepath.Join(paths.Data(), "azpanel.db")
	var pts []store.ResourcePoint
	deadline := time.Now().Add(10 * time.Second)
	for len(pts) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		if st, err := store.Open(dbPath); err == nil {
			pts, _ = st.ResourceSeries(context.Background(), store.LocalNode, 0, time.Now().Unix()+3600, store.Minute)
			st.Close()
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run после отмены: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run не остановился")
	}
	if good.Load() == 0 {
		t.Fatal("сборщик не сделал ни одного прохода")
	}
	if bad.Load() != 0 {
		t.Fatalf("запросов без верного токена: %d", bad.Load())
	}
	if info, err := os.Stat(dbPath); err != nil || info.IsDir() {
		t.Fatalf("файл базы: %v", err)
	}
	if len(pts) == 0 || pts[0].CPU != 7.5 {
		t.Fatalf("точки ресурсов: %+v", pts)
	}
}

// Занятый порт: Run возвращает ошибку, а сборщик не успевает ни разу
// обратиться к агенту (в его проходе срабатывают автоблокировки).
func TestRunBusyPortNoCollect(t *testing.T) {
	runEnv(t)
	token := strings.Repeat("ef", 32)
	secrets.Set(paths.SecretsFile(), secrets.NodeToken, token)
	var calls atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`[]`))
	}))
	defer agent.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := config.Default()
	cfg.Panel.Listen = ln.Addr().String()
	cfg.Panel.NodeURL = agent.URL
	// Занятие порта «затягивается»: будь сборщик запущен раньше, за это время
	// он успел бы обратиться к агенту.
	old := listen
	listen = func(network, addr string) (net.Listener, error) {
		time.Sleep(300 * time.Millisecond)
		return old(network, addr)
	}
	defer func() { listen = old }()
	if err := Run(context.Background(), cfg, "test"); err == nil {
		t.Fatal("занятый порт: ждали ошибку")
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("агента вызвали %d раз при занятом порте", n)
	}
}
