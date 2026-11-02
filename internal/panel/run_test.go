package panel

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
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
