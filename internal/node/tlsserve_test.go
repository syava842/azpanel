package node

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/paths"
)

func TestListenAPIServesTLSWithPinnedFingerprint(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := config.Default().Node
	n.APIListen = ""
	n.ListenTLS = "127.0.0.1:0"
	n.AllowIPs = []string{"127.0.0.1"}
	lns, err := listenAPI(n, log)
	if err != nil || len(lns) != 1 {
		t.Fatalf("%v %v", lns, err)
	}
	api := &API{Token: testToken, Version: "t", Log: log}
	srv := &http.Server{Handler: api.Handler()}
	go srv.Serve(lns[0])
	t.Cleanup(func() { srv.Close() })

	// Сертификат создан при первом старте и лежит в etc/tls.
	fp, err := agenttls.FingerprintFile(filepath.Join(paths.Etc(), "tls", agenttls.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	url := "https://" + lns[0].Addr().String()
	c, err := nodeapi.NewPinned(url, testToken, fp)
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.Info(context.Background())
	if err != nil || info.Version != "t" {
		t.Fatalf("%+v %v", info, err)
	}
	bad, _ := nodeapi.NewPinned(url, testToken, strings.Repeat("22", 32))
	if _, err := bad.Info(context.Background()); !errors.Is(err, nodeapi.ErrCertChanged) {
		t.Fatalf("err = %v", err)
	}
}

func TestListenAPIRejectsBadAllowList(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	n := config.Default().Node
	n.APIListen = ""
	n.ListenTLS = "127.0.0.1:0"
	n.AllowIPs = []string{"не адрес"}
	if _, err := listenAPI(n, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("мусор в белом списке принят")
	}
	if _, err := os.Stat(filepath.Join(paths.Etc(), "tls")); err == nil {
		t.Error("сертификат создан до проверки списка")
	}
}
