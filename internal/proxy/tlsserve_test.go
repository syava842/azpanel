package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/paths"
)

func TestListenTLSOnly(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lns, err := listen(config.Proxy{ListenTLS: "127.0.0.1:0", AllowIPs: []string{"127.0.0.1"}}, log)
	if err != nil || len(lns) != 1 {
		t.Fatalf("%v %v", lns, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"proto":1,"version":"p"}`)
	})}
	go srv.Serve(lns[0])
	t.Cleanup(func() { srv.Close() })
	fp, err := agenttls.FingerprintFile(filepath.Join(paths.Etc(), "tls", agenttls.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	c, err := nodeapi.NewPinned("https://"+lns[0].Addr().String(), "t", fp)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := c.Info(context.Background()); err != nil || info.Version != "p" {
		t.Fatalf("%+v %v", info, err)
	}
}

func TestListenTLSBadAllowList(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	_, err := listen(config.Proxy{Listen: "127.0.0.1:0", ListenTLS: "127.0.0.1:0", AllowIPs: []string{"x"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("мусор в белом списке принят")
	}
}
