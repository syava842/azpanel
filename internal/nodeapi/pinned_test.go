package nodeapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/agenttls"
)

func tlsAgent(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"proto":1,"version":"x","hostname":"h"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, agenttls.Fingerprint(srv.Certificate().Raw)
}

func TestPinnedClientMatch(t *testing.T) {
	srv, fp := tlsAgent(t)
	c, err := NewPinned(srv.URL, "tok", fp)
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.Info(context.Background())
	if err != nil || info.Hostname != "h" {
		t.Fatalf("%+v %v", info, err)
	}
	// Отпечаток в записи через двоеточия и заглавными — тот же.
	c2, err := NewPinned(srv.URL, "tok", agenttls.FormatFingerprint(fp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Info(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedClientMismatch(t *testing.T) {
	srv, _ := tlsAgent(t)
	c, err := NewPinned(srv.URL, "tok", strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Info(context.Background())
	if !errors.Is(err, ErrCertChanged) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "сертификат узла сменился") {
		t.Fatalf("текст: %v", err)
	}
}

func TestPinnedClientBadFingerprint(t *testing.T) {
	if _, err := NewPinned("https://x:1", "t", "abc"); err == nil {
		t.Fatal("короткий отпечаток принят")
	}
}

func TestNodeKeyRoundTrip(t *testing.T) {
	k := NodeKey{PanelIP: "203.0.113.9", Token: strings.Repeat("ab", 32)}
	s, err := k.Encode()
	if err != nil || !strings.HasPrefix(s, "azn1.") || strings.ContainsAny(s, "=+/") {
		t.Fatalf("%q %v", s, err)
	}
	got, err := ParseNodeKey("  " + s + "\n")
	if err != nil || got != k {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err = ParseNodeKey(s + "=="); err != nil || got != k {
		t.Fatalf("с заполнителем: %+v %v", got, err)
	}
}

func TestNodeKeyRejects(t *testing.T) {
	good, _ := NodeKey{PanelIP: "10.0.0.1", Token: strings.Repeat("00", 32)}.Encode()
	for _, bad := range []string{"", "azn2.xxx", "azn1.!!!", "azn1.e30", good[:len(good)-3]} {
		if _, err := ParseNodeKey(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
	if _, err := (NodeKey{PanelIP: "не-ip", Token: strings.Repeat("00", 32)}).Encode(); err == nil {
		t.Error("неверный IP закодирован")
	}
	if _, err := (NodeKey{PanelIP: "10.0.0.1", Token: "короткий"}).Encode(); err == nil {
		t.Error("неверный токен закодирован")
	}
}
