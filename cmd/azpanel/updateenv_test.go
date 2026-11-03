package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/update"
)

// I1: панель за префиксом отвечает 404 на /healthz без него.
func TestHealthChecksPanelWithBasePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/azpanel/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.Panel.Listen = strings.TrimPrefix(srv.URL, "http://")
	for _, bp := range []string{"/azpanel/", "/azpanel"} {
		cfg.Panel.BasePath = bp
		checks := healthChecks(cfg, "", []string{panelUnit})
		if len(checks) != 1 {
			t.Fatalf("проверок %d", len(checks))
		}
		if err := checks[0](context.Background(), "0.9.1"); err != nil {
			t.Fatalf("base_path %q: %v", bp, err)
		}
	}
	cfg.Panel.BasePath = ""
	if err := healthChecks(cfg, "", []string{panelUnit})[0](context.Background(), "0.9.1"); err == nil {
		t.Fatal("без префикса панель за префиксом признана живой")
	}
}

// I4: у прокси-агента своя проверка /v1/info.
func TestHealthChecksProxyAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"proto": 1, "version": "0.9.1"})
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.Proxy.Listen = strings.TrimPrefix(srv.URL, "http://")
	checks := healthChecks(cfg, "tok", []string{proxyUnit})
	if len(checks) != 1 {
		t.Fatalf("проверок %d", len(checks))
	}
	if err := checks[0](context.Background(), "0.9.1"); err != nil {
		t.Fatal(err)
	}
	if err := checks[0](context.Background(), "0.9.2"); err == nil {
		t.Fatal("прокси со старой версией признан живым")
	}
	if got := healthChecks(cfg, "tok", nil); len(got) != 0 {
		t.Fatalf("без служб проверок быть не должно: %d", len(got))
	}
}

// startTLSAgent поднимает настоящий TLS-порт агента с белым списком.
func startTLSAgent(t *testing.T, allow []netip.Prefix, version string) (addr string) {
	t.Helper()
	dir := t.TempDir()
	ln, _, err := agenttls.Listen("127.0.0.1:0", dir, allow, nil)
	if err != nil {
		t.Fatal(err)
	}
	old := tlsCertDir
	tlsCertDir = func() string { return dir }
	t.Cleanup(func() { tlsCertDir = old; ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"proto": 1, "version": version})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// I3: узел только с TLS проверяется через listen_tls с собственным сертификатом.
func TestHealthChecksNodeTLSOnly(t *testing.T) {
	addr := startTLSAgent(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, "0.9.1")
	cfg := config.Default()
	cfg.Node.APIListen, cfg.Node.ListenTLS, cfg.Node.AllowIPs = "", addr, []string{"127.0.0.0/8"}
	checks := healthChecks(cfg, "tok", []string{nodeUnit})
	if len(checks) != 1 {
		t.Fatalf("у узла только с TLS нет проверки: %d", len(checks))
	}
	if err := checks[0](context.Background(), "0.9.1"); err != nil {
		t.Fatal(err)
	}
	if err := checks[0](context.Background(), "0.9.2"); err == nil {
		t.Fatal("старая версия по TLS признана живой")
	}
}

func TestHealthChecksNodeTLSNotListening(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	_ = startTLSAgent(t, nil, "0.9.1") // создаёт сертификат
	cfg := config.Default()
	cfg.Node.APIListen, cfg.Node.ListenTLS = "", addr
	checks := healthChecks(cfg, "tok", []string{nodeUnit})
	if err := checks[0](context.Background(), "0.9.1"); err == nil {
		t.Fatal("закрытый порт признан живым")
	}
}

// Адреса хоста нет в allow_ips: агент закрывает соединение до рукопожатия.
// Порт отвечает, версию подтверждает проверка бинарника.
func TestHealthChecksNodeTLSAllowListDropsLocal(t *testing.T) {
	addr := startTLSAgent(t, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, "0.9.1")
	cfg := config.Default()
	cfg.Node.APIListen, cfg.Node.ListenTLS = "", addr
	checks := healthChecks(cfg, "tok", []string{nodeUnit})
	if err := checks[0](context.Background(), "0.9.1"); err != nil {
		t.Fatalf("порт жив, но проверка отказала: %v", err)
	}
}

// Смена сертификата (другой отпечаток) — не «жив».
func TestHealthChecksNodeTLSFingerprintMismatch(t *testing.T) {
	addr := startTLSAgent(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, "0.9.1")
	other := t.TempDir()
	if _, _, err := agenttls.LoadOrCreate(other); err != nil {
		t.Fatal(err)
	}
	tlsCertDir = func() string { return other }
	cfg := config.Default()
	cfg.Node.APIListen, cfg.Node.ListenTLS = "", addr
	err := healthChecks(cfg, "tok", []string{nodeUnit})[0](context.Background(), "0.9.1")
	if !errors.Is(err, agenttls.ErrFingerprint) {
		t.Fatalf("ждали ErrFingerprint: %v", err)
	}
}

func TestSelfDialAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:9100": "127.0.0.1:9100", ":9100": "127.0.0.1:9100", "[::]:9100": "127.0.0.1:9100",
		"10.0.0.5:9100": "10.0.0.5:9100",
	} {
		if got := selfDialAddr(in); got != want {
			t.Errorf("%s: %s, ждали %s", in, got, want)
		}
	}
}

// migrate-config: новый бинарник мигрирует конфиг и задаёт вопросы кодом 3.
func TestMigrateConfigMode(t *testing.T) {
	dir := t.TempDir()
	in, ans := filepath.Join(dir, "c.toml"), filepath.Join(dir, "a.json")
	os.WriteFile(in, []byte("[node]\n"), 0o600)
	os.WriteFile(ans, []byte("{}"), 0o600)
	var out bytes.Buffer
	if err := runMigrateConfig([]string{"--in", in, "--answers", ans}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "config_version = 2") {
		t.Fatalf("выход: %s", out.String())
	}
	if err := runMigrateConfig([]string{"--in", in}, &out); !errors.Is(err, errUsage) {
		t.Fatalf("аргументы: %v", err)
	}
	os.WriteFile(in, []byte("config_version = 99\n"), 0o600)
	out.Reset()
	if err := runMigrateConfig([]string{"--in", in, "--answers", ans}, &out); err == nil {
		t.Fatal("конфиг новее бинарника принят")
	}
}

func TestExitCodeErrorThroughReport(t *testing.T) {
	if got := report(exitCodeError{code: update.MigrateExitQuestions}); got != 3 {
		t.Fatalf("код %d", got)
	}
}

// unignoreSignals снимает флаг signal.Ignored, оставшийся от других тестов:
// signal.Reset его не сбрасывает (рантайм чистит флаг только в Notify), и
// без этого проверка «игнорируется» проходила бы и без защиты.
func unignoreSignals(sigs ...os.Signal) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, sigs...)
	signal.Stop(c)
	signal.Reset(sigs...)
}

// I5: с начала замены сигналы игнорируются (до конца процесса).
func TestProtectFromSignals(t *testing.T) {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
	unignoreSignals(sigs...)
	protectFromSignals()
	for _, s := range sigs {
		if !signal.Ignored(s) {
			t.Fatalf("%v не игнорируется", s)
		}
	}
}

// Apply в CLI идёт под защитой от сигналов.
func TestUpdateApplyRunsProtectedFromSignals(t *testing.T) {
	withVersion(t, "0.9.0")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := releaseServer(t, "0.9.1", priv)
	defer srv.Close()
	env, _ := fakeEnv(t, pub, nil)
	unignoreSignals(os.Interrupt, syscall.SIGHUP)
	protected := false
	env.Systemctl = func(context.Context, ...string) error {
		protected = signal.Ignored(syscall.SIGHUP) && signal.Ignored(os.Interrupt)
		return nil
	}
	env.Units = []string{"azpanel-node"}
	err := runUpdate([]string{"--yes"}, strings.NewReader(""), io.Discard, testDeps(srv, cliToken, func(io.Writer) (*update.Env, error) { return env, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Fatal("замена шла без защиты от сигналов")
	}
}
