package agenttls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadOrCreateStable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	_, fp1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, err := LoadOrCreate(dir)
	if err != nil || fp1 != fp2 {
		t.Fatalf("второй запуск сменил отпечаток: %v %q %q", err, fp1, fp2)
	}
	if got, err := FingerprintFile(filepath.Join(dir, CertFile)); err != nil || got != fp1 {
		t.Fatalf("FingerprintFile = %q %v, ждали %q", got, err, fp1)
	}
	if len(fp1) != 64 {
		t.Fatalf("отпечаток %q", fp1)
	}
}

func TestLoadOrCreateRefusesHalf(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, KeyFile))
	if _, _, err := LoadOrCreate(dir); err == nil || !strings.Contains(err.Error(), "только один") {
		t.Fatalf("err = %v", err)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	got, err := NormalizeFingerprint(FormatFingerprint(fp))
	if err != nil || got != fp {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "zz", strings.Repeat("a", 63)} {
		if _, err := NormalizeFingerprint(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
}

func serve(t *testing.T, allow []netip.Prefix, rejected func(string)) (addr, fp string) {
	t.Helper()
	ln, fp, err := Listen("127.0.0.1:0", t.TempDir(), allow, rejected)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), fp
}

func pinnedClient(t *testing.T, fp string) *http.Client {
	t.Helper()
	cfg, err := PinnedConfig(fp)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func TestPinnedMatchAndMismatch(t *testing.T) {
	addr, fp := serve(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil)
	resp, err := pinnedClient(t, fp).Get("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	_, err = pinnedClient(t, strings.Repeat("00", 32)).Get("https://" + addr)
	if !errors.Is(err, ErrFingerprint) {
		t.Fatalf("err = %v, ждали ErrFingerprint", err)
	}
	if !strings.Contains(err.Error(), "сертификат узла сменился") {
		t.Fatalf("текст ошибки: %v", err)
	}
}

func TestProbe(t *testing.T) {
	addr, fp := serve(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, nil)
	got, err := Probe(context.Background(), addr)
	if err != nil || got != fp {
		t.Fatalf("Probe = %q %v, ждали %q", got, err, fp)
	}
}

func TestAllowListClosesBeforeTLS(t *testing.T) {
	var rejected atomic.Int32
	// Клиент приходит с 127.0.0.1, в списке — только другая сеть.
	addr, _ := serve(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, func(string) { rejected.Add(1) })
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	// Сервер первым не шлёт ничего: если соединение закрыто до TLS, читаем
	// EOF или сброс, а не таймаут.
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("соединение не закрыто: %v", err)
	}
	if rejected.Load() != 1 {
		t.Fatalf("отказов = %d", rejected.Load())
	}
	// TLS-клиент с чужого адреса тоже не доходит до сертификата.
	_, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		t.Fatal("рукопожатие состоялось с адреса вне белого списка")
	}
}

func TestEmptyAllowListRejectsAll(t *testing.T) {
	var rejected atomic.Int32
	addr, _ := serve(t, nil, func(string) { rejected.Add(1) })
	if _, err := Probe(context.Background(), addr); err == nil {
		t.Fatal("пустой список пустил соединение")
	}
	if rejected.Load() == 0 {
		t.Fatal("отказ не учтён")
	}
}

// M11: об отказах одному адресу сообщается не чаще раза в минуту.
func TestRejectedLoggedOncePerMinutePerAddress(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	var mu sync.Mutex
	var reported []string
	ln := NewAllowListener(base, nil, func(remote string) { mu.Lock(); reported = append(reported, remote); mu.Unlock() })
	clock := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ln.(*allowListener).now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	knock := func() {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		// Закрытие со стороны агента видно как конец чтения.
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.ReadAll(c)
		c.Close()
	}
	for i := 0; i < 5; i++ {
		knock()
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(reported) }
	if count() != 1 {
		t.Fatalf("сообщений %d, ждали 1: %v", count(), reported)
	}
	mu.Lock()
	clock = clock.Add(61 * time.Second)
	mu.Unlock()
	knock()
	if count() != 2 {
		t.Fatalf("после минуты сообщений %d, ждали 2", count())
	}
}
