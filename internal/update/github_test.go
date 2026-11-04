package update

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "ghp_SECRETTOKEN123"

// fakeGitHub отдаёт релиз v0.9.1 с тремя файлами.
func fakeGitHub(t *testing.T, tag string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	files := map[string]string{"1": "archive-bytes", "2": "sums-bytes", "3": "sig-bytes"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/syava842/azpanel/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		// Как у публичного репозитория: без токена можно, с чужим — 401.
		if h := r.Header.Get("Authorization"); h != "" && h != "Bearer "+testToken {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(Release{Tag: tag, Body: "что нового", Assets: []Asset{
			{ID: 1, Name: ArchiveName(strings.TrimPrefix(tag, "v"), "amd64")},
			{ID: 2, Name: SumsName}, {ID: 3, Name: SigName},
		}})
	})
	mux.HandleFunc("GET /repos/syava842/azpanel/releases/assets/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/octet-stream" || r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Write([]byte(files[r.PathValue("id")]))
	})
	return httptest.NewServer(mux)
}

func TestLatestAndFetch(t *testing.T) {
	srv := fakeGitHub(t, "v0.9.1", nil)
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: testToken}
	rel, err := c.Latest(context.Background())
	if err != nil || rel.Version() != "0.9.1" || rel.Body != "что нового" {
		t.Fatalf("Latest: %+v %v", rel, err)
	}
	f, err := c.Fetch(context.Background(), rel, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Archive) != "archive-bytes" || string(f.Sums) != "sums-bytes" || string(f.Sig) != "sig-bytes" || f.Name != "azpanel_0.9.1_linux_amd64.tar.gz" {
		t.Fatalf("Fetch: %+v", f)
	}
	if _, err := c.Fetch(context.Background(), rel, "arm64"); err == nil {
		t.Fatal("нет архива arm64, а ошибки нет")
	}
}

func TestTokenNotInErrors(t *testing.T) {
	// Сервер, чей адрес и ответ содержат токен: ни одна ошибка его не покажет.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad credentials "+testToken, http.StatusForbidden)
	}))
	srv.Close() // соединение будет отказано: в ошибке сети может быть URL
	c := &Client{BaseURL: strings.Replace(srv.URL, "http://", "http://user:"+testToken+"@", 1), Token: testToken}
	_, err := c.Latest(context.Background())
	if err == nil {
		t.Fatal("ждали ошибку")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("токен в ошибке: %v", err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad credentials "+testToken, http.StatusForbidden)
	}))
	defer srv2.Close()
	_, err = (&Client{BaseURL: srv2.URL, Token: testToken}).Latest(context.Background())
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("403: %v", err)
	}
	if got := Redact("x "+testToken+" y", testToken); strings.Contains(got, testToken) {
		t.Fatal("Redact не убрал токен")
	}
}

// Анонимный 403 — исчерпан предел запросов, а не «неверный токен».
func TestClientAnonymousRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limit", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).Latest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "предел анонимных запросов") {
		t.Fatalf("ошибка: %v", err)
	}
}

// Без токена запрос анонимный: заголовка Authorization нет вовсе.
func TestClientNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); h != "" {
			t.Errorf("Authorization без токена: %q", h)
		}
		w.Write([]byte(`{"tag_name":"v1.2.3"}`))
	}))
	defer srv.Close()
	rel, err := (&Client{BaseURL: srv.URL}).Latest(context.Background())
	if err != nil || rel.Version() != "1.2.3" {
		t.Fatalf("релиз %q, %v", rel.Version(), err)
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.9.0", "0.9.1", true}, {"0.9.1", "0.9.0", false}, {"0.9.0", "0.9.0", false},
		{"0.9.9", "0.10.0", true}, {"v1.0.0", "1.0.1", true}, {"1.0.0-rc1", "1.0.1", true},
	}
	for _, c := range cases {
		got, err := Newer(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("Newer(%q,%q) = %v, %v", c.a, c.b, got, err)
		}
	}
	if _, err := Newer("dev", "1.0.0"); err == nil {
		t.Error("dev не вида x.y.z, ждали ошибку")
	}
}

func TestCheckerOffersNewVersion(t *testing.T) {
	srv := fakeGitHub(t, "v0.9.1", nil)
	defer srv.Close()
	var got []Info
	c := &Checker{
		Current: "0.9.0", Token: func() string { return testToken },
		Client:      func(tok string) *Client { return &Client{BaseURL: srv.URL, Token: tok} },
		OnAvailable: func(i Info) { got = append(got, i) },
	}
	info, err := c.Check(context.Background())
	if err != nil || !info.Available || info.Latest != "0.9.1" || info.Notes != "что нового" {
		t.Fatalf("Check: %+v %v", info, err)
	}
	c.Check(context.Background())
	if len(got) != 1 {
		t.Fatalf("уведомление должно уйти один раз на версию, ушло %d", len(got))
	}
	if !c.Last().Available {
		t.Fatal("Last потерял результат")
	}
}

func TestCheckerSameVersionNotAvailable(t *testing.T) {
	srv := fakeGitHub(t, "v0.9.0", nil)
	defer srv.Close()
	c := &Checker{Current: "0.9.0", Token: func() string { return testToken },
		Client: func(tok string) *Client { return &Client{BaseURL: srv.URL, Token: tok} }}
	info, err := c.Check(context.Background())
	if err != nil || info.Available {
		t.Fatalf("%+v %v", info, err)
	}
}

// Dev-сборка в сеть не ходит; без токена проверка идёт анонимно.
func TestCheckerDevDoesNotAskNoTokenDoes(t *testing.T) {
	var calls atomic.Int32
	srv := fakeGitHub(t, "v0.9.1", &calls)
	defer srv.Close()
	mk := func(version, token string) *Checker {
		return &Checker{Current: version, Token: func() string { return token },
			Client: func(tok string) *Client { return &Client{BaseURL: srv.URL, Token: tok} }}
	}
	if info, err := mk("dev", testToken).Check(context.Background()); !errors.Is(err, ErrDisabled) || info.Available {
		t.Fatalf("dev: %+v %v", info, err)
	}
	if calls.Load() != 0 {
		t.Fatal("dev-сборка сходила в сеть")
	}
	if info, err := mk("0.9.0", "").Check(context.Background()); err != nil || !info.Available {
		t.Fatalf("без токена: %+v %v", info, err)
	}
}

func TestCheckerErrorKeepsFoundUpdateAndHidesToken(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, testToken, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(Release{Tag: "v0.9.1"})
	}))
	defer srv.Close()
	c := &Checker{Current: "0.9.0", Token: func() string { return testToken },
		Client: func(tok string) *Client { return &Client{BaseURL: srv.URL, Token: tok} }}
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	info, err := c.Check(context.Background())
	if err == nil || !info.Available || info.Error == "" || strings.Contains(info.Error, testToken) {
		t.Fatalf("%+v %v", info, err)
	}
}

func TestCheckerRunStopsOnCancel(t *testing.T) {
	var calls atomic.Int32
	srv := fakeGitHub(t, "v0.9.1", &calls)
	defer srv.Close()
	c := &Checker{Current: "0.9.0", Interval: 20 * time.Millisecond, Token: func() string { return testToken },
		Client: func(tok string) *Client { return &Client{BaseURL: srv.URL, Token: tok} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run не остановился")
	}
	if calls.Load() < 2 {
		t.Fatalf("проверок %d, ждали несколько", calls.Load())
	}
}
