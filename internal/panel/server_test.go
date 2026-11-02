package panel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// fakeNode — поддельный агент: каждое поле-функция заменяет один метод Node.
// Не заданное поле даёт ошибку, так что неожиданный вызов виден в ответе.
type fakeNode struct {
	InfoFn         func(ctx context.Context) (nodeapi.Info, error)
	ClientsFn      func(ctx context.Context) ([]nodeapi.Client, error)
	SessionsFn     func(ctx context.Context) ([]nodeapi.Session, error)
	SystemFn       func(ctx context.Context) (nodeapi.System, error)
	ProfilesFn     func(ctx context.Context, name string) ([]nodeapi.Profile, error)
	ProfileFn      func(ctx context.Context, name string, p nodeapi.Profile) ([]byte, error)
	CreateClientFn func(ctx context.Context, req nodeapi.CreateClient) (nodeapi.Result, error)
	RenewFn        func(ctx context.Context, name string, days int) (nodeapi.Result, error)
	DeleteClientFn func(ctx context.Context, kind, name string) (nodeapi.Result, error)
	SetLimitFn     func(ctx context.Context, name string, limit int) error
	SetBlockedFn   func(ctx context.Context, name string, blocked bool) (nodeapi.Result, error)
}

var errNotSet = errors.New("fakeNode: метод не задан")

func (f *fakeNode) Info(ctx context.Context) (nodeapi.Info, error) {
	if f.InfoFn == nil {
		return nodeapi.Info{}, errNotSet
	}
	return f.InfoFn(ctx)
}
func (f *fakeNode) Clients(ctx context.Context) ([]nodeapi.Client, error) {
	if f.ClientsFn == nil {
		return nil, errNotSet
	}
	return f.ClientsFn(ctx)
}
func (f *fakeNode) Sessions(ctx context.Context) ([]nodeapi.Session, error) {
	if f.SessionsFn == nil {
		return nil, errNotSet
	}
	return f.SessionsFn(ctx)
}
func (f *fakeNode) System(ctx context.Context) (nodeapi.System, error) {
	if f.SystemFn == nil {
		return nodeapi.System{}, errNotSet
	}
	return f.SystemFn(ctx)
}
func (f *fakeNode) Profiles(ctx context.Context, name string) ([]nodeapi.Profile, error) {
	if f.ProfilesFn == nil {
		return nil, errNotSet
	}
	return f.ProfilesFn(ctx, name)
}
func (f *fakeNode) Profile(ctx context.Context, name string, p nodeapi.Profile) ([]byte, error) {
	if f.ProfileFn == nil {
		return nil, errNotSet
	}
	return f.ProfileFn(ctx, name, p)
}
func (f *fakeNode) CreateClient(ctx context.Context, req nodeapi.CreateClient) (nodeapi.Result, error) {
	if f.CreateClientFn == nil {
		return nodeapi.Result{}, errNotSet
	}
	return f.CreateClientFn(ctx, req)
}
func (f *fakeNode) Renew(ctx context.Context, name string, days int) (nodeapi.Result, error) {
	if f.RenewFn == nil {
		return nodeapi.Result{}, errNotSet
	}
	return f.RenewFn(ctx, name, days)
}
func (f *fakeNode) DeleteClient(ctx context.Context, kind, name string) (nodeapi.Result, error) {
	if f.DeleteClientFn == nil {
		return nodeapi.Result{}, errNotSet
	}
	return f.DeleteClientFn(ctx, kind, name)
}
func (f *fakeNode) SetLimit(ctx context.Context, name string, limit int) error {
	if f.SetLimitFn == nil {
		return errNotSet
	}
	return f.SetLimitFn(ctx, name, limit)
}
func (f *fakeNode) SetBlocked(ctx context.Context, name string, blocked bool) (nodeapi.Result, error) {
	if f.SetBlockedFn == nil {
		return nodeapi.Result{}, errNotSet
	}
	return f.SetBlockedFn(ctx, name, blocked)
}

const testPassword = "correct-horse-battery"

var (
	hashOnce sync.Once
	testHash string
)

// adminHash — bcrypt cost 12 дорог, считаем один раз на пакет.
func adminHash(t *testing.T) string {
	t.Helper()
	hashOnce.Do(func() {
		h, err := HashPassword(testPassword)
		if err != nil {
			panic(err)
		}
		testHash = h
	})
	return testHash
}

type testEnv struct {
	srv    *Server
	h      http.Handler
	node   *fakeNode
	sleeps []time.Duration
}

func newEnv(t *testing.T, hash string) *testEnv {
	t.Helper()
	e := &testEnv{node: &fakeNode{}}
	e.srv = &Server{
		Node:      e.node,
		AdminUser: "admin",
		AdminHash: hash,
		Version:   "test",
		Sessions:  NewSessions(time.Hour),
		Limiter:   NewLimiter(),
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep:     func(d time.Duration) { e.sleeps = append(e.sleeps, d) },
	}
	e.h = e.srv.Handler()
	return e
}

func (e *testEnv) do(req *http.Request) *httptest.ResponseRecorder {
	if req.RemoteAddr == "" || req.RemoteAddr == "192.0.2.1:1234" {
		req.RemoteAddr = "10.0.0.1:5555"
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func postForm(path string, f url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func login(e *testEnv, pw string) *httptest.ResponseRecorder {
	return e.do(postForm("/login", url.Values{"user": {"admin"}, "password": {pw}}))
}

// sessionCookie — вход напрямую через Sessions, минуя форму.
func (e *testEnv) sessionCookie(t *testing.T) (*http.Cookie, Session) {
	t.Helper()
	s, err := e.srv.Sessions.Create("admin")
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: cookieName, Value: s.ID}, s
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, adminHash(t))
	rec := e.do(httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestIndexNeedsLogin(t *testing.T) {
	e := newEnv(t, adminHash(t))
	rec := e.do(httptest.NewRequest("GET", "/", nil))
	if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	// POST без сессии — 403, а не редирект.
	if rec := e.do(postForm("/anything", url.Values{})); rec.Code != 403 {
		t.Fatalf("POST без сессии: %d", rec.Code)
	}
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) { return nil, nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	c, _ := e.sessionCookie(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if rec := e.do(req); rec.Code != 200 {
		t.Fatalf("со входом: %d", rec.Code)
	}
}

func TestLoginOK(t *testing.T) {
	e := newEnv(t, adminHash(t))
	rec := login(e, testPassword)
	if rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	var c *http.Cookie
	for _, x := range rec.Result().Cookies() {
		if x.Name == cookieName {
			c = x
		}
	}
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure || c.Path != "/" {
		t.Fatalf("cookie: %+v", c)
	}
	if _, ok := e.srv.Sessions.Get(c.Value); !ok {
		t.Fatal("сессия не создана")
	}
	// За прокси с TLS — Secure.
	r := postForm("/login", url.Values{"user": {"admin"}, "password": {testPassword}})
	r.Header.Set("X-Forwarded-Proto", "https")
	rec = e.do(r)
	found := false
	for _, x := range rec.Result().Cookies() {
		if x.Name == cookieName {
			found = true
			if !x.Secure {
				t.Fatal("нет Secure за https")
			}
		}
	}
	if !found {
		t.Fatal("cookie не выдана")
	}
}

func TestLoginFailAndLimit(t *testing.T) {
	e := newEnv(t, adminHash(t))
	rec := login(e, "wrong-password")
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "неверное имя или пароль") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(e.sleeps) != 1 || e.sleeps[0] != time.Second {
		t.Fatalf("задержка: %v", e.sleeps)
	}
	for i := 0; i < 4; i++ {
		if rec := login(e, "wrong-password"); rec.Code != 401 {
			t.Fatalf("попытка %d: %d", i+2, rec.Code)
		}
	}
	rec = login(e, testPassword) // шестая: даже верный пароль не проверяется
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), "слишком много попыток") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Другой адрес не задет.
	r := postForm("/login", url.Values{"user": {"admin"}, "password": {testPassword}})
	r.RemoteAddr = "10.0.0.2:1"
	if rec := e.do(r); rec.Code != 303 {
		t.Fatalf("другой адрес: %d", rec.Code)
	}
}

func TestLoginNoHash(t *testing.T) {
	e := newEnv(t, "")
	rec := e.do(httptest.NewRequest("GET", "/login", nil))
	if !strings.Contains(rec.Body.String(), "azpanel panel passwd") {
		t.Fatalf("нет подсказки: %s", rec.Body)
	}
	for _, pw := range []string{"", "admin", testPassword} {
		if rec := login(e, pw); rec.Code == 303 {
			t.Fatalf("вход с пустым hash и паролем %q", pw)
		}
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t, adminHash(t))
	c, s := e.sessionCookie(t)
	req := postForm("/logout", url.Values{})
	req.AddCookie(c)
	if rec := e.do(req); rec.Code != 403 {
		t.Fatalf("без csrf: %d", rec.Code)
	}
	req = postForm("/logout", url.Values{"csrf": {"неверный"}})
	req.AddCookie(c)
	if rec := e.do(req); rec.Code != 403 {
		t.Fatalf("с неверным csrf: %d", rec.Code)
	}
	req = postForm("/logout", url.Values{"csrf": {s.CSRF}})
	req.AddCookie(c)
	rec := e.do(req)
	if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if rec := e.do(req); rec.Code != 303 {
		t.Fatalf("сессия жива после выхода: %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, adminHash(t))
	rec := e.do(httptest.NewRequest("GET", "/login", nil))
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
}

func TestStaticAndNodeErr(t *testing.T) {
	e := newEnv(t, adminHash(t))
	rec := e.do(httptest.NewRequest("GET", "/static/style.css", nil))
	if rec.Code != 200 || rec.Body.Len() == 0 {
		t.Fatalf("style.css: %d", rec.Code)
	}
	cases := []struct {
		err    error
		status int
		text   string
	}{
		{&nodeapi.Error{Status: 409, Message: "уже есть"}, 400, "уже есть"},
		{&nodeapi.Error{Status: 500, Message: "сбой"}, 502, "сбой"},
		{errors.New("connection refused"), 502, "агент недоступен: connection refused"},
	}
	for _, c := range cases {
		if st, tx := e.srv.nodeErr(c.err); st != c.status || tx != c.text {
			t.Errorf("%v: %d %q", c.err, st, tx)
		}
	}
}
