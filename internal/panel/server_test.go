package panel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
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
	DenialsFn      func(ctx context.Context, since time.Time) ([]nodeapi.Denial, error)

	RoutingFilesFn      func(ctx context.Context) ([]nodeapi.RoutingFile, error)
	RoutingLinesFn      func(ctx context.Context, name string, o nodeapi.RoutingListOpts) (nodeapi.RoutingPage, error)
	PatchRoutingFn      func(ctx context.Context, name string, p nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error)
	RoutingRawFn        func(ctx context.Context, name string) (nodeapi.RoutingRaw, error)
	ReplaceRoutingFn    func(ctx context.Context, name, content, baseSHA string) (nodeapi.RoutingPutResult, error)
	RoutingBackupsFn    func(ctx context.Context, name string) ([]nodeapi.RoutingBackup, error)
	RestoreRoutingFn    func(ctx context.Context, name, stamp string) (nodeapi.RoutingFile, error)
	SetupFn             func(ctx context.Context) ([]nodeapi.SetupEntry, error)
	SetSetupFn          func(ctx context.Context, values map[string]string) (nodeapi.SetupResult, error)
	TasksFn             func(ctx context.Context) ([]nodeapi.Task, error)
	TaskFn              func(ctx context.Context, id string) (nodeapi.TaskDetail, error)
	ApplyRoutingFn      func(ctx context.Context) (nodeapi.Task, error)
	RestartAntiZapretFn func(ctx context.Context) (nodeapi.Task, error)
	RebuildProfilesFn   func(ctx context.Context) (nodeapi.Task, error)
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
func (f *fakeNode) Denials(ctx context.Context, since time.Time) ([]nodeapi.Denial, error) {
	if f.DenialsFn == nil {
		return nil, errNotSet
	}
	return f.DenialsFn(ctx, since)
}

func (f *fakeNode) RoutingFiles(ctx context.Context) ([]nodeapi.RoutingFile, error) {
	if f.RoutingFilesFn == nil {
		return nil, errNotSet
	}
	return f.RoutingFilesFn(ctx)
}
func (f *fakeNode) RoutingLines(ctx context.Context, name string, o nodeapi.RoutingListOpts) (nodeapi.RoutingPage, error) {
	if f.RoutingLinesFn == nil {
		return nodeapi.RoutingPage{}, errNotSet
	}
	return f.RoutingLinesFn(ctx, name, o)
}
func (f *fakeNode) PatchRouting(ctx context.Context, name string, p nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
	if f.PatchRoutingFn == nil {
		return nodeapi.RoutingPatchResult{}, errNotSet
	}
	return f.PatchRoutingFn(ctx, name, p)
}
func (f *fakeNode) RoutingRaw(ctx context.Context, name string) (nodeapi.RoutingRaw, error) {
	if f.RoutingRawFn == nil {
		return nodeapi.RoutingRaw{}, errNotSet
	}
	return f.RoutingRawFn(ctx, name)
}
func (f *fakeNode) ReplaceRouting(ctx context.Context, name, content, baseSHA string) (nodeapi.RoutingPutResult, error) {
	if f.ReplaceRoutingFn == nil {
		return nodeapi.RoutingPutResult{}, errNotSet
	}
	return f.ReplaceRoutingFn(ctx, name, content, baseSHA)
}
func (f *fakeNode) RoutingBackups(ctx context.Context, name string) ([]nodeapi.RoutingBackup, error) {
	if f.RoutingBackupsFn == nil {
		return nil, errNotSet
	}
	return f.RoutingBackupsFn(ctx, name)
}
func (f *fakeNode) RestoreRouting(ctx context.Context, name, stamp string) (nodeapi.RoutingFile, error) {
	if f.RestoreRoutingFn == nil {
		return nodeapi.RoutingFile{}, errNotSet
	}
	return f.RestoreRoutingFn(ctx, name, stamp)
}
func (f *fakeNode) Setup(ctx context.Context) ([]nodeapi.SetupEntry, error) {
	if f.SetupFn == nil {
		return nil, errNotSet
	}
	return f.SetupFn(ctx)
}
func (f *fakeNode) SetSetup(ctx context.Context, values map[string]string) (nodeapi.SetupResult, error) {
	if f.SetSetupFn == nil {
		return nodeapi.SetupResult{}, errNotSet
	}
	return f.SetSetupFn(ctx, values)
}
func (f *fakeNode) Tasks(ctx context.Context) ([]nodeapi.Task, error) {
	if f.TasksFn == nil {
		return nil, errNotSet
	}
	return f.TasksFn(ctx)
}
func (f *fakeNode) Task(ctx context.Context, id string) (nodeapi.TaskDetail, error) {
	if f.TaskFn == nil {
		return nodeapi.TaskDetail{}, errNotSet
	}
	return f.TaskFn(ctx, id)
}
func (f *fakeNode) ApplyRouting(ctx context.Context) (nodeapi.Task, error) {
	if f.ApplyRoutingFn == nil {
		return nodeapi.Task{}, errNotSet
	}
	return f.ApplyRoutingFn(ctx)
}
func (f *fakeNode) RestartAntiZapret(ctx context.Context) (nodeapi.Task, error) {
	if f.RestartAntiZapretFn == nil {
		return nodeapi.Task{}, errNotSet
	}
	return f.RestartAntiZapretFn(ctx)
}
func (f *fakeNode) RebuildProfiles(ctx context.Context) (nodeapi.Task, error) {
	if f.RebuildProfilesFn == nil {
		return nodeapi.Task{}, errNotSet
	}
	return f.RebuildProfilesFn(ctx)
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
	st     *store.Store
	admin  store.User
	h      http.Handler
	node   *fakeNode
	sleeps []time.Duration
}

func newEnv(t *testing.T, hash string) *testEnv {
	t.Helper()
	e := &testEnv{node: &fakeNode{}}
	st, err := store.Open(filepath.Join(t.TempDir(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e.st = st
	if hash != "" { // пустой хеш — в панели нет пользователей
		e.admin, err = st.CreateUser(context.Background(), store.User{Login: "admin", Hash: hash, Role: store.RoleAdmin})
		if err != nil {
			t.Fatal(err)
		}
	}
	e.srv = &Server{
		Node:       e.node,
		Store:      st,
		NodeID:     store.LocalNode,
		Version:    "test",
		SessionTTL: time.Hour,
		Limiter:    NewLimiter(),
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep:      func(d time.Duration) { e.sleeps = append(e.sleeps, d) },
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

// sessionCookie — вход администратора напрямую через базу, минуя форму.
func (e *testEnv) sessionCookie(t *testing.T) (*http.Cookie, Session) {
	t.Helper()
	return e.sessionFor(t, e.admin, false)
}

// sessionFor — сессия указанного пользователя (pending — ждёт код 2FA).
func (e *testEnv) sessionFor(t *testing.T, u store.User, pending bool) (*http.Cookie, Session) {
	t.Helper()
	id, s, err := e.srv.createSession(context.Background(), u, "10.0.0.1", "test-agent", pending)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: cookieName, Value: id}, s
}

// lookup — сессия по значению cookie, как её видит сервер.
func (e *testEnv) lookup(value string) (Session, bool) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: value})
	s, ok, err := e.srv.sessionFromRequest(r)
	if err != nil {
		panic(err)
	}
	return s, ok
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
	if _, ok := e.lookup(c.Value); !ok {
		t.Fatal("сессия не создана")
	}
	// За доверенным прокси с TLS — Secure.
	e.srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
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

func TestLoginParallelDoesNotBypassLimit(t *testing.T) {
	e := newEnv(t, adminHash(t))
	e.srv.Sleep = func(time.Duration) {}
	var checks atomic.Int32
	e.srv.CheckPassword = func(_, _, _, _ string) bool {
		checks.Add(1)
		return false
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := postForm("/login", url.Values{"user": {"admin"}, "password": {"wrong-password"}})
			r.RemoteAddr = "10.0.0.1:5555"
			rec := e.do(r)
			mu.Lock()
			codes[rec.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if checks.Load() > 5 {
		t.Fatalf("пароль проверен %d раз, предел 5", checks.Load())
	}
	if codes[401] != 5 || codes[429] != 15 {
		t.Fatalf("коды: %v", codes)
	}
}

func TestLoginLimitsParallelBcrypt(t *testing.T) {
	e := newEnv(t, adminHash(t))
	e.srv.Sleep = func(time.Duration) {}
	e.srv.Limiter.Max = 100
	var cur, peak atomic.Int32
	e.srv.CheckPassword = func(_, _, _, _ string) bool {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		cur.Add(-1)
		return false
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := postForm("/login", url.Values{"user": {"admin"}, "password": {"x"}})
			r.RemoteAddr = "10.0.0.1:5555"
			e.do(r)
		}()
	}
	wg.Wait()
	if peak.Load() > maxParallelBcrypt || peak.Load() < 1 {
		t.Fatalf("одновременных проверок: %d, предел %d", peak.Load(), maxParallelBcrypt)
	}
}

func logEnv(t *testing.T) (*testEnv, *bytes.Buffer) {
	t.Helper()
	e := newEnv(t, adminHash(t))
	buf := &bytes.Buffer{}
	e.srv.Log = slog.New(slog.NewTextHandler(buf, nil))
	return e, buf
}

func TestLoginLogTruncatesNameAndThrottles429(t *testing.T) {
	e, buf := logEnv(t)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	e.srv.Now = func() time.Time { return now }
	long := strings.Repeat("я", 500)
	r := postForm("/login", url.Values{"user": {long}, "password": {"wrong-password"}})
	e.do(r)
	if strings.Contains(buf.String(), strings.Repeat("я", 65)) || !strings.Contains(buf.String(), strings.Repeat("я", 64)) {
		t.Fatalf("имя в журнале не обрезано до 64 рун: %s", buf)
	}
	for i := 0; i < 4; i++ {
		login(e, "wrong-password")
	}
	for i := 0; i < 10; i++ {
		if rec := login(e, "wrong-password"); rec.Code != 429 {
			t.Fatalf("ждали 429, получили %d", rec.Code)
		}
	}
	if n := strings.Count(buf.String(), "вход заблокирован"); n != 1 {
		t.Fatalf("429 записан %d раз за минуту, ждали 1", n)
	}
	now = now.Add(61 * time.Second)
	login(e, "wrong-password")
	if n := strings.Count(buf.String(), "вход заблокирован"); n != 2 {
		t.Fatalf("через минуту 429 записан %d раз всего, ждали 2", n)
	}
}

func TestLogDoesNotLeakSecrets(t *testing.T) {
	e, buf := logEnv(t)
	login(e, "wrong-password-xyz")
	rec := login(e, testPassword)
	var cookie *http.Cookie
	for _, x := range rec.Result().Cookies() {
		if x.Name == cookieName {
			cookie = x
		}
	}
	if cookie == nil {
		t.Fatal("нет cookie после входа")
	}
	sess, _ := e.lookup(cookie.Value)
	// Действие над клиентом и выход.
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}}, nil
	}
	e.node.RenewFn = func(context.Context, string, int) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	req := postForm("/clients/bob/renew", url.Values{"csrf": {sess.CSRF}, "days": {"30"}})
	req.AddCookie(cookie)
	if rec := e.do(req); rec.Code != 303 {
		t.Fatalf("действие: %d", rec.Code)
	}
	req = postForm("/logout", url.Values{"csrf": {sess.CSRF}})
	req.AddCookie(cookie)
	e.do(req)

	out := buf.String()
	if !strings.Contains(out, "действие") || !strings.Contains(out, "вход") {
		t.Fatalf("журнал пуст: %s", out)
	}
	for name, secret := range map[string]string{
		"пароль":       testPassword,
		"неверный пар": "wrong-password-xyz",
		"хеш":          adminHash(t),
		"ID сессии":    cookie.Value,
		"хеш ID":       sess.IDHash,
		"CSRF":         sess.CSRF,
	} {
		if strings.Contains(out, secret) {
			t.Errorf("в журнале %s", name)
		}
	}
}

func TestLogoutWithoutSession(t *testing.T) {
	e := newEnv(t, adminHash(t))
	check := func(name string, req *http.Request) {
		rec := e.do(req)
		if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
		cleared := false
		for _, x := range rec.Result().Cookies() {
			if x.Name == cookieName && x.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Errorf("%s: cookie не стёрта", name)
		}
	}
	check("без cookie", postForm("/logout", url.Values{}))
	req := postForm("/logout", url.Values{})
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "unknown-session"})
	check("неизвестная сессия", req)

	// Истёкшая по времени.
	now := time.Now()
	e.srv.Now = func() time.Time { return now }
	c, _ := e.sessionCookie(t)
	now = now.Add(2 * time.Hour)
	req = postForm("/logout", url.Values{})
	req.AddCookie(c)
	check("истёкшая сессия", req)
}

func TestLoginDropsPreviousSession(t *testing.T) {
	e := newEnv(t, adminHash(t))
	old, _ := e.sessionCookie(t)
	req := postForm("/login", url.Values{"user": {"admin"}, "password": {testPassword}})
	req.AddCookie(old)
	if rec := e.do(req); rec.Code != 303 {
		t.Fatalf("вход: %d", rec.Code)
	}
	if _, ok := e.lookup(old.Value); ok {
		t.Fatal("прежняя сессия осталась жива после повторного входа")
	}
}
