package panel

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
)

var loginNow = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// authEnv — окружение с фиксированным временем и пустыми ответами агента.
func authEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t, adminHash(t))
	e.srv.Now = func() time.Time { return loginNow }
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) { return nil, nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	return e
}

// enable2FA включает администратору 2FA и десять резервных кодов
// aaaaaaaaa2..aaaaaaaaa9 и т. п.; возвращает секрет TOTP и коды.
func enable2FA(t *testing.T, e *testEnv) ([]byte, []string) {
	t.Helper()
	e.srv.DataKey = bytes.Repeat([]byte{7}, 32)
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(e.srv.DataKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	u := e.admin
	u.TOTPSecret = sealed
	if err := e.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	e.admin = u
	codes := []string{"abcdefghj2", "abcdefghj3", "abcdefghj4"}
	var hashes []string
	for _, c := range codes {
		h, err := bcrypt.GenerateFromPassword([]byte(c), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, string(h))
	}
	if err := e.st.SetBackupCodes(context.Background(), u.ID, hashes); err != nil {
		t.Fatal(err)
	}
	return secret, codes
}

func cookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName && c.MaxAge >= 0 {
			return c
		}
	}
	t.Fatalf("нет cookie сессии: %d %s", rec.Code, rec.Body)
	return nil
}

func submitCode(e *testEnv, c *http.Cookie, code string) *httptest.ResponseRecorder {
	sess, _ := e.lookup(c.Value)
	return post(e, c, "/login/2fa", url.Values{"csrf": {sess.CSRF}, "code": {code}})
}

func totpNow(secret []byte, shift int64) string {
	return TOTPCode(secret, loginNow.Unix()/30+shift)
}

func TestSessionStoredAsHash(t *testing.T) {
	e := authEnv(t)
	c := cookieOf(t, login(e, testPassword))
	if len(c.Value) != 64 {
		t.Fatalf("идентификатор в cookie: %q", c.Value)
	}
	if _, err := e.st.SessionByIDHash(context.Background(), c.Value); err == nil {
		t.Fatal("в базе лежит сам идентификатор из cookie")
	}
	x, err := e.st.SessionByIDHash(context.Background(), hashSessionID(c.Value))
	if err != nil {
		t.Fatalf("сессия по хешу не найдена: %v", err)
	}
	if x.UserID != e.admin.ID || x.CSRF == "" || x.CSRF == c.Value || x.IP != "10.0.0.1" || x.MFAPending {
		t.Fatalf("сессия: %+v", x)
	}
	if want := loginNow.Add(time.Hour).Unix(); x.Expires != want {
		t.Fatalf("expires = %d, ждали %d", x.Expires, want)
	}
}

func TestSessionExpiresAndLogoutDeletes(t *testing.T) {
	e := authEnv(t)
	a, _ := e.sessionCookie(t)
	b, _ := e.sessionCookie(t)
	if a.Value == b.Value {
		t.Fatal("одинаковые идентификаторы")
	}
	if _, ok := e.lookup(a.Value); !ok {
		t.Fatal("сессия до срока не найдена")
	}
	e.srv.Now = func() time.Time { return loginNow.Add(time.Hour + time.Second) }
	if _, ok := e.lookup(a.Value); ok {
		t.Fatal("истёкшая сессия отдана")
	}
	if _, err := e.st.SessionByIDHash(context.Background(), hashSessionID(a.Value)); err == nil {
		t.Fatal("истёкшая сессия не удалена из базы")
	}
	e.srv.Now = func() time.Time { return loginNow }
	if _, ok := e.lookup(b.Value); !ok {
		t.Fatal("вторая сессия пропала")
	}
}

func TestLoginUnknownAndDisabledLookAlike(t *testing.T) {
	e := authEnv(t)
	var calls []string
	e.srv.CheckPassword = func(want, hash, user, pw string) bool {
		calls = append(calls, want+"|"+hash)
		return CheckPassword(want, hash, user, pw)
	}
	body := func(user string) (int, string) {
		rec := e.do(postForm("/login", url.Values{"user": {user}, "password": {testPassword}}))
		return rec.Code, rec.Body.String()
	}
	// Несуществующий логин: проверка пароля всё равно запущена (фиктивный хеш).
	codeNone, bodyNone := body("nobody")
	if codeNone != 401 || !strings.Contains(bodyNone, "неверное имя или пароль") {
		t.Fatalf("несуществующий: %d", codeNone)
	}
	if len(calls) != 1 || calls[0] != "|" {
		t.Fatalf("проверка пароля для несуществующего: %v", calls)
	}
	// Отключённый — тот же ответ, хотя пароль верен.
	u := e.admin
	u.Disabled = true
	if err := e.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	codeOff, bodyOff := body("admin")
	if codeOff != 401 || !strings.Contains(bodyOff, "неверное имя или пароль") || len(calls) != 2 {
		t.Fatalf("отключённый: %d %v", codeOff, calls)
	}
	if len(e.sleeps) != 2 {
		t.Fatalf("задержка неверного входа: %v", e.sleeps)
	}
}

func TestLoginLoginIsCaseInsensitive(t *testing.T) {
	e := authEnv(t)
	rec := e.do(postForm("/login", url.Values{"user": {" Admin "}, "password": {testPassword}}))
	if rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDisabledUserSessionIsDropped(t *testing.T) {
	e := authEnv(t)
	c, _ := e.sessionCookie(t)
	if rec := get(e, c, "/"); rec.Code != 200 {
		t.Fatalf("до отключения: %d", rec.Code)
	}
	u := e.admin
	u.Disabled = true
	e.st.UpdateUser(context.Background(), u)
	rec := get(e, c, "/")
	if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("после отключения: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := e.st.SessionByIDHash(context.Background(), hashSessionID(c.Value)); err == nil {
		t.Fatal("сессия отключённого пользователя осталась в базе")
	}
}

func TestLogin2FARequiresCode(t *testing.T) {
	e := authEnv(t)
	secret, _ := enable2FA(t, e)
	rec := login(e, testPassword)
	if rec.Code != 303 || rec.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("вход с 2FA: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	pend := cookieOf(t, rec)
	x, _ := e.st.SessionByIDHash(context.Background(), hashSessionID(pend.Value))
	if !x.MFAPending || x.Expires != loginNow.Add(5*time.Minute).Unix() {
		t.Fatalf("ждущая сессия: %+v", x)
	}
	// Без кода открыт только /login/2fa и выход.
	if rec := get(e, pend, "/"); rec.Code != 303 || rec.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("GET / : %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(e, pend, "/audit"); rec.Code != 303 || rec.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("GET /audit: %d", rec.Code)
	}
	sess, _ := e.lookup(pend.Value)
	if rec := post(e, pend, "/clients/bob/renew", url.Values{"csrf": {sess.CSRF}, "days": {"1"}}); rec.Code != 403 {
		t.Fatalf("POST действие: %d", rec.Code)
	}
	rec = get(e, pend, "/login/2fa")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="code"`) || strings.Contains(rec.Body.String(), `href="/audit"`) {
		t.Fatalf("страница кода: %d %s", rec.Code, rec.Body)
	}
	// Неверный код.
	if rec := submitCode(e, pend, "000000"); rec.Code != 401 || !strings.Contains(rec.Body.String(), "неверный код") {
		t.Fatalf("неверный код: %d", rec.Code)
	}
	// Верный код.
	rec = submitCode(e, pend, totpNow(secret, 0))
	if rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Fatalf("верный код: %d %s", rec.Code, rec.Body)
	}
	full := cookieOf(t, rec)
	if full.Value == pend.Value {
		t.Fatal("идентификатор сессии не сменился после кода")
	}
	if _, ok := e.lookup(pend.Value); ok {
		t.Fatal("ждущая сессия жива после успеха")
	}
	if s, ok := e.lookup(full.Value); !ok || s.MFAPending {
		t.Fatalf("полная сессия: %+v %v", s, ok)
	}
	if rec := get(e, full, "/"); rec.Code != 200 {
		t.Fatalf("доступ после кода: %d", rec.Code)
	}
	// Ждущая сессия живёт 5 минут.
	rec = login(e, testPassword)
	late := cookieOf(t, rec)
	e.srv.Now = func() time.Time { return loginNow.Add(5*time.Minute + time.Second) }
	if _, ok := e.lookup(late.Value); ok {
		t.Fatal("ждущая сессия пережила 5 минут")
	}
}

func TestTOTPCodeNotReusableInSecondSession(t *testing.T) {
	e := authEnv(t)
	secret, _ := enable2FA(t, e)
	code := totpNow(secret, 0)
	first := cookieOf(t, login(e, testPassword))
	second := cookieOf(t, login(e, testPassword))
	if rec := submitCode(e, first, code); rec.Code != 303 {
		t.Fatalf("первое применение: %d", rec.Code)
	}
	if rec := submitCode(e, second, code); rec.Code != 401 {
		t.Fatalf("повтор кода во второй сессии: %d", rec.Code)
	}
	// Следующий шаг принимается.
	if rec := submitCode(e, second, totpNow(secret, 1)); rec.Code != 303 {
		t.Fatalf("код следующего шага: %d", rec.Code)
	}
}

func TestBackupCodeWorksOnce(t *testing.T) {
	e := authEnv(t)
	_, codes := enable2FA(t, e)
	pend := cookieOf(t, login(e, testPassword))
	if rec := submitCode(e, pend, " "+strings.ToUpper(codes[0][:5])+"-"+codes[0][5:]+" "); rec.Code != 303 {
		t.Fatalf("резервный код: %d %s", rec.Code, rec.Body)
	}
	pend = cookieOf(t, login(e, testPassword))
	if rec := submitCode(e, pend, codes[0]); rec.Code != 401 {
		t.Fatalf("повтор резервного кода: %d", rec.Code)
	}
	if rec := submitCode(e, pend, codes[1]); rec.Code != 303 {
		t.Fatalf("другой резервный код: %d", rec.Code)
	}
	list, _, _ := e.st.AuditList(context.Background(), 50, 0, "login_backup_code")
	if len(list) != 2 {
		t.Fatalf("записей о резервном коде: %d", len(list))
	}
}

func TestWrongCodesAreLimited(t *testing.T) {
	e := authEnv(t)
	secret, _ := enable2FA(t, e)
	pend := cookieOf(t, login(e, testPassword))
	for i := 0; i < 5; i++ {
		if rec := submitCode(e, pend, "000000"); rec.Code != 401 {
			t.Fatalf("попытка %d: %d", i+1, rec.Code)
		}
	}
	if len(e.sleeps) != 5 {
		t.Fatalf("задержек неверного кода: %d", len(e.sleeps))
	}
	// Шестая — 429, даже с верным кодом.
	if rec := submitCode(e, pend, totpNow(secret, 0)); rec.Code != 429 {
		t.Fatalf("после 5 неверных: %d", rec.Code)
	}
	// Первый шаг с этого адреса тоже закрыт.
	if rec := login(e, testPassword); rec.Code != 429 {
		t.Fatalf("вход после перебора кодов: %d", rec.Code)
	}
	list, _, _ := e.st.AuditList(context.Background(), 50, 0, "login_2fa_failed")
	if len(list) != 5 {
		t.Fatalf("записей login_2fa_failed: %d", len(list))
	}
}

func TestLogoutFromPendingSession(t *testing.T) {
	e := authEnv(t)
	enable2FA(t, e)
	pend := cookieOf(t, login(e, testPassword))
	sess, _ := e.lookup(pend.Value)
	rec := post(e, pend, "/logout", url.Values{"csrf": {sess.CSRF}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	if _, ok := e.lookup(pend.Value); ok {
		t.Fatal("ждущая сессия осталась после выхода")
	}
}

func TestMFAPageNeedsPendingSession(t *testing.T) {
	e := authEnv(t)
	if rec := e.do(httptest.NewRequest("GET", "/login/2fa", nil)); rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("без сессии: %d", rec.Code)
	}
	c, _ := e.sessionCookie(t)
	if rec := get(e, c, "/login/2fa"); rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Fatalf("полная сессия: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestMustChangeRedirects(t *testing.T) {
	e := authEnv(t)
	u := e.admin
	u.MustChange = true
	e.st.UpdateUser(context.Background(), u)
	e.admin = u
	c := cookieOf(t, login(e, testPassword))
	for _, p := range []string{"/", "/audit", "/monitor", "/clients/new"} {
		if rec := get(e, c, p); rec.Code != 303 || rec.Header().Get("Location") != "/account/password" {
			t.Errorf("GET %s: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	sess, _ := e.lookup(c.Value)
	if rec := post(e, c, "/clients/bob/renew", url.Values{"csrf": {sess.CSRF}, "days": {"1"}}); rec.Code != 403 {
		t.Errorf("POST действие: %d", rec.Code)
	}
	// Смена пароля не перенаправляется (страницы ещё нет — до неё доходит запрос).
	if rec := get(e, c, "/account/password"); rec.Code == 303 {
		t.Errorf("/account/password перенаправлен: %q", rec.Header().Get("Location"))
	}
	// Выход открыт.
	if rec := post(e, c, "/logout", url.Values{"csrf": {sess.CSRF}}); rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Errorf("выход: %d", rec.Code)
	}
}

func TestRequireAdmin2FARedirects(t *testing.T) {
	e := authEnv(t)
	e.srv.RequireAdmin2FA = true
	c := cookieOf(t, login(e, testPassword))
	if rec := get(e, c, "/"); rec.Code != 303 || rec.Header().Get("Location") != "/account/2fa" {
		t.Fatalf("админ без 2FA: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(e, c, "/account/2fa"); rec.Code == 303 {
		t.Fatalf("/account/2fa перенаправлен")
	}
	// Обычного пользователя настройка не касается.
	u, err := e.st.CreateUser(context.Background(), store.User{Login: "bob", Hash: adminHash(t), Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	uc, _ := e.sessionFor(t, u, false)
	if rec := get(e, uc, "/"); rec.Code != 200 {
		t.Fatalf("пользователь: %d", rec.Code)
	}
	// Админ с 2FA проходит.
	e.srv.RequireAdmin2FA = true
	secret, _ := enable2FA(t, e)
	pend := cookieOf(t, login(e, testPassword))
	full := cookieOf(t, submitCode(e, pend, totpNow(secret, 0)))
	if rec := get(e, full, "/"); rec.Code != 200 {
		t.Fatalf("админ с 2FA: %d", rec.Code)
	}
}

func TestSessionSurvivesRestart(t *testing.T) {
	e := authEnv(t)
	c := cookieOf(t, login(e, testPassword))
	e2 := &testEnv{node: e.node, st: e.st}
	e2.srv = &Server{
		Node: e.node, Store: e.st, NodeID: store.LocalNode, Version: "test", SessionTTL: time.Hour,
		Limiter: NewLimiter(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep: func(time.Duration) {}, Now: func() time.Time { return loginNow },
	}
	e2.h = e2.srv.Handler()
	if rec := get(e2, c, "/"); rec.Code != 200 {
		t.Fatalf("после перезапуска: %d", rec.Code)
	}
	// И CSRF прежний.
	s1, _ := e.lookup(c.Value)
	s2, ok := e2.lookup(c.Value)
	if !ok || s1.CSRF != s2.CSRF {
		t.Fatal("сессия после перезапуска другая")
	}
}

func TestSessionContextHasUserAndRole(t *testing.T) {
	e := authEnv(t)
	var got Session
	h := e.srv.protect(func(w http.ResponseWriter, r *http.Request) { got, _ = session(r) })
	c, _ := e.sessionCookie(t)
	r := httptest.NewRequest("GET", "/x", nil)
	r.AddCookie(c)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got.User != "admin" || got.UserID != e.admin.ID || got.Role != store.RoleAdmin || !got.IsAdmin() {
		t.Fatalf("сессия в контексте: %+v", got)
	}
}

func TestLoginWithoutStore(t *testing.T) {
	e := authEnv(t)
	e.srv.Store = nil
	if rec := login(e, testPassword); rec.Code != 503 {
		t.Fatalf("без базы: %d", rec.Code)
	}
	if rec := e.do(httptest.NewRequest("GET", "/", nil)); rec.Code != 303 {
		t.Fatalf("страница без базы: %d", rec.Code)
	}
}

func newLog() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

func TestMigrateAdminFromSecrets(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	log, buf := newLog()
	sec := map[string]string{SecretAdminUser: "Owner", SecretAdminHash: adminHash(t)}
	if err := migrateAdmin(ctx, st, sec, loginNow, log); err != nil {
		t.Fatal(err)
	}
	u, err := st.UserByLogin(ctx, "owner")
	if err != nil {
		t.Fatalf("администратор не создан: %v", err)
	}
	if u.Role != store.RoleAdmin || u.Hash != adminHash(t) || u.Disabled || u.MustChange || len(u.TOTPSecret) != 0 {
		t.Fatalf("пользователь: %+v", u)
	}
	if !strings.Contains(buf.String(), "перенесён администратор из secrets.env") {
		t.Fatalf("нет записи в журнале службы: %s", buf)
	}
	list, _, _ := st.AuditList(ctx, 10, 0, "user_migrate")
	if len(list) != 1 || list[0].Target != "owner" || !strings.Contains(list[0].After, "перенесён администратор из secrets.env") {
		t.Fatalf("журнал действий: %+v", list)
	}
	// Повторный запуск ничего не меняет, даже при другом хеше.
	sec[SecretAdminHash] = "другой"
	sec[SecretAdminUser] = "second"
	if err := migrateAdmin(ctx, st, sec, loginNow, log); err != nil {
		t.Fatal(err)
	}
	if us, _ := st.Users(ctx); len(us) != 1 || us[0].Hash != adminHash(t) {
		t.Fatalf("повторный перенос: %+v", us)
	}
}

func TestMigrateAdminDefaultsAndEmpty(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	log, buf := newLog()
	if err := migrateAdmin(ctx, st, map[string]string{}, loginNow, log); err != nil {
		t.Fatal(err)
	}
	if us, _ := st.Users(ctx); len(us) != 0 || !strings.Contains(buf.String(), "azpanel panel passwd") {
		t.Fatalf("без хеша: %+v %s", us, buf)
	}
	if err := migrateAdmin(ctx, st, map[string]string{SecretAdminHash: adminHash(t)}, loginNow, log); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UserByLogin(ctx, "admin"); err != nil {
		t.Fatalf("логин по умолчанию: %v", err)
	}
}

func TestLoadOrCreateDataKey(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets.env")
	log, _ := newLog()
	sec := map[string]string{}
	key, err := loadOrCreateDataKey(file, sec, log)
	if err != nil || len(key) != 32 {
		t.Fatalf("создание: %v %d", err, len(key))
	}
	// Ключ записан в файл и при следующем старте читается тот же.
	saved := readSecrets(t, file)
	again, err := loadOrCreateDataKey(file, saved, log)
	if err != nil || !bytes.Equal(key, again) {
		t.Fatalf("повторное чтение: %v", err)
	}
	for _, bad := range []string{"zz", strings.Repeat("ab", 16), strings.Repeat("g", 64)} {
		if _, err := loadOrCreateDataKey(file, map[string]string{SecretDataKey: bad}, log); err == nil {
			t.Errorf("испорченный ключ %q принят", bad)
		}
	}
}

func readSecrets(t *testing.T, file string) map[string]string {
	t.Helper()
	m, err := secrets.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
