package panel

import (
	"bytes"
	"context"
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// decodeSecret достаёт секрет TOTP из страницы включения 2FA.
func decodeSecret(t *testing.T, body string) []byte {
	t.Helper()
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("нет секрета на странице: %s", body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// loginFrom — вход администратора с заданного адреса.
func loginFrom(e *testEnv, addr, pw string) *httptest.ResponseRecorder {
	r := postForm("/login", url.Values{"user": {"admin"}, "password": {pw}})
	r.RemoteAddr = addr + ":5555"
	return e.do(r)
}

func codeFrom(e *testEnv, c *http.Cookie, addr, code string) *httptest.ResponseRecorder {
	sess, _ := e.lookup(c.Value)
	r := postForm("/login/2fa", url.Values{"csrf": {sess.CSRF}, "code": {code}})
	r.AddCookie(c)
	r.RemoteAddr = addr + ":5555"
	return e.do(r)
}

// C1: верный пароль не обнуляет перебор кода. Цикл «4 неверных кода, новый
// вход» с разных адресов упирается в счётчик пользователя на пятом коде:
// после него закрыты и код, и новый вход этого пользователя.
func TestMFABruteForceBlocksCodeAndLogin(t *testing.T) {
	e := authEnv(t)
	secret, _ := enable2FA(t, e)
	var last *http.Cookie
	wrong := 0
	for round := 0; wrong < 5; round++ {
		addr := "10.1.0." + strconv.Itoa(round+1)
		pend := cookieOf(t, loginFrom(e, addr, testPassword))
		last = pend
		for i := 0; i < 4 && wrong < 5; i++ {
			if rec := codeFrom(e, pend, addr, "000000"); rec.Code != 401 {
				t.Fatalf("неверный код №%d: %d", wrong+1, rec.Code)
			}
			wrong++
		}
	}
	// Верный код с нового адреса при исчерпанном счётчике пользователя — 429.
	if rec := codeFrom(e, last, "10.1.8.1", totpNow(secret, 0)); rec.Code != 429 {
		t.Fatalf("код после 5 неверных: %d", rec.Code)
	}
	// И новый вход этого пользователя с нового адреса — 429.
	if rec := loginFrom(e, "10.1.8.2", testPassword); rec.Code != 429 {
		t.Fatalf("новый вход после 5 неверных кодов: %d", rec.Code)
	}
}

// C1: счётчик адреса тоже не сбрасывается верным паролем с ждущей сессией.
func TestMFAIPKeyNotResetByPassword(t *testing.T) {
	e := authEnv(t)
	enable2FA(t, e)
	passed := 0
	for i := 0; i < 20; i++ {
		if loginFrom(e, "10.2.0.1", testPassword).Code == 303 {
			passed++
		}
	}
	if passed > 5 {
		t.Fatalf("вход с одного адреса прошёл %d раз из 20: счётчик адреса сброшен", passed)
	}
}

// Отключение 2FA: неверный код считается и сопровождается задержкой.
func TestDisable2FAWrongCodesLimited(t *testing.T) {
	e, c, csrf := accEnv(t)
	enableViaPages(t, e, c, csrf)
	e.sleeps = nil
	for i := 0; i < 5; i++ {
		if rec := post(e, c, "/account/2fa/disable", form(csrf, "password", testPassword, "code", "000000")); rec.Code != 401 {
			t.Fatalf("попытка %d: %d", i+1, rec.Code)
		}
	}
	if len(e.sleeps) < 5 {
		t.Fatalf("задержек %d", len(e.sleeps))
	}
	if rec := post(e, c, "/account/2fa/disable", form(csrf, "password", testPassword, "code", "000000")); rec.Code != 429 {
		t.Fatalf("после 5 неверных: %d", rec.Code)
	}
}

// I1: смена пароля идёт раньше включения 2FA.
func TestMustChangeWithRequireAdmin2FA(t *testing.T) {
	e := authEnv(t)
	e.srv.RequireAdmin2FA = true
	e.srv.DataKey = bytes.Repeat([]byte{7}, 32)
	if err := e.st.SetPassword(context.Background(), e.admin.ID, e.admin.Hash, true); err != nil {
		t.Fatal(err)
	}
	c := cookieOf(t, login(e, testPassword))
	if rec := get(e, c, "/"); rec.Code != 303 || rec.Header().Get("Location") != "/account/password" {
		t.Fatalf("/: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(e, c, "/account/2fa"); rec.Code != 303 || rec.Header().Get("Location") != "/account/password" {
		t.Fatalf("/account/2fa до смены пароля: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(e, c, "/account/password"); rec.Code != 200 {
		t.Fatalf("страница пароля: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	sess, _ := e.lookup(c.Value)
	rec := post(e, c, "/account/password", url.Values{"csrf": {sess.CSRF}, "old": {testPassword}, "new": {"newpassw0rd1"}, "new2": {"newpassw0rd1"}})
	if rec.Code != 303 {
		t.Fatalf("смена пароля: %d %s", rec.Code, rec.Body)
	}
	if rec := get(e, c, "/"); rec.Code != 303 || rec.Header().Get("Location") != "/account/2fa" {
		t.Fatalf("после смены пароля: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(e, c, "/account/2fa"); rec.Code != 200 {
		t.Fatalf("страница 2FA: %d", rec.Code)
	}
}

// I2: сброс пароля администратором во время смены пароля пользователем не теряется.
func TestPasswordResetDuringChangeIsKept(t *testing.T) {
	e, c, csrf := accEnv(t)
	orig := e.srv.CheckPassword
	reset := false
	e.srv.CheckPassword = func(wantUser, hash, user, pw string) bool {
		ok := orig(wantUser, hash, user, pw)
		if !reset && pw == testPassword {
			reset = true // между проверкой старого пароля и записью нового
			if err := e.st.SetPassword(context.Background(), e.admin.ID, "reset-by-admin", true); err != nil {
				t.Error(err)
			}
		}
		return ok
	}
	rec := post(e, c, "/account/password", form(csrf, "old", testPassword, "new", "newpassw0rd1", "new2", "newpassw0rd1"))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "пароль уже изменён") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	u, _ := e.st.UserByID(context.Background(), e.admin.ID)
	if u.Hash != "reset-by-admin" || !u.MustChange {
		t.Fatalf("сброс потерян: %+v", u)
	}
}

// I2: понижение роли во время смены пароля не откатывается.
func TestRoleChangeNotClobberedByPasswordChange(t *testing.T) {
	e, c, csrf := accEnv(t)
	orig := e.srv.CheckPassword
	done := false
	e.srv.CheckPassword = func(wantUser, hash, user, pw string) bool {
		ok := orig(wantUser, hash, user, pw)
		if !done && pw == testPassword {
			done = true
			e.st.SetRole(context.Background(), e.admin.ID, store.RoleUser)
		}
		return ok
	}
	post(e, c, "/account/password", form(csrf, "old", testPassword, "new", "newpassw0rd1", "new2", "newpassw0rd1"))
	if u, _ := e.st.UserByID(context.Background(), e.admin.ID); u.Role != store.RoleUser {
		t.Fatalf("роль откатилась: %+v", u)
	}
}

// M1: включение 2FA требует пароль; форма привязана к пользователю и сроку.
func TestEnable2FARequiresPasswordAndFreshForm(t *testing.T) {
	e, c, csrf := accEnv(t)
	body := get(e, c, "/account/2fa").Body.String()
	sealed := sealedRe.FindStringSubmatch(body)[1]
	exp := expRe.FindStringSubmatch(body)[1]
	code := totpNow(decodeSecret(t, body), 0)
	if rec := post(e, c, "/account/2fa", form(csrf, "sealed", sealed, "exp", exp, "code", code)); rec.Code != 401 {
		t.Fatalf("без пароля: %d", rec.Code)
	}
	if u, _ := e.st.UserByID(context.Background(), e.admin.ID); len(u.TOTPSecret) != 0 {
		t.Fatal("2FA включена без пароля")
	}
	// срок подменён: AAD не сходится
	if rec := post(e, c, "/account/2fa", form(csrf, "sealed", sealed, "exp", strconv.FormatInt(loginNow.Unix()+60, 10), "password", testPassword, "code", code)); rec.Code != 400 {
		t.Fatalf("подмена срока: %d", rec.Code)
	}
	// форма другого пользователя
	bob, _ := e.st.CreateUser(context.Background(), store.User{Login: "bob2", Hash: adminHash(t), Role: store.RoleUser})
	bc, bs := e.sessionFor(t, bob, false)
	if rec := post(e, bc, "/account/2fa", form(bs.CSRF, "sealed", sealed, "exp", exp, "password", testPassword, "code", code)); rec.Code != 400 {
		t.Fatalf("чужая форма: %d", rec.Code)
	}
	// срок вышел
	e.srv.Now = func() time.Time { return loginNow.Add(setupTTL + time.Minute) }
	if rec := post(e, c, "/account/2fa", form(csrf, "sealed", sealed, "exp", exp, "password", testPassword, "code", code)); rec.Code != 400 {
		t.Fatalf("просроченная форма: %d", rec.Code)
	}
	e.srv.Now = func() time.Time { return loginNow }
	if rec := post(e, c, "/account/2fa", form(csrf, "sealed", sealed, "exp", exp, "password", testPassword, "code", code)); rec.Code != 303 {
		t.Fatalf("верная форма: %d %s", rec.Code, rec.Body)
	}
}

// M3: заметку администратора видит только администратор.
func TestUserDoesNotSeeAdminNote(t *testing.T) {
	e, admin, user, _, _ := userEnv(t)
	err := e.st.SaveCard(context.Background(), store.Card{Node: store.LocalNode, Name: ownClient, Note: "служебная-заметка-42"})
	if err != nil {
		t.Fatal(err)
	}
	if body := get(e, user, "/clients/"+ownClient).Body.String(); strings.Contains(body, "служебная-заметка-42") {
		t.Fatal("владелец видит заметку")
	}
	if body := get(e, admin, "/clients/"+ownClient).Body.String(); !strings.Contains(body, "служебная-заметка-42") {
		t.Fatal("администратор заметки не видит")
	}
}

// M8: сброс пароля — POST, 303 и GET; обновление GET не повторяет сброс и не
// показывает пароль второй раз; чужая сессия страницу не получит.
func TestShowOnceIsPostRedirectGet(t *testing.T) {
	e, c, csrf := accEnv(t)
	bob, _ := e.st.CreateUser(context.Background(), store.User{Login: "bobby", Hash: "orig", Role: store.RoleUser})
	rec := post(e, c, "/users/"+itoa(bob.ID)+"/password", form(csrf))
	if rec.Code != 303 || rec.Header().Get("Location") != pathAccountOnce {
		t.Fatalf("POST: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if strings.Contains(rec.Body.String(), "<pre>") {
		t.Fatal("пароль в теле ответа на POST")
	}
	afterPost, _ := e.st.UserByID(context.Background(), bob.ID)
	other, _ := e.sessionCookie(t)
	if r := get(e, other, pathAccountOnce); r.Code != 303 {
		t.Fatalf("чужая сессия получила страницу: %d", r.Code)
	}
	page := get(e, c, pathAccountOnce)
	if page.Code != 200 || len(codesIn(page.Body.String())) != 1 {
		t.Fatalf("GET: %d %s", page.Code, page.Body)
	}
	if again := get(e, c, pathAccountOnce); again.Code != 303 || again.Header().Get("Location") != "/account" {
		t.Fatalf("повторный GET: %d %q", again.Code, again.Header().Get("Location"))
	}
	if u, _ := e.st.UserByID(context.Background(), bob.ID); u.Hash != afterPost.Hash {
		t.Fatal("обновление страницы повторило сброс")
	}
}

func TestOnceExpires(t *testing.T) {
	e, c, csrf := accEnv(t)
	bob, _ := e.st.CreateUser(context.Background(), store.User{Login: "bobby", Hash: "orig", Role: store.RoleUser})
	post(e, c, "/users/"+itoa(bob.ID)+"/password", form(csrf))
	e.srv.Now = func() time.Time { return loginNow.Add(onceTTL + time.Second) }
	e.srv.SessionTTL = 24 * time.Hour
	if r := get(e, c, pathAccountOnce); r.Code != 303 {
		t.Fatalf("просроченная запись показана: %d", r.Code)
	}
}
