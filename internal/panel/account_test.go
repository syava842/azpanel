package panel

import (
	"bytes"
	"context"
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/store"
)

// accEnv — администратор со сессией, фиксированное время, ключ данных.
func accEnv(t *testing.T) (*testEnv, *http.Cookie, string) {
	t.Helper()
	e := authEnv(t)
	e.srv.DataKey = bytes.Repeat([]byte{7}, 32)
	c, s := e.sessionCookie(t)
	return e, c, s.CSRF
}

func form(csrf string, kv ...string) url.Values {
	v := url.Values{"csrf": {csrf}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func TestAccountPasswordChange(t *testing.T) {
	e, c, csrf := accEnv(t)
	other, _ := e.sessionCookie(t) // вторая сессия того же пользователя
	e.admin.MustChange = true
	e.st.UpdateUser(context.Background(), e.admin)

	bad := []struct {
		name string
		kv   []string
		code int
	}{
		{"повтор не совпал", []string{"old", testPassword, "new", "newpassw0rd1", "new2", "other"}, 400},
		{"короткий", []string{"old", testPassword, "new", "a1", "new2", "a1"}, 400},
		{"без цифр", []string{"old", testPassword, "new", "onlyletters", "new2", "onlyletters"}, 400},
		{"равен логину", []string{"old", testPassword, "new", "admin", "new2", "admin"}, 400},
		{"старый неверен", []string{"old", "wrong-password", "new", "newpassw0rd1", "new2", "newpassw0rd1"}, 401},
	}
	for _, b := range bad {
		if rec := post(e, c, "/account/password", form(csrf, b.kv...)); rec.Code != b.code {
			t.Errorf("%s: код %d, ждали %d", b.name, rec.Code, b.code)
		}
	}
	if rec := post(e, c, "/account/password", form(csrf, "old", testPassword, "new", "newpassw0rd1", "new2", "newpassw0rd1")); rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	u, _ := e.st.UserByID(context.Background(), e.admin.ID)
	if u.MustChange || CheckPassword("admin", u.Hash, "admin", "newpassw0rd1") != true {
		t.Fatalf("пароль не сменился или must_change остался: %+v", u)
	}
	if _, ok := e.lookup(other.Value); ok {
		t.Error("прочая сессия жива")
	}
	if _, ok := e.lookup(c.Value); !ok {
		t.Error("текущая сессия завершена")
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "password_change")
	if len(list) != 1 || strings.Contains(list[0].After, "newpassw0rd1") {
		t.Fatalf("журнал: %+v", list)
	}
}

var (
	sealedRe = regexp.MustCompile(`name="sealed" value="([^"]+)"`)
	expRe    = regexp.MustCompile(`name="exp" value="([0-9]+)"`)
	secretRe = regexp.MustCompile(`<code>([A-Z2-7]+)</code>`)
)

func enableViaPages(t *testing.T, e *testEnv, c *http.Cookie, csrf string) (secret []byte, codes []string) {
	t.Helper()
	rec := get(e, c, "/account/2fa")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "data:image/png;base64,") {
		t.Fatalf("страница включения: %d %s", rec.Code, body)
	}
	sealed := sealedRe.FindStringSubmatch(body)
	exp := expRe.FindStringSubmatch(body)
	if exp == nil {
		t.Fatalf("нет срока формы: %s", body)
	}
	sec := secretRe.FindStringSubmatch(body)
	if sealed == nil || sec == nil {
		t.Fatalf("нет секрета или запечатанного поля: %s", body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(sec[1])
	if err != nil {
		t.Fatal(err)
	}
	// неверный код — секрет не сохранён
	if rec := post(e, c, "/account/2fa", form(csrf, "sealed", sealed[1], "exp", exp[1], "password", testPassword, "code", "000000")); rec.Code != 400 {
		t.Fatalf("неверный код: %d", rec.Code)
	}
	if u, _ := e.st.UserByID(context.Background(), e.admin.ID); len(u.TOTPSecret) != 0 {
		t.Fatal("секрет сохранён без подтверждения")
	}
	rec = post(e, c, "/account/2fa", form(csrf, "sealed", sealed[1], "exp", exp[1], "password", testPassword, "code", totpNow(secret, 0)))
	code, page := followOnce(e, c, rec)
	if code != 200 {
		t.Fatalf("включение: %d %s", code, page)
	}
	codes = codesIn(page)
	return secret, codes
}

func TestAccount2FAEnableDisable(t *testing.T) {
	e, c, csrf := accEnv(t)
	secret, codes := enableViaPages(t, e, c, csrf)
	if len(codes) != 10 {
		t.Fatalf("резервных кодов %d, ждали 10", len(codes))
	}
	u, _ := e.st.UserByID(context.Background(), e.admin.ID)
	plain, err := Open(e.srv.DataKey, u.TOTPSecret)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("секрет в базе не тот: %v", err)
	}
	if ok, _ := e.st.UseBackupCode(context.Background(), u.ID, codes[0]); !ok {
		t.Fatal("резервный код не подошёл")
	}
	// повторное включение
	if rec := get(e, c, "/account/2fa"); rec.Code != 303 {
		t.Fatalf("включённая 2FA: страница настройки %d", rec.Code)
	}
	// отключение: нужны пароль и код
	if rec := post(e, c, "/account/2fa/disable", form(csrf, "password", "wrong-password", "code", codes[1])); rec.Code != 401 {
		t.Fatalf("неверный пароль: %d", rec.Code)
	}
	if rec := post(e, c, "/account/2fa/disable", form(csrf, "password", testPassword, "code", "000000")); rec.Code != 401 {
		t.Fatalf("неверный код: %d", rec.Code)
	}
	if rec := post(e, c, "/account/2fa/disable", form(csrf, "password", testPassword, "code", codes[1])); rec.Code != 303 {
		t.Fatalf("отключение: %d %s", rec.Code, rec.Body)
	}
	if u, _ = e.st.UserByID(context.Background(), e.admin.ID); len(u.TOTPSecret) != 0 {
		t.Fatal("2FA осталась")
	}
	if ok, _ := e.st.UseBackupCode(context.Background(), u.ID, codes[2]); ok {
		t.Fatal("резервные коды не удалены")
	}
}

func TestAccountNewBackupCodes(t *testing.T) {
	e, c, csrf := accEnv(t)
	_, codes := enableViaPages(t, e, c, csrf)
	if rec := post(e, c, "/account/2fa/codes", form(csrf, "password", "wrong-password")); rec.Code != 401 {
		t.Fatalf("неверный пароль: %d", rec.Code)
	}
	code, page := followOnce(e, c, post(e, c, "/account/2fa/codes", form(csrf, "password", testPassword)))
	fresh := codesIn(page)
	if code != 200 || len(fresh) != 10 {
		t.Fatalf("%d, кодов %d", code, len(fresh))
	}
	if ok, _ := e.st.UseBackupCode(context.Background(), e.admin.ID, codes[0]); ok {
		t.Error("старый код действует")
	}
	if ok, _ := e.st.UseBackupCode(context.Background(), e.admin.ID, fresh[0]); !ok {
		t.Error("новый код не подошёл")
	}
}

func TestAccountSessions(t *testing.T) {
	e, c, csrf := accEnv(t)
	other, otherSess := e.sessionCookie(t)
	bob, _ := e.st.CreateUser(context.Background(), store.User{Login: "bob-user", Hash: "x", Role: store.RoleUser})
	bobC, _ := e.sessionFor(t, bob, false)

	body := get(e, c, "/account").Body.String()
	if !strings.Contains(body, "test-agent") || !strings.Contains(body, "10.0.0.1") || !strings.Contains(body, "текущая") {
		t.Fatalf("страница сессий: %s", body)
	}
	cur, _ := e.lookup(c.Value)
	if rec := post(e, c, "/account/sessions/revoke", form(csrf, "session", cur.IDHash)); rec.Code != 400 {
		t.Errorf("отзыв текущей: %d", rec.Code)
	}
	bobSess, _ := e.lookup(bobC.Value)
	if rec := post(e, c, "/account/sessions/revoke", form(csrf, "session", bobSess.IDHash)); rec.Code != 404 {
		t.Errorf("чужая сессия: %d", rec.Code)
	}
	if _, ok := e.lookup(bobC.Value); !ok {
		t.Error("чужая сессия отозвана")
	}
	if rec := post(e, c, "/account/sessions/revoke", form(csrf, "session", otherSess.IDHash)); rec.Code != 303 {
		t.Fatalf("отзыв: %d", rec.Code)
	}
	if _, ok := e.lookup(other.Value); ok {
		t.Error("сессия не отозвана")
	}
	if rec := post(e, c, "/account/sessions/all", form(csrf)); rec.Code != 303 {
		t.Fatalf("выйти везде: %d", rec.Code)
	}
	if _, ok := e.lookup(c.Value); ok {
		t.Error("текущая сессия жива после «Выйти везде»")
	}
}

func adminPost(e *testEnv, c *http.Cookie, csrf, path string, kv ...string) (code int, body string) {
	return followOnce(e, c, post(e, c, path, form(csrf, kv...)))
}

// followOnce: ответ-переход на страницу «показать один раз» заменяется самой
// страницей (она отдаётся один раз: повторный GET ведёт на /account).
func followOnce(e *testEnv, c *http.Cookie, rec *httptest.ResponseRecorder) (int, string) {
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != pathAccountOnce {
		return rec.Code, rec.Body.String()
	}
	page := get(e, c, pathAccountOnce)
	return page.Code, page.Body.String()
}

func TestUsersCreate(t *testing.T) {
	e, c, csrf := accEnv(t)
	ctx := context.Background()
	if code, _ := adminPost(e, c, csrf, "/users", "login", "Bad Login", "role", "user"); code != 400 {
		t.Errorf("плохой логин: %d", code)
	}
	if code, _ := adminPost(e, c, csrf, "/users", "login", "bob", "role", "root"); code != 400 {
		t.Errorf("плохая роль: %d", code)
	}
	if code, _ := adminPost(e, c, csrf, "/users", "login", "bob", "role", "user", "password", "short1"); code != 400 {
		t.Errorf("слабый пароль: %d", code)
	}
	code, body := adminPost(e, c, csrf, "/users", "login", "bob", "role", "user", "generate", "1", "must_change", "1")
	if code != 200 {
		t.Fatalf("создание: %d %s", code, body)
	}
	pw := regexp.MustCompile(`<pre>(\S+)\s*</pre>`).FindStringSubmatch(body)
	if pw == nil || len(pw[1]) != 16 {
		t.Fatalf("пароль не показан: %s", body)
	}
	u, err := e.st.UserByLogin(ctx, "bob")
	if err != nil || u.Role != store.RoleUser || !u.MustChange || !CheckPassword("bob", u.Hash, "bob", pw[1]) {
		t.Fatalf("пользователь: %+v %v", u, err)
	}
	if code, _ := adminPost(e, c, csrf, "/users", "login", "bob", "role", "user", "password", "validpass123"); code != 409 {
		t.Errorf("дубль логина: %d", code)
	}
	// свой пароль и «сменить при входе» не отмечено
	if code, _ := adminPost(e, c, csrf, "/users", "login", "carol", "role", "admin", "password", "validpass123"); code != 303 {
		t.Fatalf("создание со своим паролем: %d", code)
	}
	if u, _ := e.st.UserByLogin(ctx, "carol"); u.Role != store.RoleAdmin || u.MustChange {
		t.Fatalf("carol: %+v", u)
	}
	// список
	list := get(e, c, "/users").Body.String()
	if !strings.Contains(list, "bob") || !strings.Contains(list, "carol") {
		t.Errorf("список: %s", list)
	}
	logs, _, _ := e.st.AuditList(ctx, 20, 0, "user_create")
	if len(logs) != 2 || strings.Contains(logs[0].After+logs[1].After, pw[1]) {
		t.Fatalf("журнал: %+v", logs)
	}
}

func TestUsersLastAdminProtected(t *testing.T) {
	e, c, csrf := accEnv(t)
	ctx := context.Background()
	id := "/users/" + strconv.FormatInt(e.admin.ID, 10)
	if code, _ := adminPost(e, c, csrf, id+"/role", "role", "user"); code != 409 {
		t.Errorf("понижение последнего: %d", code)
	}
	if code, _ := adminPost(e, c, csrf, id+"/disabled", "disabled", "1"); code != 409 {
		t.Errorf("отключение последнего: %d", code)
	}
	if code, _ := adminPost(e, c, csrf, id+"/delete", "confirm", "admin"); code != 409 {
		t.Errorf("удаление последнего: %d", code)
	}
	if u, _ := e.st.UserByID(ctx, e.admin.ID); u.Role != store.RoleAdmin || u.Disabled {
		t.Fatalf("администратор изменён: %+v", u)
	}
	// второй администратор — теперь первого можно понизить, но не обоих
	second, _ := e.st.CreateUser(ctx, store.User{Login: "second", Hash: "x", Role: store.RoleAdmin})
	if code, _ := adminPost(e, c, csrf, id+"/role", "role", "user"); code != 303 {
		t.Fatalf("понижение при двух: %d", code)
	}
	sc, ss := e.sessionFor(t, second, false)
	secondID := "/users/" + strconv.FormatInt(second.ID, 10)
	if code, _ := adminPost(e, sc, ss.CSRF, secondID+"/role", "role", "user"); code != 409 {
		t.Errorf("понижение единственного оставшегося: %d", code)
	}
	if code, _ := adminPost(e, sc, ss.CSRF, secondID+"/delete", "confirm", "second"); code != 409 {
		t.Errorf("удаление единственного оставшегося: %d", code)
	}
}

func TestUsersDisableResetDelete(t *testing.T) {
	e, c, csrf := accEnv(t)
	ctx := context.Background()
	bob, _ := e.st.CreateUser(ctx, store.User{Login: "bob", Hash: "x", Role: store.RoleUser})
	bobC, _ := e.sessionFor(t, bob, false)
	id := "/users/" + strconv.FormatInt(bob.ID, 10)

	if code, _ := adminPost(e, c, csrf, id+"/disabled", "disabled", "1"); code != 303 {
		t.Fatalf("отключение: %d", code)
	}
	if _, ok := e.lookup(bobC.Value); ok {
		t.Error("сессия отключённого жива")
	}
	if code, _ := adminPost(e, c, csrf, id+"/disabled", "disabled", "0"); code != 303 {
		t.Fatalf("включение: %d", code)
	}

	// сброс пароля: показывается один раз, все сессии завершены, must_change
	bobC, _ = e.sessionFor(t, bob, false)
	code, body := adminPost(e, c, csrf, id+"/password")
	pw := regexp.MustCompile(`<pre>(\S+)\s*</pre>`).FindStringSubmatch(body)
	if code != 200 || pw == nil {
		t.Fatalf("сброс пароля: %d %s", code, body)
	}
	u, _ := e.st.UserByID(ctx, bob.ID)
	if !u.MustChange || !CheckPassword("bob", u.Hash, "bob", pw[1]) {
		t.Fatalf("после сброса: %+v", u)
	}
	if _, ok := e.lookup(bobC.Value); ok {
		t.Error("сессия жива после сброса пароля")
	}
	if strings.Contains(get(e, c, id).Body.String(), pw[1]) {
		t.Error("пароль показан повторно")
	}

	// сброс пароля самому себе — отказ, сессия жива
	selfID := "/users/" + strconv.FormatInt(e.admin.ID, 10)
	if code, body := adminPost(e, c, csrf, selfID+"/password"); code != 400 || !strings.Contains(body, "Аккаунт") {
		t.Fatalf("сброс себе: %d", code)
	}
	if _, ok := e.lookup(c.Value); !ok {
		t.Error("сессия администратора завершена отказанным сбросом")
	}

	// сброс 2FA
	e.srv.DataKey = bytes.Repeat([]byte{7}, 32)
	sealed, _ := Seal(e.srv.DataKey, []byte("0123456789abcdefghij"))
	u.TOTPSecret = sealed
	e.st.UpdateUser(ctx, u)
	e.st.SetBackupCodes(ctx, bob.ID, []string{"$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"})
	if code, _ := adminPost(e, c, csrf, id+"/2fa/reset"); code != 303 {
		t.Fatalf("сброс 2FA: %d", code)
	}
	if u, _ = e.st.UserByID(ctx, bob.ID); len(u.TOTPSecret) != 0 {
		t.Error("2FA не сброшена")
	}

	// отзыв сессии пользователя
	bobC, bs := e.sessionFor(t, bob, false)
	hash := hashSessionID(bobC.Value)
	_ = bs
	if code, _ := adminPost(e, c, csrf, id+"/sessions/revoke", "session", hash); code != 303 {
		t.Fatalf("отзыв: %d", code)
	}
	if _, ok := e.lookup(bobC.Value); ok {
		t.Error("сессия не отозвана")
	}

	// удаление: нужно вписать логин
	if code, _ := adminPost(e, c, csrf, id+"/delete", "confirm", "nope"); code != 400 {
		t.Errorf("без подтверждения: %d", code)
	}
	if code, _ := adminPost(e, c, csrf, id+"/delete", "confirm", "bob"); code != 303 {
		t.Fatalf("удаление: %d", code)
	}
	if _, err := e.st.UserByID(ctx, bob.ID); err == nil {
		t.Error("пользователь не удалён")
	}
	if rec := get(e, c, id); rec.Code != 404 {
		t.Errorf("карточка удалённого: %d", rec.Code)
	}
	if rec := get(e, c, "/users/abc"); rec.Code != 404 {
		t.Errorf("неверный id: %d", rec.Code)
	}
}

func TestUsersPageShowsClientsAndOwner(t *testing.T) {
	e, c, _ := accEnv(t)
	ctx := context.Background()
	bob, _ := e.st.CreateUser(ctx, store.User{Login: "bob", Hash: "x", Role: store.RoleUser})
	e.st.SetOwner(ctx, store.LocalNode, "c1", &bob.ID)
	body := get(e, c, "/users/"+strconv.FormatInt(bob.ID, 10)).Body.String()
	if !strings.Contains(body, "/clients/c1") {
		t.Errorf("нет клиента на карточке пользователя: %s", body)
	}
}

// codesIn — резервные коды из блока <pre> страницы.
func codesIn(body string) []string {
	m := regexp.MustCompile(`(?s)<pre>(.*?)</pre>`).FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	return strings.Fields(m[1])
}
