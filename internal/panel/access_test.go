package panel

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	ownClient     = "wg-only" // клиент пользователя bob
	foreignClient = "bob"     // клиент без владельца
)

// userEnv — окружение клиентов с пользователем bob (роль «пользователь»),
// владеющим клиентом wg-only.
func userEnv(t *testing.T) (e *testEnv, admin, user *http.Cookie, csrfUser string, bob store.User) {
	t.Helper()
	e, admin, _ = clientsEnv(t)
	bob, err := e.st.CreateUser(context.Background(), store.User{Login: "bob-user", Hash: "x", Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetOwner(context.Background(), store.LocalNode, ownClient, &bob.ID); err != nil {
		t.Fatal(err)
	}
	e.srv.DataKey = bytes.Repeat([]byte{7}, 32)
	e.node.ProfilesFn = func(context.Context, string) ([]nodeapi.Profile, error) {
		return []nodeapi.Profile{{Kind: "wireguard", Variant: "vpn", File: "w.conf"}}, nil
	}
	e.node.ProfileFn = func(context.Context, string, nodeapi.Profile) ([]byte, error) { return []byte("[Interface]\n"), nil }
	c, s := e.sessionFor(t, bob, false)
	return e, admin, c, s.CSRF, bob
}

// concrete подставляет в шаблон маршрута значения.
func concrete(pattern, name string, id int64) (method, path string) {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return http.MethodGet, pattern
	}
	path = strings.NewReplacer("{name}", name, "{kind}", "wireguard", "{variant}", "vpn", "{file}", "w.conf",
		"{id}", strconv.FormatInt(id, 10), "{$}", "").Replace(path)
	return method, path
}

func send(e *testEnv, c *http.Cookie, csrf, method, path string) int {
	if method == http.MethodGet {
		return get(e, c, path).Code
	}
	return post(e, c, path, url.Values{"csrf": {csrf}}).Code
}

// Сторож: каждый маршрут Handler() есть в таблице прав, и наоборот.
func TestRoutesTableMatchesHandler(t *testing.T) {
	e, _, _, _, _ := userEnv(t)
	got := append([]string(nil), e.srv.registered...)
	var want []string
	for p := range routes {
		want = append(want, p)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("маршруты Handler() и таблица прав расходятся:\nHandler: %q\nтаблица: %q", got, want)
	}
}

// Маршрут, которого нет в таблице, при сборке вызывает панику, а не
// открывается всем.
func TestUnlistedRoutePanics(t *testing.T) {
	s := &Server{}
	defer func() {
		if recover() == nil {
			t.Fatal("маршрут без записи в таблице прав принят")
		}
	}()
	s.route(http.NewServeMux(), "GET /secret", func(http.ResponseWriter, *http.Request) {})
}

// Пользователь-не-администратор на каждом маршруте Handler().
// accountPostWant — код ответа пользователю на POST /account/* с пустой формой.
var accountPostWant = map[string]int{
	"POST /account/password":        http.StatusBadRequest, // пароль не по правилам
	"POST /account/2fa":             http.StatusBadRequest, // нет запечатанного секрета
	"POST /account/2fa/disable":     http.StatusBadRequest, // 2FA не включена
	"POST /account/2fa/codes":       http.StatusBadRequest, // 2FA не включена
	"POST /account/sessions/revoke": http.StatusNotFound,   // такой своей сессии нет
}

func TestPermissionsEveryRouteAsUser(t *testing.T) {
	e, _, user, csrf, bob := userEnv(t)
	seen := 0
	for _, pattern := range e.srv.registered {
		a := routes[pattern]
		seen++
		switch {
		case a == accPublic || a == accMFA:
			continue // вход, выход, статика: права роли не участвуют
		case a == accAdmin:
			// и страницы, и любые действия — 403, даже над своим клиентом
			for _, name := range []string{ownClient, foreignClient} {
				m, p := concrete(pattern, name, bob.ID)
				if code := send(e, user, csrf, m, p); code != http.StatusForbidden {
					t.Errorf("%s (%s): код %d, ждали 403", pattern, name, code)
				}
			}
		case strings.Contains(pattern, "/clients/{name}"):
			// GET-маршруты клиента: чужой — 404, свой — 200
			m, p := concrete(pattern, foreignClient, bob.ID)
			if code := send(e, user, csrf, m, p); code != http.StatusNotFound {
				t.Errorf("%s чужой: код %d, ждали 404", pattern, code)
			}
			m, p = concrete(pattern, ownClient, bob.ID)
			if code := send(e, user, csrf, m, p); code != http.StatusOK {
				t.Errorf("%s свой: код %d, ждали 200", pattern, code)
			}
		case pattern == "GET /account/once":
			// без отложенного секрета страница ведёт на /account
			if code := get(e, user, pathAccountOnce).Code; code != http.StatusSeeOther {
				t.Errorf("%s: код %d, ждали 303", pattern, code)
			}
		case strings.HasPrefix(pattern, "GET /account") || pattern == "GET /{$}":
			m, p := concrete(pattern, ownClient, bob.ID)
			if code := send(e, user, csrf, m, p); code != http.StatusOK {
				t.Errorf("%s: код %d, ждали 200", pattern, code)
			}
		case pattern == "/":
			if code := get(e, user, "/no/such/page").Code; code != http.StatusNotFound {
				t.Errorf("неизвестная страница: %d", code)
			}
		case strings.HasPrefix(pattern, "POST /account"):
			// Без полей формы каждое действие над собой должно отказать по существу
			// (не 403 и не 5xx): конкретный код ждём из таблицы.
			if pattern == "POST /account/sessions/all" {
				continue // завершает все сессии пользователя: проверяется после обхода
			}
			want, known := accountPostWant[pattern]
			if !known {
				t.Errorf("%s: нет ожидаемого кода в accountPostWant", pattern)
				continue
			}
			m, p := concrete(pattern, ownClient, bob.ID)
			if code := send(e, user, csrf, m, p); code != want {
				t.Errorf("%s: код %d, ждали %d", pattern, code, want)
			}
		default:
			t.Errorf("маршрут %q есть в таблице, но тест прав не знает, как его проверить", pattern)
		}
	}
	if seen == 0 {
		t.Fatal("маршрутов нет")
	}
	if code := send(e, user, csrf, http.MethodPost, "/account/sessions/all"); code != http.StatusSeeOther {
		t.Errorf("POST /account/sessions/all: код %d, ждали 303", code)
	}
}

// Администратору открыты все страницы (GET).
func TestPermissionsAdminSeesAll(t *testing.T) {
	e, admin, _, _, bob := userEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return nodeapi.System{}, nil }
	e.node.InfoFn = func(context.Context) (nodeapi.Info, error) { return nodeapi.Info{}, nil }
	for _, pattern := range e.srv.registered {
		if !strings.HasPrefix(pattern, "GET ") || routes[pattern] == accPublic || routes[pattern] == accMFA {
			continue
		}
		_, p := concrete(pattern, ownClient, bob.ID)
		if code := get(e, admin, p).Code; code == http.StatusForbidden {
			t.Errorf("%s: администратору 403", pattern)
		}
	}
}

func TestUserSeesOnlyOwnClients(t *testing.T) {
	e, _, user, _, _ := userEnv(t)
	body := get(e, user, "/").Body.String()
	if !strings.Contains(body, ownClient) || strings.Contains(body, "azpanel-test-1") || strings.Contains(body, ">bob<") {
		t.Errorf("список: %s", body)
	}
	if strings.Contains(body, "Новый клиент") {
		t.Error("пользователю показана ссылка «Новый клиент»")
	}
	for _, hidden := range []string{`href="/monitor"`, `href="/audit"`, `href="/users"`, `href="/settings/access"`} {
		if strings.Contains(body, hidden) {
			t.Errorf("в меню пользователя %s", hidden)
		}
	}
	if !strings.Contains(body, `href="/account"`) {
		t.Error("нет ссылки на аккаунт")
	}
}

func TestUserCardHasNoManagementForms(t *testing.T) {
	e, _, user, _, _ := userEnv(t)
	rec := get(e, user, "/clients/"+ownClient)
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	body := rec.Body.String()
	for _, form := range []string{"/renew", "/limit", "/card", "/block", "/delete", "/owner"} {
		if strings.Contains(body, `action="/clients/`+ownClient+form+`"`) {
			t.Errorf("в карточке пользователя форма %s", form)
		}
	}
	if !strings.Contains(body, "/clients/"+ownClient+"/profiles/wireguard/vpn/w.conf") || !strings.Contains(body, "/qr/wireguard/vpn/w.conf") {
		t.Error("нет ссылок на профиль и QR")
	}
	// у администратора формы на месте
	admin := get(e, mustCookie(t, e), "/clients/"+ownClient).Body.String()
	for _, form := range []string{"/block", "/delete", "/card", "/owner"} {
		if !strings.Contains(admin, `action="/clients/`+ownClient+form+`"`) {
			t.Errorf("у администратора нет формы %s", form)
		}
	}
}

func mustCookie(t *testing.T, e *testEnv) *http.Cookie {
	t.Helper()
	c, _ := e.sessionCookie(t)
	return c
}

// Владельца назначает администратор; клиент появляется у пользователя.
func TestAdminSetsOwner(t *testing.T) {
	e, admin, user, _, bob := userEnv(t)
	_, as := e.lookupAdmin(t, admin)
	if get(e, user, "/clients/"+foreignClient).Code != 404 {
		t.Fatal("чужой клиент виден")
	}
	rec := post(e, admin, "/clients/"+foreignClient+"/owner", url.Values{"csrf": {as.CSRF}, "owner": {strconv.FormatInt(bob.ID, 10)}})
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if get(e, user, "/clients/"+foreignClient).Code != 200 {
		t.Fatal("клиент не появился у владельца")
	}
	if rec := post(e, admin, "/clients/"+foreignClient+"/owner", url.Values{"csrf": {as.CSRF}, "owner": {"99999"}}); rec.Code != 400 {
		t.Fatalf("несуществующий владелец: %d", rec.Code)
	}
	post(e, admin, "/clients/"+foreignClient+"/owner", url.Values{"csrf": {as.CSRF}, "owner": {""}})
	if get(e, user, "/clients/"+foreignClient).Code != 404 {
		t.Fatal("владелец не снят")
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "owner")
	if len(list) != 2 || list[1].After != "bob-user" || list[0].After != "нет" {
		t.Fatalf("журнал: %+v", list)
	}
}

func (e *testEnv) lookupAdmin(t *testing.T, c *http.Cookie) (*http.Cookie, Session) {
	t.Helper()
	s, ok := e.lookup(c.Value)
	if !ok {
		t.Fatal("нет сессии администратора")
	}
	return c, s
}
