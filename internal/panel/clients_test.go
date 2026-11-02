package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// clientsEnv — окружение со входом и четырьмя клиентами.
func clientsEnv(t *testing.T) (*testEnv, *http.Cookie, Session) {
	t.Helper()
	e := newEnv(t, adminHash(t))
	exp := time.Now().Add(10 * 24 * time.Hour)
	far := time.Now().Add(400 * 24 * time.Hour)
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{
			{Name: "azpanel-test-1", OpenVPN: true, WireGuard: true, CertExpires: &exp, Limit: 0},
			{Name: "bob", OpenVPN: true, CertExpires: &far, Limit: 3, Blocked: true},
			{Name: "wg-only", WireGuard: true, Blocked: true},
			{Name: "<script>", OpenVPN: true},
		}, nil
	}
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) {
		since := time.Now().Add(-time.Hour)
		return []nodeapi.Session{
			{Kind: "openvpn", Instance: "antizapret-udp", Name: "azpanel-test-1", Addr: "1.2.3.4:5", RxBytes: 10, TxBytes: 20, Since: &since},
			{Kind: "wireguard", Instance: "wg0", Name: "azpanel-test-1", Addr: "1.2.3.5:5", LastHandshake: &since},
		}, nil
	}
	c, s := e.sessionCookie(t)
	return e, c, s
}

func get(e *testEnv, c *http.Cookie, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.AddCookie(c)
	return e.do(r)
}

func post(e *testEnv, c *http.Cookie, path string, f url.Values) *httptest.ResponseRecorder {
	r := postForm(path, f)
	r.AddCookie(c)
	return e.do(r)
}

func TestClientsList(t *testing.T) {
	e, c, _ := clientsEnv(t)
	rec := get(e, c, "/")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{"azpanel-test-1", "bob", "Новый клиент", "заблокирован", `<td class="online">2</td>`, `<td class="limit">—</td>`, `<td class="limit">3</td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	// Сертификат с остатком меньше 30 дней выделен.
	if !strings.Contains(body, "осталось 9 дн.") && !strings.Contains(body, "осталось 10 дн.") {
		t.Errorf("нет остатка срока: %s", body)
	}
	if !strings.Contains(body, `class="warn"`) {
		t.Error("срок меньше 30 дней не выделен")
	}

	rec = get(e, c, "/?q=TeSt")
	body = rec.Body.String()
	if !strings.Contains(body, "azpanel-test-1") || strings.Contains(body, ">bob<") {
		t.Errorf("фильтр: %s", body)
	}
}

func TestClientsListEscapesName(t *testing.T) {
	e, c, _ := clientsEnv(t)
	body := get(e, c, "/").Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("имя не экранировано: %s", body)
	}
}

func TestClientsListAgentDown(t *testing.T) {
	e, c, _ := clientsEnv(t)
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return nil, &nodeapi.Error{Status: 500, Message: "сбой агента"}
	}
	rec := get(e, c, "/")
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "сбой агента") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestNewClientForm(t *testing.T) {
	e, c, _ := clientsEnv(t)
	rec := get(e, c, "/clients/new")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="kind"`) {
		t.Fatalf("%d", rec.Code)
	}
}

func TestCreateClient(t *testing.T) {
	e, c, s := clientsEnv(t)
	var got nodeapi.CreateClient
	e.node.CreateClientFn = func(_ context.Context, req nodeapi.CreateClient) (nodeapi.Result, error) {
		got = req
		return nodeapi.Result{}, nil
	}
	rec := post(e, c, "/clients", url.Values{"csrf": {s.CSRF}, "name": {"azpanel-test-9"}, "kind": {"openvpn"}, "days": {"30"}})
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), "/clients/azpanel-test-9?msg=") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got != (nodeapi.CreateClient{Name: "azpanel-test-9", Kind: "openvpn", Days: 30}) {
		t.Fatalf("агент получил %+v", got)
	}
	// Пустые дни — 0 (агент подставит 3650).
	post(e, c, "/clients", url.Values{"csrf": {s.CSRF}, "name": {"a"}, "kind": {"openvpn"}})
	if got.Days != 0 {
		t.Fatalf("дни: %d", got.Days)
	}
	// Для WireGuard дни не посылаются.
	post(e, c, "/clients", url.Values{"csrf": {s.CSRF}, "name": {"a"}, "kind": {"wireguard"}, "days": {"30"}})
	if got.Days != 0 || got.Kind != "wireguard" {
		t.Fatalf("wg: %+v", got)
	}
}

func TestCreateClientErrors(t *testing.T) {
	e, c, s := clientsEnv(t)
	e.node.CreateClientFn = func(context.Context, nodeapi.CreateClient) (nodeapi.Result, error) {
		return nodeapi.Result{}, &nodeapi.Error{Status: 409, Message: "клиент уже есть в WireGuard"}
	}
	rec := post(e, c, "/clients", url.Values{"csrf": {s.CSRF}, "name": {"dup"}, "kind": {"openvpn"}})
	body := rec.Body.String()
	if rec.Code != 400 || !strings.Contains(body, "клиент уже есть в WireGuard") || !strings.Contains(body, `value="dup"`) {
		t.Fatalf("%d %s", rec.Code, body)
	}
	for name, f := range map[string]url.Values{
		"пустое имя":   {"csrf": {s.CSRF}, "name": {""}, "kind": {"openvpn"}},
		"неверный тип": {"csrf": {s.CSRF}, "name": {"x"}, "kind": {"ipsec"}},
		"дни abc":      {"csrf": {s.CSRF}, "name": {"x"}, "kind": {"openvpn"}, "days": {"abc"}},
		"дни 0":        {"csrf": {s.CSRF}, "name": {"x"}, "kind": {"openvpn"}, "days": {"0"}},
		"дни 3651":     {"csrf": {s.CSRF}, "name": {"x"}, "kind": {"openvpn"}, "days": {"3651"}},
	} {
		calls := 0
		e.node.CreateClientFn = func(context.Context, nodeapi.CreateClient) (nodeapi.Result, error) {
			calls++
			return nodeapi.Result{}, nil
		}
		if rec := post(e, c, "/clients", f); rec.Code != 400 || calls != 0 {
			t.Errorf("%s: код %d, вызовов %d", name, rec.Code, calls)
		}
	}
}

func TestClientCard(t *testing.T) {
	e, c, _ := clientsEnv(t)
	e.node.ProfilesFn = func(_ context.Context, name string) ([]nodeapi.Profile, error) {
		return []nodeapi.Profile{
			{Kind: "openvpn", Variant: "antizapret", File: "a.ovpn"},
			{Kind: "wireguard", Variant: "vpn", File: "w b.conf"},
		}, nil
	}
	rec := get(e, c, "/clients/azpanel-test-1?msg=created")
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, body)
	}
	for _, want := range []string{"создан", "antizapret-udp", "1.2.3.4:5", "/clients/azpanel-test-1/profiles/openvpn/antizapret/a.ovpn", "/clients/azpanel-test-1/qr/wireguard/vpn/w%20b.conf", "Продлить", "Удалить OpenVPN", "Удалить WireGuard"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(body, "/qr/openvpn/") {
		t.Error("QR для OpenVPN")
	}
	// Клиент только с WireGuard: нет продления и удаления OpenVPN.
	body = get(e, c, "/clients/wg-only").Body.String()
	if strings.Contains(body, "Продлить сертификат") || strings.Contains(body, "Удалить OpenVPN") || !strings.Contains(body, "Удалить WireGuard") {
		t.Errorf("кнопки wg-only: %s", body)
	}
	if strings.Contains(body, "только на OpenVPN") {
		t.Error("осталась пометка про блокировку только OpenVPN")
	}
	// Сбой профилей не роняет карточку.
	e.node.ProfilesFn = nil
	if rec := get(e, c, "/clients/bob"); rec.Code != 200 {
		t.Fatalf("без профилей: %d", rec.Code)
	}
}

func TestProfileDownload(t *testing.T) {
	e, c, _ := clientsEnv(t)
	var gotName string
	var gotP nodeapi.Profile
	e.node.ProfileFn = func(_ context.Context, name string, p nodeapi.Profile) ([]byte, error) {
		gotName, gotP = name, p
		return []byte("конфиг"), nil
	}
	rec := get(e, c, "/clients/bob/profiles/openvpn/antizapret/bob%20x.ovpn")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "bob x.ovpn") || rec.Body.String() != "конфиг" {
		t.Fatalf("%d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	if gotName != "bob" || gotP != (nodeapi.Profile{Kind: "openvpn", Variant: "antizapret", File: "bob x.ovpn"}) {
		t.Fatalf("агенту: %q %+v", gotName, gotP)
	}
	if rec := get(e, c, "/clients/nobody/profiles/openvpn/a/b.ovpn"); rec.Code != 404 {
		t.Fatalf("неизвестный клиент: %d", rec.Code)
	}
}

func TestQR(t *testing.T) {
	e, c, _ := clientsEnv(t)
	size := 200
	e.node.ProfileFn = func(context.Context, string, nodeapi.Profile) ([]byte, error) {
		return []byte(strings.Repeat("a", size)), nil
	}
	rec := get(e, c, "/clients/wg-only/qr/wireguard/vpn/w.conf")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || !strings.HasPrefix(rec.Body.String(), "\x89PNG") {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if rec := get(e, c, "/clients/bob/qr/openvpn/a/b.ovpn"); rec.Code != 404 {
		t.Fatalf("openvpn: %d", rec.Code)
	}
	size = 3000
	rec = get(e, c, "/clients/wg-only/qr/wireguard/vpn/w.conf")
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "профиль слишком велик для QR") {
		t.Fatalf("большой: %d %s", rec.Code, rec.Body)
	}
}

func TestRenew(t *testing.T) {
	e, c, s := clientsEnv(t)
	calls := 0
	var gotDays int
	e.node.RenewFn = func(_ context.Context, name string, days int) (nodeapi.Result, error) {
		calls++
		gotDays = days
		return nodeapi.Result{}, nil
	}
	for _, d := range []string{"0", "abc", "", "3651", "-5"} {
		if rec := post(e, c, "/clients/bob/renew", url.Values{"csrf": {s.CSRF}, "days": {d}}); rec.Code != 400 {
			t.Errorf("days=%q: %d", d, rec.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("агент вызван %d раз при неверных днях", calls)
	}
	rec := post(e, c, "/clients/bob/renew", url.Values{"csrf": {s.CSRF}, "days": {"30"}})
	if rec.Code != 303 || calls != 1 || gotDays != 30 {
		t.Fatalf("%d, вызовов %d, дней %d", rec.Code, calls, gotDays)
	}
}

func TestSetLimit(t *testing.T) {
	e, c, s := clientsEnv(t)
	got := -1
	e.node.SetLimitFn = func(_ context.Context, name string, limit int) error {
		got = limit
		return nil
	}
	if rec := post(e, c, "/clients/bob/limit", url.Values{"csrf": {s.CSRF}, "limit": {"1001"}}); rec.Code != 400 || got != -1 {
		t.Fatalf("1001: %d %d", rec.Code, got)
	}
	if rec := post(e, c, "/clients/bob/limit", url.Values{"csrf": {s.CSRF}, "limit": {"-1"}}); rec.Code != 400 || got != -1 {
		t.Fatalf("-1: %d %d", rec.Code, got)
	}
	if rec := post(e, c, "/clients/bob/limit", url.Values{"csrf": {s.CSRF}, "limit": {"0"}}); rec.Code != 303 || got != 0 {
		t.Fatalf("0: %d %d", rec.Code, got)
	}
}

func TestBlock(t *testing.T) {
	e, c, s := clientsEnv(t)
	var got []bool
	e.node.SetBlockedFn = func(_ context.Context, name string, blocked bool) (nodeapi.Result, error) {
		got = append(got, blocked)
		return nodeapi.Result{Killed: 3}, nil
	}
	rec := post(e, c, "/clients/bob/block", url.Values{"csrf": {s.CSRF}, "blocked": {"1"}})
	loc, _ := url.QueryUnescape(rec.Header().Get("Location"))
	if rec.Code != 303 || !strings.HasSuffix(loc, "?msg=blocked&n=3") {
		t.Fatalf("%d %q", rec.Code, loc)
	}
	rec = post(e, c, "/clients/bob/block", url.Values{"csrf": {s.CSRF}, "blocked": {"0"}})
	if rec.Code != 303 || len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("%d %v", rec.Code, got)
	}
	if rec := post(e, c, "/clients/bob/block", url.Values{"csrf": {s.CSRF}, "blocked": {"да"}}); rec.Code != 400 || len(got) != 2 {
		t.Fatalf("неверное поле: %d", rec.Code)
	}
}

func TestDelete(t *testing.T) {
	e, c, s := clientsEnv(t)
	var gotKind, gotName string
	calls := 0
	e.node.DeleteClientFn = func(_ context.Context, kind, name string) (nodeapi.Result, error) {
		calls++
		gotKind, gotName = kind, name
		return nodeapi.Result{}, nil
	}
	for name, f := range map[string]url.Values{
		"без confirm":   {"csrf": {s.CSRF}, "kind": {"openvpn"}},
		"чужой confirm": {"csrf": {s.CSRF}, "kind": {"openvpn"}, "confirm": {"alice"}},
		"неверный тип":  {"csrf": {s.CSRF}, "kind": {"ipsec"}, "confirm": {"bob"}},
	} {
		if rec := post(e, c, "/clients/bob/delete", f); rec.Code != 400 || calls != 0 {
			t.Errorf("%s: %d, вызовов %d", name, rec.Code, calls)
		}
	}
	rec := post(e, c, "/clients/bob/delete", url.Values{"csrf": {s.CSRF}, "kind": {"openvpn"}, "confirm": {"bob"}})
	loc, _ := url.QueryUnescape(rec.Header().Get("Location"))
	if rec.Code != 303 || loc != "/?msg=deleted" || gotKind != "openvpn" || gotName != "bob" {
		t.Fatalf("%d %q %s %s", rec.Code, loc, gotKind, gotName)
	}
}

func TestActionNeedsCSRF(t *testing.T) {
	e, c, _ := clientsEnv(t)
	boom := func() { t.Error("агент вызван без csrf") }
	e.node.CreateClientFn = func(context.Context, nodeapi.CreateClient) (nodeapi.Result, error) {
		boom()
		return nodeapi.Result{}, nil
	}
	e.node.RenewFn = func(context.Context, string, int) (nodeapi.Result, error) { boom(); return nodeapi.Result{}, nil }
	e.node.SetLimitFn = func(context.Context, string, int) error { boom(); return nil }
	e.node.SetBlockedFn = func(context.Context, string, bool) (nodeapi.Result, error) { boom(); return nodeapi.Result{}, nil }
	e.node.DeleteClientFn = func(context.Context, string, string) (nodeapi.Result, error) { boom(); return nodeapi.Result{}, nil }
	for _, p := range []string{"/clients", "/clients/bob/renew", "/clients/bob/limit", "/clients/bob/block", "/clients/bob/delete"} {
		f := url.Values{"name": {"x"}, "kind": {"openvpn"}, "days": {"30"}, "limit": {"1"}, "blocked": {"1"}, "confirm": {"bob"}}
		if rec := post(e, c, p, f); rec.Code != 403 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestUnknownClient(t *testing.T) {
	e, c, s := clientsEnv(t)
	boom := func() {
		t.Error("действие агента вызвано для неизвестного клиента")
	}
	e.node.RenewFn = func(context.Context, string, int) (nodeapi.Result, error) { boom(); return nodeapi.Result{}, nil }
	e.node.SetLimitFn = func(context.Context, string, int) error { boom(); return nil }
	e.node.SetBlockedFn = func(context.Context, string, bool) (nodeapi.Result, error) { boom(); return nodeapi.Result{}, nil }
	e.node.DeleteClientFn = func(context.Context, string, string) (nodeapi.Result, error) { boom(); return nodeapi.Result{}, nil }
	f := url.Values{"csrf": {s.CSRF}, "kind": {"openvpn"}, "days": {"30"}, "limit": {"1"}, "blocked": {"1"}, "confirm": {"ghost"}}
	for _, p := range []string{"/clients/ghost/renew", "/clients/ghost/limit", "/clients/ghost/block", "/clients/ghost/delete"} {
		if rec := post(e, c, p, f); rec.Code != 404 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if rec := get(e, c, "/clients/ghost"); rec.Code != 404 {
		t.Errorf("карточка: %d", rec.Code)
	}
}

func TestActionAgentError(t *testing.T) {
	e, c, s := clientsEnv(t)
	e.node.SetLimitFn = func(context.Context, string, int) error {
		return &nodeapi.Error{Status: 409, Message: "лимит не принят"}
	}
	rec := post(e, c, "/clients/bob/limit", url.Values{"csrf": {s.CSRF}, "limit": {"5"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "лимит не принят") || !strings.Contains(rec.Body.String(), "bob") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestFlashMessagesFromServerTable(t *testing.T) {
	e, c, _ := clientsEnv(t)
	cases := []struct {
		query, want string
		shown       bool
	}{
		{"msg=created", "создан", true},
		{"msg=renewed&n=30", "продлён на 30 дн.", true},
		{"msg=blocked&n=3", "разорвано сессий: 3", true},
		{"msg=limit_set&n=5", "лимит: 5", true},
		{"msg=limit_off", "лимит снят", true},
		{"msg=" + url.QueryEscape("Пароль сброшен, войдите с паролем admin12345"), "Пароль сброшен", false},
		{"msg=renewed&n=abc", "продлён", false},
		{"msg=blocked", "разорвано", false},
		{"msg=renewed&n=-1", "продлён", false},
	}
	for _, tc := range cases {
		body := get(e, c, "/clients/bob?"+tc.query).Body.String()
		if got := strings.Contains(body, `class="flash"`); got != tc.shown {
			t.Errorf("%s: плашка показана = %v", tc.query, got)
		}
		if got := strings.Contains(body, tc.want); got != tc.shown {
			t.Errorf("%s: текст %q найден = %v", tc.query, tc.want, got)
		}
	}
	// На странице входа произвольный msg тоже не выводится.
	rec := e.do(httptest.NewRequest("GET", "/login?msg="+url.QueryEscape("войдите с паролем admin12345"), nil))
	if strings.Contains(rec.Body.String(), "admin12345") || strings.Contains(rec.Body.String(), `class="flash"`) {
		t.Fatalf("msg подставлен на странице входа: %s", rec.Body)
	}
}
