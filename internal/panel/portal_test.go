package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

// pEnv — окружение портала: пользователь bob владеет клиентом wg-only (срок
// на сутки вперёд), время зафиксировано, администратор вошёл.
type pEnv struct {
	*testEnv
	admin *http.Cookie
	csrf  string
	bob   store.User
}

func portalEnv(t *testing.T) *pEnv {
	t.Helper()
	e, _, _, _, bob := userEnv(t)
	e.srv.Now = func() time.Time { return histNow }
	admin, as := e.sessionCookie(t)
	ctx := context.Background()
	// в основной выдаче wg-only заблокирован; портальные тесты начинают с активного
	base := e.node.ClientsFn
	e.node.ClientsFn = func(c context.Context) ([]nodeapi.Client, error) {
		list, err := base(c)
		for i := range list {
			if list[i].Name == ownClient {
				list[i].Blocked = false
			}
		}
		return list, err
	}
	e.node.DeleteClientFn = func(context.Context, string, string) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	if err := e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: ownClient, AccessUntil: ptr(histNow.Unix() + dayS)}); err != nil {
		t.Fatal(err)
	}
	return &pEnv{testEnv: e, admin: admin, csrf: as.CSRF, bob: bob}
}

// clientLink выпускает токен ссылки клиента и возвращает путь /p/c_….
func (p *pEnv) clientLink(t *testing.T, name string) string {
	t.Helper()
	tok, err := p.st.CreateClientLink(context.Background(), store.LocalNode, name, histNow.Unix())
	if err != nil {
		t.Fatal(err)
	}
	return "/p/c_" + tok
}

func (p *pEnv) userLink(t *testing.T, id int64) string {
	t.Helper()
	tok, err := p.st.CreateUserLink(context.Background(), id, histNow.Unix())
	if err != nil {
		t.Fatal(err)
	}
	return "/p/u_" + tok
}

func (p *pEnv) pget(path string) *httptest.ResponseRecorder {
	return p.do(httptest.NewRequest("GET", path, nil))
}

// ppost — форма портала с заголовком same-origin.
func (p *pEnv) ppost(path string, f url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	r := postForm(path, f)
	if hdr == nil {
		hdr = map[string]string{"Sec-Fetch-Site": "same-origin"}
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return p.do(r)
}

func (p *pEnv) codes(t *testing.T, n int, uid *int64) []string {
	t.Helper()
	return issueFor(t, p.st, store.IssueParams{Count: n, Days: 30, UserID: uid})
}

func untilOf(t *testing.T, p *pEnv, name string) int64 {
	t.Helper()
	eff, err := p.st.EffectiveUntil(context.Background(), store.LocalNode, name)
	if err != nil || eff == nil {
		t.Fatalf("срок %s: %v %v", name, eff, err)
	}
	return *eff
}

// Портал открывается без входа, не ставит cookie и не читает cookie сессии панели.
func TestPortalNoSessionNoCookie(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	rec := p.pget(link)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Fatalf("портал поставил cookie: %v", sc)
	}
	for h, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "same-origin"} {
		if got := rec.Header().Get(h); got != want {
			t.Errorf("%s = %q", h, got)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "script-src") {
		t.Errorf("CSP: %q", csp)
	}
	body := rec.Body.String()
	for _, want := range []string{ownClient, "активен", "UTC", "<svg"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(body, "<script") || strings.Contains(body, `name="csrf"`) {
		t.Error("в портале скрипт или CSRF-поле")
	}

	// с cookie администратора страница та же: сессия не читается
	r := httptest.NewRequest("GET", link, nil)
	r.AddCookie(p.admin)
	with := p.do(r)
	if with.Code != 200 || len(with.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("с cookie: %d %v", with.Code, with.Header().Values("Set-Cookie"))
	}
	wb := with.Body.String()
	if strings.Contains(wb, "Выйти") || strings.Contains(wb, "Аккаунт (") || wb != body {
		t.Error("портал отличается при наличии cookie панели")
	}
	// битый cookie не мешает и ничего не стирает
	r = httptest.NewRequest("GET", link, nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "garbage"})
	if bad := p.do(r); bad.Code != 200 || len(bad.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("битый cookie: %d %v", bad.Code, bad.Header().Values("Set-Cookie"))
	}
	// POST портала тоже не ставит cookie
	post := p.ppost(link+"/unlock", url.Values{"code": {"AAAA-AAAA-AAAA-AAAA"}}, nil)
	if len(post.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("unlock поставил cookie: %v", post.Header().Values("Set-Cookie"))
	}
}

// Неверный токен — одинаковая 404 с задержкой 300 мс; отозванный неотличим.
func TestPortalBadTokenIdenticalDelayed(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	old := link
	link = p.clientLink(t, ownClient) // перевыпуск
	p.sleeps = nil
	bodies := map[string]bool{}
	for _, path := range []string{"/p/c_" + strings.Repeat("A", 43), old, "/p/x", "/p/u_" + strings.TrimPrefix(link, "/p/c_"), "/p/c_", "/p/", "/p/c_a/b/c"} {
		rec := p.pget(path)
		if rec.Code != 404 {
			t.Errorf("%s: %d", path, rec.Code)
		}
		bodies[rec.Body.String()] = true
		if len(rec.Header().Values("Set-Cookie")) != 0 {
			t.Errorf("%s: cookie", path)
		}
	}
	if len(bodies) != 1 {
		t.Errorf("тела ответов 404 различаются: %d вариантов", len(bodies))
	}
	for i, d := range p.sleeps {
		if d != 300*time.Millisecond {
			t.Errorf("задержка %d = %v", i, d)
		}
	}
	if len(p.sleeps) < 6 {
		t.Errorf("задержек %d", len(p.sleeps))
	}
	if rec := p.pget(link); rec.Code != 200 {
		t.Fatalf("новая ссылка: %d", rec.Code)
	}
}

// Перевыпуск из панели убивает прежнюю ссылку и показывает новую один раз.
func TestPortalReissueFromPanelKillsOld(t *testing.T) {
	p := portalEnv(t)
	p.srv.PublicURL = "https://vpn.example.org/"
	old := p.clientLink(t, ownClient)
	rec := post(p.testEnv, p.admin, "/clients/"+ownClient+"/portal", url.Values{"csrf": {p.csrf}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/account/once" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	page := get(p.testEnv, p.admin, "/account/once").Body.String()
	i := strings.Index(page, "https://vpn.example.org/p/c_")
	if i < 0 {
		t.Fatalf("нет полной ссылки: %s", page)
	}
	fresh := page[i:]
	fresh = fresh[:strings.IndexAny(fresh, "<\" \n")]
	path := strings.TrimPrefix(fresh, "https://vpn.example.org")
	if p.pget(old).Code != 404 {
		t.Error("прежняя ссылка жива")
	}
	if p.pget(path).Code != 200 {
		t.Error("новая ссылка не открылась")
	}
	// второй показ невозможен
	if again := get(p.testEnv, p.admin, "/account/once"); again.Code != 303 || strings.Contains(again.Body.String(), "p/c_") {
		t.Error("ссылка показана повторно")
	}
	// в карточке теперь «Создана», самой ссылки нет
	card := get(p.testEnv, p.admin, "/clients/"+ownClient).Body.String()
	if !strings.Contains(card, "Перевыпустить") || !strings.Contains(card, "UTC") || strings.Contains(card, fresh) {
		t.Error("карточка после выпуска")
	}
	list, _, _ := p.st.AuditList(context.Background(), 10, 0, "portal_link")
	if len(list) != 1 || strings.Contains(list[0].After+list[0].Before+list[0].Target, "p/c_") {
		t.Errorf("журнал: %+v", list)
	}
}

// Без panel.public_url ссылка относительная и есть пометка.
func TestPortalRelativeLinkWithoutPublicURL(t *testing.T) {
	p := portalEnv(t)
	post(p.testEnv, p.admin, "/clients/"+ownClient+"/portal", url.Values{"csrf": {p.csrf}})
	page := get(p.testEnv, p.admin, "/account/once").Body.String()
	if !strings.Contains(page, "/p/c_") || strings.Contains(page, "https://") || !strings.Contains(page, "panel.public_url") {
		t.Errorf("страница: %s", page)
	}
	if card := get(p.testEnv, p.admin, "/clients/"+ownClient).Body.String(); !strings.Contains(card, "panel.public_url") {
		t.Error("в карточке нет пометки об адресе")
	}
}

// Профиль чужого клиента через портал — 404; свой отдаётся; QR только WireGuard.
func TestPortalProfileScope(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	if rec := p.pget(link + "/profile/" + ownClient + "/wireguard/vpn/w.conf"); rec.Code != 200 || rec.Body.String() != "[Interface]\n" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "w.conf") {
		t.Fatalf("свой профиль: %d %q", rec.Code, rec.Body)
	}
	if rec := p.pget(link + "/qr/" + ownClient + "/wireguard/vpn/w.conf"); rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("QR: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, path := range []string{
		link + "/profile/" + foreignClient + "/wireguard/vpn/w.conf",
		link + "/qr/" + foreignClient + "/wireguard/vpn/w.conf",
		link + "/profile/azpanel-test-1/wireguard/vpn/w.conf",
	} {
		if rec := p.pget(path); rec.Code != 404 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if rec := p.pget(link + "/qr/" + ownClient + "/openvpn/x/a.ovpn"); rec.Code != 404 {
		t.Errorf("QR openvpn: %d", rec.Code)
	}
	// ссылка клиента без владельца работает так же, но только для него
	other := p.clientLink(t, foreignClient)
	if rec := p.pget(other + "/profile/" + ownClient + "/wireguard/vpn/w.conf"); rec.Code != 404 {
		t.Errorf("профиль чужого по чужой ссылке: %d", rec.Code)
	}
}

// Ссылка пользователя показывает всех его клиентов, и профили только их.
func TestPortalUserLinkAllClients(t *testing.T) {
	p := portalEnv(t)
	ctx := context.Background()
	if err := p.st.SetOwner(ctx, store.LocalNode, "azpanel-test-1", &p.bob.ID); err != nil {
		t.Fatal(err)
	}
	link := p.userLink(t, p.bob.ID)
	body := p.pget(link).Body.String()
	if !strings.Contains(body, ">"+ownClient+"<") || !strings.Contains(body, "azpanel-test-1") || strings.Contains(body, ">bob<") {
		t.Fatalf("клиенты на странице: %s", body)
	}
	if rec := p.pget(link + "/profile/azpanel-test-1/wireguard/vpn/w.conf"); rec.Code != 200 {
		t.Errorf("второй клиент: %d", rec.Code)
	}
	if rec := p.pget(link + "/profile/" + foreignClient + "/wireguard/vpn/w.conf"); rec.Code != 404 {
		t.Errorf("чужой клиент: %d", rec.Code)
	}
	// ссылка клиента не открывается как ссылка пользователя и наоборот
	if rec := p.pget("/p/u_" + strings.TrimPrefix(p.clientLink(t, ownClient), "/p/c_")); rec.Code != 404 {
		t.Errorf("c-токен как u: %d", rec.Code)
	}
}

// Статус: заблокирован, причина и срок; трафик за 30 дней.
func TestPortalStatusAndTraffic(t *testing.T) {
	p := portalEnv(t)
	ctx := context.Background()
	p.st.SetAutoBlock(ctx, store.LocalNode, ownClient, store.AutoBlockExpired, "")
	base := p.node.ClientsFn
	p.node.ClientsFn = func(c context.Context) ([]nodeapi.Client, error) {
		list, err := base(c)
		for i := range list {
			if list[i].Name == ownClient {
				list[i].Blocked = true
			}
		}
		return list, err
	}
	p.st.AddTraffic(ctx, store.LocalNode, histNow.Add(-2*time.Hour).Unix(), map[string]store.Bytes{ownClient: {Rx: 1 << 20, Tx: 3 << 20}})
	body := p.pget(p.clientLink(t, ownClient)).Body.String()
	for _, want := range []string{"заблокирован автоматически: истёк срок", "2026-11-05 12:00 UTC", "↓ 3.0 МБ", "↑ 1.0 МБ"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
}

func TestPortalHelpPage(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	body := p.pget(link + "/help").Body.String()
	for _, want := range []string{"Android", "iOS", "Windows", "macOS", "OpenVPN Connect", "WireGuard", "AmneziaWG"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if p.pget("/p/c_"+strings.Repeat("B", 43)+"/help").Code != 404 {
		t.Error("инструкция по чужому токену")
	}
}

// POST портала: cross-site и запрос без заголовков отклоняются 403, Origin по хосту принимается.
func TestPortalUnlockOriginCheck(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	code := p.codes(t, 1, nil)[0]
	f := url.Values{"code": {code}}
	for name, hdr := range map[string]map[string]string{
		"cross-site":       {"Sec-Fetch-Site": "cross-site"},
		"same-site":        {"Sec-Fetch-Site": "same-site"},
		"без заголовков":   {"X-Test": "1"},
		"чужой Origin":     {"Origin": "https://evil.example"},
		"cross при Origin": {"Sec-Fetch-Site": "cross-site", "Origin": "http://example.com"},
	} {
		if rec := p.ppost(link+"/unlock", f, hdr); rec.Code != 403 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if untilOf(t, p, ownClient) != histNow.Unix()+dayS {
		t.Fatal("срок изменился при отклонённых запросах")
	}
	// httptest.NewRequest ставит Host example.com
	if rec := p.ppost(link+"/unlock", f, map[string]string{"Origin": "http://example.com"}); rec.Code != 303 {
		t.Fatalf("Origin по хосту: %d %s", rec.Code, rec.Body)
	}
}

// Ввод кода в портале продлевает срок, второй ввод того же кода отказывает,
// сообщение на странице; в журнал код не пишется.
func TestPortalUnlockExtendsOnce(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	codes := p.codes(t, 2, nil)
	rec := p.ppost(link+"/unlock", url.Values{"code": {strings.ToLower(codes[0])}}, nil)
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), link+"?msg=access_extended") {
		t.Fatalf("%d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if got := untilOf(t, p, ownClient); got != histNow.Unix()+31*dayS {
		t.Fatalf("срок %d", got)
	}
	if page := p.pget(rec.Header().Get("Location")); !strings.Contains(page.Body.String(), "доступ продлён на 30 дн.") {
		t.Error("нет сообщения о продлении")
	}
	again := p.ppost(link+"/unlock", url.Values{"code": {codes[0]}}, nil)
	if again.Code != 400 || !strings.Contains(again.Body.String(), "код неверен или уже использован") {
		t.Fatalf("повтор: %d %s", again.Code, again.Body)
	}
	list, _, _ := p.st.AuditList(context.Background(), 10, 0, "redeem")
	if len(list) != 1 || list[0].User != "портал" || strings.Contains(list[0].After+list[0].Before, codes[0]) {
		t.Fatalf("журнал: %+v", list)
	}
}

// Код на пользователя: ссылка u_ принимает только его, а ссылка клиента — по владельцу.
func TestPortalUnlockUserBoundCodeAndUserLink(t *testing.T) {
	p := portalEnv(t)
	ctx := context.Background()
	carol, _ := p.st.CreateUser(ctx, store.User{Login: "carol", Hash: "x", Role: store.RoleUser})
	forCarol := p.codes(t, 1, &carol.ID)[0]
	forBob := p.codes(t, 1, &p.bob.ID)[0]
	clientLink := p.clientLink(t, ownClient)
	if rec := p.ppost(clientLink+"/unlock", url.Values{"code": {forCarol}}, nil); rec.Code != 400 {
		t.Fatalf("код чужого пользователя: %d", rec.Code)
	}
	ul := p.userLink(t, p.bob.ID)
	// клиент не из списка пользователя
	if rec := p.ppost(ul+"/unlock", url.Values{"code": {forBob}, "client": {foreignClient}}, nil); rec.Code != 400 {
		t.Fatalf("чужой клиент: %d", rec.Code)
	}
	if rec := p.ppost(ul+"/unlock", url.Values{"code": {forBob}}, nil); rec.Code != 400 {
		t.Fatalf("без клиента: %d", rec.Code)
	}
	if rec := p.ppost(ul+"/unlock", url.Values{"code": {forBob}, "client": {ownClient}}, nil); rec.Code != 303 {
		t.Fatalf("свой код по ссылке пользователя: %d %s", rec.Code, rec.Body)
	}
	if untilOf(t, p, ownClient) != histNow.Unix()+31*dayS {
		t.Fatal("срок не продлён")
	}
}

// 5 неверных кодов за час закрывают ввод на этот токен: шестая попытка — 429,
// даже с верным кодом. Другой токен и следующий час не затронуты.
func TestPortalUnlockRateLimitPerToken(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	otherLink := p.userLink(t, p.bob.ID)
	good := p.codes(t, 2, nil)
	for i := 1; i <= 5; i++ {
		rec := p.ppost(link+"/unlock", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}, nil)
		if rec.Code != 400 {
			t.Fatalf("попытка %d: %d", i, rec.Code)
		}
		if want := "Осталось попыток: "; i < 5 && !strings.Contains(rec.Body.String(), want) {
			t.Errorf("попытка %d: нет счётчика", i)
		}
	}
	rec := p.ppost(link+"/unlock", url.Values{"code": {good[0]}}, nil)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "3600" {
		t.Fatalf("шестая: %d %v", rec.Code, rec.Header())
	}
	if untilOf(t, p, ownClient) != histNow.Unix()+dayS {
		t.Fatal("срок продлён при закрытом вводе")
	}
	// другой токен считает отдельно
	if rec := p.ppost(otherLink+"/unlock", url.Values{"code": {good[1]}, "client": {ownClient}}, nil); rec.Code != 303 {
		t.Fatalf("другой токен: %d %s", rec.Code, rec.Body)
	}
	// через час ввод снова открыт
	p.srv.Now = func() time.Time { return histNow.Add(61 * time.Minute) }
	if rec := p.ppost(link+"/unlock", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}, nil); rec.Code != 400 {
		t.Fatalf("после часа: %d", rec.Code)
	}
}

// Верные коды счётчик ошибок не растят.
func TestPortalUnlockSuccessDoesNotCount(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	for _, c := range p.codes(t, 7, nil) {
		if rec := p.ppost(link+"/unlock", url.Values{"code": {c}}, nil); rec.Code != 303 {
			t.Fatalf("верный код: %d", rec.Code)
		}
	}
}

// Клиент без срока: отказ, код цел, ошибка не засчитана.
func TestPortalUnlockNoLimitKeepsCode(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, foreignClient) // карточки нет
	code := p.codes(t, 1, nil)[0]
	for i := 0; i < 7; i++ {
		if rec := p.ppost(link+"/unlock", url.Values{"code": {code}}, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "нет срока доступа") {
			t.Fatalf("попытка %d: %d", i, rec.Code)
		}
	}
}

// Одноразовая ссылка: без PIN — одно скачивание, второе 410.
func TestDownloadLinkOnce(t *testing.T) {
	p := portalEnv(t)
	form := url.Values{"csrf": {p.csrf}, "profile": {"wireguard/vpn/w.conf"}}
	rec := post(p.testEnv, p.admin, "/clients/"+ownClient+"/dl", form)
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	page := get(p.testEnv, p.admin, "/account/once").Body.String()
	i := strings.Index(page, "/dl/")
	if i < 0 {
		t.Fatalf("нет ссылки: %s", page)
	}
	path := page[i:]
	path = path[:strings.IndexAny(path, "<\" \n")]
	view := p.pget(path)
	if view.Code != 200 || !strings.Contains(view.Body.String(), "Скачать") || strings.Contains(view.Body.String(), `name="pin"`) {
		t.Fatalf("страница: %d %s", view.Code, view.Body)
	}
	if p.pget(path).Code != 200 {
		t.Fatal("просмотр сжёг ссылку")
	}
	dl := p.ppost(path, url.Values{}, nil)
	if dl.Code != 200 || dl.Body.String() != "[Interface]\n" || !strings.Contains(dl.Header().Get("Content-Disposition"), "w.conf") {
		t.Fatalf("скачивание: %d %q", dl.Code, dl.Body)
	}
	if again := p.ppost(path, url.Values{}, nil); again.Code != 410 {
		t.Fatalf("второе скачивание: %d", again.Code)
	}
	if p.pget(path).Code != 410 {
		t.Error("страница использованной ссылки жива")
	}
	if len(dl.Header().Values("Set-Cookie")) != 0 || dl.Header().Get("Cache-Control") != "no-store" {
		t.Error("заголовки скачивания")
	}
	if p.ppost(path, url.Values{}, map[string]string{"Sec-Fetch-Site": "cross-site"}).Code != 403 {
		t.Error("cross-site скачивание принято")
	}
	if p.pget("/dl/"+strings.Repeat("Z", 43)).Code != 410 {
		t.Error("неизвестная ссылка")
	}
}

// PIN: 5 неверных закрывают ссылку навсегда, даже верный PIN после этого 410.
func TestDownloadLinkPINClosesAfterFive(t *testing.T) {
	p := portalEnv(t)
	tok, err := p.st.CreateDownloadLink(context.Background(), store.DownloadParams{Node: store.LocalNode, Client: ownClient,
		PKind: "wireguard", Variant: "vpn", File: "w.conf", PIN: "4821", Expires: histNow.Add(time.Hour).Unix(), Now: histNow.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	path := "/dl/" + tok
	if body := p.pget(path).Body.String(); !strings.Contains(body, `name="pin"`) || !strings.Contains(body, "осталось попыток: 5") {
		t.Fatalf("форма PIN: %s", body)
	}
	for i := 1; i <= 4; i++ {
		rec := p.ppost(path, url.Values{"pin": {"0000"}}, nil)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "неверный PIN") {
			t.Fatalf("попытка %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := p.ppost(path, url.Values{"pin": {"0000"}}, nil); rec.Code != 410 {
		t.Fatalf("пятая неверная: %d", rec.Code)
	}
	if rec := p.ppost(path, url.Values{"pin": {"4821"}}, nil); rec.Code != 410 {
		t.Fatalf("верный PIN после закрытия: %d", rec.Code)
	}
}

func TestDownloadLinkPINCorrect(t *testing.T) {
	p := portalEnv(t)
	form := url.Values{"csrf": {p.csrf}, "profile": {"wireguard/vpn/w.conf"}, "pin": {"4821"}}
	post(p.testEnv, p.admin, "/clients/"+ownClient+"/dl", form)
	page := get(p.testEnv, p.admin, "/account/once").Body.String()
	path := page[strings.Index(page, "/dl/"):]
	path = path[:strings.IndexAny(path, "<\" \n")]
	if rec := p.ppost(path, url.Values{"pin": {"1111"}}, nil); rec.Code != 403 {
		t.Fatalf("неверный PIN: %d", rec.Code)
	}
	if rec := p.ppost(path, url.Values{"pin": {"4821"}}, nil); rec.Code != 200 || rec.Body.String() != "[Interface]\n" {
		t.Fatalf("верный PIN: %d", rec.Code)
	}
	if rec := p.ppost(path, url.Values{"pin": {"4821"}}, nil); rec.Code != 410 {
		t.Fatalf("повтор: %d", rec.Code)
	}
}

// Срок жизни — 24 часа.
func TestDownloadLinkExpires(t *testing.T) {
	p := portalEnv(t)
	post(p.testEnv, p.admin, "/clients/"+ownClient+"/dl", url.Values{"csrf": {p.csrf}, "profile": {"wireguard/vpn/w.conf"}})
	page := get(p.testEnv, p.admin, "/account/once").Body.String()
	path := page[strings.Index(page, "/dl/"):]
	path = path[:strings.IndexAny(path, "<\" \n")]
	p.srv.Now = func() time.Time { return histNow.Add(24*time.Hour + time.Minute) }
	if p.pget(path).Code != 410 {
		t.Error("просроченная ссылка жива")
	}
}

// Сбой агента не сжигает ссылку.
func TestDownloadLinkNodeFailureKeepsLink(t *testing.T) {
	p := portalEnv(t)
	post(p.testEnv, p.admin, "/clients/"+ownClient+"/dl", url.Values{"csrf": {p.csrf}, "profile": {"wireguard/vpn/w.conf"}})
	page := get(p.testEnv, p.admin, "/account/once").Body.String()
	path := page[strings.Index(page, "/dl/"):]
	path = path[:strings.IndexAny(path, "<\" \n")]
	okFn := p.node.ProfileFn
	p.node.ProfileFn = func(context.Context, string, nodeapi.Profile) ([]byte, error) { return nil, context.DeadlineExceeded }
	if rec := p.ppost(path, url.Values{}, nil); rec.Code != 502 {
		t.Fatalf("сбой агента: %d", rec.Code)
	}
	p.node.ProfileFn = okFn
	if rec := p.ppost(path, url.Values{}, nil); rec.Code != 200 {
		t.Fatalf("после восстановления: %d", rec.Code)
	}
}

// Форма выпуска проверяет профиль и PIN.
func TestDownloadLinkIssueValidation(t *testing.T) {
	p := portalEnv(t)
	for name, f := range map[string]url.Values{
		"нет профиля":     {"profile": {""}},
		"чужой профиль":   {"profile": {"wireguard/vpn/other.conf"}},
		"короткий PIN":    {"profile": {"wireguard/vpn/w.conf"}, "pin": {"12"}},
		"PIN с буквами":   {"profile": {"wireguard/vpn/w.conf"}, "pin": {"12ab"}},
		"мусор в профиле": {"profile": {"a/b"}},
	} {
		f.Set("csrf", p.csrf)
		if rec := post(p.testEnv, p.admin, "/clients/"+ownClient+"/dl", f); rec.Code != 400 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	// пользователю выпуск недоступен
	user, us := p.sessionFor(t, p.bob, false)
	if rec := post(p.testEnv, user, "/clients/"+ownClient+"/dl", url.Values{"csrf": {us.CSRF}, "profile": {"wireguard/vpn/w.conf"}}); rec.Code != 403 {
		t.Errorf("пользователь: %d", rec.Code)
	}
	if rec := post(p.testEnv, user, "/clients/"+ownClient+"/portal", url.Values{"csrf": {us.CSRF}}); rec.Code != 403 {
		t.Errorf("пользователь, портал: %d", rec.Code)
	}
}

// Ссылка портала удаляется вместе с клиентом (и при пересоздании с тем же именем).
func TestPortalLinkDeletedWithClient(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	if p.pget(link).Code != 200 {
		t.Fatal("ссылка не открылась")
	}
	rec := post(p.testEnv, p.admin, "/clients/"+ownClient+"/delete", url.Values{"csrf": {p.csrf}, "kind": {"wireguard"}, "confirm": {ownClient}})
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	tok := strings.TrimPrefix(link, "/p/c_")
	if _, err := p.st.PortalLinkByToken(context.Background(), tok); err == nil {
		t.Fatal("ссылка клиента осталась в базе")
	}
	if p.pget(link).Code != 404 {
		t.Fatal("ссылка удалённого клиента жива")
	}
}

// Удаление одного из двух типов клиента ссылку не трогает.
func TestPortalLinkKeptWhileOtherKindRemains(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, "azpanel-test-1") // OpenVPN + WireGuard
	rec := post(p.testEnv, p.admin, "/clients/azpanel-test-1/delete", url.Values{"csrf": {p.csrf}, "kind": {"openvpn"}, "confirm": {"azpanel-test-1"}})
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if p.pget(link).Code != 200 {
		t.Fatal("ссылка пропала при удалении одного типа")
	}
}

// Ссылка пользователя уходит вместе с ним; из панели выпускается и перевыпускается.
func TestPortalUserLinkFromPanel(t *testing.T) {
	p := portalEnv(t)
	href := "/users/" + strconv.FormatInt(p.bob.ID, 10)
	if rec := post(p.testEnv, p.admin, href+"/portal", url.Values{"csrf": {p.csrf}}); rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	page := get(p.testEnv, p.admin, "/account/once").Body.String()
	i := strings.Index(page, "/p/u_")
	if i < 0 {
		t.Fatalf("нет ссылки: %s", page)
	}
	path := page[i:]
	path = path[:strings.IndexAny(path, "<\" \n")]
	if p.pget(path).Code != 200 {
		t.Fatal("ссылка пользователя не открылась")
	}
	if up := get(p.testEnv, p.admin, href).Body.String(); !strings.Contains(up, "Перевыпустить") {
		t.Error("на странице пользователя нет перевыпуска")
	}
	post(p.testEnv, p.admin, href+"/portal", url.Values{"csrf": {p.csrf}})
	if p.pget(path).Code != 404 {
		t.Error("прежняя ссылка пользователя жива")
	}
}

// Белый список адресов панели не действует на /p/ и /dl/ (и на статику для них).
func TestAllowGateSkipsPortal(t *testing.T) {
	p := portalEnv(t)
	nets, _ := config.ParseAllowIPs([]string{"10.0.0.0/8"})
	p.srv.Allow.Set(nets)
	link := p.clientLink(t, ownClient)
	outsider := func(method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "192.0.2.5:4000"
		return p.do(r).Code
	}
	if code := outsider("GET", "/login"); code != 403 {
		t.Fatalf("панель снаружи: %d", code)
	}
	if code := outsider("GET", link); code != 200 {
		t.Errorf("портал снаружи: %d", code)
	}
	if code := outsider("GET", "/p/c_"+strings.Repeat("Q", 43)); code != 404 {
		t.Errorf("портал, неверный токен: %d", code)
	}
	if code := outsider("GET", "/dl/"+strings.Repeat("Q", 43)); code != 410 {
		t.Errorf("dl снаружи: %d", code)
	}
	if code := outsider("GET", "/static/style.css"); code != 200 {
		t.Errorf("статика портала: %d", code)
	}
	if code := outsider("GET", "/users"); code != 403 {
		t.Errorf("закрытое: %d", code)
	}
}
