package panel

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

var codeRevokeRe = regexp.MustCompile(`action="/codes/[0-9]+/revoke"`)

const wrongCode = "AAAA-BBBB-CCCC-DDDD"

// dlPath выпускает одноразовую ссылку напрямую в хранилище и возвращает путь.
func (p *pEnv) dlPath(t *testing.T, client string) string {
	t.Helper()
	tok, err := p.st.CreateDownloadLink(context.Background(), store.DownloadParams{Node: store.LocalNode, Client: client,
		PKind: "wireguard", Variant: "vpn", File: "w.conf", Expires: histNow.Add(time.Hour).Unix(), Now: histNow.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return "/dl/" + tok
}

// I1: форма принимается и без Sec-Fetch-Site, если Origin или Referer свои.
func TestPortalSameOriginFallbacks(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	codes := p.codes(t, 9, nil)
	f := func(i int) url.Values { return url.Values{"code": {codes[i]}} }
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"Sec-Fetch-Site none", map[string]string{"Sec-Fetch-Site": "none"}, 303},
		{"Origin своего хоста", map[string]string{"Origin": "http://example.com"}, 303},
		{"Origin: null", map[string]string{"Origin": "null"}, 403},
		{"чужой Origin", map[string]string{"Origin": "https://evil.example"}, 403},
		{"Origin с чужим Referer своего хоста", map[string]string{"Origin": "https://evil.example", "Referer": "http://example.com/p/x"}, 403},
		{"Referer своего хоста без Origin", map[string]string{"Referer": "http://example.com/p/c_x"}, 303},
		{"чужой Referer без Origin", map[string]string{"Referer": "https://evil.example/p/c_x"}, 403},
		{"ни Origin, ни Referer", map[string]string{"X-Test": "1"}, 403},
		{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://example.com"}, 403},
	}
	for i, c := range cases {
		if rec := p.ppost(link+"/unlock", f(i), c.hdr); rec.Code != c.want {
			t.Errorf("%s: %d, ждали %d", c.name, rec.Code, c.want)
		}
	}
}

// I1: за обратным прокси Origin совпадает с panel.public_url, а не с Host запроса.
func TestPortalSameOriginPublicURL(t *testing.T) {
	p := portalEnv(t)
	p.srv.PublicURL = "https://vpn.example.org"
	link := p.clientLink(t, ownClient)
	codes := p.codes(t, 2, nil)
	if rec := p.ppost(link+"/unlock", url.Values{"code": {codes[0]}}, map[string]string{"Origin": "https://vpn.example.org"}); rec.Code != 303 {
		t.Fatalf("Origin из public_url: %d", rec.Code)
	}
	if rec := p.ppost(link+"/unlock", url.Values{"code": {codes[1]}}, map[string]string{"Origin": "https://other.example.org"}); rec.Code != 403 {
		t.Fatalf("чужой Origin при public_url: %d", rec.Code)
	}
}

// I1: Referrer-Policy — same-origin на портале и одноразовых ссылках, no-referrer на остальном.
func TestReferrerPolicyPortalSameOrigin(t *testing.T) {
	p := portalEnv(t)
	for _, path := range []string{p.clientLink(t, ownClient), p.clientLink(t, ownClient) + "/help", p.dlPath(t, ownClient), "/p/c_zzz", "/dl/zzz"} {
		if got := p.pget(path).Header().Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf("%s: %q", path, got)
		}
	}
	if got := get(p.testEnv, p.admin, "/").Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("панель: %q", got)
	}
}

// I3: одноразовая ссылка не переживает удаление клиента через панель.
func TestDownloadLinkDiesWithClient(t *testing.T) {
	p := portalEnv(t)
	path := p.dlPath(t, ownClient)
	if p.pget(path).Code != 200 {
		t.Fatal("ссылка не открылась")
	}
	rec := post(p.testEnv, p.admin, "/clients/"+ownClient+"/delete", url.Values{"csrf": {p.csrf}, "kind": {"wireguard"}, "confirm": {ownClient}})
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if p.pget(path).Code != 410 || p.ppost(path, url.Values{}, nil).Code != 410 {
		t.Fatal("одноразовая ссылка пережила удаление клиента")
	}
}

// I3: клиента удалили мимо панели и создали заново с тем же именем: старая ссылка не оживает.
func TestDownloadLinkDiesOnRecreate(t *testing.T) {
	p := portalEnv(t)
	path := p.dlPath(t, "newcomer")
	// клиента «newcomer» у агента нет: создание считается пересозданием после ухода мимо панели
	p.node.CreateClientFn = func(context.Context, nodeapi.CreateClient) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	rec := post(p.testEnv, p.admin, "/clients", url.Values{"csrf": {p.csrf}, "name": {"newcomer"}, "kind": {"wireguard"}})
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if p.pget(path).Code != 410 {
		t.Fatal("старая одноразовая ссылка жива после пересоздания")
	}
}

// I3: перевыпуск сертификата OpenVPN в панели гасит одноразовые ссылки клиента.
func TestDownloadLinkDiesOnRenew(t *testing.T) {
	p := portalEnv(t)
	p.node.RenewFn = func(context.Context, string, int) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	path := p.dlPath(t, "bob")
	if rec := post(p.testEnv, p.admin, "/clients/bob/renew", url.Values{"csrf": {p.csrf}, "days": {"30"}}); rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if p.pget(path).Code != 410 {
		t.Fatal("ссылка пережила перевыпуск")
	}
}

// I3: клиент пропал у агента мимо панели — ссылка c_ и одноразовые гаснут со второго прохода.
func TestCollectorDropsLinksOfGoneClient(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}, {Name: "keep", OpenVPN: true}}
	tok, _ := e.st.CreateClientLink(ctx, store.LocalNode, "a", 1)
	keepTok, _ := e.st.CreateClientLink(ctx, store.LocalNode, "keep", 1)
	dl, _ := e.st.CreateDownloadLink(ctx, store.DownloadParams{Node: store.LocalNode, Client: "a", PKind: "openvpn", Variant: "v", File: "f", Expires: e.now.Unix() + 3600, Now: 1})
	e.tick(t)
	e.clients = []nodeapi.Client{{Name: "keep", OpenVPN: true}}
	e.advance(time.Minute)
	e.tick(t)
	if _, err := e.st.PortalLinkByToken(ctx, tok); err != nil {
		t.Fatalf("ссылка снята после одного прохода: %v", err)
	}
	e.advance(time.Minute)
	e.tick(t)
	if _, err := e.st.PortalLinkByToken(ctx, tok); err == nil {
		t.Fatal("ссылка пропавшего клиента жива")
	}
	if _, err := e.st.DownloadLinkByToken(ctx, dl, e.now.Unix()); err == nil {
		t.Fatal("одноразовая ссылка пропавшего клиента жива")
	}
	if _, err := e.st.PortalLinkByToken(ctx, keepTok); err != nil {
		t.Fatalf("ссылка живого клиента снята: %v", err)
	}
}

// I4: пользователь с истёкшим сроком удалён — его клиент остаётся заблокированным.
func TestDeletedDebtorClientStaysBlocked(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	u, err := e.st.CreateUser(ctx, store.User{Login: "debtor", Hash: "x", Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a"})
	e.st.SetOwner(ctx, store.LocalNode, "a", &u.ID)
	past := e.now.Add(-time.Hour).Unix()
	e.st.SetUserAccessUntil(ctx, u.ID, &past)
	e.tick(t)
	if len(e.blocks) != 1 || e.blocks[0] != "a:true" {
		t.Fatalf("клиент не заблокирован по сроку: %v", e.blocks)
	}
	if err := e.st.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Minute)
	e.tick(t)
	if len(e.blocks) != 1 || !e.clients[0].Blocked {
		t.Fatalf("должник разблокирован после удаления: %v", e.blocks)
	}
}

// M1: пять ошибок за 56 минут закрывают ввод на час от пятой, а не от первой.
func TestPortalLockoutFromFifthAttempt(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	good := p.codes(t, 1, nil)[0]
	for i := 0; i < 5; i++ {
		at := histNow.Add(time.Duration(i) * 14 * time.Minute) // 0, 14, 28, 42, 56 мин
		p.srv.Now = func() time.Time { return at }
		if rec := p.ppost(link+"/unlock", url.Values{"code": {wrongCode}}, nil); rec.Code != 400 {
			t.Fatalf("попытка %d: %d", i, rec.Code)
		}
	}
	// 70 минут: первая ошибка давно вне окна, но ввод ещё закрыт (до 116-й минуты)
	p.srv.Now = func() time.Time { return histNow.Add(70 * time.Minute) }
	rec := p.ppost(link+"/unlock", url.Values{"code": {good}}, nil)
	want := strconv.Itoa((56 + 60 - 70) * 60)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != want {
		t.Fatalf("на 70-й минуте: %d, Retry-After %q, ждали %s", rec.Code, rec.Header().Get("Retry-After"), want)
	}
	if !strings.Contains(rec.Body.String(), "46 мин") {
		t.Errorf("нет оставшегося времени: %s", rec.Body)
	}
	// на 117-й минуте открыт
	p.srv.Now = func() time.Time { return histNow.Add(117 * time.Minute) }
	if rec := p.ppost(link+"/unlock", url.Values{"code": {good}}, nil); rec.Code != 303 {
		t.Fatalf("после закрытия: %d %s", rec.Code, rec.Body)
	}
}

// M2: параллельные неверные коды по одному токену не обходят предел.
func TestPortalParallelWrongCodesBounded(t *testing.T) {
	p := portalEnv(t)
	link := p.clientLink(t, ownClient)
	var wg sync.WaitGroup
	var bad, closed atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch p.ppost(link+"/unlock", url.Values{"code": {wrongCode}}, nil).Code {
			case 400:
				bad.Add(1)
			case 429:
				closed.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 5 || closed.Load() != 7 {
		t.Fatalf("неверных принято %d, закрыто %d (ждали 5 и 7)", bad.Load(), closed.Load())
	}
}

// M2: медленный агент в одном портале не останавливает ввод кодов в другом.
func TestPortalSlowAgentDoesNotBlockOtherTokens(t *testing.T) {
	p := portalEnv(t)
	linkA := p.clientLink(t, ownClient)
	linkB := p.userLink(t, p.bob.ID)
	codes := p.codes(t, 2, nil)
	base := p.node.ClientsFn
	entered := make(chan struct{})
	release := make(chan struct{})
	var first atomic.Bool
	p.node.ClientsFn = func(c context.Context) ([]nodeapi.Client, error) {
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return base(c)
	}
	done := make(chan int, 1)
	go func() { done <- p.ppost(linkA+"/unlock", url.Values{"code": {codes[0]}}, nil).Code }()
	<-entered
	got := make(chan int, 1)
	go func() {
		got <- p.ppost(linkB+"/unlock", url.Values{"code": {codes[1]}, "client": {ownClient}}, nil).Code
	}()
	select {
	case c := <-got:
		if c != 303 {
			t.Fatalf("второй портал: %d", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("второй портал ждёт медленный агент первого")
	}
	close(release)
	if c := <-done; c != 303 && c != 400 {
		t.Fatalf("первый портал: %d", c)
	}
}

// M3: «Продлить кодом» в панели — те же 5 неверных в час по пользователю.
func TestPanelRedeemRateLimitPerUser(t *testing.T) {
	p := portalEnv(t)
	good := p.codes(t, 2, nil)
	for i := 1; i <= 5; i++ {
		rec := redeem(p.testEnv, p.admin, p.csrf, ownClient, wrongCode)
		if rec.Code != 400 {
			t.Fatalf("попытка %d: %d", i, rec.Code)
		}
	}
	rec := redeem(p.testEnv, p.admin, p.csrf, ownClient, good[0])
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "3600" {
		t.Fatalf("шестая: %d %v", rec.Code, rec.Header())
	}
	if untilOf(t, p, ownClient) != histNow.Unix()+dayS {
		t.Fatal("срок продлён при закрытом вводе")
	}
	// счёт отдельный: другой пользователь панели и портал не затронуты
	link := p.clientLink(t, ownClient)
	if rec := p.ppost(link+"/unlock", url.Values{"code": {good[1]}}, nil); rec.Code != 303 {
		t.Fatalf("портал: %d", rec.Code)
	}
	// верные коды счёт не растят
	p2 := portalEnv(t)
	for _, c := range p2.codes(t, 7, nil) {
		if rec := redeem(p2.testEnv, p2.admin, p2.csrf, ownClient, c); rec.Code != 303 {
			t.Fatalf("верный код: %d %s", rec.Code, rec.Body)
		}
	}
}

// M5: ссылка u_ отключённого пользователя — та же 404, что и неверная.
func TestPortalUserLinkDisabledUser(t *testing.T) {
	p := portalEnv(t)
	ul := p.userLink(t, p.bob.ID)
	if p.pget(ul).Code != 200 {
		t.Fatal("ссылка не открылась")
	}
	if err := p.st.SetDisabled(context.Background(), p.bob.ID, true); err != nil {
		t.Fatal(err)
	}
	bad := p.pget("/p/u_" + strings.Repeat("B", 43))
	for _, path := range []string{ul, ul + "/help", ul + "/profile/" + ownClient + "/wireguard/vpn/w.conf"} {
		rec := p.pget(path)
		if rec.Code != 404 || rec.Body.String() != bad.Body.String() {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if rec := p.ppost(ul+"/unlock", url.Values{"code": {wrongCode}, "client": {ownClient}}, nil); rec.Code != 404 {
		t.Errorf("ввод кода: %d", rec.Code)
	}
	p.st.SetDisabled(context.Background(), p.bob.ID, false)
	if p.pget(ul).Code != 200 {
		t.Error("после включения ссылка не открылась")
	}
}

// M6: клиент под ручной блокировкой — отказ, код цел; блокировка сборщика не мешает.
func TestRedeemRefusedForManuallyBlockedClient(t *testing.T) {
	p := portalEnv(t)
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
	link := p.clientLink(t, ownClient)
	code := p.codes(t, 1, nil)[0]
	for i := 0; i < 7; i++ { // отказ не засчитывается как неверный код
		rec := p.ppost(link+"/unlock", url.Values{"code": {code}}, nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "заблокирован администратором") {
			t.Fatalf("портал, попытка %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := redeem(p.testEnv, p.admin, p.csrf, ownClient, code); rec.Code != 400 || !strings.Contains(rec.Body.String(), "заблокирован администратором") {
		t.Fatalf("панель: %d", rec.Code)
	}
	left, _ := p.st.Codes(context.Background(), store.CodeFilter{State: store.CodeActive}, histNow.Unix())
	if len(left) != 1 {
		t.Fatalf("код потрачен: %+v", left)
	}
	if untilOf(t, p, ownClient) != histNow.Unix()+dayS {
		t.Fatal("срок изменился")
	}
	// автоблокировка по сроку: продление нужно именно ей
	if err := p.st.SaveCard(context.Background(), store.Card{Node: store.LocalNode, Name: ownClient, AccessUntil: ptr(histNow.Unix() + dayS), AutoBlock: store.AutoBlockExpired}); err != nil {
		t.Fatal(err)
	}
	if rec := p.ppost(link+"/unlock", url.Values{"code": {code}}, nil); rec.Code != 303 {
		t.Fatalf("автоблокировка: %d %s", rec.Code, rec.Body)
	}
}

// M7: список кодов — по 100 на страницу, сводки пачек считает база.
func TestCodesPagePagination(t *testing.T) {
	p := portalEnv(t)
	issueFor(t, p.st, store.IssueParams{Count: 150, Days: 5})
	issueFor(t, p.st, store.IssueParams{Count: 100, Days: 7})
	rows := func(path string) (int, string) {
		rec := get(p.testEnv, p.admin, path)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		return len(codeRevokeRe.FindAllString(rec.Body.String(), -1)), rec.Body.String()
	}
	n1, b1 := rows("/codes")
	if n1 != 100 || !strings.Contains(b1, "page=2") || strings.Contains(b1, "← Назад") {
		t.Fatalf("страница 1: %d строк", n1)
	}
	n3, b3 := rows("/codes?page=3")
	if n3 != 50 || strings.Contains(b3, "Вперёд") || !strings.Contains(b3, "page=2") {
		t.Fatalf("страница 3: %d строк", n3)
	}
	if !strings.Contains(b1, "<td>250</td>") && !strings.Contains(b1, "<td>150</td>") {
		t.Error("нет сводки пачек")
	}
	// мусор в page не ломает страницу
	if rec := get(p.testEnv, p.admin, "/codes?page=abc"); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}
