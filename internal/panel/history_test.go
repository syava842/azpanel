package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

var histNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// storeEnv — окружение со входом, четырьмя клиентами, базой и фиксированным временем.
func storeEnv(t *testing.T) (*testEnv, *http.Cookie, string) {
	t.Helper()
	e, c, s := clientsEnv(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e.srv.Store, e.srv.NodeID = st, store.LocalNode
	e.srv.Now = func() time.Time { return histNow }
	return e, c, s.CSRF
}

func TestCardSavesFieldsAndAudits(t *testing.T) {
	e, c, csrf := storeEnv(t)
	rec := post(e, c, "/clients/bob/card", url.Values{"csrf": {csrf}, "note": {" ноутбук "}, "until": {"2026-12-31"},
		"limit_gb": {"1,5"}, "period": {"week"}})
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	card, _ := e.srv.Store.Card(context.Background(), store.LocalNode, "bob")
	wantUntil := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
	if card.Note != "ноутбук" || card.AccessUntil == nil || *card.AccessUntil != wantUntil ||
		card.TrafficLimit != int64(1.5*(1<<30)) || card.TrafficPeriod != store.PeriodWeek {
		t.Fatalf("карточка: %+v", card)
	}
	list, _, _ := e.srv.Store.AuditList(context.Background(), 10, 0, "")
	if len(list) != 1 || list[0].Action != "card" || list[0].Target != "bob" || list[0].User != "admin" || list[0].IP != "10.0.0.1" ||
		!strings.Contains(list[0].After, "доступ до: 2026-12-31") || !strings.Contains(list[0].Before, "доступ до: —") {
		t.Fatalf("журнал: %+v", list)
	}
	// страница карточки показывает сохранённое
	body := get(e, c, "/clients/bob").Body.String()
	for _, want := range []string{`value="ноутбук"`, `value="2026-12-31"`, `value="1.5"`, `<option value="week" selected>`, "<svg"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	// пустой срок сбрасывает срок
	post(e, c, "/clients/bob/card", url.Values{"csrf": {csrf}, "until": {""}, "limit_gb": {"0"}, "period": {"month"}})
	card, _ = e.srv.Store.Card(context.Background(), store.LocalNode, "bob")
	if card.AccessUntil != nil || card.TrafficLimit != 0 {
		t.Fatalf("срок не сброшен: %+v", card)
	}
}

func TestCardRejectsBadInput(t *testing.T) {
	e, c, csrf := storeEnv(t)
	for name, f := range map[string]url.Values{
		"неверная дата":    {"until": {"31.12.2026"}, "limit_gb": {"0"}, "period": {"month"}},
		"отрицательный ГБ": {"until": {""}, "limit_gb": {"-1"}, "period": {"month"}},
		"ГБ не число":      {"until": {""}, "limit_gb": {"много"}, "period": {"month"}},
		"заметка длинная":  {"note": {strings.Repeat("я", 501)}, "limit_gb": {"0"}, "period": {"month"}},
		"период":           {"limit_gb": {"0"}, "period": {"год"}},
	} {
		f.Set("csrf", csrf)
		if rec := post(e, c, "/clients/bob/card", f); rec.Code != 400 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if list, _, _ := e.srv.Store.AuditList(context.Background(), 10, 0, ""); len(list) != 0 {
		t.Fatalf("отказ попал в журнал: %+v", list)
	}
	// ровно 500 рун проходит
	f := url.Values{"csrf": {csrf}, "note": {strings.Repeat("я", 500)}, "limit_gb": {"0"}, "period": {"month"}}
	if rec := post(e, c, "/clients/bob/card", f); rec.Code != 303 {
		t.Fatalf("500 рун: %d", rec.Code)
	}
}

func TestClientsListSortsByTraffic(t *testing.T) {
	e, c, _ := storeEnv(t)
	ctx := context.Background()
	e.srv.Store.AddTraffic(ctx, store.LocalNode, histNow.Add(-time.Hour).Unix(), map[string]store.Bytes{
		"bob": {Rx: 5 << 20, Tx: 5 << 20}, "wg-only": {Rx: 1 << 20}, "azpanel-test-1": {Rx: 100}})
	until := histNow.Add(48 * time.Hour).Unix()
	e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "wg-only", AccessUntil: &until})
	pos := func(body, name string) int { return strings.Index(body, ">"+name+"</a>") }
	body := get(e, c, "/?sort=traffic").Body.String()
	if !(pos(body, "bob") < pos(body, "wg-only") && pos(body, "wg-only") < pos(body, "azpanel-test-1")) {
		t.Fatalf("порядок по трафику: %s", body)
	}
	if !strings.Contains(body, "10.0 МБ") || !strings.Contains(body, "2026-11-06") {
		t.Fatalf("нет трафика или срока: %s", body)
	}
	body = get(e, c, "/?sort=until").Body.String()
	if pos(body, "wg-only") > pos(body, "azpanel-test-1") {
		t.Fatalf("клиент со сроком должен быть первым: %s", body)
	}
	body = get(e, c, "/").Body.String()
	if !(pos(body, "azpanel-test-1") < pos(body, "bob")) {
		t.Fatalf("порядок по имени: %s", body)
	}
}

func TestAuditPageSearchAndPaging(t *testing.T) {
	e, c, _ := storeEnv(t)
	ctx := context.Background()
	for i := 0; i < 150; i++ {
		target := fmt.Sprintf("client%03d", i)
		if i%10 == 0 {
			target = fmt.Sprintf("special%03d", i)
		}
		e.srv.Store.Audit(ctx, store.AuditEntry{TS: int64(1000 + i), User: "admin", IP: "10.0.0.1", Action: "limit", Target: target, Before: "1", After: "2"})
	}
	p1 := get(e, c, "/audit")
	if p1.Code != 200 || strings.Count(p1.Body.String(), "<td>admin</td>") != 100 || !strings.Contains(p1.Body.String(), "page=2") {
		t.Fatalf("страница 1: %d, строк %d", p1.Code, strings.Count(p1.Body.String(), "<td>admin</td>"))
	}
	p2 := get(e, c, "/audit?page=2").Body.String()
	if strings.Count(p2, "<td>admin</td>") != 50 || strings.Contains(p2, "Старее") {
		t.Fatalf("страница 2: %d строк", strings.Count(p2, "<td>admin</td>"))
	}
	q := get(e, c, "/audit?q=SPECIAL").Body.String()
	if strings.Count(q, "<td>admin</td>") != 15 || strings.Contains(q, "client001") || !strings.Contains(q, "1 → 2") {
		t.Fatalf("поиск: %d строк", strings.Count(q, "<td>admin</td>"))
	}
}

func TestLoginLogoutAudited(t *testing.T) {
	e, _, _ := storeEnv(t)
	login(e, "wrong-password")
	rec := login(e, testPassword)
	if rec.Code != 303 {
		t.Fatalf("вход: %d", rec.Code)
	}
	list, _, _ := e.srv.Store.AuditList(context.Background(), 10, 0, "")
	got := map[string]store.AuditEntry{}
	for _, a := range list {
		got[a.Action] = a
	}
	if got["login"].User != "admin" || got["login"].IP != "10.0.0.1" || got["login_failed"].Target != "admin" {
		t.Fatalf("журнал входов: %+v", list)
	}
	for _, a := range list {
		if strings.Contains(a.Before+a.After+a.Target, "password") || strings.Contains(a.Before+a.After, testPassword) {
			t.Fatalf("секрет в журнале: %+v", a)
		}
	}
}

func TestMonitorDenialsAndFlapping(t *testing.T) {
	e, c, _ := storeEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return monitorSystem(), nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) {
		return []nodeapi.Session{
			{Kind: nodeapi.KindWireGuard, Instance: "wg0", Name: "alice", Addr: "1.2.3.4:5"},
			{Kind: nodeapi.KindWireGuard, Instance: "wg0", Name: "calm", Addr: "1.2.3.9:5"},
		}, nil
	}
	var since time.Time
	e.node.DenialsFn = func(_ context.Context, s time.Time) ([]nodeapi.Denial, error) {
		since = s
		var out []nodeapi.Denial
		for i := 0; i < 60; i++ {
			out = append(out, nodeapi.Denial{Time: histNow.Add(-time.Duration(i) * time.Minute), Name: fmt.Sprintf("d%02d", i), Instance: "udp", Addr: "9.9.9.9", Reason: "limit", Count: 3, Limit: 2})
		}
		return out, nil
	}
	e.srv.Collector = &Collector{flap: map[string]bool{"alice": true}}
	body := get(e, c, "/monitor").Body.String()
	if !since.Equal(histNow.Add(-24 * time.Hour)) {
		t.Errorf("since = %v", since)
	}
	if !strings.Contains(body, "превышен лимит подключений: 3 из 2") || !strings.Contains(body, ">d00<") || !strings.Contains(body, ">d49<") || strings.Contains(body, ">d50<") {
		t.Errorf("отказы: %s", body)
	}
	if strings.Count(body, "адрес меняется часто — возможно") != 1 {
		t.Errorf("пометка смены адреса: %s", body)
	}
	if strings.Contains(body, "Город") {
		t.Error("Geo nil: столбцов быть не должно")
	}
	if !strings.Contains(body, "<svg") || !strings.Contains(body, "?range=7d") {
		t.Error("нет графиков ресурсов")
	}
}

func TestMonitorOldAgentWithoutDenials(t *testing.T) {
	e, c, _ := storeEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return monitorSystem(), nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	e.node.DenialsFn = func(context.Context, time.Time) ([]nodeapi.Denial, error) {
		return nil, &nodeapi.Error{Status: 404, Message: "not found"}
	}
	rec := get(e, c, "/monitor")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "агент не поддерживает журнал отказов") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestMonitorChartsFromHistory(t *testing.T) {
	e, c, _ := storeEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return monitorSystem(), nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	e.node.DenialsFn = func(context.Context, time.Time) ([]nodeapi.Denial, error) { return nil, nil }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		e.srv.Store.AddResource(ctx, store.LocalNode, store.ResourcePoint{TS: histNow.Add(-time.Duration(3-i) * time.Minute).Unix(),
			CPU: float64(10 * (i + 1)), MemUsed: 1, MemTotal: 2, NetRx: int64(1000 * i), NetTx: int64(500 * i), Online: i})
	}
	body := get(e, c, "/monitor?range=1d").Body.String()
	if strings.Contains(body, "нет данных") || strings.Count(body, `class="line s1"`) != 4 {
		t.Fatalf("графики: %s", body)
	}
}

func TestDeleteClientDeletesCard(t *testing.T) {
	e, c, csrf := storeEnv(t)
	ctx := context.Background()
	e.node.DeleteClientFn = func(context.Context, string, string) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "bob", Note: "x"})
	e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "azpanel-test-1", Note: "y"})
	rec := post(e, c, "/clients/bob/delete", url.Values{"csrf": {csrf}, "kind": {"openvpn"}, "confirm": {"bob"}})
	if rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	if card, _ := e.srv.Store.Card(ctx, store.LocalNode, "bob"); card.Note != "" {
		t.Fatalf("карточка осталась: %+v", card)
	}
	// у клиента остаётся WireGuard — карточка нужна
	post(e, c, "/clients/azpanel-test-1/delete", url.Values{"csrf": {csrf}, "kind": {"openvpn"}, "confirm": {"azpanel-test-1"}})
	if card, _ := e.srv.Store.Card(ctx, store.LocalNode, "azpanel-test-1"); card.Note != "y" {
		t.Fatalf("карточка удалена при живом WireGuard: %+v", card)
	}
	list, _, _ := e.srv.Store.AuditList(ctx, 10, 0, "delete")
	if len(list) != 2 {
		t.Fatalf("журнал удалений: %+v", list)
	}
}

func TestManualUnblockOfAutoBlockedRemembersReason(t *testing.T) {
	e, c, csrf := storeEnv(t)
	ctx := context.Background()
	e.node.SetBlockedFn = func(context.Context, string, bool) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	until := histNow.Add(-time.Hour).Unix()
	e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "bob", AccessUntil: &until, AutoBlock: store.AutoBlockExpired})
	body := get(e, c, "/clients/bob").Body.String()
	if !strings.Contains(body, "заблокирован автоматически: истёк срок") {
		t.Fatalf("нет пометки автоблокировки: %s", body)
	}
	if rec := post(e, c, "/clients/bob/block", url.Values{"csrf": {csrf}, "blocked": {"0"}}); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	card, _ := e.srv.Store.Card(ctx, store.LocalNode, "bob")
	if card.AutoBlock != "" || card.AutoSkip != fmt.Sprintf("expired:%d", until) {
		t.Fatalf("карточка: %+v", card)
	}
	// ручная блокировка клиента без метки карточку не трогает
	e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "wg-only"})
	post(e, c, "/clients/wg-only/block", url.Values{"csrf": {csrf}, "blocked": {"0"}})
	if card, _ := e.srv.Store.Card(ctx, store.LocalNode, "wg-only"); card.AutoSkip != "" {
		t.Fatalf("лишний отпечаток: %+v", card)
	}
}

func TestClientTrafficRangeAndTotals(t *testing.T) {
	e, c, _ := storeEnv(t)
	ctx := context.Background()
	e.srv.Store.AddTraffic(ctx, store.LocalNode, histNow.Add(-time.Hour).Unix(), map[string]store.Bytes{"bob": {Rx: 2 << 20, Tx: 3 << 20}})
	body := get(e, c, "/clients/bob?range=1d").Body.String()
	if !strings.Contains(body, "↓ 3.0 МБ, ↑ 2.0 МБ") {
		t.Fatalf("итоги: %s", body)
	}
	if body = get(e, c, "/clients/bob?range=что-то").Body.String(); !strings.Contains(body, "<b>1d</b>") {
		t.Fatal("неизвестный период должен давать 1d")
	}
	if body = get(e, c, "/clients/bob?range=30d").Body.String(); !strings.Contains(body, "<b>30d</b>") {
		t.Fatal("30d не выбран")
	}
}
