package panel

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

// I1: агент поставил блок, но вернул ошибку (тайм-аут на мьютексе) — блок не
// должен стать «ручным».
func TestCollectorBlockErrorAfterApplyStaysAuto(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	past := e.now.Add(-time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &past})
	e.node.SetBlockedFn = func(_ context.Context, name string, b bool) (nodeapi.Result, error) {
		e.blocks = append(e.blocks, fmt.Sprintf("%s:%v", name, b))
		if b {
			e.clients[0].Blocked = true // блок встал, но ответ потерян
			return nodeapi.Result{}, errors.New("context deadline exceeded")
		}
		e.clients[0].Blocked = false
		return nodeapi.Result{}, nil
	}
	if err := e.c.Tick(ctx); err == nil {
		t.Fatal("ошибка агента потерялась")
	}
	if c, _ := e.st.Card(ctx, store.LocalNode, "a"); c.AutoBlock != store.AutoBlockExpired {
		t.Fatalf("пометка потеряна: %+v", c)
	}
	e.advance(time.Minute)
	e.tick(t) // блок не считается ручным, повторно не ставится
	if len(e.blocks) != 1 {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	c, _ := e.st.Card(ctx, store.LocalNode, "a")
	future := e.now.Add(48 * time.Hour).Unix()
	c.AccessUntil = &future
	e.st.SaveCard(ctx, c)
	e.advance(time.Minute)
	e.tick(t)
	if len(e.blocks) != 2 || e.blocks[1] != "a:false" || e.clients[0].Blocked {
		t.Fatalf("после продления: %v, blocked=%v", e.blocks, e.clients[0].Blocked)
	}
}

// Агент вернул ошибку и блока нет — пометка откатывается.
func TestCollectorBlockErrorWithoutApplyRollsBackMark(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	past := e.now.Add(-time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &past})
	e.node.SetBlockedFn = func(context.Context, string, bool) (nodeapi.Result, error) {
		return nodeapi.Result{}, errors.New("агент недоступен")
	}
	if err := e.c.Tick(ctx); err == nil {
		t.Fatal("ошибка агента потерялась")
	}
	if c, _ := e.st.Card(ctx, store.LocalNode, "a"); c.AutoBlock != "" {
		t.Fatalf("пометка осталась: %+v", c)
	}
}

// I2: 31 октября, трафик 1 октября, history_days=30 — сумма не падает.
func TestCollectorMonthLimitSurvivesHistoryDays(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.now = time.Date(2026, 10, 1, 5, 0, 30, 0, time.UTC)
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", TrafficLimit: 1000, TrafficPeriod: store.PeriodMonth})
	e.st.AddTraffic(ctx, store.LocalNode, time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC).Unix(),
		map[string]store.Bytes{"a": {Rx: 600, Tx: 500}})
	e.tick(t)
	if len(e.blocks) != 1 {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	e.now = time.Date(2026, 10, 31, 12, 0, 30, 0, time.UTC)
	e.tick(t)
	if len(e.blocks) != 1 {
		t.Fatalf("блок снят посреди периода: %v", e.blocks)
	}
	tot, _ := e.st.TrafficTotals(ctx, store.LocalNode, periodStart(store.PeriodMonth, e.now).Unix(), e.now.Unix()+1)
	if tot["a"].Rx+tot["a"].Tx != 1100 {
		t.Fatalf("сумма = %v", tot)
	}
}

// M2: снятый вручную блок по сроку не выключает проверку трафика.
func TestCollectorTrafficCheckedWhenExpiredSkipped(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	until := e.now.Add(-time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &until, TrafficLimit: 1000,
		TrafficPeriod: store.PeriodMonth, AutoSkip: fmt.Sprintf("expired:%d", until)})
	e.st.AddTraffic(ctx, store.LocalNode, e.now.Add(-time.Hour).Unix(), map[string]store.Bytes{"a": {Rx: 600, Tx: 500}})
	e.tick(t)
	if c, _ := e.st.Card(ctx, store.LocalNode, "a"); len(e.blocks) != 1 || c.AutoBlock != store.AutoBlockTraffic {
		t.Fatalf("блокировки %v, карточка %+v", e.blocks, c)
	}
}

// M3: клиента только с WireGuard не автоблокируем, в журнал — раз в сутки.
func TestCollectorWGOnlySkippedLoggedOncePerDay(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	past := e.now.Add(-time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "w", WireGuard: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "w", AccessUntil: &past})
	for i := 0; i < 5; i++ {
		e.tick(t)
		e.advance(time.Minute)
	}
	if len(e.blocks) != 0 {
		t.Fatalf("WG-клиент заблокирован: %v", e.blocks)
	}
	list, _, _ := e.st.AuditList(ctx, 10, 0, "")
	if len(list) != 1 || !strings.Contains(list[0].After, "WireGuard появится позже") {
		t.Fatalf("журнал: %+v", list)
	}
	e.advance(25 * time.Hour)
	e.tick(t)
	if list, _, _ = e.st.AuditList(ctx, 10, 0, ""); len(list) != 2 {
		t.Fatalf("сутки спустя запись не повторена: %+v", list)
	}
}

// M5: сброс одного направления не удваивает другое.
func TestCollectorDeltaPerDirection(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	old := e.now.Add(-time.Hour)
	e.sessions = []nodeapi.Session{ovpn("a", "udp", old, 1000, 2000)}
	e.tick(t)
	e.advance(time.Minute)
	e.sessions = []nodeapi.Session{ovpn("a", "udp", old, 1100, 30)} // tx сброшен, rx растёт
	e.tick(t)
	tot, _ := e.st.TrafficTotals(ctx, store.LocalNode, 0, e.now.Unix()+1)
	if tot["a"] != (store.Bytes{Rx: 100, Tx: 30}) {
		t.Fatalf("итог = %+v", tot["a"])
	}
}

// M7: HistoryDays == 0 не стирает часовую историю.
func TestCollectorZeroHistoryDaysKeepsHours(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.c.HistoryDays = 0
	e.st.AddResource(ctx, store.LocalNode, store.ResourcePoint{TS: e.now.Add(-3 * time.Hour).Unix()})
	e.tick(t)
	pts, _ := e.st.ResourceSeries(ctx, store.LocalNode, 0, e.now.Unix()+1, store.Hour)
	if len(pts) == 0 {
		t.Fatal("часовая история стёрта")
	}
}

// I3: ручной блок поверх автоблока делает блок ручным.
func TestManualBlockOverAutoBlockBecomesManual(t *testing.T) {
	e, c, csrf := storeEnv(t)
	ctx := context.Background()
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true, Blocked: true}, {Name: "both", OpenVPN: true, WireGuard: true}}, nil
	}
	e.node.SetBlockedFn = func(context.Context, string, bool) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	until := histNow.Add(-time.Hour).Unix()
	e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "bob", AccessUntil: &until,
		AutoBlock: store.AutoBlockExpired, AutoSkip: "x"})
	if rec := post(e, c, "/clients/bob/block", url.Values{"csrf": {csrf}, "blocked": {"1"}}); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	card, _ := e.srv.Store.Card(ctx, store.LocalNode, "bob")
	if card.AutoBlock != "" || card.AutoSkip != "x" {
		t.Fatalf("карточка: %+v", card)
	}
	// у клиента с WireGuard в журнале оговорка
	post(e, c, "/clients/both/block", url.Values{"csrf": {csrf}, "blocked": {"1"}})
	list, _, _ := e.srv.Store.AuditList(ctx, 10, 0, "block")
	var both, bob string
	for _, x := range list {
		switch x.Target {
		case "both":
			both = x.After
		case "bob":
			bob = x.After
		}
	}
	if !strings.Contains(both, "только OpenVPN") || strings.Contains(bob, "только OpenVPN") {
		t.Fatalf("журнал: both=%q bob=%q", both, bob)
	}
}

// I4: новый клиент не наследует карточку и трафик прежнего владельца имени.
func TestCreateClientDropsStaleCard(t *testing.T) {
	e, c, csrf := storeEnv(t)
	ctx := context.Background()
	e.node.CreateClientFn = func(context.Context, nodeapi.CreateClient) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	past := histNow.Add(-time.Hour).Unix()
	for _, n := range []string{"ghost", "bob"} {
		e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: n, Note: "старая", AccessUntil: &past})
		e.srv.Store.AddTraffic(ctx, store.LocalNode, histNow.Unix(), map[string]store.Bytes{n: {Rx: 5}})
	}
	post(e, c, "/clients", url.Values{"csrf": {csrf}, "name": {"ghost"}, "kind": {"openvpn"}})
	if card, _ := e.srv.Store.Card(ctx, store.LocalNode, "ghost"); card.Note != "" || card.AccessUntil != nil {
		t.Fatalf("старая карточка осталась: %+v", card)
	}
	if tot, _ := e.srv.Store.TrafficTotals(ctx, store.LocalNode, 0, histNow.Unix()+60); tot["ghost"].Rx != 0 {
		t.Fatalf("старый трафик остался: %v", tot)
	}
	// bob у агента есть (добавляем второй тип) — ничего не трогаем
	post(e, c, "/clients", url.Values{"csrf": {csrf}, "name": {"bob"}, "kind": {"wireguard"}})
	if card, _ := e.srv.Store.Card(ctx, store.LocalNode, "bob"); card.Note != "старая" {
		t.Fatalf("карточка существующего клиента удалена: %+v", card)
	}
}

// M11, M12: огромный page не ломает страницу; время журнала в UTC с подписью.
func TestAuditPageHugePageAndUTC(t *testing.T) {
	e, c, _ := storeEnv(t)
	e.srv.Store.Audit(context.Background(), store.AuditEntry{TS: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Unix(),
		User: "admin", Action: "Вход"})
	rec := get(e, c, "/audit?page=9223372036854775807")
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	body := get(e, c, "/audit?q=%D0%B2%D1%85%D0%BE%D0%B4").Body.String()
	if !strings.Contains(body, "2026-01-02 03:04:05") || !strings.Contains(body, "Время (UTC)") || !strings.Contains(body, "<td>Вход</td>") {
		t.Fatalf("страница: %s", body)
	}
}
