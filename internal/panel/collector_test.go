package panel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

type collEnv struct {
	c        *Collector
	node     *fakeNode
	st       *store.Store
	now      time.Time
	sessions []nodeapi.Session
	clients  []nodeapi.Client
	blocks   []string // "имя:true/false"
}

func newCollEnv(t *testing.T) *collEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &collEnv{node: &fakeNode{}, st: st, now: time.Date(2026, 11, 4, 10, 0, 30, 0, time.UTC)} // среда
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return e.sessions, nil }
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return nodeapi.System{}, nil }
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) { return e.clients, nil }
	e.node.SetBlockedFn = func(_ context.Context, name string, b bool) (nodeapi.Result, error) {
		e.blocks = append(e.blocks, name+":"+map[bool]string{true: "true", false: "false"}[b])
		for i := range e.clients {
			if e.clients[i].Name == name {
				e.clients[i].Blocked = b
			}
		}
		return nodeapi.Result{}, nil
	}
	e.c = &Collector{Node: e.node, Store: st, NodeID: store.LocalNode, HistoryDays: 30,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return e.now }}
	return e
}

func (e *collEnv) tick(t *testing.T) {
	t.Helper()
	if err := e.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (e *collEnv) advance(d time.Duration) { e.now = e.now.Add(d) }

func ovpn(name, inst string, since time.Time, rx, tx int64) nodeapi.Session {
	return nodeapi.Session{Kind: nodeapi.KindOpenVPN, Instance: inst, Name: name, Since: &since, RxBytes: rx, TxBytes: tx}
}

func TestCollectorTrafficDeltas(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	old := e.now.Add(-time.Hour)
	e.sessions = []nodeapi.Session{ovpn("a", "udp", old, 1000, 2000), ovpn("a", "tcp", old, 500, 500)}
	e.tick(t) // базовая линия: ничего не записано
	if tot, _ := e.st.TrafficTotals(ctx, store.LocalNode, 0, e.now.Unix()+1); len(tot) != 0 {
		t.Fatalf("первый проход записал трафик: %v", tot)
	}
	e.advance(time.Minute)
	e.sessions = []nodeapi.Session{ovpn("a", "udp", old, 1100, 2300), ovpn("a", "tcp", old, 600, 700)}
	e.tick(t)
	e.advance(time.Minute)
	// udp: сброс счётчика — дельта равна новым значениям
	e.sessions = []nodeapi.Session{ovpn("a", "udp", old, 50, 60), ovpn("a", "tcp", old, 650, 700)}
	e.tick(t)
	tot, err := e.st.TrafficTotals(ctx, store.LocalNode, 0, e.now.Unix()+1)
	if err != nil {
		t.Fatal(err)
	}
	// проход 2: (100+100, 300+200); проход 3: (50+50, 60+0)
	want := store.Bytes{Rx: 300, Tx: 560}
	if tot["a"] != want {
		t.Fatalf("сумма = %+v, нужно %+v", tot["a"], want)
	}
	pts, _ := e.st.TrafficSeries(ctx, store.LocalNode, "a", 0, e.now.Unix()+1, store.Minute)
	if len(pts) != 2 || pts[0].Rx != 200 || pts[0].Tx != 500 {
		t.Fatalf("минуты = %+v", pts)
	}
}

func TestCollectorNewSessionCountsFull(t *testing.T) {
	e := newCollEnv(t)
	e.tick(t)
	e.advance(time.Minute)
	e.sessions = []nodeapi.Session{ovpn("b", "udp", e.now.Add(-10*time.Second), 70, 80)}
	e.tick(t)
	tot, _ := e.st.TrafficTotals(context.Background(), store.LocalNode, 0, e.now.Unix()+1)
	if tot["b"] != (store.Bytes{Rx: 70, Tx: 80}) {
		t.Fatalf("новая сессия: %+v", tot)
	}
}

func TestCollectorResourcesOnline(t *testing.T) {
	e := newCollEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) {
		var s nodeapi.System
		s.Resources.CPUPercent = 12.5
		s.Resources.Memory.TotalBytes = 1000
		s.Resources.Memory.AvailableBytes = 400
		return s, nil
	}
	e.sessions = []nodeapi.Session{ovpn("a", "udp", e.now.Add(-time.Hour), 1, 1), ovpn("b", "udp", e.now.Add(-time.Hour), 1, 1)}
	e.tick(t)
	pts, _ := e.st.ResourceSeries(context.Background(), store.LocalNode, 0, e.now.Unix()+1, store.Minute)
	if len(pts) != 1 || pts[0].CPU != 12.5 || pts[0].MemUsed != 600 || pts[0].Online != 2 {
		t.Fatalf("ресурсы = %+v", pts)
	}
}

func TestCollectorExpiredBlocksOnce(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	past := e.now.Add(-time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &past})
	e.tick(t)
	e.advance(time.Minute)
	e.tick(t)
	if len(e.blocks) != 1 || e.blocks[0] != "a:true" {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	c, _ := e.st.Card(ctx, store.LocalNode, "a")
	if c.AutoBlock != store.AutoBlockExpired {
		t.Fatalf("auto_block = %q", c.AutoBlock)
	}
	list, _, _ := e.st.AuditList(ctx, 10, 0, "")
	if len(list) != 1 || list[0].User != "система" || list[0].IP != "" || list[0].Target != "a" {
		t.Fatalf("журнал = %+v", list)
	}
	// срок продлён — разблокировка
	future := e.now.Add(24 * time.Hour).Unix()
	c.AccessUntil = &future
	e.st.SaveCard(ctx, c)
	e.advance(time.Minute)
	e.tick(t)
	if len(e.blocks) != 2 || e.blocks[1] != "a:false" {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	if c, _ = e.st.Card(ctx, store.LocalNode, "a"); c.AutoBlock != "" {
		t.Fatalf("auto_block = %q", c.AutoBlock)
	}
}

func TestCollectorManualBlockKept(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.clients = []nodeapi.Client{{Name: "m", OpenVPN: true, Blocked: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "m", Note: "x"})
	e.tick(t)
	e.tick(t)
	if len(e.blocks) != 0 {
		t.Fatalf("ручной блок тронут: %v", e.blocks)
	}
}

func TestCollectorAdminUnblockClearsMark(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	future := e.now.Add(time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true, Blocked: false}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &future, AutoBlock: store.AutoBlockExpired})
	e.tick(t)
	if len(e.blocks) != 0 {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	if c, _ := e.st.Card(ctx, store.LocalNode, "a"); c.AutoBlock != "" {
		t.Fatalf("auto_block = %q", c.AutoBlock)
	}
}

func TestCollectorTrafficLimitAndNewPeriod(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", TrafficLimit: 1000, TrafficPeriod: store.PeriodMonth})
	e.st.AddTraffic(ctx, store.LocalNode, e.now.Add(-time.Hour).Unix(), map[string]store.Bytes{"a": {Rx: 600, Tx: 500}})
	e.tick(t)
	if len(e.blocks) != 1 || e.blocks[0] != "a:true" {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	if c, _ := e.st.Card(ctx, store.LocalNode, "a"); c.AutoBlock != store.AutoBlockTraffic {
		t.Fatalf("auto_block = %q", c.AutoBlock)
	}
	e.advance(time.Minute)
	e.tick(t)
	if len(e.blocks) != 1 {
		t.Fatalf("повторный блок: %v", e.blocks)
	}
	e.now = time.Date(2026, 12, 1, 0, 5, 0, 0, time.UTC) // новый месяц
	e.tick(t)
	if len(e.blocks) != 2 || e.blocks[1] != "a:false" {
		t.Fatalf("блокировки = %v", e.blocks)
	}
}

func TestPeriodStart(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC) // среда
	for p, want := range map[string]time.Time{
		store.PeriodDay:   time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC),
		store.PeriodWeek:  time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
		store.PeriodMonth: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
	} {
		if got := periodStart(p, now); !got.Equal(want) {
			t.Errorf("%s: %v, нужно %v", p, got, want)
		}
	}
	sun := time.Date(2026, 11, 8, 23, 0, 0, 0, time.UTC)
	if got := periodStart(store.PeriodWeek, sun); got.Day() != 2 {
		t.Errorf("воскресенье: %v", got)
	}
}

func TestCollectorRollupOnHourChange(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.tick(t) // 10:00 — свёртка при запуске, базовая линия сессий
	hourStart := e.now.Truncate(time.Hour).Unix()
	e.advance(time.Minute)
	e.sessions = []nodeapi.Session{ovpn("a", "udp", e.now.Add(-10*time.Second), 100, 100)}
	e.tick(t) // новая сессия: трафик записан в минуту 10:01
	e.now = time.Date(2026, 11, 4, 11, 0, 10, 0, time.UTC)
	e.tick(t) // смена часа — свёртка
	pts, _ := e.st.TrafficSeries(ctx, store.LocalNode, "a", hourStart, hourStart+3600, store.Hour)
	if len(pts) != 1 || pts[0].Rx != 100 {
		t.Fatalf("часовые точки: %+v", pts)
	}
}

func TestCollectorFlapping(t *testing.T) {
	e := newCollEnv(t)
	wg := func(name, addr string) nodeapi.Session {
		return nodeapi.Session{Kind: nodeapi.KindWireGuard, Instance: "wg0", Name: name, Addr: addr}
	}
	for _, a := range []string{"1.1.1.1:1", "2.2.2.2:1", "3.3.3.3:1"} {
		e.sessions = []nodeapi.Session{wg("fl", a), wg("calm", "9.9.9.9:1")}
		e.tick(t)
		e.advance(time.Minute)
	}
	f := e.c.Flapping()
	if !f["fl"] || f["calm"] {
		t.Fatalf("Flapping = %v", f)
	}
	e.advance(10 * time.Minute)
	e.sessions = nil
	e.tick(t)
	if len(e.c.Flapping()) != 0 {
		t.Fatalf("метки не истекли: %v", e.c.Flapping())
	}
}

func TestCollectorStepErrorDoesNotStopOthers(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, errors.New("нет связи") }
	past := e.now.Add(-time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &past})
	if err := e.c.Tick(ctx); err == nil {
		t.Fatal("ожидалась ошибка шага")
	}
	if len(e.blocks) != 1 {
		t.Fatalf("автоблокировка не выполнена: %v", e.blocks)
	}
	if pts, _ := e.st.ResourceSeries(ctx, store.LocalNode, 0, e.now.Unix()+1, store.Minute); len(pts) != 1 {
		t.Fatalf("ресурсы не записаны: %v", pts)
	}
}

func TestCollectorManualUnblockSkipsSameReason(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	until := e.now.Add(-time.Hour).Unix()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	// админ снял автоблокировку истёкшего клиента: панель записала отпечаток
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", Note: "н", AccessUntil: &until,
		AutoSkip: fmt.Sprintf("expired:%d", until)})
	e.tick(t)
	e.advance(time.Minute)
	e.tick(t)
	if len(e.blocks) != 0 {
		t.Fatalf("клиент заблокирован снова: %v", e.blocks)
	}
	// продлили и срок снова истёк — другой отпечаток, блокировка
	again := e.now.Add(-time.Minute).Unix()
	c, _ := e.st.Card(ctx, store.LocalNode, "a")
	c.AccessUntil = &again
	e.st.SaveCard(ctx, c)
	e.tick(t)
	if len(e.blocks) != 1 || e.blocks[0] != "a:true" {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	if c, _ = e.st.Card(ctx, store.LocalNode, "a"); c.AutoBlock != store.AutoBlockExpired || c.Note != "н" {
		t.Fatalf("карточка = %+v", c)
	}
}

func TestCollectorManualUnblockSkipsTrafficUntilLimitChanges(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}}
	start := periodStart(store.PeriodMonth, e.now).Unix()
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", TrafficLimit: 1000, TrafficPeriod: store.PeriodMonth,
		AutoSkip: fmt.Sprintf("traffic:%d:%d", start, 1000)})
	e.st.AddTraffic(ctx, store.LocalNode, e.now.Add(-time.Hour).Unix(), map[string]store.Bytes{"a": {Rx: 600, Tx: 500}})
	e.tick(t)
	if len(e.blocks) != 0 {
		t.Fatalf("блокировки = %v", e.blocks)
	}
	c, _ := e.st.Card(ctx, store.LocalNode, "a")
	c.TrafficLimit = 1100 // лимит изменили, но и он исчерпан
	e.st.SaveCard(ctx, c)
	e.tick(t)
	if len(e.blocks) != 1 {
		t.Fatalf("блокировки = %v", e.blocks)
	}
}

func TestCollectorReleasesOwnerOfGoneClient(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	u, err := e.st.CreateUser(ctx, store.User{Login: "bob", Hash: "x", Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	e.clients = []nodeapi.Client{{Name: "alive", OpenVPN: true}, {Name: "gone", OpenVPN: true}}
	for _, n := range []string{"alive", "gone"} {
		if err := e.st.SetOwner(ctx, store.LocalNode, n, &u.ID); err != nil {
			t.Fatal(err)
		}
	}
	e.tick(t)
	e.clients = e.clients[:1] // «gone» удалён на сервере мимо панели
	e.advance(time.Minute)
	e.tick(t)
	if _, has, _ := e.st.OwnerOf(ctx, store.LocalNode, "gone"); !has {
		t.Fatal("владелец снят с первого же прохода")
	}
	// Клиент вернулся на проход — отсчёт начинается заново.
	e.clients = append(e.clients, nodeapi.Client{Name: "gone", OpenVPN: true})
	e.advance(time.Minute)
	e.tick(t)
	e.clients = e.clients[:1]
	e.advance(time.Minute)
	e.tick(t)
	if _, has, _ := e.st.OwnerOf(ctx, store.LocalNode, "gone"); !has {
		t.Fatal("владелец снят, хотя пропажа была не два прохода подряд")
	}
	e.advance(time.Minute)
	e.tick(t)
	if _, has, _ := e.st.OwnerOf(ctx, store.LocalNode, "gone"); has {
		t.Fatal("владелец пропавшего клиента не снят")
	}
	if _, has, _ := e.st.OwnerOf(ctx, store.LocalNode, "alive"); !has {
		t.Fatal("владелец живого клиента снят")
	}
	list, _, _ := e.st.AuditList(ctx, 20, 0, "owner_cleared")
	if len(list) != 1 || !strings.Contains(list[0].After, "клиент пропал") || list[0].Target != "gone" {
		t.Fatalf("журнал: %+v", list)
	}
}
