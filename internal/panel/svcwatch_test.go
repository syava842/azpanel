package panel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/update"
)

func watchEnv(t *testing.T) (*Watcher, *svcNode, *testEnv) {
	t.Helper()
	e := newEnv(t, adminHash(t))
	n := &svcNode{fakeNode: e.node}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	w := &Watcher{Node: n, Store: e.st, Alerts: &config.Telegram{Enabled: true, Notify: config.TelegramNotifyKinds},
		Now: func() time.Time { return now }}
	return w, n, e
}

func outboxTexts(t *testing.T, e *testEnv) (kinds, texts []string) {
	t.Helper()
	items, err := e.st.Pending(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		kinds = append(kinds, it.Kind)
		texts = append(texts, it.Payload)
	}
	return
}

func TestWatcherAZVersionDailyOncePerCommit(t *testing.T) {
	w, n, e := watchEnv(t)
	now := w.Now()
	calls := 0
	n.AZVersionFn = func(context.Context) (nodeapi.AZVersion, error) {
		calls++
		return nodeapi.AZVersion{Current: azOld, Latest: &nodeapi.AZCommit{SHA: azNew},
			Behind: []nodeapi.AZCommit{{SHA: azNew, Message: "Правка маршрутов"}}}, nil
	}
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return nodeapi.AZUpdateState{}, nil }
	n.UpdateResultFn = func(context.Context) (*update.Result, error) { return nil, nil }
	w.Tick(context.Background())
	kinds, texts := outboxTexts(t, e)
	if len(kinds) != 1 || kinds[0] != "antizapret_update" || !strings.Contains(texts[0], "Правка маршрутов") || !strings.Contains(texts[0], "2222222") {
		t.Fatalf("первый проход: %v %v", kinds, texts)
	}
	w.Tick(context.Background()) // тот же день: даже не спрашиваем
	if calls != 1 {
		t.Fatalf("версию спросили %d раз за сутки", calls)
	}
	later := now.Add(25 * time.Hour)
	w.Now = func() time.Time { return later }
	w.Tick(context.Background()) // следующие сутки, тот же коммит: уведомления нет
	if calls != 2 {
		t.Fatalf("через сутки не спросили: %d", calls)
	}
	if kinds, _ := outboxTexts(t, e); len(kinds) != 1 {
		t.Fatalf("повторное уведомление о том же коммите: %v", kinds)
	}
}

func TestWatcherAZVersionUnknownOrOffIsSilent(t *testing.T) {
	w, n, e := watchEnv(t)
	n.AZVersionFn = func(context.Context) (nodeapi.AZVersion, error) {
		return nodeapi.AZVersion{Latest: &nodeapi.AZCommit{SHA: azNew}, Behind: []nodeapi.AZCommit{{SHA: azNew}}, Message: "версия неизвестна"}, nil
	}
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return nodeapi.AZUpdateState{}, nil }
	n.UpdateResultFn = func(context.Context) (*update.Result, error) { return nil, nil }
	w.Tick(context.Background())
	if kinds, _ := outboxTexts(t, e); len(kinds) != 0 {
		t.Fatalf("неизвестная версия дала уведомление: %v", kinds)
	}
	// вид выключен — в outbox не попадает
	n.AZVersionFn = func(context.Context) (nodeapi.AZVersion, error) {
		return nodeapi.AZVersion{Current: azOld, Latest: &nodeapi.AZCommit{SHA: azNew}, Behind: []nodeapi.AZCommit{{SHA: azNew}}}, nil
	}
	w.Alerts = &config.Telegram{Enabled: true, Notify: []string{"node_down"}}
	e.st.ClearMeta(context.Background(), metaAZChecked)
	w.Tick(context.Background())
	if kinds, _ := outboxTexts(t, e); len(kinds) != 0 {
		t.Fatalf("выключенный вид попал в очередь: %v", kinds)
	}
}

func TestWatcherAZResultOncePerRun(t *testing.T) {
	w, n, e := watchEnv(t)
	fin := w.Now().Add(-time.Hour)
	st := nodeapi.AZUpdateState{Action: "update", Status: nodeapi.AZStatusFailed, Started: fin.Add(-20 * time.Minute), Finished: &fin,
		Reasons: []string{"пропал клиент bob"}, CanRestore: true}
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return st, nil }
	n.AZVersionFn = func(context.Context) (nodeapi.AZVersion, error) {
		return nodeapi.AZVersion{UpToDate: true, Current: azOld}, nil
	}
	n.UpdateResultFn = func(context.Context) (*update.Result, error) { return nil, nil }
	w.Tick(context.Background())
	w.Tick(context.Background())
	kinds, texts := outboxTexts(t, e)
	if len(kinds) != 1 || kinds[0] != "update_result" || !strings.Contains(texts[0], "пропал клиент bob") || !strings.Contains(texts[0], "восстановить") {
		t.Fatalf("%v %v", kinds, texts)
	}
	// агент недоступен (перезагрузка) — тишина, без ошибок
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return nodeapi.AZUpdateState{}, errNotSetNet }
	w.Tick(context.Background())
	// итог старше 48 часов не пересказывается
	e.st.ClearMeta(context.Background(), metaAZResult)
	old := w.Now().Add(-72 * time.Hour)
	st.Finished = &old
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return st, nil }
	w.Tick(context.Background())
	if kinds, _ := outboxTexts(t, e); len(kinds) != 1 {
		t.Fatalf("старый итог пересказан: %v", kinds)
	}
}

func TestWatcherSelfResult(t *testing.T) {
	w, n, e := watchEnv(t)
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return nodeapi.AZUpdateState{}, nil }
	n.AZVersionFn = func(context.Context) (nodeapi.AZVersion, error) {
		return nodeapi.AZVersion{UpToDate: true, Current: azOld}, nil
	}
	n.UpdateResultFn = func(context.Context) (*update.Result, error) {
		return &update.Result{OK: false, From: "0.9.0", To: "0.9.1", Reason: "healthz не ответил", Time: w.Now().Add(-time.Minute)}, nil
	}
	w.Tick(context.Background())
	w.Tick(context.Background())
	kinds, texts := outboxTexts(t, e)
	if len(kinds) != 1 || kinds[0] != "update_result" || !strings.Contains(texts[0], "откачено") || !strings.Contains(texts[0], "healthz не ответил") {
		t.Fatalf("%v %v", kinds, texts)
	}
}

func TestWatcherAZResultFailedLate(t *testing.T) {
	w, n, e := watchEnv(t)
	fin := w.Now().Add(-time.Hour)
	st := nodeapi.AZUpdateState{Action: "update", Status: nodeapi.AZStatusFailedLate, Started: fin.Add(-20 * time.Minute), Finished: &fin,
		Reasons: []string{"setup.sh завершился с кодом 1"}, CanRetry: true, CanRestore: true}
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return st, nil }
	n.AZVersionFn = func(context.Context) (nodeapi.AZVersion, error) {
		return nodeapi.AZVersion{UpToDate: true, Current: azOld}, nil
	}
	n.UpdateResultFn = func(context.Context) (*update.Result, error) { return nil, nil }
	w.Tick(context.Background())
	w.Tick(context.Background())
	kinds, texts := outboxTexts(t, e)
	if len(kinds) != 1 || kinds[0] != "update_result" {
		t.Fatalf("%v %v", kinds, texts)
	}
	for _, want := range []string{"VPN на сервере не работает", "setup.sh завершился с кодом 1", "повторить установку с сохранённым бэкапом", "восстановить из бэкапа"} {
		if !strings.Contains(texts[0], want) {
			t.Errorf("в уведомлении нет %q: %s", want, texts[0])
		}
	}
}
