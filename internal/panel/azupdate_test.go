package panel

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

const (
	azOld = "1111111111111111111111111111111111111111"
	azNew = "2222222222222222222222222222222222222222"
)

func azBehindNode(n *svcNode) {
	n.AZVersionFn = func(context.Context) (nodeapi.AZVersion, error) {
		return nodeapi.AZVersion{
			Current: azOld, CurrentSource: "recorded",
			Latest: &nodeapi.AZCommit{SHA: azNew, Message: "Новая <b>версия</b>", Date: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)},
			Behind: []nodeapi.AZCommit{{SHA: azNew, Message: "Новая <b>версия</b>", Date: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)}},
		}, nil
	}
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return nodeapi.AZUpdateState{}, nil }
	n.AZPreflightFn = func(context.Context) (nodeapi.AZPreflight, error) {
		return nodeapi.AZPreflight{OK: false, Reasons: []string{"мало места в /root"}}, nil
	}
	n.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) {
		return []nodeapi.SetupEntry{
			{Key: "MTU", Title: "MTU", Value: "1400", Kind: "int", Apply: []string{nodeapi.ApplyReinstall}},
			{Key: "ROUTE_ALL", Value: "n", Kind: "yn", Apply: []string{nodeapi.ApplyDoall}, Editable: true},
		}, nil
	}
}

func TestAZPageShowsVersionPreflightAndEscapes(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	azBehindNode(n)
	rec := get(e, c, "/antizapret/update")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	b := rec.Body.String()
	for _, want := range []string{"1111111", "2222222", "Новая &lt;b&gt;версия&lt;/b&gt;", "2026-11-01 10:00 UTC", "мало места в /root", "name=\"v_MTU\"", "перезагрузит"} {
		if !strings.Contains(b, want) {
			t.Errorf("нет %q в странице", want)
		}
	}
	if strings.Contains(b, "<b>версия</b>") {
		t.Error("сообщение коммита не экранировано")
	}
	if strings.Contains(b, "v_ROUTE_ALL") {
		t.Error("ключ без reinstall показан среди переустановочных")
	}
	if !strings.Contains(b, `name="commit" value="`+azNew+`"`) {
		t.Error("страница не запоминает коммит, который показала")
	}
}

func TestAZPageNoSupport(t *testing.T) {
	e := newEnv(t, adminHash(t))
	c, _ := e.sessionCookie(t)
	if rec := get(e, c, "/antizapret/update"); rec.Code != 501 {
		t.Fatalf("узел без сервисов: %d", rec.Code)
	}
}

func TestAZStartNeedsConfirmAndPassesValues(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	azBehindNode(n)
	var got nodeapi.AZUpdateRequest
	n.AZUpdateFn = func(_ context.Context, req nodeapi.AZUpdateRequest) (nodeapi.AZUpdateState, error) {
		got = req
		return nodeapi.AZUpdateState{Status: nodeapi.AZStatusRunning, Phase: nodeapi.AZPhasePrepare, TaskID: "0123456789ab"}, nil
	}
	f := url.Values{"csrf": {csrf}, "commit": {azNew}, "v_MTU": {"1380"}}
	rec := post(e, c, "/antizapret/update", f)
	if rec.Code != 400 || n.called("AZUpdate") != 0 {
		t.Fatalf("без подтверждения: %d, вызовов %d", rec.Code, n.called("AZUpdate"))
	}
	f.Set("confirm", "1")
	rec = post(e, c, "/antizapret/update", f)
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), "/antizapret/update?msg=az_started") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got.Commit != azNew || len(got.Values) != 1 || got.Values["MTU"] != "1380" {
		t.Fatalf("запрос агенту: %+v", got)
	}
	if !e.srv.az.running() {
		t.Error("панель не запомнила, что обновление идёт")
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "az_update")
	if len(list) != 1 || !strings.Contains(list[0].After, "MTU=1380") {
		t.Fatalf("журнал действий: %+v", list)
	}
}

func TestAZStartRejectsBadCommitAndShowsAgentRefusal(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	azBehindNode(n)
	n.AZUpdateFn = func(context.Context, nodeapi.AZUpdateRequest) (nodeapi.AZUpdateState, error) {
		return nodeapi.AZUpdateState{}, &nodeapi.Error{Status: 422, Message: "мало места; идёт apt"}
	}
	rec := post(e, c, "/antizapret/update", url.Values{"csrf": {csrf}, "confirm": {"1"}, "commit": {"abc"}})
	if rec.Code != 400 || n.called("AZUpdate") != 0 {
		t.Fatalf("плохой коммит: %d", rec.Code)
	}
	rec = post(e, c, "/antizapret/update", url.Values{"csrf": {csrf}, "confirm": {"1"}})
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "мало места; идёт apt") {
		t.Fatalf("отказ проверок: %d %s", rec.Code, rec.Body)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "az_update")
	if len(list) != 1 || !strings.Contains(list[0].After, "отказ (422)") {
		t.Fatalf("отказ не в журнале: %+v", list)
	}
}

func TestAZRebootShownAsRebootNotRefusal(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	calls := 0
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) {
		calls++
		if calls == 1 {
			return nodeapi.AZUpdateState{Action: "update", Status: nodeapi.AZStatusRunning, Phase: nodeapi.AZPhaseReboot, Commit: azNew, Started: time.Now()}, nil
		}
		return nodeapi.AZUpdateState{}, errNotSetNet
	}
	rec := get(e, c, "/antizapret/update")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "перезагружается") || !strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("running: %d %s", rec.Code, rec.Body)
	}
	rec = get(e, c, "/antizapret/update")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Сервер перезагружается") {
		t.Fatalf("после обрыва связи: %d %s", rec.Code, rec.Body)
	}
	// связь вернулась с итогом — режим «перезагрузка» кончился
	azBehindNode(n)
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) {
		fin := time.Now()
		return nodeapi.AZUpdateState{Action: "update", Status: nodeapi.AZStatusFailed, Commit: azNew, Started: time.Now(), Finished: &fin,
			Reasons: []string{"пропал клиент bob"}, CanRestore: true, Backup: "backup-azpanel-1.tar.gz",
			Backups: []nodeapi.AZBackup{{Name: "backup-azpanel-1.tar.gz", Bytes: 2048, Time: time.Now()}}}, nil
	}
	rec = get(e, c, "/antizapret/update")
	b := rec.Body.String()
	if strings.Contains(b, "Сервер перезагружается") || !strings.Contains(b, "пропал клиент bob") || !strings.Contains(b, "Восстановить из бэкапа") {
		t.Fatalf("итог failed: %s", b)
	}
}

func TestAZRestoreOnlyListedBackupWithConfirm(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	var restored string
	n.AZRestoreFn = func(_ context.Context, name string) (nodeapi.AZUpdateState, error) {
		restored = name
		return nodeapi.AZUpdateState{Status: nodeapi.AZStatusRunning, Action: "restore", TaskID: "0123456789ab"}, nil
	}
	azBehindNode(n)
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) {
		return nodeapi.AZUpdateState{Backups: []nodeapi.AZBackup{{Name: "backup-azpanel-1.tar.gz"}}}, nil
	}
	f := url.Values{"csrf": {csrf}, "backup": {"backup-azpanel-1.tar.gz"}}
	if rec := post(e, c, "/antizapret/update/restore", f); rec.Code != 400 || restored != "" {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	f.Set("confirm", "1")
	f.Set("backup", "../../etc/passwd")
	if rec := post(e, c, "/antizapret/update/restore", f); rec.Code != 400 || restored != "" {
		t.Fatalf("чужое имя: %d", rec.Code)
	}
	f.Set("backup", "backup-azpanel-1.tar.gz")
	rec := post(e, c, "/antizapret/update/restore", f)
	if rec.Code != 303 || restored != "backup-azpanel-1.tar.gz" {
		t.Fatalf("%d %q", rec.Code, restored)
	}
}

func TestAZRoutesAdminOnly(t *testing.T) {
	e, _, _, _ := svcEnv(t)
	for _, p := range []string{"GET /antizapret/update", "POST /antizapret/update", "POST /antizapret/update/restore"} {
		if routes[p] != accAdmin {
			t.Errorf("%s не только для администратора", p)
		}
	}
	_ = e
}

// failedLateState — установка прервалась: VPN не работает.
func failedLateState(retry, restore bool) nodeapi.AZUpdateState {
	fin := time.Now()
	return nodeapi.AZUpdateState{Action: "update", Status: nodeapi.AZStatusFailedLate, Commit: azNew, Started: time.Now(), Finished: &fin,
		Reasons: []string{"setup.sh завершился с кодом 1"}, CanRetry: retry, CanRestore: restore, Backup: "backup-azpanel-1.tar.gz",
		Backups: []nodeapi.AZBackup{{Name: "backup-azpanel-1.tar.gz", Bytes: 2048, Time: time.Now()}}}
}

func TestAZPageFailedLateShowsButtonsByFlags(t *testing.T) {
	const (
		retryBtn   = "Повторить установку с сохранённым бэкапом"
		restoreBtn = `name="backup" value="backup-azpanel-1.tar.gz"`
	)
	for _, tc := range []struct {
		name            string
		retry, restore  bool
		wantRetry, want bool
	}{
		{"оба", true, true, true, true},
		{"только повтор", true, false, true, false},
		{"только восстановление", false, true, false, true},
		{"ни одной", false, false, false, false},
	} {
		e, n, c, _ := svcEnv(t)
		azBehindNode(n)
		st := failedLateState(tc.retry, tc.restore)
		n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return st, nil }
		b := get(e, c, "/antizapret/update").Body.String()
		if !strings.Contains(b, "VPN не работает, установка прервалась") {
			t.Errorf("%s: нет заголовка failed_late", tc.name)
		}
		if got := strings.Contains(b, retryBtn); got != tc.wantRetry {
			t.Errorf("%s: кнопка повтора = %v", tc.name, got)
		}
		// форма восстановления в карточке состояния (до списка бэкапов)
		card := b[:strings.Index(b, "Бэкапы на узле")]
		if got := strings.Contains(card, restoreBtn); got != tc.want {
			t.Errorf("%s: кнопка восстановления в карточке = %v", tc.name, got)
		}
	}
}

// Обычный failed — без кнопок повтора и восстановления в карточке состояния.
func TestAZPageFailedPlainHasNoStateButtons(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	azBehindNode(n)
	st := failedLateState(true, true)
	st.Status = nodeapi.AZStatusFailed
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return st, nil }
	b := get(e, c, "/antizapret/update").Body.String()
	if strings.Contains(b, "Повторить установку") || strings.Contains(b, "VPN не работает") {
		t.Fatal("у обычного failed показаны кнопки или заголовок failed_late")
	}
	card := b[:strings.Index(b, "Бэкапы на узле")]
	if strings.Contains(card, `name="backup"`) {
		t.Fatal("в карточке failed есть форма восстановления")
	}
}

func TestAZRetryNeedsConfirmAndFreshState(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	azBehindNode(n)
	retried := 0
	n.AZRetryFn = func(context.Context) (nodeapi.AZUpdateState, error) {
		retried++
		return nodeapi.AZUpdateState{Status: nodeapi.AZStatusRunning, Action: "update", Phase: nodeapi.AZPhasePrepare, TaskID: "0123456789ab"}, nil
	}
	late := failedLateState(true, true)
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return late, nil }
	f := url.Values{"csrf": {csrf}}
	if rec := post(e, c, "/antizapret/update/retry", f); rec.Code != 400 || retried != 0 {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	f.Set("confirm", "1")
	// страница устарела: повторять уже нечего
	stale := failedLateState(false, true)
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return stale, nil }
	if rec := post(e, c, "/antizapret/update/retry", f); rec.Code != 409 || retried != 0 {
		t.Fatalf("нечего повторять: %d", rec.Code)
	}
	plain := failedLateState(true, true)
	plain.Status = nodeapi.AZStatusFailed
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return plain, nil }
	if rec := post(e, c, "/antizapret/update/retry", f); rec.Code != 409 || retried != 0 {
		t.Fatalf("обычный failed: %d", rec.Code)
	}
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return late, nil }
	rec := post(e, c, "/antizapret/update/retry", f)
	if rec.Code != 303 || retried != 1 || !strings.Contains(rec.Header().Get("Location"), "msg=az_retry_started") {
		t.Fatalf("%d %q retried=%d", rec.Code, rec.Header().Get("Location"), retried)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "az_retry")
	if len(list) != 1 || list[0].Target != "backup-azpanel-1.tar.gz" {
		t.Fatalf("журнал: %+v", list)
	}
}

func TestAZRetryAgentRefusalShown(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	azBehindNode(n)
	late := failedLateState(true, true)
	n.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) { return late, nil }
	n.AZRetryFn = func(context.Context) (nodeapi.AZUpdateState, error) {
		return nodeapi.AZUpdateState{}, &nodeapi.Error{Status: 409, Message: "идёт другая задача"}
	}
	rec := post(e, c, "/antizapret/update/retry", url.Values{"csrf": {csrf}, "confirm": {"1"}})
	if rec.Code == 303 || !strings.Contains(rec.Body.String(), "идёт другая задача") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
