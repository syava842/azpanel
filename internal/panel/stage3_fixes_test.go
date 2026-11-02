package panel

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// testSHA — отпечаток в формах «Целиком» тестов, где его значение не важно.
var testSHA = strings.Repeat("a", 64)

// I3: значение вне вариантов показывается выбранным пунктом, и форма с другим
// изменённым ключом не отправляет агенту этот.
func TestSetupNonStandardValueKeptAndNotSent(t *testing.T) {
	e, c := routingEnv(t)
	entries := []nodeapi.SetupEntry{
		{Key: "TORRENT_GUARD", Value: "Y", Kind: "yn", Apply: []string{"restart"}, Title: "Защита от торрентов", Editable: true, Present: true},
		{Key: "VPN_WARP", Value: "4", Kind: "enum", Options: []string{"1", "2", "3", "n"}, Apply: []string{"doall"}, Title: "WARP", Editable: true, Present: true},
		{Key: "SSH_PROTECTION", Value: "y", Kind: "yn", Apply: []string{"restart"}, Title: "SSH", Editable: true, Present: true},
		{Key: "ROUTE_ALL", Value: "", Kind: "yn", Apply: []string{"doall"}, Title: "Всё через VPN", Editable: true, Present: false},
	}
	e.node.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) { return entries, nil }
	body := get(e, c, "/settings/antizapret").Body.String()
	for _, want := range []string{
		`<option value="Y" selected>Y (нестандартное)</option>`,
		`<option value="4" selected>4 (нестандартное)</option>`,
		`<option value="" selected></option>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q в %s", want, body)
		}
	}
	if strings.Contains(body, `name="v_TORRENT_GUARD"><option value="y" selected>`) {
		t.Error("за человека выбран вариант y")
	}

	// Браузер отправляет все выбранные пункты; изменён только SSH_PROTECTION.
	var sent map[string]string
	e.node.SetSetupFn = func(_ context.Context, v map[string]string) (nodeapi.SetupResult, error) {
		sent = v
		return nodeapi.SetupResult{Changed: []string{"SSH_PROTECTION"}, Apply: []string{"restart"}}, nil
	}
	rec := post(e, c, "/settings/antizapret", url.Values{"csrf": {csrfOf(t, e, c)},
		"v_TORRENT_GUARD": {"Y"}, "v_VPN_WARP": {"4"}, "v_SSH_PROTECTION": {"n"}, "v_ROUTE_ALL": {""}})
	if rec.Code != 303 || len(sent) != 1 || sent["SSH_PROTECTION"] != "n" {
		t.Fatalf("%d, агент получил %v", rec.Code, sent)
	}
}

// I4: «Целиком» показывает файл как есть (с комментариями), форма несёт
// отпечаток и возвращает его агенту.
func TestFullTabUsesRawAndSendsBaseSHA(t *testing.T) {
	e, c := routingEnv(t)
	raw := "# заметка\n\nexample.com\n"
	sum := strings.Repeat("b", 64)
	e.node.RoutingRawFn = func(_ context.Context, name string) (nodeapi.RoutingRaw, error) {
		return nodeapi.RoutingRaw{Name: name, Content: raw, SHA256: sum}, nil
	}
	body := get(e, c, "/routing/files/include-hosts.txt?tab=full").Body.String()
	if !strings.Contains(body, "# заметка") || !strings.Contains(body, `name="base_sha256" value="`+sum+`"`) {
		t.Fatalf("нет комментария или отпечатка: %s", body)
	}
	var gotSHA, gotText string
	e.node.ReplaceRoutingFn = func(_ context.Context, _, text, sha string) (nodeapi.RoutingPutResult, error) {
		gotText, gotSHA = text, sha
		return nodeapi.RoutingPutResult{Applied: true, Lines: 1}, nil
	}
	csrf := csrfOf(t, e, c)
	rec := post(e, c, "/routing/files/include-hosts.txt/replace", url.Values{"csrf": {csrf}, "base_sha256": {sum}, "content": {"# заметка\r\n\r\nexample.com\r\n"}})
	if rec.Code != 303 || gotSHA != sum || gotText != raw {
		t.Fatalf("%d sha=%q text=%q", rec.Code, gotSHA, gotText)
	}
	// Без отпечатка или с мусором вместо него запрос до агента не доходит.
	gotSHA = "не вызывался"
	for _, bad := range []string{"", "xyz", strings.Repeat("A", 64)} {
		rec = post(e, c, "/routing/files/include-hosts.txt/replace", url.Values{"csrf": {csrf}, "base_sha256": {bad}, "content": {"x.example.com\n"}})
		if rec.Code != 400 || gotSHA != "не вызывался" {
			t.Errorf("base_sha256=%q: %d, агент вызван: %q", bad, rec.Code, gotSHA)
		}
	}
	// 409 от агента: текст и отпечаток остаются в форме, отказ — в журнале.
	e.node.ReplaceRoutingFn = func(context.Context, string, string, string) (nodeapi.RoutingPutResult, error) {
		return nodeapi.RoutingPutResult{}, &nodeapi.Error{Status: 409, Message: "файл изменился с момента открытия"}
	}
	rec = post(e, c, "/routing/files/include-hosts.txt/replace", url.Values{"csrf": {csrf}, "base_sha256": {sum}, "content": {"мой текст\n"}})
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "файл изменился") || !strings.Contains(rec.Body.String(), "мой текст") ||
		!strings.Contains(rec.Body.String(), `value="`+sum+`"`) {
		t.Fatalf("конфликт: %d %s", rec.Code, rec.Body)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "routing_replace")
	var refused int
	for _, a := range list {
		if strings.Contains(a.After, "отказ (409)") {
			refused++
		}
	}
	if refused != 1 {
		t.Errorf("отказ 409 в журнале: %d, записи %+v", refused, list)
	}
}

// M3: повтор уже имеющейся строки и удаление отсутствующей — не ошибка.
func TestRoutingNothingChangedIsNotAnError(t *testing.T) {
	e, c := routingEnv(t)
	csrf := csrfOf(t, e, c)
	e.node.PatchRoutingFn = func(context.Context, string, nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		return nodeapi.RoutingPatchResult{Applied: false, Skipped: 2}, nil
	}
	for _, f := range []struct{ path, field string }{
		{"/routing/files/include-hosts.txt/add", "lines"},
		{"/routing/files/include-hosts.txt/remove", "del"},
	} {
		rec := post(e, c, f.path, url.Values{"csrf": {csrf}, f.field: {"a.example.com"}})
		loc := rec.Header().Get("Location")
		if rec.Code != 303 || !strings.Contains(loc, "msg=routing_nochange") || !strings.Contains(loc, "n=2") {
			t.Fatalf("%s: %d %q", f.path, rec.Code, loc)
		}
		page := get(e, c, loc).Body.String()
		if !strings.Contains(page, "ничего не изменилось") || strings.Contains(page, "агент не применил") {
			t.Errorf("%s: уведомление: %s", f.path, page)
		}
	}
	// Настоящая ошибка строки остаётся ошибкой.
	e.node.PatchRoutingFn = func(context.Context, string, nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		return nodeapi.RoutingPatchResult{Errors: []nodeapi.RoutingLineError{{Line: 1, Value: "bad", Reason: "плохо"}}}, nil
	}
	if rec := post(e, c, "/routing/files/include-hosts.txt/add", url.Values{"csrf": {csrf}, "lines": {"bad"}}); rec.Code != 400 {
		t.Errorf("ошибка строки: %d", rec.Code)
	}
}

// I2/M7: 409 при идущей задаче показывается человеком и пишется в журнал.
func TestRoutingBusyConflictAudited(t *testing.T) {
	e, c := routingEnv(t)
	e.node.PatchRoutingFn = func(context.Context, string, nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		return nodeapi.RoutingPatchResult{}, &nodeapi.Error{Status: 409, Message: "идёт задача doall (применение списков) — дождитесь её окончания и повторите"}
	}
	rec := post(e, c, "/routing/files/include-hosts.txt/add", url.Values{"csrf": {csrfOf(t, e, c)}, "lines": {"a.example.com"}})
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "идёт задача doall") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "routing_add")
	if len(list) != 1 || !strings.Contains(list[0].After, "отказ (409)") {
		t.Errorf("журнал: %+v", list)
	}
}

func TestTaskStartRefusalAudited(t *testing.T) {
	e, c := routingEnv(t)
	e.node.RestartAntiZapretFn = func(context.Context) (nodeapi.Task, error) {
		return nodeapi.Task{}, &nodeapi.Error{Status: 409, Message: "уже идёт задача doall (0123456789ab)"}
	}
	post(e, c, "/tasks/start", url.Values{"csrf": {csrfOf(t, e, c)}, "kind": {"restart"}})
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "task_start")
	if len(list) != 1 || list[0].Target != "restart" || !strings.Contains(list[0].After, "отказ (409)") {
		t.Errorf("журнал: %+v", list)
	}
}

// M6: остановленная по пределу задача показывается отдельным итогом.
func TestTaskRowTimedOut(t *testing.T) {
	now := time.Now()
	row := newTaskRow(nodeapi.Task{ID: "aaaaaaaaaaaa", Kind: "doall", Started: now, Finished: &now, TimedOut: true})
	if !row.Failure || row.Status != "остановлена по пределу времени" || row.Running {
		t.Fatalf("%+v", row)
	}
}
