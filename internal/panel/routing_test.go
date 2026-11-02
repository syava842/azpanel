package panel

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

func routingEnv(t *testing.T) (*testEnv, *http.Cookie) {
	t.Helper()
	e := newEnv(t, adminHash(t))
	e.node.RoutingFilesFn = func(context.Context) ([]nodeapi.RoutingFile, error) {
		return []nodeapi.RoutingFile{
			{Name: "include-hosts.txt", Kind: "hosts", Title: "Свои домены", Lines: 2, Bytes: 40},
			{Name: "big-hosts.txt", Kind: "hosts", Title: "Большой", Lines: 300000, Bytes: 7 << 20},
			{Name: "readme.txt", Title: "Прочее", Lines: 1, Bytes: 5},
		}, nil
	}
	e.node.RoutingLinesFn = func(_ context.Context, name string, o nodeapi.RoutingListOpts) (nodeapi.RoutingPage, error) {
		return nodeapi.RoutingPage{Name: name, Lines: []string{"a.example.com", "b.example.com"}, Total: 2, Limit: o.Limit}, nil
	}
	e.node.RoutingBackupsFn = func(context.Context, string) ([]nodeapi.RoutingBackup, error) {
		return []nodeapi.RoutingBackup{{Stamp: "20261102T101500.123Z", Bytes: 30}}, nil
	}
	c, _ := e.sessionCookie(t)
	return e, c
}

func csrfOf(t *testing.T, e *testEnv, c *http.Cookie) string {
	t.Helper()
	s, ok := e.lookup(c.Value)
	if !ok {
		t.Fatal("нет сессии")
	}
	return s.CSRF
}

func TestRoutingListAndApplyButtons(t *testing.T) {
	e, c := routingEnv(t)
	rec := get(e, c, "/routing")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "include-hosts.txt") || !strings.Contains(body, "Применить (doall.sh)") ||
		!strings.Contains(body, "Обновить списки сейчас") || !strings.Contains(body, "300000") {
		t.Fatalf("%d %s", rec.Code, body)
	}
}

func TestRoutingFileShowsLinesBackupsAndFullTab(t *testing.T) {
	e, c := routingEnv(t)
	body := get(e, c, "/routing/files/include-hosts.txt").Body.String()
	for _, want := range []string{"a.example.com", `name="del"`, "2026-11-02 10:15 UTC", "Вернуть", "Целиком", "Добавить"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	// большой файл: вкладки «Целиком» нет
	big := get(e, c, "/routing/files/big-hosts.txt").Body.String()
	if strings.Contains(big, "?tab=full") {
		t.Error("у файла больше 1 МБ есть вкладка «Целиком»")
	}
	// файл вне видов — только чтение
	ro := get(e, c, "/routing/files/readme.txt").Body.String()
	if strings.Contains(ro, `name="del"`) || strings.Contains(ro, "/add") {
		t.Error("у файла только для чтения есть правка")
	}
	if code := get(e, c, "/routing/files/..%2Fsetup").Code; code != 404 {
		t.Errorf("чужое имя: %d", code)
	}
	if code := get(e, c, "/routing/files/nope.txt").Code; code != 404 {
		t.Errorf("нет такого списка: %d", code)
	}
}

func TestRoutingFileSearchAndPaging(t *testing.T) {
	e, c := routingEnv(t)
	var got nodeapi.RoutingListOpts
	e.node.RoutingLinesFn = func(_ context.Context, name string, o nodeapi.RoutingListOpts) (nodeapi.RoutingPage, error) {
		got = o
		return nodeapi.RoutingPage{Name: name, Lines: []string{"x.example.com"}, Total: 450}, nil
	}
	body := get(e, c, "/routing/files/include-hosts.txt?q=exa&page=2").Body.String()
	if got.Query != "exa" || got.Offset != 200 || got.Limit != 200 {
		t.Fatalf("параметры агенту: %+v", got)
	}
	if !strings.Contains(body, "page=1") || !strings.Contains(body, "page=3") {
		t.Errorf("нет ссылок страниц: %s", body)
	}
}

func TestRoutingAddSendsLinesToAgent(t *testing.T) {
	e, c := routingEnv(t)
	var patch nodeapi.RoutingPatch
	e.node.PatchRoutingFn = func(_ context.Context, name string, p nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		patch = p
		return nodeapi.RoutingPatchResult{Applied: true, Added: 2}, nil
	}
	rec := post(e, c, "/routing/files/include-hosts.txt/add", url.Values{
		"csrf": {csrfOf(t, e, c)}, "lines": {"one.example.com\r\n\r\n two.example.com \r\n"}})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "msg=routing_changed") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	if strings.Join(patch.Add, "|") != "one.example.com|two.example.com" || len(patch.Remove) != 0 {
		t.Fatalf("агент получил %+v", patch)
	}
	// плашка «вступят в силу после применения» с кнопкой
	page := get(e, c, rec.Header().Get("Location")).Body.String()
	if !strings.Contains(page, "вступят в силу после применения") || !strings.Contains(page, `value="doall"`) {
		t.Errorf("нет плашки применения: %s", page)
	}
	// журнал действий
	list, _, err := e.st.AuditList(context.Background(), 10, 0, "routing_add")
	if err != nil || len(list) != 1 || list[0].Target != "include-hosts.txt" {
		t.Errorf("журнал: %v %+v", err, list)
	}
}

// Агент отвечает на ошибки строк кодом 200 и applied=false: панель обязана
// показать ошибки и не говорить «изменено».
func TestRoutingAddShowsLineErrors(t *testing.T) {
	e, c := routingEnv(t)
	e.node.PatchRoutingFn = func(context.Context, string, nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		return nodeapi.RoutingPatchResult{Applied: false, Errors: []nodeapi.RoutingLineError{
			{Line: 2, Value: "bad_host", Reason: "недопустимый символ"}}}, nil
	}
	rec := post(e, c, "/routing/files/include-hosts.txt/add", url.Values{
		"csrf": {csrfOf(t, e, c)}, "lines": {"ok.example.com\n\nbad_host\n"}})
	body := rec.Body.String()
	if rec.Code != 400 {
		t.Fatalf("код %d", rec.Code)
	}
	// агент считал по присланным строкам (2-я = bad_host), в поле это строка 3
	if !strings.Contains(body, "строка 3: bad_host — недопустимый символ") {
		t.Errorf("нет построчной ошибки: %s", body)
	}
	if !strings.Contains(body, "ok.example.com") { // введённое сохранено
		t.Error("введённый текст потерян")
	}
	if list, _, _ := e.st.AuditList(context.Background(), 10, 0, "routing_add"); len(list) != 0 {
		t.Error("неудача записана в журнал как успех")
	}
}

func TestRoutingRemoveAndRestoreAndReplace(t *testing.T) {
	e, c := routingEnv(t)
	csrf := csrfOf(t, e, c)
	var patch nodeapi.RoutingPatch
	e.node.PatchRoutingFn = func(_ context.Context, _ string, p nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		patch = p
		return nodeapi.RoutingPatchResult{Applied: true, Removed: len(p.Remove)}, nil
	}
	rec := post(e, c, "/routing/files/include-hosts.txt/remove", url.Values{"csrf": {csrf}, "del": {"a.example.com", "b.example.com"}})
	if rec.Code != 303 || strings.Join(patch.Remove, ",") != "a.example.com,b.example.com" {
		t.Fatalf("remove: %d %+v", rec.Code, patch)
	}
	if rec := post(e, c, "/routing/files/include-hosts.txt/remove", url.Values{"csrf": {csrf}}); rec.Code != 400 {
		t.Errorf("пустой выбор: %d", rec.Code)
	}

	var stamp string
	e.node.RestoreRoutingFn = func(_ context.Context, _, st string) (nodeapi.RoutingFile, error) {
		stamp = st
		return nodeapi.RoutingFile{}, nil
	}
	if rec := post(e, c, "/routing/files/include-hosts.txt/restore", url.Values{"csrf": {csrf}, "stamp": {"20261102T101500.123Z"}}); rec.Code != 303 || stamp != "20261102T101500.123Z" {
		t.Errorf("restore: %d %q", rec.Code, stamp)
	}
	if rec := post(e, c, "/routing/files/include-hosts.txt/restore", url.Values{"csrf": {csrf}, "stamp": {"../x"}}); rec.Code != 400 {
		t.Errorf("негодная метка: %d", rec.Code)
	}

	var content string
	e.node.ReplaceRoutingFn = func(_ context.Context, _, text, _ string) (nodeapi.RoutingPutResult, error) {
		content = text
		return nodeapi.RoutingPutResult{Applied: true, Lines: 1}, nil
	}
	if rec := post(e, c, "/routing/files/include-hosts.txt/replace", url.Values{"csrf": {csrf}, "base_sha256": {testSHA}, "content": {"z.example.com\r\n"}}); rec.Code != 303 || content != "z.example.com\n" {
		t.Errorf("replace: %d %q", rec.Code, content)
	}
	e.node.ReplaceRoutingFn = func(context.Context, string, string, string) (nodeapi.RoutingPutResult, error) {
		return nodeapi.RoutingPutResult{Applied: false, Errors: []nodeapi.RoutingLineError{{Line: 1, Value: "x", Reason: "плохо"}}}, nil
	}
	rec = post(e, c, "/routing/files/include-hosts.txt/replace", url.Values{"csrf": {csrf}, "base_sha256": {testSHA}, "content": {"x\n"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "строка 1: x — плохо") {
		t.Errorf("replace с ошибкой: %d %s", rec.Code, rec.Body)
	}
	for _, a := range []string{"routing_remove", "routing_restore", "routing_replace"} {
		if list, _, _ := e.st.AuditList(context.Background(), 10, 0, a); len(list) != 1 {
			t.Errorf("%s: записей %d", a, len(list))
		}
	}
}

func TestRoutingFullTabBigBody(t *testing.T) {
	e, c := routingEnv(t)
	var content string
	e.node.ReplaceRoutingFn = func(_ context.Context, _, text, _ string) (nodeapi.RoutingPutResult, error) {
		content = text
		return nodeapi.RoutingPutResult{Applied: true}, nil
	}
	e.node.RoutingRawFn = func(_ context.Context, name string) (nodeapi.RoutingRaw, error) {
		return nodeapi.RoutingRaw{Name: name, Content: "a.example.com\n", SHA256: testSHA}, nil
	}
	big := strings.Repeat("host.example.com\n", 10000) // 170 КБ: больше обычного предела форм
	rec := post(e, c, "/routing/files/include-hosts.txt/replace", url.Values{"csrf": {csrfOf(t, e, c)}, "base_sha256": {testSHA}, "content": {big}})
	if rec.Code != 303 || content != big {
		t.Fatalf("%d, получено %d байт", rec.Code, len(content))
	}
	if body := get(e, c, "/routing/files/include-hosts.txt?tab=full").Body.String(); !strings.Contains(body, "Заменить список целиком") {
		t.Error("нет вкладки «Целиком»")
	}
}

func TestTaskStartRedirectsToTask(t *testing.T) {
	e, c := routingEnv(t)
	csrf := csrfOf(t, e, c)
	e.node.ApplyRoutingFn = func(context.Context) (nodeapi.Task, error) {
		return nodeapi.Task{ID: "0123456789ab", Kind: "doall", Started: time.Now()}, nil
	}
	e.node.RestartAntiZapretFn = func(context.Context) (nodeapi.Task, error) {
		return nodeapi.Task{}, &nodeapi.Error{Status: 409, Message: "уже идёт задача doall (0123456789ab)"}
	}
	rec := post(e, c, "/tasks/start", url.Values{"csrf": {csrf}, "kind": {"doall"}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/tasks/0123456789ab" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	if list, _, _ := e.st.AuditList(context.Background(), 10, 0, "task_start"); len(list) != 1 || list[0].Target != "doall" {
		t.Errorf("журнал: %+v", list)
	}
	rec = post(e, c, "/tasks/start", url.Values{"csrf": {csrf}, "kind": {"restart"}})
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "уже идёт задача doall") {
		t.Errorf("конфликт: %d %s", rec.Code, rec.Body)
	}
	if rec := post(e, c, "/tasks/start", url.Values{"csrf": {csrf}, "kind": {"rm -rf"}}); rec.Code != 400 {
		t.Errorf("неизвестный вид: %d", rec.Code)
	}
}

func TestTaskPageRefreshOnlyWhileRunning(t *testing.T) {
	e, c := routingEnv(t)
	now := time.Now()
	zero := 0
	e.node.TaskFn = func(_ context.Context, id string) (nodeapi.TaskDetail, error) {
		if id == "aaaaaaaaaaaa" {
			return nodeapi.TaskDetail{Task: nodeapi.Task{ID: id, Kind: "doall", Started: now}, Tail: "работаю <b>\n"}, nil
		}
		return nodeapi.TaskDetail{Task: nodeapi.Task{ID: id, Kind: "doall", Started: now, Finished: &now, ExitCode: &zero}, Tail: "готово\n"}, nil
	}
	run := get(e, c, "/tasks/aaaaaaaaaaaa")
	if run.Code != 200 || !strings.Contains(run.Body.String(), `http-equiv="refresh" content="3"`) ||
		!strings.Contains(run.Body.String(), "работаю &lt;b&gt;") {
		t.Errorf("идёт: %d %s", run.Code, run.Body)
	}
	done := get(e, c, "/tasks/bbbbbbbbbbbb")
	if done.Code != 200 || strings.Contains(done.Body.String(), "http-equiv") || !strings.Contains(done.Body.String(), "успешно") ||
		!strings.Contains(done.Body.String(), "UTC") {
		t.Errorf("закончилась: %d %s", done.Code, done.Body)
	}
	if code := get(e, c, "/tasks/not-an-id").Code; code != 404 {
		t.Errorf("негодный id: %d", code)
	}
}

func TestTasksListStatuses(t *testing.T) {
	e, c := routingEnv(t)
	now := time.Now()
	two := 2
	e.node.TasksFn = func(context.Context) ([]nodeapi.Task, error) {
		return []nodeapi.Task{
			{ID: "111111111111", Kind: "doall", Started: now},
			{ID: "222222222222", Kind: "restart", Started: now, Finished: &now, ExitCode: &two},
			{ID: "333333333333", Kind: "profiles", Started: now, Finished: &now, Interrupted: true},
		}, nil
	}
	rec := get(e, c, "/tasks")
	body := rec.Body.String()
	for _, want := range []string{"идёт", "ошибка, код 2", "прервана", `content="5"`} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
}

func setupEntries() []nodeapi.SetupEntry {
	return []nodeapi.SetupEntry{
		{Key: "ROUTE_ALL", Value: "n", Kind: "yn", Apply: []string{"doall"}, Title: "Всё через VPN", Editable: true, Present: true},
		{Key: "SCAN_PROTECTION", Value: "y", Kind: "yn", Apply: []string{"restart"}, Title: "Защита от сканирования", Editable: true, Present: true},
		{Key: "OPENVPN_BACKUP_UDP", Value: "y", Kind: "yn", Apply: []string{"restart"}, Title: "Резервный UDP", Editable: true, Present: true},
		{Key: "OPENVPN_HOST", Value: "", Kind: "host", Apply: []string{"profiles"}, Title: "Адрес OpenVPN", Editable: true, Present: true},
		{Key: "MTU", Value: "1420", Apply: []string{"reinstall"}, Title: "MTU", Present: true},
	}
}

func TestSetupPageGroups(t *testing.T) {
	e, c := routingEnv(t)
	e.node.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) { return setupEntries(), nil }
	body := get(e, c, "/settings/antizapret").Body.String()
	for _, want := range []string{"Маршрутизация списков", "Защита", "Резервные порты", "Адреса для профилей", "меняется переустановкой AntiZapret", `name="v_ROUTE_ALL"`} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(body, `name="v_MTU"`) {
		t.Error("ключ только для чтения можно править")
	}
}

func TestSetupSaveSendsOnlyChangedAndOffersTasks(t *testing.T) {
	e, c := routingEnv(t)
	csrf := csrfOf(t, e, c)
	e.node.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) { return setupEntries(), nil }
	var sent map[string]string
	e.node.SetSetupFn = func(_ context.Context, v map[string]string) (nodeapi.SetupResult, error) {
		sent = v
		return nodeapi.SetupResult{Changed: []string{"SCAN_PROTECTION"}, Apply: []string{"restart"}}, nil
	}
	rec := post(e, c, "/settings/antizapret", url.Values{"csrf": {csrf}, "v_ROUTE_ALL": {"n"}, "v_SCAN_PROTECTION": {"n"}, "v_MTU": {"9999"}})
	if rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(sent) != 1 || sent["SCAN_PROTECTION"] != "n" {
		t.Fatalf("агент получил %v", sent)
	}
	page := get(e, c, rec.Header().Get("Location")).Body.String()
	if !strings.Contains(page, "VPN прервётся на несколько секунд") || !strings.Contains(page, `value="restart"`) || strings.Contains(page, `value="profiles"`) {
		t.Errorf("предложение задач: %s", page)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "setup_set")
	if len(list) != 1 || list[0].Before != "SCAN_PROTECTION=y" || list[0].After != "SCAN_PROTECTION=n" {
		t.Errorf("журнал: %+v", list)
	}
	// профили: свое предупреждение
	e.node.SetSetupFn = func(context.Context, map[string]string) (nodeapi.SetupResult, error) {
		return nodeapi.SetupResult{Apply: []string{"profiles", "<script>"}}, nil
	}
	rec = post(e, c, "/settings/antizapret", url.Values{"csrf": {csrf}, "v_OPENVPN_HOST": {"vpn.example.com"}})
	page = get(e, c, rec.Header().Get("Location")).Body.String()
	if !strings.Contains(page, "старые файлы перестанут совпадать") || strings.Contains(page, "<script>") {
		t.Errorf("профили: %s", page)
	}
}

func TestSetupSaveErrorKeepsInput(t *testing.T) {
	e, c := routingEnv(t)
	e.node.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) { return setupEntries(), nil }
	e.node.SetSetupFn = func(context.Context, map[string]string) (nodeapi.SetupResult, error) {
		return nodeapi.SetupResult{}, &nodeapi.Error{Status: 400, Message: "OPENVPN_HOST: недопустимый адрес"}
	}
	rec := post(e, c, "/settings/antizapret", url.Values{"csrf": {csrfOf(t, e, c)}, "v_OPENVPN_HOST": {"bad host"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "OPENVPN_HOST: недопустимый адрес") || !strings.Contains(rec.Body.String(), `value="bad host"`) {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
	// Отказ агента — в журнал действий.
	if list, _, _ := e.st.AuditList(context.Background(), 10, 0, "setup_set"); len(list) != 1 || !strings.Contains(list[0].After, "отказ (400)") {
		t.Errorf("отказ не записан в журнал: %+v", list)
	}
}

func TestRoutingPagesAdminOnly(t *testing.T) {
	e, _, user, csrf, _ := userEnv(t)
	for _, p := range []string{"/routing", "/routing/files/include-hosts.txt", "/settings/antizapret", "/tasks", "/tasks/0123456789ab"} {
		if code := get(e, user, p).Code; code != http.StatusForbidden {
			t.Errorf("GET %s: %d", p, code)
		}
	}
	for _, p := range []string{"/tasks/start", "/settings/antizapret", "/routing/files/include-hosts.txt/add"} {
		if code := post(e, user, p, url.Values{"csrf": {csrf}, "kind": {"doall"}}).Code; code != http.StatusForbidden {
			t.Errorf("POST %s: %d", p, code)
		}
	}
}
