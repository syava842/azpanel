package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/update"
)

// updEnv — окружение страницы «Обновление» с токеном GitHub и найденной
// новой версией 0.9.1.
func updEnv(t *testing.T, version string) (*testEnv, *svcNode, *http.Cookie, string, *int) {
	t.Helper()
	e, n, c, csrf := svcEnv(t)
	e.srv.Version = version
	e.srv.SecretsFile = filepath.Join(t.TempDir(), "secrets.env")
	if err := secrets.Set(e.srv.SecretsFile, update.TokenKey, "ghp_SECRETTOKEN0123"); err != nil {
		t.Fatal(err)
	}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v0.9.1","body":"Исправлено <script>alert(1)</script>\n- второе"}`))
	}))
	t.Cleanup(gh.Close)
	e.srv.Updates = &update.Checker{Current: version, Token: e.srv.UpdateToken,
		Client: func(tok string) *update.Client { return &update.Client{BaseURL: gh.URL, Token: tok} }}
	fetches := new(int)
	e.srv.FetchUpdate = func(context.Context) (update.Fetched, error) {
		*fetches++
		return update.Fetched{Version: "0.9.1", Name: "azpanel_0.9.1_linux_amd64.tar.gz", Archive: []byte("A"), Sums: []byte("S"), Sig: []byte("G")}, nil
	}
	n.UpdateResultFn = func(context.Context) (*nodeapi.UpdateResult, error) { return nil, nil }
	e.node.TasksFn = func(context.Context) ([]nodeapi.Task, error) { return nil, nil }
	return e, n, c, csrf, fetches
}

func TestUpdatePageDisabledReasons(t *testing.T) {
	e, _, c, _, _ := updEnv(t, "dev")
	b := get(e, c, "/update").Body.String()
	if !strings.Contains(b, "сборка dev") || strings.Contains(b, "Подтверждаю") {
		t.Fatalf("dev: %s", b)
	}
	e, _, c, _, _ = updEnv(t, "0.9.0")
	if err := secrets.Delete(e.srv.SecretsFile, update.TokenKey); err != nil {
		t.Fatal(err)
	}
	b = get(e, c, "/update").Body.String()
	if !strings.Contains(b, "не задан токен GitHub") || !strings.Contains(b, "GITHUB_TOKEN") {
		t.Fatalf("без токена: %s", b)
	}
}

func TestUpdateCheckShowsNotesBadgeAndHidesToken(t *testing.T) {
	e, _, c, csrf, _ := updEnv(t, "0.9.0")
	if b := get(e, c, "/update").Body.String(); strings.Contains(b, "есть обновление") {
		t.Fatal("пометка до проверки")
	}
	rec := post(e, c, "/update/check", url.Values{"csrf": {csrf}})
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), "/update?msg=update_checked") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = get(e, c, "/update")
	b := rec.Body.String()
	for _, want := range []string{"Изменения в 0.9.1", "Исправлено &lt;script&gt;alert(1)&lt;/script&gt;", "- второе", "UTC", "Обновить до 0.9.1"} {
		if !strings.Contains(b, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(b, "<script>alert") || strings.Contains(b, "SECRETTOKEN") {
		t.Error("описание релиза не экранировано или токен на странице")
	}
	// пометка в шапке на любой странице администратора
	e.node.TasksFn = func(context.Context) ([]nodeapi.Task, error) { return nil, nil }
	if hb := get(e, c, "/tasks").Body.String(); !strings.Contains(hb, "есть обновление 0.9.1") {
		t.Fatalf("нет пометки в шапке: %s", hb)
	}
}

func TestUpdateStartConfirmAndSend(t *testing.T) {
	e, n, c, csrf, fetches := updEnv(t, "0.9.0")
	var got nodeapi.UpdateRequest
	n.UpdateFn = func(_ context.Context, req nodeapi.UpdateRequest) (nodeapi.Task, error) {
		got = req
		return nodeapi.Task{ID: "0123456789ab", Kind: "selfupdate"}, nil
	}
	f := url.Values{"csrf": {csrf}, "version": {"0.9.1"}}
	if rec := post(e, c, "/update", f); rec.Code != 400 || n.called("Update") != 0 || *fetches != 0 {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	f.Set("confirm", "1")
	rec := post(e, c, "/update", f)
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), "/update?msg=update_started") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got.Name != "azpanel_0.9.1_linux_amd64.tar.gz" || string(got.Archive) != "A" || string(got.Sums) != "S" || string(got.Sig) != "G" {
		t.Fatalf("агенту: %+v", got)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "azpanel_update")
	if len(list) != 1 || list[0].Target != "0.9.1" || list[0].Before != "0.9.0" || strings.Contains(list[0].After, "SECRET") {
		t.Fatalf("журнал: %+v", list)
	}
}

func TestUpdateQuestionsReuseDownloadedArchive(t *testing.T) {
	e, n, c, csrf, fetches := updEnv(t, "0.9.0")
	post(e, c, "/update/check", url.Values{"csrf": {csrf}})
	calls := 0
	var answers map[string]string
	n.UpdateFn = func(_ context.Context, req nodeapi.UpdateRequest) (nodeapi.Task, error) {
		calls++
		if req.Answers["panel.new_key"] == "" {
			return nodeapi.Task{}, &nodeapi.Error{Status: 409, Message: "нужны ответы",
				Questions: []nodeapi.UpdateQuestion{{Key: "panel.new_key", Text: "Новый ключ <b>конфига</b>"}}}
		}
		answers = req.Answers
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	f := url.Values{"csrf": {csrf}, "version": {"0.9.1"}, "confirm": {"1"}}
	rec := post(e, c, "/update", f)
	b := rec.Body.String()
	if rec.Code != 409 || !strings.Contains(b, `name="a_panel.new_key"`) || !strings.Contains(b, "Новый ключ &lt;b&gt;конфига&lt;/b&gt;") {
		t.Fatalf("вопросы: %d %s", rec.Code, b)
	}
	f.Set("a_panel.new_key", "значение")
	rec = post(e, c, "/update", f)
	if rec.Code != 303 || answers["panel.new_key"] != "значение" {
		t.Fatalf("ответ: %d %v", rec.Code, answers)
	}
	if *fetches != 1 || calls != 2 {
		t.Fatalf("скачиваний %d (нужно 1), вызовов агента %d", *fetches, calls)
	}
}

func TestUpdateAgentRefusalShown(t *testing.T) {
	e, n, c, csrf, _ := updEnv(t, "0.9.0")
	n.UpdateFn = func(context.Context, nodeapi.UpdateRequest) (nodeapi.Task, error) {
		return nodeapi.Task{}, &nodeapi.Error{Status: 422, Message: "подпись не сошлась"}
	}
	rec := post(e, c, "/update", url.Values{"csrf": {csrf}, "version": {"0.9.1"}, "confirm": {"1"}})
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "подпись не сошлась") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "azpanel_update")
	if len(list) != 1 || !strings.Contains(list[0].After, "отказ (422)") {
		t.Fatalf("журнал: %+v", list)
	}
	// dev-сборка не ставит обновление вовсе
	e.srv.Version = "dev"
	n.Calls = nil
	if rec := post(e, c, "/update", url.Values{"csrf": {csrf}, "confirm": {"1"}}); rec.Code != 400 || n.called("Update") != 0 {
		t.Fatalf("dev: %d", rec.Code)
	}
}

func TestUpdatePageShowsLastResultAndRunningTask(t *testing.T) {
	e, n, c, _, _ := updEnv(t, "0.9.1")
	n.UpdateResultFn = func(context.Context) (*nodeapi.UpdateResult, error) {
		return &nodeapi.UpdateResult{OK: false, From: "0.9.0", To: "0.9.1", Reason: "/healthz не ответил", Time: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}, nil
	}
	e.node.TasksFn = func(context.Context) ([]nodeapi.Task, error) {
		return []nodeapi.Task{{ID: "0123456789ab", Kind: "selfupdate", Started: time.Now()}}, nil
	}
	b := get(e, c, "/update").Body.String()
	for _, want := range []string{"откачено", "/healthz не ответил", "2026-11-02 10:00 UTC", `http-equiv="refresh"`, "/tasks/0123456789ab"} {
		if !strings.Contains(b, want) {
			t.Errorf("нет %q", want)
		}
	}
}

func TestNotifyUpdateAvailableOncePerVersion(t *testing.T) {
	e := newEnv(t, adminHash(t))
	tg := &config.Telegram{Enabled: true, Notify: config.TelegramNotifyKinds}
	info := update.Info{Current: "0.9.0", Latest: "0.9.1", Available: true, Notes: "Что нового"}
	now := time.Now()
	for i := 0; i < 2; i++ { // второй вызов — как после перезапуска панели
		if err := notifyUpdateAvailable(context.Background(), e.st, tg, now, info); err != nil {
			t.Fatal(err)
		}
	}
	kinds, texts := outboxTexts(t, e)
	if len(kinds) != 1 || kinds[0] != "azpanel_update" || !strings.Contains(texts[0], "0.9.1") || !strings.Contains(texts[0], "Что нового") {
		t.Fatalf("%v %v", kinds, texts)
	}
	info.Latest = "0.9.2"
	notifyUpdateAvailable(context.Background(), e.st, tg, now, info)
	if kinds, _ := outboxTexts(t, e); len(kinds) != 2 {
		t.Fatalf("новая версия не уведомлена: %v", kinds)
	}
}

func TestAzpanelUpdateKindInConfig(t *testing.T) {
	c := config.Default()
	found := false
	for _, k := range c.Telegram.Notify {
		found = found || k == "azpanel_update"
	}
	if !found {
		t.Fatal("azpanel_update нет в видах уведомлений по умолчанию")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Telegram.Notify = []string{"azpanel_update", "update_result", "antizapret_update"}
	if err := c.Validate(); err != nil {
		t.Fatalf("виды обновлений не проходят проверку: %v", err)
	}
	c.Telegram.Notify = []string{"azpanel_updat"}
	if err := c.Validate(); err == nil {
		t.Fatal("неизвестный вид прошёл проверку")
	}
}

func TestUpdateRoutesAdminOnly(t *testing.T) {
	for _, p := range []string{"GET /update", "POST /update", "POST /update/check"} {
		if routes[p] != accAdmin {
			t.Errorf("%s: не администратор", p)
		}
	}
}
