package panel

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/config"
)

// offEnv — окружение с выключенным panel.experimental (как в боевой панели
// по умолчанию).
func offEnv(t *testing.T) (*testEnv, *http.Cookie, string) {
	t.Helper()
	e, c, sess := clientsEnv(t)
	e.srv.Experimental = false
	e.h = e.srv.Handler()
	return e, c, sess.CSRF
}

// Отложенные маршруты не зарегистрированы вовсе, оставленные — на месте.
func TestExperimentalOffRoutesNotRegistered(t *testing.T) {
	e, _, _ := offEnv(t)
	reg := e.srv.registered
	for _, p := range []string{
		"GET /nodes", "POST /nodes", "GET /nodes/{id}", "GET /groups", "POST /groups/{id}/update",
		"GET /users/telegram", "POST /users/telegram/unban", "POST /users/{id}/telegram/unlink",
		"POST /account/telegram", "POST /account/telegram/unlink", "POST /clients/{name}/kinds",
		"GET /update", "POST /update", "POST /update/check",
	} {
		if slices.Contains(reg, p) {
			t.Errorf("маршрут %q зарегистрирован при panel.experimental = false", p)
		}
	}
	for _, p := range []string{
		"GET /antizapret/update", "POST /antizapret/update/restore", "GET /telemt", "GET /warp",
		"GET /routing", "GET /users", "GET /users/{id}", "POST /tasks/start", "GET /account",
	} {
		if !slices.Contains(reg, p) {
			t.Errorf("маршрут %q пропал", p)
		}
	}
}

func TestExperimentalOffPagesAre404(t *testing.T) {
	e, c, csrf := offEnv(t)
	for _, p := range []string{"/nodes", "/nodes/new", "/groups", "/users/telegram", "/update"} {
		if code := get(e, c, p).Code; code != http.StatusNotFound {
			t.Errorf("GET %s: %d, ждали 404", p, code)
		}
	}
	for _, p := range []string{"/account/telegram", "/update", "/update/check", "/groups"} {
		if code := post(e, c, p, url.Values{"csrf": {csrf}}).Code; code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: %d, ждали 404/405", p, code)
		}
	}
}

func TestExperimentalOffMenuAndPages(t *testing.T) {
	e, c, _ := offEnv(t)
	body := get(e, c, "/").Body.String()
	for _, hidden := range []string{`href="/nodes"`, `href="/groups"`, `href="/update"`} {
		if strings.Contains(body, hidden) {
			t.Errorf("в меню осталось %s", hidden)
		}
	}
	for _, shown := range []string{`href="/routing"`, `href="/antizapret/update"`, `href="/telemt"`, `href="/warp"`, `href="/proxy"`} {
		if !strings.Contains(body, shown) {
			t.Errorf("в меню нет %s", shown)
		}
	}
	if b := get(e, c, "/account").Body.String(); strings.Contains(b, "Telegram") {
		t.Error("на /account осталась привязка Telegram")
	}
	if b := get(e, c, "/users").Body.String(); strings.Contains(b, "/users/telegram") {
		t.Error("на /users осталась ссылка на страницу бота")
	}
	if b := get(e, c, "/clients/bob").Body.String(); strings.Contains(b, "Профили в Telegram") {
		t.Error("в карточке клиента остались профили в Telegram")
	}
}

func TestExperimentalOnMenuHasDeferred(t *testing.T) {
	e, c, _ := clientsEnv(t)
	body := get(e, c, "/").Body.String()
	for _, shown := range []string{`href="/nodes"`, `href="/groups"`, `href="/update"`} {
		if !strings.Contains(body, shown) {
			t.Errorf("при panel.experimental = true в меню нет %s", shown)
		}
	}
}

// Настройки: бота и GITHUB_TOKEN нет, а сохранение формы не трогает скрытое.
func TestExperimentalOffSettings(t *testing.T) {
	e := newSetEnv(t)
	e.srv.Experimental = false
	e.h = e.srv.Handler()
	c, _ := e.sessionCookie(t)
	body := e.get("/settings", "10.0.0.1", c).Body.String()
	for _, f := range config.Fields() {
		if f.Kind == config.KindReadonly || f.Page != "" {
			continue
		}
		has := strings.Contains(body, `name="f:`+f.Path+`"`)
		if f.Section == "telegram" && has {
			t.Errorf("поле бота %s показано", f.Path)
		}
		if f.Section != "telegram" && !has {
			t.Errorf("на странице нет поля %s", f.Path)
		}
	}
	if !strings.Contains(body, `name="f:panel.experimental"`) {
		t.Error("нет переключателя panel.experimental")
	}
	for _, hidden := range []string{"GITHUB_TOKEN", "TELEGRAM_BOT_TOKEN"} {
		if strings.Contains(body, hidden) {
			t.Errorf("секрет %s показан", hidden)
		}
	}
	// замена скрытого секрета отклоняется
	rec := e.post(t, "/settings/secrets", "10.0.0.1", url.Values{"key": {"GITHUB_TOKEN"}, "action": {"replace"}, "value": {"x"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("замена GITHUB_TOKEN: %d, ждали 400", rec.Code)
	}
}

// Сохранение формы без полей бота не выключает бота в config.toml.
func TestExperimentalOffSaveKeepsTelegram(t *testing.T) {
	e := newSetEnv(t)
	cfg := config.Default()
	cfg.Telegram.Enabled = true
	cfg.Telegram.NotifyChats = []int64{42}
	if err := config.Save(e.cfgFile, cfg); err != nil {
		t.Fatal(err)
	}
	e.srv.Experimental = false
	e.h = e.srv.Handler()
	form := e.form(t, map[string]string{"panel.history_days": "7"})
	for k := range form {
		if strings.HasPrefix(k, "f:telegram.") {
			delete(form, k)
		}
	}
	rec := e.post(t, "/settings", "10.0.0.1", form)
	m := draftRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	e.apply(t, m[1])
	got := e.cfg(t)
	if !got.Telegram.Enabled || got.Telegram.NotifyChats[0] != 42 || got.Panel.HistoryDays != 7 {
		t.Fatalf("telegram затронут: %+v история %d", got.Telegram, got.Panel.HistoryDays)
	}
}
