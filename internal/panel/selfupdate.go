package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/panel/bot"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/update"
)

const (
	fetchedTTL       = 15 * time.Minute // скачанный релиз ждёт ответов на вопросы миграции
	fetchTimeout     = 3 * time.Minute
	notesInNotice    = 600 // знаков описания релиза в уведомлении
	metaSelfNotified = "self_update_notified"
)

// fetchedRelease — релиз, уже скачанный панелью: пока администратор отвечает
// на вопросы миграции, повторно качать архив не нужно.
type fetchedRelease struct {
	mu sync.Mutex
	f  *update.Fetched
	at time.Time
}

func (c *fetchedRelease) get(version string, now time.Time) (update.Fetched, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f != nil && c.f.Version == version && now.Sub(c.at) < fetchedTTL {
		return *c.f, true
	}
	return update.Fetched{}, false
}

func (c *fetchedRelease) put(f update.Fetched, now time.Time) {
	c.mu.Lock()
	c.f, c.at = &f, now
	c.mu.Unlock()
}

func (c *fetchedRelease) drop() {
	c.mu.Lock()
	c.f = nil
	c.mu.Unlock()
}

// updateToken — токен GitHub из secrets.env; читается при каждом обращении:
// владелец мог задать его в настройках без перезапуска.
func (s *Server) updateToken() string {
	sec, err := secrets.Load(s.secretsPath())
	if err != nil {
		return ""
	}
	return sec[update.TokenKey]
}

// UpdateToken — функция токена для проверяющего обновления; панель отдаёт её
// и странице, и Checker.
func (s *Server) UpdateToken() string { return s.updateToken() }

// updateDisabledReason — почему проверка обновлений выключена; пусто — включена.
func (s *Server) updateDisabledReason() string {
	switch {
	case update.IsDev(s.Version):
		return "сборка dev: обновления не предлагаются и не ставятся"
	}
	return ""
}

// fetchRelease скачивает последний релиз под архитектуру панели и проверяет
// только его наличие; подпись проверит агент вшитым ключом.
func (s *Server) fetchRelease(ctx context.Context) (update.Fetched, error) {
	if s.FetchUpdate != nil {
		return s.FetchUpdate(ctx)
	}
	// Токен необязателен: без него запрос анонимный.
	cl := &update.Client{Token: s.updateToken()}
	rel, err := cl.Latest(ctx)
	if err != nil {
		return update.Fetched{}, err
	}
	return cl.Fetch(ctx, rel, runtime.GOARCH)
}

// updateAvailable — пометка для шапки: версия, на которую можно обновиться.
func (s *Server) updateAvailable() string {
	if s.Updates == nil {
		return ""
	}
	if i := s.Updates.Last(); i.Available {
		return i.Latest
	}
	return ""
}

type updQuestion struct{ Key, Text, Value string }

func (s *Server) updatePage(w http.ResponseWriter, r *http.Request) {
	s.updateView(w, r, http.StatusOK, "", nil, nil)
}

// updateView — страница «Обновление azpanel»: текущая и последняя версии,
// изменения релиза, вопросы миграции, итог последнего обновления.
func (s *Server) updateView(w http.ResponseWriter, r *http.Request, status int, errText string, qs []nodeapi.UpdateQuestion, answers map[string]string) {
	data := map[string]any{"Current": s.Version, "Dev": update.IsDev(s.Version)}
	if errText != "" {
		data["Error"] = errText
	}
	if reason := s.updateDisabledReason(); reason != "" {
		data["Disabled"] = reason
	}
	if s.Updates != nil {
		i := s.Updates.Last()
		data["Info"] = i
		data["Checked"] = formatTime(&i.Checked)
		data["Latest"] = i.Latest
	}
	if len(qs) > 0 {
		rows := make([]updQuestion, 0, len(qs))
		for _, q := range qs {
			rows = append(rows, updQuestion{Key: q.Key, Text: q.Text, Value: answers[q.Key]})
		}
		data["Questions"] = rows
	}
	if n := s.serviceNode(); n != nil {
		if res, err := n.UpdateResult(r.Context()); err == nil && res != nil {
			t := res.Time
			data["Result"] = res
			data["ResultTime"] = formatTime(&t)
		}
	}
	if list, err := s.nodeFor(r).Tasks(r.Context()); err == nil {
		for _, t := range list {
			if t.Kind == "selfupdate" {
				row := newTaskRow(t)
				data["Task"] = row
				data["Running"] = row.Running
				break
			}
		}
	}
	s.render(w, r, status, "update", data)
}

// updateCheck — проверить обновление сейчас.
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	if s.Updates == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "проверка обновлений не запущена")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	info, err := s.Updates.Check(ctx)
	switch {
	case errors.Is(err, update.ErrDisabled):
		s.updateView(w, r, http.StatusOK, "", nil, nil)
		return
	case err != nil:
		s.updateView(w, r, http.StatusBadGateway, "Проверка не удалась: "+err.Error(), nil, nil)
		return
	}
	s.audit(r, "update_check", "azpanel", "", "последняя версия "+info.Latest)
	s.redirectMsg(w, r, "/update", "update_checked")
}

// updateStart скачивает релиз (или берёт уже скачанный), передаёт его агенту и
// ведёт обратно на страницу. Подтверждение обязательно: панель и агент
// перезапустятся.
func (s *Server) updateStart(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	answers := map[string]string{}
	for k, v := range r.PostForm {
		if key, found := strings.CutPrefix(k, "a_"); found && len(v) > 0 {
			answers[key] = strings.TrimSpace(v[0])
		}
	}
	if reason := s.updateDisabledReason(); reason != "" {
		s.updateView(w, r, http.StatusBadRequest, "Обновление недоступно: "+reason, nil, nil)
		return
	}
	if !formConfirmed(r) {
		s.updateView(w, r, http.StatusBadRequest, "Отметьте подтверждение: панель и агент перезапустятся.", nil, answers)
		return
	}
	want := strings.TrimSpace(r.PostForm.Get("version"))
	f, have := s.upd.get(want, s.now())
	if !have {
		ctx, cancel := context.WithTimeout(r.Context(), fetchTimeout)
		defer cancel()
		var err error
		if f, err = s.fetchRelease(ctx); err != nil {
			s.Log.Warn("действие", "user", s.user(r), "op", "azpanel_update", "err", err)
			s.auditRefused(r, "azpanel_update", want, http.StatusBadGateway, "релиз не скачан: "+err.Error())
			s.updateView(w, r, http.StatusBadGateway, "Релиз не скачан: "+err.Error(), nil, answers)
			return
		}
		if want != "" && f.Version != want {
			s.updateView(w, r, http.StatusConflict, fmt.Sprintf("Вышла другая версия (%s вместо %s): откройте страницу заново.", f.Version, want), nil, nil)
			return
		}
		s.upd.put(f, s.now())
	}
	t, err := n.Update(r.Context(), nodeapi.UpdateRequest{Name: f.Name, Archive: f.Archive, Sums: f.Sums, Sig: f.Sig, Answers: answers})
	if err != nil {
		var ne *nodeapi.Error
		if errors.As(err, &ne) && ne.Status == http.StatusConflict && len(ne.Questions) > 0 {
			s.updateView(w, r, http.StatusConflict, "Для миграции конфига нужны ответы на вопросы ниже.", ne.Questions, answers)
			return
		}
		s.upd.drop()
		s.Log.Warn("действие", "user", s.user(r), "op", "azpanel_update", "version", f.Version, "err", err)
		st, tx := s.svcErr(err)
		s.auditRefused(r, "azpanel_update", f.Version, st, tx)
		s.updateView(w, r, st, tx, nil, nil)
		return
	}
	s.upd.drop()
	s.Log.Info("действие", "user", s.user(r), "op", "azpanel_update", "version", f.Version, "task", t.ID)
	s.audit(r, "azpanel_update", f.Version, s.Version, "запущено; задача "+t.ID)
	s.redirectMsg(w, r, "/update", "update_started")
}

// notifyUpdateAvailable — уведомление azpanel_update: один раз на версию, и
// после перезапуска панели тоже (версия запоминается в meta).
func notifyUpdateAvailable(ctx context.Context, st *store.Store, tg *config.Telegram, now time.Time, i update.Info) error {
	if st == nil {
		return nil
	}
	if v, found, err := st.Meta(ctx, metaSelfNotified); err != nil {
		return err
	} else if found && v == i.Latest {
		return nil
	}
	text := fmt.Sprintf("Доступно обновление azpanel %s (установлена %s).", i.Latest, i.Current)
	if notes := strings.TrimSpace(i.Notes); notes != "" {
		if r := []rune(notes); len(r) > notesInNotice {
			notes = string(r[:notesInNotice]) + "…"
		}
		text += "\n" + notes
	}
	text += "\nУстановка — в панели, раздел «Обновление»."
	if err := enqueueNotice(ctx, st, tg, now, bot.KindAzpanelUpdate, text); err != nil {
		return err
	}
	return st.SetMeta(ctx, metaSelfNotified, i.Latest)
}
