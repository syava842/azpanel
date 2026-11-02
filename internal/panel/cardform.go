package panel

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	maxNoteRunes = 500
	maxLimitGB   = 1_000_000 // ГБ; вдвое больше любого реального лимита
)

var periodNames = map[string]string{
	store.PeriodDay:   "сутки",
	store.PeriodWeek:  "неделя",
	store.PeriodMonth: "месяц",
}

// cardForm — значения формы «Карточка».
type cardForm struct {
	Note, Until, LimitGB, Period string
}

func newCardForm(c store.Card) cardForm {
	f := cardForm{Note: c.Note, LimitGB: gbText(c.TrafficLimit), Period: c.TrafficPeriod}
	if c.AccessUntil != nil {
		f.Until = untilText(c.AccessUntil)
	}
	return f
}

// autoBlockText — почему клиент заблокирован панелью; пусто, если не ею.
func autoBlockText(c nodeapi.Client, card store.Card) string {
	if !c.Blocked {
		return ""
	}
	switch card.AutoBlock {
	case store.AutoBlockExpired:
		return "заблокирован автоматически: истёк срок"
	case store.AutoBlockTraffic:
		return "заблокирован автоматически: превышен трафик"
	}
	return ""
}

// addHistory добавляет на карточку клиента график трафика, форму
// «Карточка» и пометку автоблокировки. Без базы блок не показывается; сбой
// чтения базы выводится текстом и карточку не роняет.
func (s *Server) addHistory(r *http.Request, c nodeapi.Client, data map[string]any) {
	if s.Store == nil {
		return
	}
	data["HasStore"] = true
	h := parseRange(r)
	data["Ranges"] = rangeLinks(clientHref(c.Name), h)
	if chart, down, up, err := s.clientTraffic(r.Context(), c.Name, h, s.now()); err != nil {
		s.Log.Warn("трафик клиента не прочитан", "client", c.Name, "err", err)
		data["HistoryErr"] = "история трафика недоступна"
	} else {
		data["TrafficChart"], data["TrafficDown"], data["TrafficUp"] = chart, down, up
	}
	card, err := s.Store.Card(r.Context(), s.NodeID, c.Name)
	if err != nil {
		s.Log.Warn("карточка клиента не прочитана", "client", c.Name, "err", err)
		data["HistoryErr"] = "карточка недоступна"
		data["HasStore"] = false
		return
	}
	data["CardForm"] = newCardForm(card)
	data["AutoBlockText"] = autoBlockText(c, card)
}

// parseCardForm разбирает форму «Карточка»; ошибка — текст для страницы.
func parseCardForm(r *http.Request, old store.Card) (store.Card, error) {
	c := old
	note := strings.TrimSpace(r.PostForm.Get("note"))
	if utf8.RuneCountInString(note) > maxNoteRunes {
		return c, fmt.Errorf("заметка: не больше %d символов", maxNoteRunes)
	}
	c.Note = note
	c.AccessUntil = nil
	if v := strings.TrimSpace(r.PostForm.Get("until")); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return c, fmt.Errorf("доступ до: нужна дата в виде ГГГГ-ММ-ДД")
		}
		end := t.UTC().Add(24*time.Hour - time.Second).Unix() // конец дня по UTC
		c.AccessUntil = &end
	}
	gb := 0.0
	if v := strings.TrimSpace(r.PostForm.Get("limit_gb")); v != "" {
		var err error
		gb, err = strconv.ParseFloat(strings.ReplaceAll(v, ",", "."), 64)
		if err != nil || math.IsNaN(gb) || math.IsInf(gb, 0) || gb < 0 || gb > maxLimitGB {
			return c, fmt.Errorf("лимит трафика: нужно число ГБ от 0 до %d", maxLimitGB)
		}
	}
	c.TrafficLimit = int64(gb * (1 << 30))
	period := r.PostForm.Get("period")
	if _, ok := periodNames[period]; !ok {
		return c, fmt.Errorf("период: сутки, неделя или месяц")
	}
	c.TrafficPeriod = period
	return c, nil
}

// cardDiff — изменённые поля карточки словами: «было» и «стало».
func cardDiff(a, b store.Card) (before, after string) {
	var bs, as []string
	add := func(name, x, y string) {
		if x != y {
			bs, as = append(bs, name+": "+x), append(as, name+": "+y)
		}
	}
	add("заметка", a.Note, b.Note)
	add("доступ до", untilText(a.AccessUntil), untilText(b.AccessUntil))
	limit := func(c store.Card) string {
		if c.TrafficLimit <= 0 {
			return "без лимита"
		}
		return gbText(c.TrafficLimit) + " ГБ"
	}
	add("лимит трафика", limit(a), limit(b))
	add("период", periodNames[a.TrafficPeriod], periodNames[b.TrafficPeriod])
	return strings.Join(bs, "; "), strings.Join(as, "; ")
}

func (s *Server) saveCard(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.Store == nil {
		s.card(w, r, c, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	old, err := s.Store.Card(r.Context(), s.NodeID, c.Name)
	if err != nil {
		s.Log.Error("карточка не прочитана", "client", c.Name, "err", err)
		s.card(w, r, c, http.StatusInternalServerError, "карточка недоступна")
		return
	}
	next, err := parseCardForm(r, old)
	if err != nil {
		s.card(w, r, c, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.SaveCardFields(r.Context(), next); err != nil {
		s.Log.Error("карточка не сохранена", "client", c.Name, "err", err)
		s.card(w, r, c, http.StatusInternalServerError, "карточка не сохранена")
		return
	}
	before, after := cardDiff(old, next)
	s.Log.Info("действие", "user", s.user(r), "op", "card", "client", c.Name, "detail", after)
	if before != "" || after != "" {
		s.audit(r, "card", c.Name, before, after)
	}
	redirectMsg(w, r, clientHref(c.Name), "card_saved")
}

// forgetAutoBlock: ручная разблокировка клиента, которого заблокировала
// панель, обнуляет auto_block и запоминает отпечаток причины в auto_skip —
// сборщик не вернёт блокировку, пока причина (срок, лимит, период) та же.
func (s *Server) forgetAutoBlock(r *http.Request, c nodeapi.Client) {
	if s.Store == nil {
		return
	}
	card, err := s.Store.Card(r.Context(), s.NodeID, c.Name)
	if err != nil || card.AutoBlock == "" {
		return
	}
	fp := blockFingerprint(card.AutoBlock, card, s.now())
	if err := s.Store.SetAutoBlock(r.Context(), s.NodeID, c.Name, "", fp); err != nil {
		s.Log.Warn("отметка автоблокировки не снята", "client", c.Name, "err", err)
	}
}
