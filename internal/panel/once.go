package panel

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	pathAccountOnce = "/account/once"
	onceTTL         = 5 * time.Minute // сколько ждёт запись «показать один раз»
)

// onceEntry — страница с секретом, который показывается один раз.
type onceEntry struct {
	title, note, back, backText string
	batch                       string // не пусто — на странице кнопка «Скачать .txt» (пачка кодов)
	items                       []string
	expires                     time.Time
}

// onceStore держит такие записи в памяти по хешу ID сессии: на диск и в логи
// секрет не попадает, а после перезапуска панели пропадает.
type onceStore struct {
	mu sync.Mutex
	m  map[string]onceEntry
}

func (o *onceStore) put(key string, e onceEntry, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil {
		o.m = map[string]onceEntry{}
	}
	for k, v := range o.m { // просроченные уходят при каждой записи
		if !v.expires.After(now) {
			delete(o.m, k)
		}
	}
	e.expires = now.Add(onceTTL)
	o.m[key] = e
}

// take отдаёт запись и удаляет её; просроченную не отдаёт.
func (o *onceStore) take(key string, now time.Time) (onceEntry, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.m[key]
	delete(o.m, key)
	if !ok || !e.expires.After(now) {
		return onceEntry{}, false
	}
	return e, true
}

// showOnce откладывает секрет (резервные коды, созданный пароль) в
// одноразовую запись сессии и отвечает переходом 303 на GET /account/once:
// обновление страницы не повторяет действие.
func (s *Server) showOnce(w http.ResponseWriter, r *http.Request, title, note, back, backText string, items []string) {
	s.showOnceFile(w, r, title, note, back, backText, items, "")
}

// showOnceFile — то же, но со скачиванием: batch (идентификатор пачки) даёт
// на странице кнопку «Скачать .txt».
func (s *Server) showOnceFile(w http.ResponseWriter, r *http.Request, title, note, back, backText string, items []string, batch string) {
	sess, _ := session(r)
	s.once.put(sess.IDHash, onceEntry{title: title, note: note, back: back, backText: backText, items: items, batch: batch}, s.now())
	s.redirect(w, r, pathAccountOnce, http.StatusSeeOther)
}

// oncePage показывает отложенный секрет и стирает его; записи нет (уже
// показана, истекла) — возврат на страницу аккаунта.
func (s *Server) oncePage(w http.ResponseWriter, r *http.Request) {
	sess, _ := session(r)
	e, ok := s.once.take(sess.IDHash, s.now())
	if !ok {
		s.redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "once", map[string]any{"Title": e.title, "Note": e.note, "Items": e.items,
		"Back": e.back, "BackText": e.backText, "Batch": e.batch, "Joined": strings.Join(e.items, ",")})
}
