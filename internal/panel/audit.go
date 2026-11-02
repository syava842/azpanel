package panel

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

const (
	auditPageSize = 100
	auditMaxPage  = 100000 // дальше (page-1)*100 приближается к переполнению int
)

// audit пишет действие в журнал базы: время, пользователь сессии, IP,
// действие, объект, «было → стало». Без базы (Store nil) ничего не делает;
// сбой записи не ломает само действие и уходит в журнал службы.
func (s *Server) audit(r *http.Request, action, target, before, after string) {
	s.auditAs(r, s.user(r), action, target, before, after)
}

func (s *Server) auditAs(r *http.Request, user, action, target, before, after string) {
	if s.Store == nil {
		return
	}
	err := s.Store.Audit(r.Context(), store.AuditEntry{
		TS: s.now().Unix(), User: user, IP: s.remoteHost(r),
		Action: action, Target: target, Before: before, After: after,
	})
	if err != nil {
		s.Log.Warn("запись в журнал действий не удалась", "action", action, "err", err)
	}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type auditRow struct {
	Time, User, IP, Action, Target, Before, After string
}

// auditPage — страница /audit: поиск ?q= и страницы по 100 (?page=).
func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	if page > auditMaxPage {
		page = auditMaxPage
	}
	list, total, err := s.Store.AuditList(r.Context(), auditPageSize, (page-1)*auditPageSize, q)
	if err != nil {
		s.Log.Error("журнал действий не прочитан", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "журнал недоступен")
		return
	}
	rows := make([]auditRow, 0, len(list))
	for _, e := range list {
		rows = append(rows, auditRow{
			Time: time.Unix(e.TS, 0).UTC().Format("2006-01-02 15:04:05"),
			User: e.User, IP: e.IP, Action: e.Action, Target: e.Target, Before: e.Before, After: e.After,
		})
	}
	link := func(p int) string {
		v := url.Values{}
		if q != "" {
			v.Set("q", q)
		}
		v.Set("page", strconv.Itoa(p))
		return "/audit?" + v.Encode()
	}
	data := map[string]any{"Rows": rows, "Q": q, "Total": total, "Page": page}
	if page > 1 {
		data["Prev"] = link(page - 1)
	}
	if page*auditPageSize < total {
		data["Next"] = link(page + 1)
	}
	s.render(w, r, http.StatusOK, "audit", data)
}
