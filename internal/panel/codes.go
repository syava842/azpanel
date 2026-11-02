package panel

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

const (
	maxIssueCodes = 500  // кодов в одной пачке (в хранилище допустимо больше)
	maxCodeDays   = 3650 // дней продления в одном коде
	codesPerPage  = 100  // строк списка кодов на странице
	maxCodePage   = 1000 // дальше этой страницы список не листается (сужайте фильтром)
	maxBatchRows  = 100  // пачек в сводке
)

var (
	batchRe    = regexp.MustCompile(`^[0-9a-f]{12}$`)
	codeLineRe = regexp.MustCompile(`^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$`)
)

var codeStateText = map[string]string{
	store.CodeActive:  "не использован",
	store.CodeUsed:    "использован",
	store.CodeExpired: "просрочен",
	store.CodeRevoked: "отозван",
}

// codeStates — порядок состояний в фильтре.
var codeStates = []string{store.CodeActive, store.CodeUsed, store.CodeExpired, store.CodeRevoked}

type batchRow struct {
	ID, Created, By, Who                  string
	Total, Active, Used, Expired, Revoked int
	Days                                  string
	CanRevoke                             bool
}

type codeRow struct {
	ID         int64
	Batch      string
	State      string
	StateText  string
	Days       int64
	ValidUntil string
	Who        string
	UsedBy     string
	CanRevoke  bool
}

// loginsByID — логины пользователей для показа «на кого» и «кем использован».
func (s *Server) loginsByID(r *http.Request) (map[int64]string, []store.User, error) {
	users, err := s.Store.Users(r.Context())
	if err != nil {
		return nil, nil, err
	}
	m := make(map[int64]string, len(users))
	for _, u := range users {
		m[u.ID] = u.Login
	}
	return m, users, nil
}

func whoText(uid *int64, logins map[int64]string) string {
	if uid == nil {
		return "любой"
	}
	if l, ok := logins[*uid]; ok {
		return l
	}
	return "удалённый пользователь"
}

// codesPage — список пачек и кодов. Сводки по пачкам считает база, коды
// читаются постранично (codesPerPage), поэтому страница не дорожает с годами.
func (s *Server) codesPage(w http.ResponseWriter, r *http.Request) {
	now := s.now().Unix()
	logins, _, err := s.loginsByID(r)
	if err != nil {
		s.internalError(w, r, "пользователи не прочитаны", err)
		return
	}
	batchFilter := strings.TrimSpace(r.URL.Query().Get("batch"))
	stateFilter := r.URL.Query().Get("state")
	if _, ok := codeStateText[stateFilter]; !ok {
		stateFilter = ""
	}
	page := 1
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n > 1 && n <= maxCodePage {
		page = n
	}
	stats, err := s.Store.Batches(r.Context(), now, maxBatchRows)
	if err != nil {
		s.internalError(w, r, "пачки не прочитаны", err)
		return
	}
	brs := make([]batchRow, 0, len(stats))
	for _, b := range stats {
		brs = append(brs, batchRow{ID: b.Batch, Created: unixText(b.Created), By: b.CreatedBy, Who: whoText(b.UserID, logins),
			Days: strconv.FormatInt(b.Days, 10), Total: b.Total, Active: b.Active, Used: b.Used, Expired: b.Expired,
			Revoked: b.Revoked, CanRevoke: b.Active+b.Expired > 0})
	}
	// на одну строку больше страницы: так видно, есть ли следующая
	list, err := s.Store.CodesPage(r.Context(), store.CodeFilter{Batch: batchFilter, State: stateFilter}, now,
		codesPerPage+1, (page-1)*codesPerPage)
	if err != nil {
		s.internalError(w, r, "коды не прочитаны", err)
		return
	}
	more := len(list) > codesPerPage
	if more {
		list = list[:codesPerPage]
	}
	rows := make([]codeRow, 0, len(list))
	for _, c := range list {
		st := c.State(now)
		row := codeRow{ID: c.ID, Batch: c.Batch, State: st, StateText: codeStateText[st], Days: c.Days,
			ValidUntil: time.Unix(c.ValidUntil, 0).UTC().Format("2006-01-02") + " UTC",
			Who:        whoText(c.UserID, logins), CanRevoke: st == store.CodeActive || st == store.CodeExpired}
		if st == store.CodeUsed {
			row.UsedBy = c.UsedClient
			if c.UsedAt != nil {
				row.UsedBy += ", " + unixText(*c.UsedAt)
			}
		}
		rows = append(rows, row)
	}
	states := make([]map[string]any, 0, len(codeStates))
	for _, st := range codeStates {
		states = append(states, map[string]any{"Value": st, "Text": codeStateText[st], "Selected": st == stateFilter})
	}
	pageHref := func(n int) string {
		q := url.Values{}
		if batchFilter != "" {
			q.Set("batch", batchFilter)
		}
		if stateFilter != "" {
			q.Set("state", stateFilter)
		}
		if n > 1 {
			q.Set("page", strconv.Itoa(n))
		}
		if len(q) == 0 {
			return "/codes"
		}
		return "/codes?" + q.Encode()
	}
	data := map[string]any{"Batches": brs, "Codes": rows, "Batch": batchFilter, "States": states,
		"Page": page, "BatchesCut": len(stats) >= maxBatchRows, "PerPage": codesPerPage}
	if page > 1 {
		data["PrevHref"] = pageHref(page - 1)
	}
	if more && page < maxCodePage {
		data["NextHref"] = pageHref(page + 1)
	}
	s.render(w, r, http.StatusOK, "codes", data)
}

type codeForm struct{ Count, Days, Until, User string }

func (s *Server) codesNewView(w http.ResponseWriter, r *http.Request, status int, errText string, f codeForm) {
	_, users, err := s.loginsByID(r)
	if err != nil {
		s.internalError(w, r, "пользователи не прочитаны", err)
		return
	}
	type option struct {
		ID       int64
		Login    string
		Selected bool
	}
	opts := []option{}
	for _, u := range users {
		opts = append(opts, option{u.ID, u.Login, strconv.FormatInt(u.ID, 10) == f.User})
	}
	data := map[string]any{"Form": f, "Users": opts, "MaxCount": maxIssueCodes, "MaxDays": maxCodeDays}
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "codes_new", data)
}

func (s *Server) codesNewForm(w http.ResponseWriter, r *http.Request) {
	s.codesNewView(w, r, http.StatusOK, "", codeForm{Count: "10", Days: "30"})
}

// codesIssue выпускает пачку и показывает коды один раз.
func (s *Server) codesIssue(w http.ResponseWriter, r *http.Request) {
	f := codeForm{Count: strings.TrimSpace(r.PostForm.Get("count")), Days: strings.TrimSpace(r.PostForm.Get("days")),
		Until: strings.TrimSpace(r.PostForm.Get("until")), User: strings.TrimSpace(r.PostForm.Get("user"))}
	fail := func(text string) { s.codesNewView(w, r, http.StatusBadRequest, text, f) }
	count, err := atoiRange("количество", f.Count, 1, maxIssueCodes)
	if err != nil {
		fail(err.Error())
		return
	}
	days, err := atoiRange("дней", f.Days, 1, maxCodeDays)
	if err != nil {
		fail(err.Error())
		return
	}
	until, err := parseUntil(f.Until)
	if err != nil || until == nil {
		fail("код действует до: нужна дата в виде ГГГГ-ММ-ДД")
		return
	}
	now := s.now()
	if *until < now.Unix() {
		fail("код действует до: дата уже прошла")
		return
	}
	var uid *int64
	who := "любой"
	if f.User != "" {
		id, err := strconv.ParseInt(f.User, 10, 64)
		if err != nil {
			fail("на кого: неверный пользователь")
			return
		}
		u, err := s.Store.UserByID(r.Context(), id)
		if err != nil {
			fail("на кого: такого пользователя нет")
			return
		}
		uid, who = &u.ID, u.Login
	}
	batch, codes, err := s.Store.IssueCodes(r.Context(), store.IssueParams{Count: count, Days: int64(days),
		ValidUntil: *until, UserID: uid, CreatedBy: s.user(r), Now: now.Unix()})
	if err != nil {
		s.internalError(w, r, "коды не выпущены", err)
		return
	}
	s.audit(r, "codes_issue", batch, "", fmt.Sprintf("кодов: %d, дней: %d, действуют до %s UTC, на: %s",
		count, days, time.Unix(*until, 0).UTC().Format("2006-01-02"), who))
	s.showOnceFile(w, r, "Коды выпущены (пачка "+batch+")",
		"Коды показаны один раз: после ухода со страницы их не восстановить, в панели хранятся только хеши. Скачайте файл или перепишите.",
		"/codes?batch="+batch, "К кодам пачки", codes, batch)
}

// codesDownload отдаёт коды текстовым файлом. Коды в панели не хранятся, их
// присылает страница выпуска; в файл попадают только строки вида кода.
func (s *Server) codesDownload(w http.ResponseWriter, r *http.Request) {
	batch := r.PostForm.Get("batch")
	if !batchRe.MatchString(batch) {
		s.errorPage(w, r, http.StatusBadRequest, "пачка: неверный идентификатор")
		return
	}
	var sb strings.Builder
	n := 0
	for _, line := range strings.Split(r.PostForm.Get("codes"), ",") {
		line = strings.TrimSpace(line)
		if n < 1000 && codeLineRe.MatchString(line) {
			sb.WriteString(line + "\n")
			n++
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="azpanel-codes-`+batch+`.txt"`)
	w.Write([]byte(sb.String()))
}

func (s *Server) codeRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil && id > 0 {
		err = s.Store.RevokeCode(r.Context(), id)
	} else {
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "код не найден или уже использован")
		return
	}
	if err != nil {
		s.internalError(w, r, "код не отозван", err)
		return
	}
	s.audit(r, "code_revoke", strconv.FormatInt(id, 10), "", "отозван")
	redirectMsg(w, r, backToCodes(r), "code_revoked")
}

func (s *Server) codeBatchRevoke(w http.ResponseWriter, r *http.Request) {
	batch := r.PathValue("batch")
	if !batchRe.MatchString(batch) {
		s.errorPage(w, r, http.StatusNotFound, "пачка не найдена")
		return
	}
	n, err := s.Store.RevokeBatch(r.Context(), batch)
	if err != nil {
		s.internalError(w, r, "пачка не отозвана", err)
		return
	}
	s.audit(r, "code_revoke", batch, "", fmt.Sprintf("отозвана пачка, кодов: %d", n))
	redirectMsg(w, r, "/codes", "codes_revoked", int(n))
}

// backToCodes — куда вернуться после отзыва: на список (с фильтром пачки, если
// он был в форме).
func backToCodes(r *http.Request) string {
	if b := r.PostForm.Get("batch"); batchRe.MatchString(b) {
		return "/codes?batch=" + b
	}
	return "/codes"
}
