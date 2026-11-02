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

	"github.com/syava842/azpanel/internal/nodeapi"
)

const (
	routingPageSize = 200     // строк списка на странице
	fullTabMax      = 1 << 20 // «Целиком» — только для файлов до 1 МБ
	maxPageNumber   = 100000
)

var (
	reRoutingName  = regexp.MustCompile(`^[a-z0-9-]+\.txt$`)
	reRoutingStamp = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z$`)
	reSHA256       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// kindTitles — подписи видов списков.
var kindTitles = map[string]string{
	"hosts": "домены",
	"ips":   "адреса и сети",
	"rpz":   "правила RPZ",
}

type routingRow struct {
	Name, Title, Kind string
	Href              string
	Lines             int
	Size              string
	Editable          bool
}

func routingHref(name string) string { return "/routing/files/" + url.PathEscape(name) }

// agentErr — ошибка агента для страницы: 404 остаётся 404, 409 — 409
// («уже идёт задача»), остальное — как у nodeErr.
func (s *Server) agentErr(err error) (int, string) {
	var ne *nodeapi.Error
	if errors.As(err, &ne) {
		switch ne.Status {
		case http.StatusNotFound:
			return http.StatusNotFound, ne.Message
		case http.StatusConflict:
			return http.StatusConflict, ne.Message
		}
	}
	return s.nodeErr(err)
}

func (s *Server) routingPage(w http.ResponseWriter, r *http.Request) {
	files, err := s.nodeFor(r).RoutingFiles(r.Context())
	if err != nil {
		st, tx := s.agentErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	rows := make([]routingRow, 0, len(files))
	for _, f := range files {
		rows = append(rows, routingRow{Name: f.Name, Title: f.Title, Kind: kindTitles[f.Kind], Href: routingHref(f.Name),
			Lines: f.Lines, Size: humanBytes(uint64(max(f.Bytes, 0))), Editable: f.Kind != ""})
	}
	s.render(w, r, http.StatusOK, "routing", map[string]any{"Rows": rows})
}

// fileView — состояние страницы списка, которое форма возвращает при ошибке.
type fileView struct {
	Tab      string // "" — записи, "full" — целиком
	AddText  string
	FullText string // подставляется вместо загруженного содержимого
	HasFull  bool
	BaseSHA  string // отпечаток текста, с которого начата правка «Целиком»
	Errors   []string
	Changed  bool
	NoChange string // уведомление «ничего не изменилось»
	Status   int
}

// routingFile — страница списка: поиск, страницы по 200 строк, правка.
func (s *Server) routingFile(w http.ResponseWriter, r *http.Request) {
	v := fileView{Tab: r.URL.Query().Get("tab"), Changed: r.URL.Query().Get("msg") == "routing_changed", Status: http.StatusOK}
	if r.URL.Query().Get("msg") == "routing_nochange" {
		if n, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && n >= 0 && n <= 1_000_000 {
			v.NoChange = fmt.Sprintf("ничего не изменилось: строк пропущено — %d (уже были в списке или не найдены)", n)
		}
	}
	s.fileView(w, r, v)
}

func (s *Server) fileView(w http.ResponseWriter, r *http.Request, v fileView) {
	name := r.PathValue("name")
	if !reRoutingName.MatchString(name) {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	files, err := s.nodeFor(r).RoutingFiles(r.Context())
	if err != nil {
		st, tx := s.agentErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	var file nodeapi.RoutingFile
	found := false
	for _, f := range files {
		if f.Name == name {
			file, found = f, true
		}
	}
	if !found {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	editable := file.Kind != "" && !replicaFor(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page := 1
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n >= 1 {
		page = min(n, maxPageNumber)
	}
	canFull := editable && file.Bytes <= fullTabMax
	full := v.Tab == "full" && canFull
	data := map[string]any{"File": file, "Name": name, "Href": routingHref(name), "Editable": editable, "Q": q,
		"Size": humanBytes(uint64(max(file.Bytes, 0))), "KindTitle": kindTitles[file.Kind],
		"CanFull": canFull, "Full": full, "AddText": v.AddText, "Changed": v.Changed, "NoChange": v.NoChange}
	if len(v.Errors) > 0 {
		data["Errors"] = v.Errors
	}
	if full {
		text, sum := v.FullText, v.BaseSHA
		if !v.HasFull {
			raw, err := s.nodeFor(r).RoutingRaw(r.Context(), name)
			if err != nil {
				st, tx := s.agentErr(err)
				s.errorPage(w, r, st, tx)
				return
			}
			text, sum = raw.Content, raw.SHA256
		}
		data["FullText"] = text
		data["BaseSHA"] = sum
	} else {
		pg, err := s.nodeFor(r).RoutingLines(r.Context(), name, nodeapi.RoutingListOpts{Query: q, Offset: (page - 1) * routingPageSize, Limit: routingPageSize})
		if err != nil {
			st, tx := s.agentErr(err)
			s.errorPage(w, r, st, tx)
			return
		}
		data["Lines"] = pg.Lines
		data["Total"] = pg.Total
		data["Page"] = page
		base := routingHref(name) + "?"
		if q != "" {
			base += "q=" + url.QueryEscape(q) + "&"
		}
		if page > 1 {
			data["Prev"] = base + "page=" + strconv.Itoa(page-1)
		}
		if page*routingPageSize < pg.Total {
			data["Next"] = base + "page=" + strconv.Itoa(page+1)
		}
	}
	if editable {
		if bs, err := s.nodeFor(r).RoutingBackups(r.Context(), name); err != nil {
			_, tx := s.agentErr(err)
			data["BackupsErr"] = "копии недоступны: " + tx
		} else {
			data["Backups"] = backupRows(bs)
		}
	}
	s.render(w, r, v.Status, "routing_file", data)
}

type backupRow struct {
	Stamp, Time, Size string
}

// backupRows: метка вида 20261102T101500.123Z показывается временем UTC.
func backupRows(bs []nodeapi.RoutingBackup) []backupRow {
	out := make([]backupRow, 0, len(bs))
	for _, b := range bs {
		row := backupRow{Stamp: b.Stamp, Time: b.Stamp, Size: humanBytes(uint64(max(b.Bytes, 0)))}
		if t, err := time.Parse("20060102T150405.000Z", b.Stamp); err == nil {
			row.Time = formatTime(&t)
		}
		out = append(out, row)
	}
	return out
}

// splitInput режет textarea на непустые строки; orig[i] — номер i-й строки
// в присланном тексте (с единицы), чтобы ошибки агента указывали на строку
// в поле, а не на номер после выбрасывания пустых.
func splitInput(text string) (lines []string, orig []int) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	for i, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		lines = append(lines, strings.TrimSpace(l))
		orig = append(orig, i+1)
	}
	return lines, orig
}

// lineErrors превращает построчные ошибки агента в тексты; orig — соответствие
// номеров (nil — номера как есть).
func lineErrors(errs []nodeapi.RoutingLineError, orig []int) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		n := e.Line
		if orig != nil && e.Line >= 1 && e.Line <= len(orig) {
			n = orig[e.Line-1]
		}
		if n > 0 {
			out = append(out, fmt.Sprintf("строка %d: %s — %s", n, e.Value, e.Reason))
		} else {
			out = append(out, fmt.Sprintf("%s — %s", e.Value, e.Reason))
		}
	}
	return out
}

func (s *Server) routingAdd(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	text := r.PostForm.Get("lines")
	if !reRoutingName.MatchString(name) {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	lines, orig := splitInput(text)
	if len(lines) == 0 {
		s.fileView(w, r, fileView{AddText: text, Status: http.StatusBadRequest, Errors: []string{"нет строк для добавления"}})
		return
	}
	res, err := s.nodeFor(r).PatchRouting(r.Context(), name, nodeapi.RoutingPatch{Add: lines})
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_add", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "routing_add", name, st, tx)
		s.fileView(w, r, fileView{AddText: text, Status: st, Errors: []string{tx}})
		return
	}
	if noChange(res) {
		s.redirectMsg(w, r, routingHref(name), "routing_nochange", res.Skipped)
		return
	}
	if !res.Applied { // агент отвечает 200, но файл не менялся
		s.fileView(w, r, fileView{AddText: text, Status: http.StatusBadRequest, Errors: errorsOrDefault(lineErrors(res.Errors, orig))})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_add", "file", name, "added", res.Added)
	s.audit(r, "routing_add", name, "", fmt.Sprintf("добавлено %d, пропущено %d", res.Added, res.Skipped))
	s.redirectRouting(w, r, name)
}

func (s *Server) routingRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !reRoutingName.MatchString(name) {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	sel := r.PostForm["del"]
	if len(sel) == 0 {
		s.fileView(w, r, fileView{Status: http.StatusBadRequest, Errors: []string{"ничего не выбрано"}})
		return
	}
	res, err := s.nodeFor(r).PatchRouting(r.Context(), name, nodeapi.RoutingPatch{Remove: sel})
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_remove", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "routing_remove", name, st, tx)
		s.fileView(w, r, fileView{Status: st, Errors: []string{tx}})
		return
	}
	if noChange(res) {
		s.redirectMsg(w, r, routingHref(name), "routing_nochange", res.Skipped)
		return
	}
	if !res.Applied {
		s.fileView(w, r, fileView{Status: http.StatusBadRequest, Errors: errorsOrDefault(lineErrors(res.Errors, nil))})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_remove", "file", name, "removed", res.Removed)
	s.audit(r, "routing_remove", name, fmt.Sprintf("выбрано %d", len(sel)), fmt.Sprintf("удалено %d", res.Removed))
	s.redirectRouting(w, r, name)
}

func (s *Server) routingReplace(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !reRoutingName.MatchString(name) {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	text := strings.ReplaceAll(r.PostForm.Get("content"), "\r\n", "\n")
	sum := r.PostForm.Get("base_sha256")
	if !reSHA256.MatchString(sum) {
		s.fileView(w, r, fileView{Tab: "full", FullText: text, HasFull: true, Status: http.StatusBadRequest,
			Errors: []string{"форма устарела: откройте вкладку «Целиком» заново"}})
		return
	}
	res, err := s.nodeFor(r).ReplaceRouting(r.Context(), name, text, sum)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_replace", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "routing_replace", name, st, tx)
		s.fileView(w, r, fileView{Tab: "full", FullText: text, HasFull: true, BaseSHA: sum, Status: st, Errors: []string{tx}})
		return
	}
	if !res.Applied {
		s.fileView(w, r, fileView{Tab: "full", FullText: text, HasFull: true, BaseSHA: sum, Status: http.StatusBadRequest,
			Errors: errorsOrDefault(lineErrors(res.Errors, nil))})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_replace", "file", name, "lines", res.Lines)
	s.audit(r, "routing_replace", name, "", fmt.Sprintf("записей: %d", res.Lines))
	s.redirectRouting(w, r, name)
}

func (s *Server) routingRestore(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !reRoutingName.MatchString(name) {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	stamp := r.PostForm.Get("stamp")
	if !reRoutingStamp.MatchString(stamp) {
		s.fileView(w, r, fileView{Status: http.StatusBadRequest, Errors: []string{"метка копии не распознана"}})
		return
	}
	if _, err := s.nodeFor(r).RestoreRouting(r.Context(), name, stamp); err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_restore", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "routing_restore", name, st, tx)
		s.fileView(w, r, fileView{Status: st, Errors: []string{tx}})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_restore", "file", name, "stamp", stamp)
	s.audit(r, "routing_restore", name, "", stamp)
	s.redirectRouting(w, r, name)
}

// noChange: агент ответил 200, ошибок строк нет, а правка ничего не изменила
// (всё добавляемое уже есть, удаляемое не найдено) — это не ошибка.
func noChange(res nodeapi.RoutingPatchResult) bool {
	return !res.Applied && len(res.Errors) == 0 && res.Skipped > 0
}

// auditRefused пишет в журнал действий отказ агента (в том числе 409).
func (s *Server) auditRefused(r *http.Request, op, target string, status int, text string) {
	s.audit(r, op, target, "", fmt.Sprintf("отказ (%d): %s", status, text))
}

func errorsOrDefault(e []string) []string {
	if len(e) == 0 {
		return []string{"агент не применил изменения"}
	}
	return e
}

// redirectRouting ведёт на страницу списка с плашкой «вступят в силу после применения».
func (s *Server) redirectRouting(w http.ResponseWriter, r *http.Request, name string) {
	s.redirectMsg(w, r, routingHref(name), "routing_changed")
}
