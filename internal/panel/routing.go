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
	fullTabPages    = 200     // страховка цикла сборки файла: 200 страниц по 1000 строк
	maxPageNumber   = 100000
)

var (
	reRoutingName  = regexp.MustCompile(`^[a-z0-9-]+\.txt$`)
	reRoutingStamp = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z$`)
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
	files, err := s.Node.RoutingFiles(r.Context())
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
	Errors   []string
	Changed  bool
	Status   int
}

// routingFile — страница списка: поиск, страницы по 200 строк, правка.
func (s *Server) routingFile(w http.ResponseWriter, r *http.Request) {
	v := fileView{Tab: r.URL.Query().Get("tab"), Changed: r.URL.Query().Get("msg") == "routing_changed", Status: http.StatusOK}
	s.fileView(w, r, v)
}

func (s *Server) fileView(w http.ResponseWriter, r *http.Request, v fileView) {
	name := r.PathValue("name")
	if !reRoutingName.MatchString(name) {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	files, err := s.Node.RoutingFiles(r.Context())
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
	editable := file.Kind != ""
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page := 1
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n >= 1 {
		page = min(n, maxPageNumber)
	}
	canFull := editable && file.Bytes <= fullTabMax
	full := v.Tab == "full" && canFull
	data := map[string]any{"File": file, "Name": name, "Href": routingHref(name), "Editable": editable, "Q": q,
		"Size": humanBytes(uint64(max(file.Bytes, 0))), "KindTitle": kindTitles[file.Kind],
		"CanFull": canFull, "Full": full, "AddText": v.AddText, "Changed": v.Changed}
	if len(v.Errors) > 0 {
		data["Errors"] = v.Errors
	}
	if full {
		text := v.FullText
		if !v.HasFull {
			if text, err = s.loadWhole(r, name); err != nil {
				st, tx := s.agentErr(err)
				s.errorPage(w, r, st, tx)
				return
			}
		}
		data["FullText"] = text
	} else {
		pg, err := s.Node.RoutingLines(r.Context(), name, nodeapi.RoutingListOpts{Query: q, Offset: (page - 1) * routingPageSize, Limit: routingPageSize})
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
		if bs, err := s.Node.RoutingBackups(r.Context(), name); err != nil {
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

// loadWhole собирает записи списка страницами по 1000 (предел агента).
func (s *Server) loadWhole(r *http.Request, name string) (string, error) {
	var b strings.Builder
	for i := 0; i < fullTabPages; i++ {
		pg, err := s.Node.RoutingLines(r.Context(), name, nodeapi.RoutingListOpts{Offset: i * 1000, Limit: 1000})
		if err != nil {
			return "", err
		}
		for _, l := range pg.Lines {
			b.WriteString(l)
			b.WriteByte('\n')
		}
		if (i+1)*1000 >= pg.Total || len(pg.Lines) == 0 {
			break
		}
	}
	return b.String(), nil
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
	res, err := s.Node.PatchRouting(r.Context(), name, nodeapi.RoutingPatch{Add: lines})
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_add", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.fileView(w, r, fileView{AddText: text, Status: st, Errors: []string{tx}})
		return
	}
	if !res.Applied { // агент отвечает 200, но файл не менялся
		s.fileView(w, r, fileView{AddText: text, Status: http.StatusBadRequest, Errors: errorsOrDefault(lineErrors(res.Errors, orig))})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_add", "file", name, "added", res.Added)
	s.audit(r, "routing_add", name, "", fmt.Sprintf("добавлено %d, пропущено %d", res.Added, res.Skipped))
	redirectRouting(w, r, name)
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
	res, err := s.Node.PatchRouting(r.Context(), name, nodeapi.RoutingPatch{Remove: sel})
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_remove", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.fileView(w, r, fileView{Status: st, Errors: []string{tx}})
		return
	}
	if !res.Applied {
		s.fileView(w, r, fileView{Status: http.StatusBadRequest, Errors: errorsOrDefault(lineErrors(res.Errors, nil))})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_remove", "file", name, "removed", res.Removed)
	s.audit(r, "routing_remove", name, fmt.Sprintf("выбрано %d", len(sel)), fmt.Sprintf("удалено %d", res.Removed))
	redirectRouting(w, r, name)
}

func (s *Server) routingReplace(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !reRoutingName.MatchString(name) {
		s.errorPage(w, r, http.StatusNotFound, "список не найден")
		return
	}
	text := strings.ReplaceAll(r.PostForm.Get("content"), "\r\n", "\n")
	res, err := s.Node.ReplaceRouting(r.Context(), name, text)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_replace", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.fileView(w, r, fileView{Tab: "full", FullText: text, HasFull: true, Status: st, Errors: []string{tx}})
		return
	}
	if !res.Applied {
		s.fileView(w, r, fileView{Tab: "full", FullText: text, HasFull: true, Status: http.StatusBadRequest,
			Errors: errorsOrDefault(lineErrors(res.Errors, nil))})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_replace", "file", name, "lines", res.Lines)
	s.audit(r, "routing_replace", name, "", fmt.Sprintf("записей: %d", res.Lines))
	redirectRouting(w, r, name)
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
	if _, err := s.Node.RestoreRouting(r.Context(), name, stamp); err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "routing_restore", "file", name, "err", err)
		st, tx := s.agentErr(err)
		s.fileView(w, r, fileView{Status: st, Errors: []string{tx}})
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "routing_restore", "file", name, "stamp", stamp)
	s.audit(r, "routing_restore", name, "", stamp)
	redirectRouting(w, r, name)
}

func errorsOrDefault(e []string) []string {
	if len(e) == 0 {
		return []string{"агент не применил изменения"}
	}
	return e
}

// redirectRouting ведёт на страницу списка с плашкой «вступят в силу после применения».
func redirectRouting(w http.ResponseWriter, r *http.Request, name string) {
	redirectMsg(w, r, routingHref(name), "routing_changed")
}
