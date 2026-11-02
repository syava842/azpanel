package node

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
)

const (
	defaultRoutingLimit = 200
	maxRoutingLimit     = 1000
	// maxRoutingBody — тело PUT/PATCH списков: строки по одной на 200 000 записей
	// и файл до 1 МБ в JSON с экранированием укладываются с запасом.
	maxRoutingBody = 8 << 20
)

func toRoutingFile(f antizapret.RoutingFile) nodeapi.RoutingFile {
	return nodeapi.RoutingFile{Name: f.Name, Kind: f.Kind, Title: f.Title, Lines: f.Lines, Bytes: f.Bytes}
}

func toLineErrors(in []antizapret.LineError) []nodeapi.RoutingLineError {
	out := make([]nodeapi.RoutingLineError, 0, len(in))
	for _, e := range in {
		out = append(out, nodeapi.RoutingLineError{Line: e.Line, Value: e.Value, Reason: e.Reason})
	}
	return out
}

// routingErr переводит ошибку списка в ответ; false — ошибки нет.
func (a *API) routingErr(w http.ResponseWriter, what string, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, antizapret.ErrNoList):
		writeErr(w, http.StatusNotFound, "такого списка нет")
	case errors.Is(err, antizapret.ErrReadOnly), errors.Is(err, antizapret.ErrBadStamp):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, antizapret.ErrTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
	case errors.Is(err, antizapret.ErrChanged):
		writeErr(w, http.StatusConflict, err.Error())
	case isBusy(err):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		a.fail(w, what, err)
	}
	return true
}

// isBusy — запись отложена из-за идущей задачи.
func isBusy(err error) bool {
	var be *antizapret.BusyError
	return errors.As(err, &be)
}

func (a *API) routingReady(w http.ResponseWriter) bool {
	if a.Routing == nil {
		writeErr(w, http.StatusServiceUnavailable, "списки маршрутизации не настроены")
		return false
	}
	return true
}

// decodeRouting — как decode, но слишком большое тело даёт 413.
func decodeRouting(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "запрос слишком большой — редактируйте по строкам")
			return false
		}
		writeErr(w, http.StatusBadRequest, "неверный запрос: "+err.Error())
		return false
	}
	return true
}

func (a *API) routingFiles(w http.ResponseWriter, r *http.Request) {
	if !a.routingReady(w) {
		return
	}
	files, err := a.Routing.Files()
	if a.routingErr(w, "списки не прочитаны", err) {
		return
	}
	out := make([]nodeapi.RoutingFile, 0, len(files))
	for _, f := range files {
		out = append(out, toRoutingFile(f))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) routingLines(w http.ResponseWriter, r *http.Request) {
	if !a.routingReady(w) {
		return
	}
	offset, limit := 0, defaultRoutingLimit
	if s := r.URL.Query().Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "offset — целое число от 0")
			return
		}
		offset = n
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "limit — целое число от 1")
			return
		}
		limit = min(n, maxRoutingLimit)
	}
	name := r.PathValue("name")
	pg, err := a.Routing.Lines(name, r.URL.Query().Get("q"), offset, limit)
	if a.routingErr(w, "список не прочитан", err) {
		return
	}
	writeJSON(w, http.StatusOK, nodeapi.RoutingPage{Name: name, Lines: pg.Lines, Total: pg.Total, Offset: offset, Limit: limit})
}

// routingRaw отдаёт файл как есть и sha256 его байтов.
func (a *API) routingRaw(w http.ResponseWriter, r *http.Request) {
	if !a.routingReady(w) {
		return
	}
	name := r.PathValue("name")
	content, sum, err := a.Routing.Raw(name)
	if a.routingErr(w, "список не прочитан", err) {
		return
	}
	writeJSON(w, http.StatusOK, nodeapi.RoutingRaw{Name: name, Content: content, SHA256: sum})
}

func (a *API) routingPatch(w http.ResponseWriter, r *http.Request) {
	if !a.routingReady(w) {
		return
	}
	var req nodeapi.RoutingPatch
	if !decodeRouting(w, r, &req) {
		return
	}
	name := r.PathValue("name")
	res, err := a.Routing.Patch(name, req.Add, req.Remove)
	if a.routingErr(w, "список не изменён", err) {
		return
	}
	if res.Applied {
		a.Log.Info("список изменён", "file", name, "added", res.Added, "removed", res.Removed)
	}
	writeJSON(w, http.StatusOK, nodeapi.RoutingPatchResult{
		Applied: res.Applied, Added: res.Added, Removed: res.Removed, Skipped: res.Skipped, Errors: toLineErrors(res.Errors),
	})
}

func (a *API) routingPut(w http.ResponseWriter, r *http.Request) {
	if !a.routingReady(w) {
		return
	}
	var req nodeapi.RoutingPut
	if !decodeRouting(w, r, &req) {
		return
	}
	name := r.PathValue("name")
	n, errs, err := a.Routing.Replace(name, req.Content, req.BaseSHA256)
	if a.routingErr(w, "список не заменён", err) {
		return
	}
	applied := len(errs) == 0
	if applied {
		a.Log.Info("список заменён целиком", "file", name, "lines", n)
	}
	writeJSON(w, http.StatusOK, nodeapi.RoutingPutResult{Applied: applied, Lines: n, Errors: toLineErrors(errs)})
}

func (a *API) routingBackups(w http.ResponseWriter, r *http.Request) {
	if !a.routingReady(w) {
		return
	}
	list, err := a.Routing.BackupList(r.PathValue("name"))
	if a.routingErr(w, "копии не прочитаны", err) {
		return
	}
	out := make([]nodeapi.RoutingBackup, 0, len(list))
	for _, b := range list {
		out = append(out, nodeapi.RoutingBackup{Stamp: b.Stamp, Bytes: b.Bytes})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) routingRestore(w http.ResponseWriter, r *http.Request) {
	if !a.routingReady(w) {
		return
	}
	name, stamp := r.PathValue("name"), r.PathValue("stamp")
	if a.routingErr(w, "копия не возвращена", a.Routing.Restore(name, stamp)) {
		return
	}
	a.Log.Info("список возвращён из копии", "file", name, "stamp", stamp)
	f, err := a.Routing.File(name)
	if a.routingErr(w, "список не прочитан", err) {
		return
	}
	writeJSON(w, http.StatusOK, toRoutingFile(f))
}
