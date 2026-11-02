package node

import (
	"errors"
	"net/http"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
)

func (a *API) setupReady(w http.ResponseWriter) bool {
	if a.Setup == nil {
		writeErr(w, http.StatusServiceUnavailable, "файл setup не настроен")
		return false
	}
	return true
}

func (a *API) getSetup(w http.ResponseWriter, r *http.Request) {
	if !a.setupReady(w) {
		return
	}
	list, err := a.Setup.List()
	if err != nil {
		a.fail(w, "setup не прочитан", err)
		return
	}
	out := make([]nodeapi.SetupEntry, 0, len(list))
	for _, e := range list {
		apply := e.Apply
		if apply == nil {
			apply = []string{}
		}
		out = append(out, nodeapi.SetupEntry{
			Key: e.Key, Value: e.Value, Kind: e.Kind, Apply: apply, Title: e.Title, Editable: e.Editable,
			Hint: e.Hint, Options: e.Options, Min: e.Min, Max: e.Max,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) putSetup(w http.ResponseWriter, r *http.Request) {
	if !a.setupReady(w) {
		return
	}
	var req nodeapi.SetupPut
	if !decode(w, r, &req) {
		return
	}
	if len(req.Values) == 0 {
		writeErr(w, http.StatusBadRequest, "не указано ни одного значения")
		return
	}
	res, err := a.Setup.Set(req.Values)
	var bad *antizapret.SetupError
	switch {
	case errors.As(err, &bad):
		writeErr(w, http.StatusBadRequest, bad.Error())
		return
	case err != nil:
		a.fail(w, "setup не записан", err)
		return
	}
	if len(res.Changed) > 0 {
		a.Log.Info("setup изменён", "keys", res.Changed, "apply", res.Apply)
	}
	writeJSON(w, http.StatusOK, nodeapi.SetupResult{Changed: res.Changed, Apply: res.Apply})
}
