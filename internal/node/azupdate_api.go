package node

import (
	"errors"
	"net/http"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
)

// azBusy возвращает проверку для Routing.Busy и SetupFile.Busy: пока идёт
// обновление или восстановление AntiZapret, списки и setup не правятся.
func azBusy(u *AZUpdater) func() error {
	return func() error {
		if u != nil && u.Active() {
			return &antizapret.BusyError{Reason: "идёт обновление AntiZapret — дождитесь его окончания и повторите"}
		}
		return nil
	}
}

// anyBusy объединяет проверки: первая вернувшая ошибку отклоняет запись.
func anyBusy(checks ...func() error) func() error {
	return func() error {
		for _, c := range checks {
			if err := c(); err != nil {
				return err
			}
		}
		return nil
	}
}

// azActive отвечает 409, если идёт обновление или восстановление AntiZapret:
// клиентов, перезагрузку службы и применение списков в это время не запускают.
func (a *API) azActive(w http.ResponseWriter) bool {
	if a.AZ != nil && a.AZ.Active() {
		writeErr(w, http.StatusConflict, "идёт обновление AntiZapret — дождитесь его окончания")
		return true
	}
	return false
}

func (a *API) azReady(w http.ResponseWriter) bool {
	if a.AZ == nil {
		writeErr(w, http.StatusServiceUnavailable, "обновление AntiZapret не настроено")
		return false
	}
	return true
}

func (a *API) azState(w http.ResponseWriter, r *http.Request) {
	if !a.azReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, a.AZ.State())
}

func (a *API) azPreflight(w http.ResponseWriter, r *http.Request) {
	if !a.azReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, a.AZ.Preflight())
}

func (a *API) azUpdate(w http.ResponseWriter, r *http.Request) {
	if !a.azReady(w) {
		return
	}
	var req nodeapi.AZUpdateRequest
	if !decode(w, r, &req) {
		return
	}
	// Как у пересоздания профилей: стартует, только когда нет операции client.sh.
	if !a.ops.TryLock() {
		writeErr(w, http.StatusConflict, "идёт операция над клиентом — повторите, когда она закончится")
		return
	}
	defer a.ops.Unlock()
	st, err := a.AZ.Start(r.Context(), req)
	a.azReply(w, "обновление не запущено", err, st)
}

func (a *API) azRestore(w http.ResponseWriter, r *http.Request) {
	if !a.azReady(w) {
		return
	}
	var req nodeapi.AZRestoreRequest
	if !decode(w, r, &req) {
		return
	}
	if !a.ops.TryLock() {
		writeErr(w, http.StatusConflict, "идёт операция над клиентом — повторите, когда она закончится")
		return
	}
	defer a.ops.Unlock()
	st, err := a.AZ.Restore(r.Context(), req.Backup)
	a.azReply(w, "восстановление не запущено", err, st)
}

func (a *API) azReply(w http.ResponseWriter, what string, err error, st nodeapi.AZUpdateState) {
	var busy *BusyError
	var pre *PreflightError
	switch {
	case errors.As(err, &busy):
		writeErr(w, http.StatusConflict, busy.Error())
	case errors.As(err, &pre) && pre.Busy:
		writeErr(w, http.StatusConflict, pre.Error())
	case errors.As(err, &pre):
		writeErr(w, http.StatusUnprocessableEntity, pre.Error())
	case err != nil:
		a.fail(w, what, err)
	default:
		writeJSON(w, http.StatusAccepted, st)
	}
}
