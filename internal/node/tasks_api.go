package node

import (
	"errors"
	"net/http"
	"path/filepath"
	"regexp"

	"github.com/syava842/azpanel/internal/nodeapi"
)

var taskIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// profilesBusy отвечает 409, если идёт задача profiles: client.sh 7 пересоздаёт
// профили всех клиентов, и параллельный client.sh из API клиентов правил бы
// те же файлы. Вызывается под a.ops: задача profiles стартует тоже под ops,
// поэтому гонки между проверкой и стартом нет.
func (a *API) profilesBusy(w http.ResponseWriter) bool {
	if a.azActive(w) {
		return true
	}
	if a.Tasks == nil {
		return false
	}
	if t, ok := a.Tasks.Running(); ok {
		switch t.Kind {
		case TaskProfiles:
			writeErr(w, http.StatusConflict, "идёт задача пересоздания профилей — дождитесь её окончания")
			return true
		case TaskBackup:
			// client.sh 8 читает те же файлы клиентов: архив вышел бы несогласованным.
			writeErr(w, http.StatusConflict, "идёт бэкап сервера — дождитесь его окончания")
			return true
		}
	}
	return false
}

func (a *API) listTasks(w http.ResponseWriter, r *http.Request) {
	out := []nodeapi.Task{}
	if a.Tasks != nil {
		out = a.Tasks.List()
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getTask(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if a.Tasks == nil || !taskIDRe.MatchString(id) {
		writeErr(w, http.StatusNotFound, "задачи с таким номером нет")
		return
	}
	t, ok := a.Tasks.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "задачи с таким номером нет")
		return
	}
	tail, err := a.Tasks.Tail(t)
	if err != nil {
		a.fail(w, "журнал задачи не прочитан", err)
		return
	}
	writeJSON(w, http.StatusOK, nodeapi.TaskDetail{Task: t, Tail: tail})
}

func (a *API) applyRouting(w http.ResponseWriter, r *http.Request) {
	a.startTask(w, TaskDoall, []string{filepath.Join(a.AntiZapretDir, "doall.sh")}, false)
}

func (a *API) restartAntiZapret(w http.ResponseWriter, r *http.Request) {
	a.startTask(w, TaskRestart, []string{"systemctl", "restart", "antizapret"}, false)
}

func (a *API) rebuildProfiles(w http.ResponseWriter, r *http.Request) {
	a.startTask(w, TaskProfiles, []string{filepath.Join(a.AntiZapretDir, "client.sh"), "7"}, true)
}

// startTask запускает задачу и отвечает 202. withClientOps — задача трогает
// файлы клиентов: стартует только когда нет операции client.sh из API клиентов.
func (a *API) startTask(w http.ResponseWriter, kind string, argv []string, withClientOps bool) {
	if a.Tasks == nil {
		writeErr(w, http.StatusServiceUnavailable, "фоновые задачи не настроены")
		return
	}
	if a.azActive(w) {
		return
	}
	if withClientOps {
		if !a.ops.TryLock() {
			writeErr(w, http.StatusConflict, "идёт операция над клиентом — повторите, когда она закончится")
			return
		}
		defer a.ops.Unlock()
	}
	t, err := a.Tasks.Start(kind, argv)
	var busy *BusyError
	switch {
	case errors.As(err, &busy):
		writeErr(w, http.StatusConflict, busy.Error())
		return
	case err != nil:
		a.fail(w, "задача не запущена", err)
		return
	}
	a.Log.Info("задача запущена", "id", t.ID, "kind", kind)
	writeJSON(w, http.StatusAccepted, t)
}
