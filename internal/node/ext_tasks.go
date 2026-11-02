package node

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Виды задач telemt (этап 10). Они идут вне песочницы агента:
// пишут в /etc/telemt и /usr/local/bin и перезапускают службу.
const (
	TaskTelemtUpdate  = "telemt-update"
	TaskTelemtInstall = "telemt-install"
	TaskTelemtRestart = "telemt-restart"
)

func init() {
	DefaultTaskTimeouts[TaskTelemtUpdate] = 600 * time.Second
	DefaultTaskTimeouts[TaskTelemtInstall] = 900 * time.Second
	DefaultTaskTimeouts[TaskTelemtRestart] = 120 * time.Second
}

// writeParamsFile кладёт параметры задачи (возможно, секретные) в файл 0600
// и возвращает путь. Задача читает файл и сразу удаляет его; в командную
// строку и окружение юнита секреты не попадают.
func writeParamsFile(dir string, v any) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "params-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return filepath.Clean(f.Name()), nil
}

// startExtTask запускает задачу и отвечает 202 с описанием задачи.
func (a *API) startExtTask(w http.ResponseWriter, kind string, argv []string, params string) {
	if t, ok := a.launchExtTask(w, kind, argv, params); ok {
		writeJSON(w, http.StatusAccepted, t)
	}
}

// launchExtTask запускает задачу; при отказе сам отвечает ошибкой. params —
// файл параметров: не запустилась задача — файл удаляется, секретам в нём
// делать нечего.
func (a *API) launchExtTask(w http.ResponseWriter, kind string, argv []string, params string) (Task, bool) {
	fail := func() {
		if params != "" {
			os.Remove(params)
		}
	}
	if a.Tasks == nil {
		fail()
		writeErr(w, http.StatusServiceUnavailable, "фоновые задачи не настроены")
		return Task{}, false
	}
	if a.azActive(w) {
		fail()
		return Task{}, false
	}
	t, err := a.Tasks.Start(kind, argv)
	var busy *BusyError
	switch {
	case errors.As(err, &busy):
		fail()
		writeErr(w, http.StatusConflict, busy.Error())
		return Task{}, false
	case err != nil:
		fail()
		a.fail(w, "задача не запущена", err)
		return Task{}, false
	}
	a.Log.Info("задача запущена", "id", t.ID, "kind", kind)
	return t, true
}
