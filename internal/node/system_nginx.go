package node

import (
	"net/http"
	"os"
	"time"

	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/nodeapi"
)

// TaskNginxSnippet — правка фрагмента nginx панели: пишет в /etc/nginx и
// перезагружает nginx, поэтому идёт задачей вне песочницы агента.
const TaskNginxSnippet = "nginx-snippet"

func init() { DefaultTaskTimeouts[TaskNginxSnippet] = 120 * time.Second }

// NginxService — окружение правки фрагмента nginx.
type NginxService struct {
	Self      string // путь к бинарнику azpanel, которым запускается задача
	ParamsDir string // каталог файлов параметров задач (0700)
	// Present — стоит ли фрагмент панели; nil — проверка файла SnippetPath.
	Present func() bool
}

func (s *NginxService) present() bool {
	if s.Present != nil {
		return s.Present()
	}
	_, err := os.Stat(install.SnippetPath)
	return err == nil
}

func (a *API) registerNginx(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/system/nginx-snippet", a.nginxSnippet)
}

// nginxSnippet: POST /v1/system/nginx-snippet {base_path, upstream}. Фрагмента
// нет — 200 {"done":false}, nginx не трогается. Иначе 202 {"done":true,
// "task":{…}}: задача nginx-snippet (копия в backup/nginx, nginx -t, откат при
// отказе, reload); неудача видна в итоге и журнале задачи.
func (a *API) nginxSnippet(w http.ResponseWriter, r *http.Request) {
	if a.Nginx == nil {
		writeErr(w, http.StatusServiceUnavailable, "правка nginx не настроена")
		return
	}
	var req nodeapi.NginxSnippetRequest
	if !decode(w, r, &req) {
		return
	}
	if err := install.ValidateSnippetArgs(req.BasePath, req.Upstream); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !a.Nginx.present() {
		writeJSON(w, http.StatusOK, nodeapi.NginxSnippetResult{Done: false})
		return
	}
	file, err := writeParamsFile(a.Nginx.ParamsDir, req)
	if err != nil {
		a.fail(w, "параметры задачи не записаны", err)
		return
	}
	t, ok := a.launchExtTask(w, TaskNginxSnippet, []string{a.Nginx.Self, "internal", "nginx-snippet", "--params", file}, file)
	if ok {
		writeJSON(w, http.StatusAccepted, nodeapi.NginxSnippetResult{Done: true, Task: &t})
	}
}
