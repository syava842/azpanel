package node

import (
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/update"
	"github.com/syava842/azpanel/internal/updateapi"
)

// TaskSelfUpdate — обновление самого azpanel. Идёт задачей systemd-run, чтобы
// пережить перезапуск агента, который сама же и делает.
const TaskSelfUpdate = "selfupdate"

// maxUpdateBody — предел тела POST /v1/update; для остальных маршрутов он
// остаётся прежним.
const maxUpdateBody = nodeapi.MaxUpdateBody

func init() {
	DefaultTaskTimeouts[TaskSelfUpdate] = 600 * time.Second
}

// UpdateService — самообновление агента. Подпись проверяет сам агент ключом,
// вшитым в бинарник; панели в этом он не верит. Разбор запроса и проверки —
// в updateapi, общем с агентом прокси.
type UpdateService struct {
	Root      string            // корень установки (/opt/azpanel)
	Pub       ed25519.PublicKey // ключ релизов; в тестах — тестовый
	Self      string            // путь к бинарнику azpanel, которым запускается задача
	ParamsDir string            // каталог файлов параметров задач (0700)
	StageDir  string            // куда складываются принятые файлы до задачи (0700)
	// Exec запускает новый бинарник для предварительной миграции конфига; nil —
	// настоящий запуск.
	Exec update.ExecFunc
}

// updateParams — JSON-контракт режима `azpanel internal selfupdate`.
type updateParams = updateapi.Params

func (a *API) registerUpdate(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/update", a.updatePost)
	mux.HandleFunc("GET /v1/update/result", a.updateResult)
}

// updateService собирает общий обработчик; задача запускается как остальные
// задачи агента (одна за раз, с журналом).
func (a *API) updateService() *updateapi.Service {
	s := a.Update
	return &updateapi.Service{
		Root: s.Root, Pub: s.Pub, Self: s.Self, ParamsDir: s.ParamsDir, StageDir: s.StageDir,
		Exec: s.Exec, Version: a.Version, Log: a.Log,
		Launch: func(w http.ResponseWriter, argv []string, params string) (any, bool) {
			t, ok := a.launchExtTask(w, TaskSelfUpdate, argv, params)
			return t, ok
		},
	}
}

func (a *API) updateResult(w http.ResponseWriter, r *http.Request) {
	if a.Update == nil {
		writeErr(w, http.StatusServiceUnavailable, "обновление не настроено")
		return
	}
	a.updateService().Result(w, r)
}

func (a *API) updatePost(w http.ResponseWriter, r *http.Request) {
	if a.Update == nil {
		writeErr(w, http.StatusServiceUnavailable, "обновление не настроено")
		return
	}
	a.updateService().Post(w, r)
}
