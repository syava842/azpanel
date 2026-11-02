package node

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/telemt"
)

// releaseTTL — как долго держится ответ GitHub о последнем релизе (60 запросов
// в час на адрес без токена).
const releaseTTL = time.Hour

// TelemtService — telemt на узле: чтение состояния самим агентом, изменения —
// задачами `azpanel internal telemt-…` вне песочницы агента.
type TelemtService struct {
	Env       *telemt.Env
	Self      string // путь к бинарнику azpanel, которым запускаются задачи
	ParamsDir string // каталог файлов параметров задач (0700)

	watch   telemt.Watcher
	mu      sync.Mutex
	release *nodeapi.TelemtRelease
	relAt   time.Time
}

func (a *API) registerTelemt(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/telemt", a.telemtStatus)
	mux.HandleFunc("GET /v1/telemt/release", a.telemtRelease)
	mux.HandleFunc("GET /v1/telemt/preflight", a.telemtPreflight)
	mux.HandleFunc("POST /v1/telemt/users", a.telemtAddUser)
	mux.HandleFunc("DELETE /v1/telemt/users/{name}", a.telemtRemoveUser)
	mux.HandleFunc("GET /v1/telemt/users/{name}/link", a.telemtLink)
	mux.HandleFunc("POST /v1/telemt/restart", a.telemtRestart)
	mux.HandleFunc("POST /v1/telemt/update", a.telemtUpdate)
	mux.HandleFunc("POST /v1/telemt/install", a.telemtInstall)
}

func (a *API) telemtReady(w http.ResponseWriter) bool {
	if a.Telemt == nil {
		writeErr(w, http.StatusServiceUnavailable, "telemt не настроен")
		return false
	}
	return true
}

func (a *API) telemtStatus(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	st := a.Telemt.Env.Status(r.Context())
	if st.Installed && st.ActiveState != "" {
		st.RestartsGrewAt = a.Telemt.watch.Observe(st.NRestarts, a.now())
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) telemtRelease(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	s := a.Telemt
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.release == nil || a.now().Sub(s.relAt) > releaseTTL {
		rel, err := s.Env.LatestRelease(r.Context())
		if err != nil {
			writeErr(w, http.StatusBadGateway, "последний релиз telemt не получен: "+err.Error())
			return
		}
		s.release = &nodeapi.TelemtRelease{Latest: rel.Version(), Checked: a.now()}
		s.relAt = a.now()
	}
	out := *s.release
	if cur, err := s.Env.Version(r.Context()); err == nil {
		out.Current = cur
		out.UpdateAvailable = telemt.CompareVersions(cur, out.Latest) < 0
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) telemtPreflight(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	if err != nil || port < 1 || port > 65535 {
		writeErr(w, http.StatusBadRequest, "порт: число 1–65535")
		return
	}
	env := a.Telemt.Env
	writeJSON(w, http.StatusOK, nodeapi.TelemtPreflight{
		Port: port, PortFree: env.CheckPort(port) == nil,
		Busy: env.BusyPorts(80, 443, 504, 508),
	})
}

// telemtTask запускает «azpanel internal <cmd> --params <файл>».
func (a *API) telemtTask(w http.ResponseWriter, kind, cmd string, params any) {
	s := a.Telemt
	file, err := writeParamsFile(s.ParamsDir, params)
	if err != nil {
		a.fail(w, "параметры задачи не записаны", err)
		return
	}
	a.startExtTask(w, kind, []string{s.Self, "internal", cmd, "--params", file}, file)
}

func (a *API) telemtAddUser(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	var req nodeapi.TelemtAddUser
	if !decode(w, r, &req) {
		return
	}
	if !telemt.ValidUserName(req.Name) {
		writeErr(w, http.StatusBadRequest, "имя пользователя: 1–32 символа a-z, A-Z, 0-9, _ и -")
		return
	}
	doc, err := a.Telemt.Env.ReadConfig()
	if err != nil {
		a.fail(w, "конфиг telemt не прочитан", err)
		return
	}
	secret := ""
	if req.Secret == "" {
		if secret, err = telemt.NewSecret(); err != nil {
			a.fail(w, "секрет не сгенерирован", err)
			return
		}
	} else if secret, err = telemt.SecretFromInput(req.Secret, doc.TLSDomain()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Дубли ловим сразу, а не в задаче: ответ 400 понятнее провала через минуту.
	trial, _ := telemt.ParseConfig(doc.Bytes())
	if err := trial.AddUser(req.Name, secret); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	file, err := writeParamsFile(a.Telemt.ParamsDir, telemt.ApplyParams{Op: "add", Name: req.Name, Secret: secret})
	if err != nil {
		a.fail(w, "параметры задачи не записаны", err)
		return
	}
	a.startUserTask(w, req.Name, secret, file)
}

func (a *API) startUserTask(w http.ResponseWriter, name, secret, file string) {
	t, ok := a.launchExtTask(w, TaskTelemtRestart, []string{a.Telemt.Self, "internal", "telemt-apply", "--params", file}, file)
	if !ok {
		return
	}
	res := nodeapi.TelemtUserResult{Task: t, Name: name}
	if secret != "" {
		res.SecretMasked = telemt.MaskSecret(secret)
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (a *API) telemtRemoveUser(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	name := r.PathValue("name")
	doc, err := a.Telemt.Env.ReadConfig()
	if err != nil {
		a.fail(w, "конфиг telemt не прочитан", err)
		return
	}
	trial, _ := telemt.ParseConfig(doc.Bytes())
	if err := trial.RemoveUser(name); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if len(trial.Users()) == 0 {
		writeErr(w, http.StatusConflict, "нельзя удалить последнего пользователя: telemt без пользователей не запустится")
		return
	}
	file, err := writeParamsFile(a.Telemt.ParamsDir, telemt.ApplyParams{Op: "remove", Name: name})
	if err != nil {
		a.fail(w, "параметры задачи не записаны", err)
		return
	}
	a.startUserTask(w, name, "", file)
}

func (a *API) telemtLink(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	li, err := a.Telemt.Env.UserLink(r.Context(), r.PathValue("name"), r.URL.Query().Get("server"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	// Секрет виден целиком — только в этом ответе, и пишем об этом в журнал агента без значения.
	a.Log.Info("ссылка telemt выдана", "user", li.Name)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, li)
}

func (a *API) telemtRestart(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	a.telemtTask(w, TaskTelemtRestart, "telemt-apply", telemt.ApplyParams{Op: "restart"})
}

func (a *API) telemtUpdate(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	if !a.Telemt.Env.Installed() {
		writeErr(w, http.StatusConflict, "telemt не установлен")
		return
	}
	s := a.Telemt
	a.startExtTask(w, TaskTelemtUpdate, []string{s.Self, "internal", "telemt-update"}, "")
}

func (a *API) telemtInstall(w http.ResponseWriter, r *http.Request) {
	if !a.telemtReady(w) {
		return
	}
	var p telemt.InstallParams
	if !decode(w, r, &p) {
		return
	}
	p.Defaults()
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	env := a.Telemt.Env
	if env.Installed() {
		writeErr(w, http.StatusConflict, "telemt уже установлен — используйте обновление")
		return
	}
	if err := env.CheckPort(p.Port); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	a.telemtTask(w, TaskTelemtInstall, "telemt-install", p)
}
