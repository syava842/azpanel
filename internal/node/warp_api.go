package node

import (
	"net/http"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/warp"
)

// Виды задач WARP (этап 11): идут вне песочницы агента, пишут в /root/warper.
const (
	TaskWarpUpdate  = "warp-update"
	TaskWarpInstall = "warp-install"
	TaskWarpSync    = "warp-sync"
)

func init() {
	DefaultTaskTimeouts[TaskWarpUpdate] = 900 * time.Second
	DefaultTaskTimeouts[TaskWarpInstall] = 1800 * time.Second
	DefaultTaskTimeouts[TaskWarpSync] = 600 * time.Second
}

// WarpService — WARP на узле: чтение состояния самим агентом, изменения —
// задачами `azpanel internal warp-…` вне песочницы агента (пишут в
// /root/warper и перезапускают службы).
type WarpService struct {
	Warper    *warp.Warper
	Self      string // путь к бинарнику azpanel, которым запускаются задачи
	ParamsDir string // каталог файлов параметров задач (0700)
}

func (a *API) registerWarp(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/warp", a.warpSummary)
	mux.HandleFunc("GET /v1/warp/domains", a.warpDomains)
	mux.HandleFunc("GET /v1/warp/ips", a.warpIPs)
	mux.HandleFunc("POST /v1/warp/domains", a.warpEditDomains)
	mux.HandleFunc("POST /v1/warp/ips", a.warpEditIPs)
	mux.HandleFunc("POST /v1/warp/sync", a.warpSync)
	mux.HandleFunc("POST /v1/warp/update", a.warpUpdate)
	mux.HandleFunc("POST /v1/warp/install", a.warpInstall)
}

func (a *API) warpReady(w http.ResponseWriter) bool {
	if a.Warp == nil {
		writeErr(w, http.StatusServiceUnavailable, "WARP не настроен")
		return false
	}
	return true
}

// warpBuiltin — интерфейсы warp-* встроенного WARP AntiZapret (wg show). Без
// публичных ключей пиров: панели нужны только рукопожатие и счётчики.
func (a *API) warpBuiltin(r *http.Request) []nodeapi.WarpIface {
	out := []nodeapi.WarpIface{}
	if a.WGCmd == nil || a.WGShow == nil {
		return out
	}
	raw, err := a.WGCmd(r.Context(), "wg", "show", "interfaces")
	if err != nil {
		return out
	}
	for _, name := range strings.Fields(string(raw)) {
		if !strings.HasPrefix(name, "warp") {
			continue
		}
		iface := nodeapi.WarpIface{Name: name, Peers: []nodeapi.WarpPeer{}}
		peers, err := a.WGShow(r.Context(), name)
		if err != nil {
			out = append(out, iface)
			continue
		}
		for _, p := range peers {
			wp := nodeapi.WarpPeer{Endpoint: p.Endpoint, RxBytes: p.RxBytes, TxBytes: p.TxBytes}
			if !p.LatestHandshake.IsZero() {
				t := p.LatestHandshake
				wp.LatestHandshake = &t
			}
			iface.Peers = append(iface.Peers, wp)
		}
		out = append(out, iface)
	}
	return out
}

func (a *API) warpSummary(w http.ResponseWriter, r *http.Request) {
	if !a.warpReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, nodeapi.Warp{Builtin: a.warpBuiltin(r), AZ: a.Warp.Warper.Status(r.Context())})
}

func (a *API) warpLists(w http.ResponseWriter, r *http.Request, list func() ([]string, error), what string) {
	if !a.warpReady(w) {
		return
	}
	if _, ok := a.Warp.Warper.Version(); !ok {
		writeErr(w, http.StatusConflict, "AZ-WARP не установлен")
		return
	}
	lines, err := list()
	if err != nil {
		a.fail(w, what+" не прочитан", err)
		return
	}
	writeJSON(w, http.StatusOK, nodeapi.WarpList{Lines: lines})
}

func (a *API) warpDomains(w http.ResponseWriter, r *http.Request) {
	if a.Warp == nil {
		a.warpReady(w)
		return
	}
	a.warpLists(w, r, func() ([]string, error) { return a.Warp.Warper.Domains(r.Context()) }, "список доменов")
}

func (a *API) warpIPs(w http.ResponseWriter, r *http.Request) {
	if a.Warp == nil {
		a.warpReady(w)
		return
	}
	a.warpLists(w, r, func() ([]string, error) { return a.Warp.Warper.IPs(r.Context()) }, "список подсетей")
}

// warpRun запускает warp-run: команды warper по порядку, разделённые «--».
func (a *API) warpRun(w http.ResponseWriter, kind string, steps [][]string) {
	argv := []string{a.Warp.Self, "internal", "warp-run"}
	for _, s := range steps {
		argv = append(argv, "--")
		argv = append(argv, s...)
	}
	a.startExtTask(w, kind, argv, "")
}

// warpEdit — общая часть правок доменов и подсетей: допустимые действия и
// имя синхронизации различаются.
func (a *API) warpEdit(w http.ResponseWriter, r *http.Request, allowed map[string]bool, syncOp string) {
	if !a.warpReady(w) {
		return
	}
	var req nodeapi.WarpEdit
	if !decode(w, r, &req) {
		return
	}
	if _, ok := a.Warp.Warper.Version(); !ok {
		writeErr(w, http.StatusConflict, "AZ-WARP не установлен")
		return
	}
	for _, o := range req.Ops {
		if !allowed[o.Op] {
			writeErr(w, http.StatusBadRequest, "действие "+o.Op+" здесь не допускается")
			return
		}
	}
	if req.Sync {
		req.Ops = append(req.Ops, warp.Op{Op: syncOp})
	}
	steps, err := warp.Steps(req.Ops)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.warpRun(w, TaskWarpSync, steps)
}

func (a *API) warpEditDomains(w http.ResponseWriter, r *http.Request) {
	a.warpEdit(w, r, map[string]bool{"add": true, "remove": true, "enable": true, "disable": true, "save": true}, "sync")
}

func (a *API) warpEditIPs(w http.ResponseWriter, r *http.Request) {
	a.warpEdit(w, r, map[string]bool{"ipadd": true, "ipremove": true}, "ipsync")
}

func (a *API) warpSync(w http.ResponseWriter, r *http.Request) {
	if !a.warpReady(w) {
		return
	}
	if _, ok := a.Warp.Warper.Version(); !ok {
		writeErr(w, http.StatusConflict, "AZ-WARP не установлен")
		return
	}
	a.warpRun(w, TaskWarpSync, [][]string{{"sync"}})
}

func (a *API) warpUpdate(w http.ResponseWriter, r *http.Request) {
	if !a.warpReady(w) {
		return
	}
	if _, ok := a.Warp.Warper.Version(); !ok {
		writeErr(w, http.StatusConflict, "AZ-WARP не установлен")
		return
	}
	// Итог обновления — состояние без секретов и doctor в журнале задачи.
	a.warpRun(w, TaskWarpUpdate, [][]string{{"update"}, {warp.StatusJSONStep}, {"doctor"}})
}

func (a *API) warpInstall(w http.ResponseWriter, r *http.Request) {
	if !a.warpReady(w) {
		return
	}
	var ans warp.InstallAnswers
	if !decode(w, r, &ans) {
		return
	}
	if err := ans.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := a.Warp.Warper.Version(); ok {
		writeErr(w, http.StatusConflict, "AZ-WARP уже установлен — используйте обновление")
		return
	}
	file, err := writeParamsFile(a.Warp.ParamsDir, ans)
	if err != nil {
		a.fail(w, "параметры задачи не записаны", err)
		return
	}
	a.startExtTask(w, TaskWarpInstall, []string{a.Warp.Self, "internal", "warp-install", "--params", file}, file)
}
