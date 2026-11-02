package node

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const (
	maxAPIBody    = 64 << 10
	wgOnlineAfter = 3 * time.Minute // рукопожатие свежее — пир на связи
	killTimeout   = 2 * time.Second
	maxLimit      = 1000
)

// API — HTTP API агента для панели. Клиенты AntiZapret меняются только
// через client.sh; лимиты и блокировки — в limits.json, который читает хук.
type API struct {
	Token         string
	Version       string
	Tracker       *Tracker
	LimitsPath    string
	Inventory     antizapret.Inventory
	ClientSh      *antizapret.ClientSh
	AntiZapretDir string
	BackupDir     string // куда client.sh 8 кладёт backup*.tar.gz; пусто — /root
	SocketDir     string
	Sampler       *sysinfo.Sampler
	Denials       *Denials                   // отказы хука; nil — журнал пуст
	Tasks         *Tasks                     // фоновые задачи AntiZapret
	Routing       *antizapret.Routing        // списки config/*.txt; nil — не настроены
	Setup         *antizapret.SetupFile      // ключи setup; nil — не настроены
	AZ            *AZUpdater                 // обновление AntiZapret; nil — не настроено
	AZVersion     *antizapret.VersionService // версия AntiZapret по коммитам; nil — не настроена
	Services      func(ctx context.Context) ([]sysinfo.Service, error)
	WGShow        func(ctx context.Context, iface string) ([]antizapret.WGPeer, error)
	Kill          func(sock, name string, timeout time.Duration) (int, error)
	WGCmd         func(ctx context.Context, name string, args ...string) ([]byte, error) // wg, wg-quick; nil — сторож WireGuard выключен
	Log           *slog.Logger
	Now           func() time.Time

	// ops сериализует операции над клиентами: поиск + client.sh + уборка
	// лимитов, а также правки лимита и блокировки. Порядок захвата всегда
	// ops → mu; ops при удерживаемом mu не берётся.
	ops sync.Mutex
	mu  sync.Mutex // чтение-изменение-запись limits.json
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", a.info)
	mux.HandleFunc("GET /v1/clients", a.clients)
	mux.HandleFunc("POST /v1/clients", a.createClient)
	mux.HandleFunc("POST /v1/clients/openvpn/{name}/renew", a.renew)
	mux.HandleFunc("DELETE /v1/clients/{kind}/{name}", a.deleteClient)
	mux.HandleFunc("GET /v1/clients/{name}/profiles", a.profiles)
	mux.HandleFunc("GET /v1/clients/{name}/profiles/{kind}/{variant}/{file}", a.profile)
	mux.HandleFunc("PUT /v1/clients/{name}/limit", a.setLimit)
	mux.HandleFunc("PUT /v1/clients/{name}/blocked", a.setBlocked)
	mux.HandleFunc("GET /v1/sessions", a.sessions)
	mux.HandleFunc("GET /v1/system", a.system)
	mux.HandleFunc("GET /v1/denials", a.denials)
	mux.HandleFunc("GET /v1/tasks", a.listTasks)
	mux.HandleFunc("GET /v1/tasks/{id}", a.getTask)
	mux.HandleFunc("POST /v1/routing/apply", a.applyRouting)
	mux.HandleFunc("POST /v1/antizapret/restart", a.restartAntiZapret)
	mux.HandleFunc("POST /v1/clients/profiles/rebuild", a.rebuildProfiles)
	mux.HandleFunc("GET /v1/routing/files", a.routingFiles)
	mux.HandleFunc("GET /v1/routing/files/{name}", a.routingLines)
	mux.HandleFunc("GET /v1/routing/files/{name}/raw", a.routingRaw)
	mux.HandleFunc("PATCH /v1/routing/files/{name}", a.routingPatch)
	mux.HandleFunc("PUT /v1/routing/files/{name}", a.routingPut)
	mux.HandleFunc("GET /v1/routing/backups/{name}", a.routingBackups)
	mux.HandleFunc("POST /v1/routing/backups/{name}/{stamp}/restore", a.routingRestore)
	mux.HandleFunc("POST /v1/system/reboot", a.rebootServer)
	mux.HandleFunc("POST /v1/backups", a.createBackup)
	mux.HandleFunc("GET /v1/backups", a.listBackups)
	mux.HandleFunc("GET /v1/backups/{name}", a.getBackup)
	mux.HandleFunc("GET /v1/setup", a.getSetup)
	mux.HandleFunc("PUT /v1/setup", a.putSetup)
	mux.HandleFunc("GET /v1/antizapret/version", a.azVersion)
	mux.HandleFunc("GET /v1/antizapret/update", a.azState)
	mux.HandleFunc("GET /v1/antizapret/update/preflight", a.azPreflight)
	mux.HandleFunc("POST /v1/antizapret/update", a.azUpdate)
	mux.HandleFunc("POST /v1/antizapret/restore", a.azRestore)
	return a.auth(mux)
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(nodeapi.ProtoHeader, strconv.Itoa(nodeapi.Proto))
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || a.Token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.Token)) != 1 {
			a.Log.Warn("API: запрос без верного токена", "remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
			writeErr(w, http.StatusUnauthorized, "нужен токен узла")
			return
		}
		limit := int64(maxAPIBody)
		if strings.HasPrefix(r.URL.Path, "/v1/routing/files/") && (r.Method == http.MethodPut || r.Method == http.MethodPatch) {
			limit = maxRoutingBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// WireGuardEnabled — WIREGUARD_ENABLE=y в setup AntiZapret.
func (a *API) WireGuardEnabled() bool {
	m, err := antizapret.ReadSetup(filepath.Join(a.AntiZapretDir, "setup"))
	return err == nil && m["WIREGUARD_ENABLE"] == "y"
}

func (a *API) info(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, nodeapi.Info{Proto: nodeapi.Proto, Version: a.Version, Hostname: host, WireGuard: a.WireGuardEnabled()})
}

func (a *API) clients(w http.ResponseWriter, r *http.Request) {
	list, err := a.Inventory.Clients()
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	lim, err := limits.Load(a.LimitsPath)
	if err != nil {
		a.fail(w, "limits.json не прочитан", err)
		return
	}
	out := make([]nodeapi.Client, 0, len(list))
	for _, c := range list {
		nc := nodeapi.Client{Name: c.Name, OpenVPN: c.OpenVPN, WireGuard: c.WireGuard, Limit: lim.Limits[c.Name], Blocked: lim.Blocked[c.Name]}
		if !c.CertExpires.IsZero() {
			t := c.CertExpires
			nc.CertExpires = &t
		}
		out = append(out, nc)
	}
	writeJSON(w, http.StatusOK, out)
}

// find — клиент по имени; нет — found == false.
func (a *API) find(name string) (antizapret.ClientInfo, bool, error) {
	list, err := a.Inventory.Clients()
	if err != nil {
		return antizapret.ClientInfo{}, false, err
	}
	for _, c := range list {
		if c.Name == name {
			return c, true, nil
		}
	}
	return antizapret.ClientInfo{}, false, nil
}

// noCancel: обрыв соединения панелью не должен прерывать client.sh на
// середине — недоделанный клиент хуже долгого ответа. Тайм-аут у ClientSh свой.
func noCancel(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }

func (a *API) createClient(w http.ResponseWriter, r *http.Request) {
	var req nodeapi.CreateClient
	if !decode(w, r, &req) {
		return
	}
	if !limits.ValidName(req.Name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента: 1–32 символа a-z, A-Z, 0-9, _ и -")
		return
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	if a.profilesBusy(w) {
		return
	}
	c, _, err := a.find(req.Name)
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	// client.sh строит файлы профилей из имени без приставок antizapret-/vpn-:
	// «x», «antizapret-x» и «vpn-x» писали бы одни и те же файлы.
	list, err := a.Inventory.Clients()
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	for _, o := range list {
		if o.Name != req.Name && antizapret.ProfileBase(o.Name) == antizapret.ProfileBase(req.Name) {
			writeErr(w, http.StatusConflict, fmt.Sprintf("имя конфликтует с клиентом «%s»: у них общие файлы профилей", o.Name))
			return
		}
	}
	var out string
	switch req.Kind {
	case nodeapi.KindOpenVPN:
		if c.OpenVPN {
			// client.sh 1 для существующего клиента продлил бы сертификат.
			writeErr(w, http.StatusConflict, "клиент OpenVPN с таким именем уже есть")
			return
		}
		days := req.Days
		if days == 0 {
			days = antizapret.MaxCertDays
		}
		if days < 1 || days > antizapret.MaxCertDays {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("срок сертификата — 1..%d дней", antizapret.MaxCertDays))
			return
		}
		out, err = a.ClientSh.AddOpenVPN(noCancel(r), req.Name, days)
	case nodeapi.KindWireGuard:
		if c.WireGuard {
			writeErr(w, http.StatusConflict, "клиент WireGuard с таким именем уже есть")
			return
		}
		out, err = a.ClientSh.AddWireGuard(noCancel(r), req.Name)
	default:
		writeErr(w, http.StatusBadRequest, "kind — openvpn или wireguard")
		return
	}
	if err != nil {
		a.fail(w, "клиент не создан", err)
		return
	}
	a.Log.Info("клиент создан", "name", req.Name, "kind", req.Kind)
	a.guardAfterClientSh(noCancel(r))
	writeJSON(w, http.StatusCreated, nodeapi.Result{Output: out})
}

func (a *API) renew(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req nodeapi.Renew
	if !decode(w, r, &req) {
		return
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	if a.profilesBusy(w) {
		return
	}
	c, found, err := a.find(name)
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	if !found || !c.OpenVPN {
		writeErr(w, http.StatusNotFound, "клиента OpenVPN с таким именем нет")
		return
	}
	if req.Days < 1 || req.Days > antizapret.MaxCertDays {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("срок сертификата — 1..%d дней", antizapret.MaxCertDays))
		return
	}
	out, err := a.ClientSh.AddOpenVPN(noCancel(r), name, req.Days)
	if err != nil {
		a.fail(w, "сертификат не продлён", err)
		return
	}
	a.Log.Info("сертификат продлён", "name", name, "days", req.Days)
	a.guardAfterClientSh(noCancel(r))
	writeJSON(w, http.StatusOK, nodeapi.Result{Output: out})
}

func (a *API) deleteClient(w http.ResponseWriter, r *http.Request) {
	kind, name := r.PathValue("kind"), r.PathValue("name")
	a.ops.Lock()
	defer a.ops.Unlock()
	if a.profilesBusy(w) {
		return
	}
	c, _, err := a.find(name)
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	var out string
	switch kind {
	case nodeapi.KindOpenVPN:
		if !c.OpenVPN {
			writeErr(w, http.StatusNotFound, "клиента OpenVPN с таким именем нет")
			return
		}
		out, err = a.ClientSh.DeleteOpenVPN(noCancel(r), name)
	case nodeapi.KindWireGuard:
		if !c.WireGuard {
			writeErr(w, http.StatusNotFound, "клиента WireGuard с таким именем нет")
			return
		}
		out, err = a.ClientSh.DeleteWireGuard(noCancel(r), name)
	default:
		writeErr(w, http.StatusBadRequest, "kind — openvpn или wireguard")
		return
	}
	if err != nil {
		a.fail(w, "клиент не удалён", err)
		return
	}
	a.Log.Info("клиент удалён", "name", name, "kind", kind)
	a.guardAfterClientSh(noCancel(r))
	// Клиента не осталось ни в одном виде — его лимит и блокировка больше
	// ничего не значат, а с тем же именем может появиться новый клиент.
	_, still, err := a.find(name)
	switch {
	case err != nil:
		a.Log.Error("лимит удалённого клиента не снят: состав клиентов не прочитан", "name", name, "err", err)
	case !still:
		if err := a.updateLimits(func(d *limits.Data) { delete(d.Limits, name); delete(d.Blocked, name) }); err != nil {
			a.Log.Error("лимит удалённого клиента не снят", "name", name, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, nodeapi.Result{Output: out})
}

func (a *API) profiles(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	ps, err := antizapret.Profiles(a.AntiZapretDir, name)
	if err != nil {
		a.fail(w, "профили не прочитаны", err)
		return
	}
	out := make([]nodeapi.Profile, 0, len(ps))
	for _, p := range ps {
		out = append(out, nodeapi.Profile{Kind: p.Kind, Variant: p.Variant, File: p.File})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) profile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	p, err := antizapret.ProfilePath(a.AntiZapretDir, name, r.PathValue("kind"), r.PathValue("variant"), r.PathValue("file"))
	if errors.Is(err, antizapret.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "профиль не найден")
		return
	}
	if err != nil {
		a.fail(w, "профили не прочитаны", err)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		a.fail(w, "профиль не прочитан", err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(p)}))
	w.Write(data)
	a.Log.Info("профиль выдан", "name", name, "file", filepath.Base(p))
}

func (a *API) setLimit(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	var req nodeapi.SetLimit
	if !decode(w, r, &req) {
		return
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	if req.Limit < 0 || req.Limit > maxLimit {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("лимит — 0 (без ограничения) или 1..%d", maxLimit))
		return
	}
	err := a.updateLimits(func(d *limits.Data) {
		if req.Limit == 0 {
			delete(d.Limits, name)
		} else {
			d.Limits[name] = req.Limit
		}
	})
	if err != nil {
		a.fail(w, "лимит не записан", err)
		return
	}
	a.Log.Info("лимит изменён", "name", name, "limit", req.Limit)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setBlocked(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	var req nodeapi.SetBlocked
	if !decode(w, r, &req) {
		return
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	err := a.updateLimits(func(d *limits.Data) {
		if req.Blocked {
			d.Blocked[name] = true
		} else {
			delete(d.Blocked, name)
		}
	})
	if err != nil {
		a.fail(w, "блокировка не записана", err)
		return
	}
	var res nodeapi.Result
	if req.Blocked {
		// Файл уже записан: переподключение после kill хук не пустит.
		socks, err := antizapret.ListSockets(a.SocketDir)
		if err != nil {
			a.Log.Warn("сокеты OpenVPN не найдены, сессии не разорваны", "name", name, "err", err)
		}
		for _, s := range socks {
			n, err := a.Kill(s, name, killTimeout)
			if err != nil {
				a.Log.Warn("сессии клиента не разорваны", "socket", s, "name", name, "err", err)
				continue
			}
			res.Killed += n
		}
	}
	// WireGuard: пира нельзя «выгнать» командой, его снимают с интерфейса;
	// при разблокировке возвращают из конфига. Сбой не отменяет блокировку в
	// limits.json — сторож повторит проход по таймеру.
	if req.Blocked {
		n, err := a.guardWG(noCancel(r))
		if err != nil {
			a.Log.Warn("пиры WireGuard не сняты", "name", name, "err", err)
		}
		res.Killed += n
	} else if _, err := a.restoreWG(noCancel(r), name); err != nil {
		a.Log.Warn("пиры WireGuard не возвращены", "name", name, "err", err)
	}
	a.Log.Info("блокировка изменена", "name", name, "blocked", req.Blocked, "killed", res.Killed)
	writeJSON(w, http.StatusOK, res)
}

// updateLimits — чтение, правка, атомарная запись. Испорченный файл не
// перезаписывается: ошибка уходит вызывающему, хук продолжает работать
// по последней прочитанной версии.
func (a *API) updateLimits(edit func(*limits.Data)) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := limits.Load(a.LimitsPath)
	if err != nil {
		return err
	}
	edit(&d)
	return limits.Save(a.LimitsPath, d)
}

func (a *API) sessions(w http.ResponseWriter, r *http.Request) {
	out := []nodeapi.Session{}
	for _, s := range a.Tracker.Sessions() {
		since := s.ConnectedSince.UTC()
		out = append(out, nodeapi.Session{
			Kind: nodeapi.KindOpenVPN, Instance: s.Instance, Name: s.CommonName, Addr: s.RealAddr,
			RxBytes: s.BytesRx, TxBytes: s.BytesTx, Since: &since,
		})
	}
	peers, err := a.Inventory.WireGuardPeers()
	if err != nil {
		a.Log.Warn("конфиги WireGuard не прочитаны", "err", err)
		writeJSON(w, http.StatusOK, out)
		return
	}
	now := a.Now()
	for _, iface := range antizapret.WGInterfaces {
		list, err := a.WGShow(r.Context(), iface)
		if err != nil {
			a.Log.Warn("wg show не ответил", "iface", iface, "err", err)
			continue
		}
		for _, p := range list {
			name, ok := peers[iface][p.PublicKey]
			if !ok || p.LatestHandshake.IsZero() || now.Sub(p.LatestHandshake) > wgOnlineAfter {
				continue
			}
			hs := p.LatestHandshake.UTC()
			out = append(out, nodeapi.Session{
				Kind: nodeapi.KindWireGuard, Instance: iface, Name: name, Addr: p.Endpoint,
				RxBytes: p.RxBytes, TxBytes: p.TxBytes, LastHandshake: &hs,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// denials отдаёт отказы хука новее ?since=<unix>.
func (a *API) denials(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if q := r.URL.Query().Get("since"); q != "" {
		ts, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "since — секунды Unix")
			return
		}
		since = time.Unix(ts, 0)
	}
	out := []nodeapi.Denial{}
	if a.Denials != nil {
		out = a.Denials.Since(since)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) system(w http.ResponseWriter, r *http.Request) {
	snap, err := a.Sampler.Sample(a.Now())
	if err != nil {
		a.fail(w, "ресурсы не прочитаны", err)
		return
	}
	svcs, err := a.Services(r.Context())
	if err != nil {
		a.Log.Warn("состояние служб не получено", "err", err)
		svcs = []sysinfo.Service{}
	}
	writeJSON(w, http.StatusOK, nodeapi.System{Resources: snap, Services: svcs})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "неверный запрос: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, nodeapi.ErrorBody{Error: msg})
}

func (a *API) fail(w http.ResponseWriter, what string, err error) {
	a.Log.Error(what, "err", err)
	writeErr(w, http.StatusInternalServerError, what+": "+err.Error())
}
