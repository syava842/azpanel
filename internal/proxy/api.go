package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/proxyapi"
	"github.com/syava842/azpanel/internal/sysinfo"
	"github.com/syava842/azpanel/internal/updateapi"
)

const maxAPIBody = 64 << 10

// API — HTTP API прокси-агента для панели: токен узла, заголовок протокола
// и коды ошибок — как у агента узла.
type API struct {
	Token     string
	Version   string
	Apply     *Applier
	Conntrack func(ctx context.Context) (io.ReadCloser, error)
	Sampler   *sysinfo.Sampler
	// Update — самообновление (POST /v1/update) тем же кодом, что у агента
	// узла; nil — маршруты не регистрируются.
	Update *updateapi.Service
	Log    *slog.Logger
	Now    func() time.Time
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", a.info)
	mux.HandleFunc("GET /v1/proxy/state", a.state)
	mux.HandleFunc("GET /v1/proxy/conntrack", a.conntrack)
	mux.HandleFunc("PUT /v1/proxy/target", a.setTarget)
	if a.Update != nil {
		mux.HandleFunc("POST /v1/update", a.Update.Post)
		mux.HandleFunc("GET /v1/update/result", a.Update.Result)
	}
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
		if r.URL.Path == "/v1/update" && r.Method == http.MethodPost {
			limit = nodeapi.MaxUpdateBody // архив релиза не влезает в 64 КБ
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func (a *API) info(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, nodeapi.Info{Proto: nodeapi.Proto, Version: a.Version, Hostname: host})
}

// conns читает таблицу соединений.
func (a *API) conns(ctx context.Context) ([]proxyapi.Conn, error) {
	rc, err := a.Conntrack(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return ParseConntrack(rc), nil
}

func (a *API) state(w http.ResponseWriter, r *http.Request) {
	tb, err := a.Apply.Table(r.Context())
	if err != nil {
		a.fail(w, "правила nat не прочитаны", err)
		return
	}
	st := proxyapi.State{Alive: true, Groups: tb.Groups(), Forwards: make([]proxyapi.Forward, 0, len(tb.Forwards))}
	for _, f := range tb.Forwards {
		st.Forwards = append(st.Forwards, f.Forward)
	}
	if cs, err := a.conns(r.Context()); err != nil {
		a.Log.Warn("таблица соединений не прочитана", "err", err)
	} else {
		st.Connections = len(cs)
	}
	if snap, err := a.Sampler.Sample(a.Now()); err != nil {
		a.Log.Warn("ресурсы не прочитаны", "err", err)
	} else {
		st.Resources = snap
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *API) conntrack(w http.ResponseWriter, r *http.Request) {
	cs, err := a.conns(r.Context())
	if err != nil {
		a.fail(w, "таблица соединений не прочитана", err)
		return
	}
	if cs == nil {
		cs = []proxyapi.Conn{}
	}
	writeJSON(w, http.StatusOK, cs)
}

func (a *API) setTarget(w http.ResponseWriter, r *http.Request) {
	var req proxyapi.SetTarget
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "неверный запрос: "+err.Error())
		return
	}
	res, err := a.Apply.SetTarget(r.Context(), req.Group, req.IP)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, res)
	case IsInput(err):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNoRules), errors.Is(err, ErrChanged):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		a.fail(w, "адрес назначения не изменён", err)
	}
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
