package panel

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

// Раздел WARP — родная веб-панель AZ-WARP (warper-web) во встроенном окне.
// Панель azpanel отдаёт её под своим адресом /warp/ui/, пересылая запросы на
// внутренний порт gunicorn: так окно открывается с того же источника, что и
// azpanel (X-Frame-Options: SAMEORIGIN у warper-web), а вход в него закрыт
// сессией администратора azpanel. Свой вход у AZ-WARP остаётся.

// warpModes — режимы установки AZ-WARP в порядке установщика.
var warpModes = []struct{ Value, Title string }{
	{"warp", "Cloudflare WARP"},
	{"slave", "Донор (Shadowsocks)"},
	{"wg", "WireGuard"},
	{"vless", "VLESS"},
	{"hy2", "Hysteria2"},
	{"openvpn", "OpenVPN"},
}

// warpUIPath — путь встроенной панели AZ-WARP без base_path.
const warpUIPath = "/warp/ui"

// warpPortTTL — сколько помнить внутренний порт веб-панели: окно шлёт десятки
// запросов, а `warper web status` на каждый — лишний запуск bash.
const warpPortTTL = 30 * time.Second

type warpPortCache struct {
	mu   sync.Mutex
	port int
	at   time.Time
}

func (s *Server) warpPage(w http.ResponseWriter, r *http.Request) {
	s.warpView(w, r, http.StatusOK, "", nil)
}

func (s *Server) warpView(w http.ResponseWriter, r *http.Request, status int, errText string, typed map[string]string) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	if typed == nil {
		typed = map[string]string{}
	}
	data := map[string]any{"Typed": typed, "Modes": warpModes}
	if errText != "" {
		data["Error"] = errText
	}
	wp, err := n.Warp(r.Context())
	if err != nil {
		_, tx := s.svcErr(err)
		data["WarpErr"] = "состояние AZ-WARP недоступно: " + tx
		s.render(w, r, status, "warp", data)
		return
	}
	data["AZ"], data["Web"] = wp.AZ, wp.Web
	switch {
	case !wp.AZ.Installed || !wp.Web.Installed:
		// форма установки AZ-WARP или его веб-панели
	case s.nodeIDFor(r) != store.LocalNode:
		data["NotLocal"] = true
	case !wp.Web.Active || wp.Web.BackendPort == 0:
		data["WebDown"] = true
	default:
		s.rememberWarpPort(wp.Web.BackendPort)
		data["Frame"] = true
	}
	s.render(w, r, status, "warp", data)
}

// warpWebAnswers — логин и пароль веб-панели из формы.
func warpWebAnswers(f map[string][]string) nodeapi.WarpWebAnswers {
	get := func(k string) string {
		if v := f[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	return nodeapi.WarpWebAnswers{User: strings.TrimSpace(get("web_user")), Password: get("web_pass")}
}

// warpInstall — форма вопросов установщика AZ-WARP; веб-панель ставится той
// же задачей. Секреты (ключи, пароли) в журнал, аудит и ответ не попадают.
func (s *Server) warpInstall(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	f := r.PostForm
	get := func(k string) string { return strings.TrimSpace(f.Get(k)) }
	typed := map[string]string{"mode": get("mode"), "subnet": get("subnet"), "mtu": get("mtu"), "warp_key": get("warp_key"),
		"slave_link": get("slave_link"), "slave_port": get("slave_port"), "proxy_link": get("proxy_link"),
		"wg_endpoint": get("wg_endpoint"), "wg_address": get("wg_address"), "wg_public_key": get("wg_public_key"),
		"wg_keepalive": get("wg_keepalive"), "wg_conf_index": get("wg_conf_index"), "ovpn_path": get("ovpn_path"), "ovpn_user": get("ovpn_user"),
		"web_user": get("web_user")}
	bad := func(text string) { s.warpView(w, r, http.StatusBadRequest, text, typed) }
	web := warpWebAnswers(f)
	a := nodeapi.WarpInstallAnswers{
		Mode: get("mode"), NoGemini: f.Get("no_gemini") == "1", NoChatGPT: f.Get("no_chatgpt") == "1",
		Subnet: get("subnet"), ForceSubnet: f.Get("force_subnet") == "1",
		SlaveLink: get("slave_link"), SlavePort: get("slave_port"), SlaveKey: get("slave_key"),
		ProxyLink: get("proxy_link"), OvpnPath: get("ovpn_path"), OvpnUser: get("ovpn_user"), OvpnPass: f.Get("ovpn_pass"),
		Web: &web,
	}
	for _, x := range []struct {
		key string
		dst *int
		msg string
	}{
		{"mtu", &a.MTU, "MTU: число от 1280 до 1500."},
		{"warp_key", &a.WarpKey, "Номер источника ключей: целое число."},
		{"wg_conf_index", &a.WGConfIndex, "Номер найденного .conf: целое число."},
	} {
		v := get(x.key)
		if v == "" {
			continue
		}
		num, err := strconv.Atoi(v)
		if err != nil {
			bad(x.msg)
			return
		}
		*x.dst = num
	}
	if a.Mode == "wg" && a.WGConfIndex == 0 {
		a.WG = &nodeapi.WarpWGManual{Endpoint: get("wg_endpoint"), Address: get("wg_address"), PrivateKey: get("wg_private_key"),
			PublicKey: get("wg_public_key"), PresharedKey: get("wg_preshared_key"), Keepalive: get("wg_keepalive")}
	}
	if err := a.Validate(); err != nil {
		bad(err.Error())
		return
	}
	t, err := n.InstallWarp(r.Context(), a)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "warp_install", "mode", a.Mode, "err", err)
		st, tx := s.svcErr(err)
		s.auditRefused(r, "warp_install", a.Mode, st, tx)
		s.warpView(w, r, st, tx, typed)
		return
	}
	detail := "режим " + a.Mode
	if a.Subnet != "" {
		detail += ", подсеть " + a.Subnet
	}
	if a.MTU != 0 {
		detail += ", MTU " + strconv.Itoa(a.MTU)
	}
	s.taskStarted(w, r, "warp_install", a.Mode, detail+", веб-панель "+web.User+";", t)
}

// warpWebInstall ставит веб-панель на уже установленный AZ-WARP.
func (s *Server) warpWebInstall(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	a := warpWebAnswers(r.PostForm)
	typed := map[string]string{"web_user": a.User}
	if err := a.Validate(); err != nil {
		s.warpView(w, r, http.StatusBadRequest, err.Error(), typed)
		return
	}
	t, err := n.InstallWarpWeb(r.Context(), a)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "warp_web_install", "err", err)
		st, tx := s.svcErr(err)
		s.auditRefused(r, "warp_web_install", a.User, st, tx)
		s.warpView(w, r, st, tx, typed)
		return
	}
	s.taskStarted(w, r, "warp_web_install", a.User, "логин "+a.User+";", t)
}

func (s *Server) rememberWarpPort(port int) {
	s.warpPort.mu.Lock()
	s.warpPort.port, s.warpPort.at = port, s.now()
	s.warpPort.mu.Unlock()
}

func (s *Server) forgetWarpPort() {
	s.warpPort.mu.Lock()
	s.warpPort.port = 0
	s.warpPort.mu.Unlock()
}

// warpBackend — внутренний порт веб-панели AZ-WARP; 0 — не установлена или
// не работает.
func (s *Server) warpBackend(ctx context.Context) int {
	s.warpPort.mu.Lock()
	port, at := s.warpPort.port, s.warpPort.at
	s.warpPort.mu.Unlock()
	if port != 0 && s.now().Sub(at) < warpPortTTL {
		return port
	}
	n := s.serviceNode()
	if n == nil {
		return 0
	}
	st, err := n.WarpWeb(ctx)
	if err != nil || !st.Installed || !st.Active || st.BackendPort == 0 {
		s.forgetWarpPort()
		return 0
	}
	s.rememberWarpPort(st.BackendPort)
	return st.BackendPort
}

// warpUI пересылает запрос во веб-панель AZ-WARP. Она живёт под префиксом
// base_path + /warp/ui (заголовок SCRIPT_NAME для gunicorn), видит настоящий
// хост и адрес клиента, а cookie сессии azpanel не получает.
func (s *Server) warpUI(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		s.errorPage(w, r, http.StatusForbidden, "запрос с чужого сайта")
		return
	}
	if s.nodeIDFor(r) != store.LocalNode {
		s.errorPage(w, r, http.StatusNotFound, "панель AZ-WARP открывается только для локального узла")
		return
	}
	port := s.warpBackend(r.Context())
	if port == 0 {
		s.errorPage(w, r, http.StatusBadGateway, "веб-панель AZ-WARP не установлена или не работает")
		return
	}
	prefix := strings.TrimSuffix(s.BasePath, "/") + warpUIPath
	client, proto := s.remoteHost(r), "http"
	if s.isHTTPS(r) {
		proto = "https"
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			pr.Out.URL.Path = prefix + strings.TrimPrefix(pr.In.URL.Path, warpUIPath)
			pr.Out.URL.RawPath = ""
			pr.Out.Host = pr.In.Host
			h := pr.Out.Header
			h.Set("SCRIPT_NAME", prefix)
			h.Set("X-Forwarded-Host", pr.In.Host)
			h.Set("X-Forwarded-Proto", proto)
			h.Set("X-Forwarded-For", client)
			dropCookie(h, cookieName)
		},
		FlushInterval: -1, // поток обновления AZ-WARP (text/event-stream) — без задержки
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.forgetWarpPort()
			s.Log.Warn("веб-панель AZ-WARP не ответила", "err", err)
			s.errorPage(w, r, http.StatusBadGateway, "веб-панель AZ-WARP не отвечает")
		},
	}
	// Защитные заголовки azpanel рассчитаны на её страницы без встроенных
	// скриптов; страницам AZ-WARP оставляем только запрет чужих рамок.
	h := w.Header()
	h.Del("Cache-Control")
	h.Set("Content-Security-Policy", "frame-ancestors 'self'")
	h.Set("Referrer-Policy", "same-origin")
	rp.ServeHTTP(w, r)
}

// dropCookie убирает из заголовка Cookie одну cookie по имени.
func dropCookie(h http.Header, name string) {
	var keep []string
	for _, line := range h.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			p := strings.TrimSpace(part)
			if p == "" || strings.HasPrefix(p, name+"=") {
				continue
			}
			keep = append(keep, p)
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}
