package panel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	tls  bool // gunicorn без nginx с HTTPS: говорит TLS сам
	at   time.Time
}

// warpTLSTransport — к gunicorn с самоподписанным сертификатом. Только
// 127.0.0.1 этого же сервера: проверять сертификат там не от чего.
var warpTLSTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // только loopback
	return t
}()

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
	data["AZ"], data["Web"], data["Opt"] = wp.AZ, wp.Web, wp.Install
	switch {
	case !wp.AZ.Installed || !wp.Web.Installed:
		// форма установки AZ-WARP или его веб-панели
	case s.nodeIDFor(r) != store.LocalNode:
		data["NotLocal"] = true
	case !wp.Web.Active || wp.Web.BackendPort == 0:
		data["WebDown"] = true
	default:
		s.rememberWarpPort(wp.Web)
		data["Frame"] = true
	}
	s.render(w, r, status, "warp", data)
}

// warpWebAnswers — ответы установщику веб-панели из формы. Неверный порт —
// ошибка, а не умолчание: установщик получил бы не то, что просили.
func warpWebAnswers(f url.Values) (nodeapi.WarpWebAnswers, error) {
	a := nodeapi.WarpWebAnswers{User: strings.TrimSpace(f.Get("web_user")), Password: f.Get("web_pass"),
		HTTPS: f.Get("web_https") == "1", Domain: strings.TrimSpace(f.Get("web_domain")), Publish: strings.TrimSpace(f.Get("web_publish"))}
	for _, x := range []struct {
		key string
		dst *int
	}{{"web_port", &a.Port}, {"web_backend_port", &a.BackendPort}} {
		v := strings.TrimSpace(f.Get(x.key))
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return a, errors.New("порт веб-панели: число от 1 до 65535")
		}
		*x.dst = n
	}
	return a, nil
}

// warpTyped — введённое в форму без секретов: вернуть при ошибке.
func warpTyped(f url.Values) map[string]string {
	typed := map[string]string{}
	for _, k := range []string{"mode", "subnet", "force_subnet", "mtu", "warp_source", "gemini", "chatgpt",
		"slave_link", "slave_port", "proxy_link", "wg_conf", "wg_endpoint", "wg_address", "wg_public_key", "wg_keepalive",
		"ovpn_file", "ovpn_path", "ovpn_user", "web_user", "web_port", "web_backend_port", "web_https", "web_domain", "web_publish"} {
		typed[k] = strings.TrimSpace(f.Get(k))
	}
	return typed
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
	typed := warpTyped(f)
	bad := func(text string) { s.warpView(w, r, http.StatusBadRequest, text, typed) }
	web, err := warpWebAnswers(f)
	if err != nil {
		bad(err.Error())
		return
	}
	a := nodeapi.WarpInstallAnswers{
		Mode: get("mode"), Gemini: f.Get("gemini") == "1", ChatGPT: f.Get("chatgpt") == "1",
		Subnet: get("subnet"), ForceSubnet: f.Get("force_subnet") == "1", WarpSource: get("warp_source"),
		ProxyLink: get("proxy_link"), Web: &web,
	}
	switch a.Mode {
	case "slave":
		a.SlaveLink, a.SlavePort, a.SlaveKey = get("slave_link"), get("slave_port"), get("slave_key")
	case "wg":
		if a.WGConf = get("wg_conf"); a.WGConf == "" {
			a.WG = &nodeapi.WarpWGManual{Endpoint: get("wg_endpoint"), Address: get("wg_address"), PrivateKey: get("wg_private_key"),
				PublicKey: get("wg_public_key"), PresharedKey: get("wg_preshared_key"), Keepalive: get("wg_keepalive")}
		}
	case "openvpn":
		if a.OvpnPath = get("ovpn_file"); a.OvpnPath == "" {
			a.OvpnPath = get("ovpn_path")
		}
		a.OvpnUser, a.OvpnPass = get("ovpn_user"), f.Get("ovpn_pass")
	}
	if a.Mode != "vless" && a.Mode != "hy2" {
		a.ProxyLink = ""
	}
	if a.Mode != "warp" {
		a.WarpSource = ""
	}
	if v := get("mtu"); v != "" {
		if a.MTU, err = strconv.Atoi(v); err != nil {
			bad("MTU: число от 1280 до 1500.")
			return
		}
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
	if a.WarpSource != "" {
		detail += ", ключи " + a.WarpSource
	}
	var lists []string
	if a.Gemini {
		lists = append(lists, "Gemini")
	}
	if a.ChatGPT {
		lists = append(lists, "ChatGPT")
	}
	if len(lists) > 0 {
		detail += ", домены " + strings.Join(lists, " и ")
	}
	s.taskStarted(w, r, "warp_install", a.Mode, detail+", веб-панель "+web.User+";", t)
}

// warpWebInstall ставит веб-панель на уже установленный AZ-WARP.
func (s *Server) warpWebInstall(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	a, err := warpWebAnswers(r.PostForm)
	typed := warpTyped(r.PostForm)
	if err == nil {
		err = a.Validate()
	}
	if err != nil {
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

func (s *Server) rememberWarpPort(st nodeapi.WarpWeb) {
	s.warpPort.mu.Lock()
	s.warpPort.port, s.warpPort.tls, s.warpPort.at = st.BackendPort, st.TLS, s.now()
	s.warpPort.mu.Unlock()
}

func (s *Server) forgetWarpPort() {
	s.warpPort.mu.Lock()
	s.warpPort.port = 0
	s.warpPort.mu.Unlock()
}

// warpBackend — порт веб-панели AZ-WARP на 127.0.0.1 и говорит ли она TLS;
// порт 0 — не установлена или не работает.
func (s *Server) warpBackend(ctx context.Context) (int, bool) {
	s.warpPort.mu.Lock()
	port, useTLS, at := s.warpPort.port, s.warpPort.tls, s.warpPort.at
	s.warpPort.mu.Unlock()
	if port != 0 && s.now().Sub(at) < warpPortTTL {
		return port, useTLS
	}
	n := s.serviceNode()
	if n == nil {
		return 0, false
	}
	st, err := n.WarpWeb(ctx)
	if err != nil || !st.Installed || !st.Active || st.BackendPort == 0 {
		s.forgetWarpPort()
		return 0, false
	}
	s.rememberWarpPort(st)
	return st.BackendPort, st.TLS
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
	port, useTLS := s.warpBackend(r.Context())
	if port == 0 {
		s.errorPage(w, r, http.StatusBadGateway, "веб-панель AZ-WARP не установлена или не работает")
		return
	}
	prefix := strings.TrimSuffix(s.BasePath, "/") + warpUIPath
	client, proto := s.remoteHost(r), "http"
	if s.isHTTPS(r) {
		proto = "https"
	}
	scheme := "http"
	var transport http.RoundTripper
	if useTLS {
		scheme, transport = "https", warpTLSTransport
	}
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = scheme
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
