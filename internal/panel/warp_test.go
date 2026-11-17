package panel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/warp"
)

// warpNode — AZ-WARP в заданном состоянии; web.BackendPort — порт поддельной
// веб-панели.
func warpNode(n *svcNode, installed bool, web nodeapi.WarpWeb) {
	n.WarpFn = func(context.Context) (nodeapi.Warp, error) {
		var w nodeapi.Warp
		w.AZ.Installed, w.AZ.Version = installed, "1.5.7"
		w.Web = web
		return w, nil
	}
	n.WarpWebFn = func(context.Context) (nodeapi.WarpWeb, error) { return web, nil }
}

func TestWarpPageStates(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	for _, tc := range []struct {
		name      string
		installed bool
		web       nodeapi.WarpWeb
		want      []string
		not       string
	}{
		{"не установлен", false, nodeapi.WarpWeb{}, []string{`action="/warp/install"`, `name="web_user"`, `name="web_pass"`, `name="mode"`}, "<iframe"},
		{"без веб-панели", true, nodeapi.WarpWeb{}, []string{`action="/warp/web/install"`, `name="web_pass"`}, `name="mode"`},
		{"панель не работает", true, nodeapi.WarpWeb{Installed: true, BackendPort: 16060}, []string{"warper web start"}, "<iframe"},
		{"окно", true, nodeapi.WarpWeb{Installed: true, Active: true, Port: 6060, BackendPort: 16060}, []string{`<iframe class="app-frame" src="/warp/ui/"`}, `action="/warp/`},
	} {
		warpNode(n, tc.installed, tc.web)
		rec := get(e, c, "/warp")
		b := rec.Body.String()
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", tc.name, rec.Code, b)
		}
		for _, w := range tc.want {
			if !strings.Contains(b, w) {
				t.Errorf("%s: нет %q", tc.name, w)
			}
		}
		if strings.Contains(b, tc.not) {
			t.Errorf("%s: лишнее %q", tc.name, tc.not)
		}
	}
	// Форма показывает то, что нашёл агент: ключи, конфиги, рекомендуемый MTU;
	// домены по умолчанию не отмечены.
	n.WarpFn = func(context.Context) (nodeapi.Warp, error) {
		return nodeapi.Warp{Install: &nodeapi.WarpInstallOptions{PhysMTU: 1450, RecMTU: 1370, ChatGPTListed: true,
			WarpSources: []warp.WarpSource{{ID: "wgcf", Label: "/root/warper/wgcf/wgcf-profile.conf (172.16.0.3/32)"}, {ID: "generate", Label: "Сгенерировать новый ключ WARP"}},
			WGConfs:     []warp.WGConfFound{{Path: "/root/home.conf", Endpoint: "198.51.100.5:51820"}},
			OvpnFiles:   []warp.OvpnFound{{Path: "/root/a.ovpn", Auth: true}}}}, nil
	}
	b := get(e, c, "/warp").Body.String()
	for _, w := range []string{`value="wgcf"`, "wgcf-profile.conf (172.16.0.3/32)", `value="/root/home.conf"`, "198.51.100.5:51820",
		`value="/root/a.ovpn"`, "нужен логин и пароль", "рекомендуемый 1370", `placeholder="1370"`, `name="gemini" value="1">`,
		"Домены ChatGPT уже в списке", `name="web_port"`, `name="web_https" value="1">`} {
		if !strings.Contains(b, w) {
			t.Errorf("варианты: нет %q", w)
		}
	}
	if strings.Contains(b, `name="chatgpt"`) || strings.Contains(b, "checked") {
		t.Errorf("лишнее в форме: chatgpt или отмеченный флажок")
	}
	n.WarpFn = func(context.Context) (nodeapi.Warp, error) {
		return nodeapi.Warp{}, &nodeapi.Error{Status: 503, Message: "WARP не настроен"}
	}
	if b := get(e, c, "/warp").Body.String(); !strings.Contains(b, "состояние AZ-WARP недоступно") {
		t.Fatalf("ошибка агента: %s", b)
	}
}

func TestWarpInstallWithWebPanel(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	warpNode(n, false, nodeapi.WarpWeb{})
	var got nodeapi.WarpInstallAnswers
	n.InstallWarpFn = func(_ context.Context, a nodeapi.WarpInstallAnswers) (nodeapi.Task, error) {
		got = a
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	f := url.Values{"csrf": {csrf}, "mode": {"wg"}, "mtu": {"1380"}, "subnet": {"10.224.0.0/16"}, "chatgpt": {"1"},
		"warp_source": {"generate"}, "proxy_link": {"vless://лишнее"}, "wg_conf": {""},
		"wg_endpoint": {"vpn.example.org:51820"}, "wg_address": {"10.9.0.2/32"}, "wg_private_key": {"PRIVATEKEYSECRET="}, "wg_public_key": {"PUB="},
		"web_user": {"boss"}, "web_pass": {"ПАРОЛЬ-ПАНЕЛИ"}, "web_port": {"7443"}, "web_https": {"1"}}
	rec := post(e, c, "/warp/install", f)
	if rec.Code != 303 || got.Mode != "wg" || got.MTU != 1380 || !got.ChatGPT || got.Gemini || got.WG == nil || got.WG.PrivateKey != "PRIVATEKEYSECRET=" ||
		got.WarpSource != "" || got.ProxyLink != "" ||
		got.Web == nil || got.Web.User != "boss" || got.Web.Password != "ПАРОЛЬ-ПАНЕЛИ" || got.Web.Port != 7443 || got.Web.BackendPort != 0 || !got.Web.HTTPS {
		t.Fatalf("install: %d %+v", rec.Code, got)
	}
	// Найденный конфиг — путём, ручные поля не нужны.
	f = url.Values{"csrf": {csrf}, "mode": {"wg"}, "wg_conf": {"/root/home.conf"}, "web_user": {"boss"}, "web_pass": {"secret1"}}
	if rec := post(e, c, "/warp/install", f); rec.Code != 303 || got.WGConf != "/root/home.conf" || got.WG != nil || got.Gemini || got.ChatGPT {
		t.Fatalf("конфиг из списка: %d %+v", rec.Code, got)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "warp_install")
	if len(list) != 2 || strings.Contains(list[1].After+list[1].Target, "PRIVATEKEY") || strings.Contains(list[1].After+list[1].Target, "ПАРОЛЬ-ПАНЕЛИ") {
		t.Fatalf("секрет в журнале: %+v", list)
	}
	// Без пароля панели и с неполными ответами — отказ до запуска; секреты
	// в форму не возвращаются.
	n.Calls = nil
	for _, f := range []url.Values{
		{"csrf": {csrf}, "mode": {"warp"}, "web_user": {"boss"}},
		{"csrf": {csrf}, "mode": {"warp"}, "web_user": {"boss"}, "web_pass": {"secret1"}, "web_port": {"шесть"}},
		{"csrf": {csrf}, "mode": {"warp"}, "web_user": {"boss"}, "web_pass": {"secret1"}, "web_domain": {"panel.example.com"}},
		{"csrf": {csrf}, "mode": {"slave"}, "web_user": {"boss"}, "web_pass": {"secret1"}},
		{"csrf": {csrf}, "mode": {"nope"}, "ovpn_pass": {"HUNTER2"}, "web_user": {"boss"}, "web_pass": {"ПАРОЛЬ-ПАНЕЛИ"}},
	} {
		rec := post(e, c, "/warp/install", f)
		if rec.Code != 400 || strings.Contains(rec.Body.String(), "HUNTER2") || strings.Contains(rec.Body.String(), "ПАРОЛЬ-ПАНЕЛИ") {
			t.Fatalf("%v: %d", f, rec.Code)
		}
	}
	if n.called("InstallWarp") != 0 {
		t.Fatal("установка запущена с неверными ответами")
	}
}

func TestWarpWebInstall(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	warpNode(n, true, nodeapi.WarpWeb{})
	var got nodeapi.WarpWebAnswers
	n.InstallWarpWebFn = func(_ context.Context, a nodeapi.WarpWebAnswers) (nodeapi.Task, error) {
		got = a
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	if rec := post(e, c, "/warp/web/install", url.Values{"csrf": {csrf}, "web_user": {"x"}, "web_pass": {"secret1"}}); rec.Code != 400 || n.called("InstallWarpWeb") != 0 {
		t.Fatalf("короткий логин: %d", rec.Code)
	}
	rec := post(e, c, "/warp/web/install", url.Values{"csrf": {csrf}, "web_user": {"boss"}, "web_pass": {"secret1"}})
	if rec.Code != 303 || got.User != "boss" || got.Password != "secret1" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
}

// warpBackend — поддельная веб-панель AZ-WARP: запоминает, что получила.
func warpBackend(t *testing.T) (*httptest.Server, int, *http.Request, *string) {
	t.Helper()
	last := &http.Request{}
	body := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*last = *r.Clone(context.Background())
		b, _ := io.ReadAll(r.Body)
		*body = string(b)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<script src="/x/static/app.js"></script>ok`))
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return srv, port, last, body
}

func TestWarpUIProxy(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	e.srv.BasePath = "/azpanel/"
	e.h = e.srv.Handler()
	_, port, last, body := warpBackend(t)
	warpNode(n, true, nodeapi.WarpWeb{Installed: true, Active: true, BackendPort: port})

	r := httptest.NewRequest(http.MethodPost, "/azpanel/warp/ui/htmx/domains/add?x=1", strings.NewReader("domain=example.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "panel.example"
	r.AddCookie(c)
	r.AddCookie(&http.Cookie{Name: "session", Value: "warper-cookie"})
	rec := e.do(r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("POST без токена формы: %d %s", rec.Code, rec.Body.String())
	}
	if last.URL.Path != "/azpanel/warp/ui/htmx/domains/add" || last.URL.RawQuery != "x=1" || *body != "domain=example.com" {
		t.Fatalf("переслано: %s?%s %q", last.URL.Path, last.URL.RawQuery, *body)
	}
	h := last.Header
	if h.Get("Script_name") != "/azpanel/warp/ui" || h.Get("X-Forwarded-Host") != "panel.example" || last.Host != "panel.example" {
		t.Fatalf("заголовки: %v host %s", h, last.Host)
	}
	if ck := h.Get("Cookie"); strings.Contains(ck, cookieName) || !strings.Contains(ck, "session=warper-cookie") {
		t.Fatalf("cookie: %q", ck)
	}
	rh := rec.Header()
	if rh.Get("X-Frame-Options") != "SAMEORIGIN" || rh.Get("Content-Security-Policy") != "frame-ancestors 'self'" {
		t.Fatalf("заголовки ответа: %v", rh)
	}

	// Запрос с чужого сайта и без входа не проходят.
	r = httptest.NewRequest(http.MethodGet, "/azpanel/warp/ui/", nil)
	r.AddCookie(c)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := e.do(r); rec.Code != 403 {
		t.Fatalf("чужой сайт: %d", rec.Code)
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/azpanel/warp/ui/", nil)); rec.Code != 303 {
		t.Fatalf("без входа: %d", rec.Code)
	}
}

func TestWarpUIBackendDown(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	warpNode(n, true, nodeapi.WarpWeb{Installed: true, Active: false, BackendPort: 16060})
	if rec := get(e, c, "/warp/ui/"); rec.Code != 502 {
		t.Fatalf("панель не работает: %d", rec.Code)
	}
	// Порт есть, но там никто не слушает.
	srv, port, _, _ := warpBackend(t)
	srv.Close()
	warpNode(n, true, nodeapi.WarpWeb{Installed: true, Active: true, BackendPort: port})
	if rec := get(e, c, "/warp/ui/"); rec.Code != 502 || !strings.Contains(rec.Body.String(), "не отвечает") {
		t.Fatalf("недоступна: %d", rec.Code)
	}
}

// Веб-панель без nginx с HTTPS: gunicorn сам говорит TLS на внешнем порту.
func TestWarpUIProxyTLSBackend(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tls-ok " + r.Header.Get("Script_name")))
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	warpNode(n, true, nodeapi.WarpWeb{Installed: true, Active: true, Mode: "standalone", Port: port, BackendPort: port, TLS: true})
	if rec := get(e, c, "/warp/ui/"); rec.Code != 200 || rec.Body.String() != "tls-ok /warp/ui" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestWarpWebPublishMode(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	warpNode(n, true, nodeapi.WarpWeb{})
	var got nodeapi.WarpWebAnswers
	n.InstallWarpWebFn = func(_ context.Context, a nodeapi.WarpWebAnswers) (nodeapi.Task, error) {
		got = a
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	rec := post(e, c, "/warp/web/install", url.Values{"csrf": {csrf}, "web_user": {"boss"}, "web_pass": {"secret1"}, "web_publish": {"direct"}})
	if rec.Code != 303 || got.Publish != "direct" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
	if rec := post(e, c, "/warp/web/install", url.Values{"csrf": {csrf}, "web_user": {"boss"}, "web_pass": {"secret1"}, "web_publish": {"apache"}}); rec.Code != 400 {
		t.Fatalf("неизвестный режим: %d", rec.Code)
	}
}

func TestWarpRoutesAdminOnly(t *testing.T) {
	for p, want := range map[string]access{"GET /warp": accAdmin, "POST /warp/install": accAdmin, "POST /warp/web/install": accAdmin,
		"GET /warp/ui/": accAdminProxy, "POST /warp/ui/": accAdminProxy} {
		if routes[p] != want {
			t.Errorf("%s: права %v", p, routes[p])
		}
	}
}
