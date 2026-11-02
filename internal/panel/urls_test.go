package panel

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
)

var attrRe = regexp.MustCompile(`(?:href|action|src)="(/[^"]*)"`)

// Сторож: ни один шаблон не содержит href/action/src, начинающихся с «/»
// напрямую, и не берёт готовый путь из данных без функции url.
func TestTemplatesUseURLFunc(t *testing.T) {
	bare := regexp.MustCompile(`(?:href|action|src)="(?:/|\{\{[.$][A-Za-z]+\}\})`)
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := fs.ReadFile(templatesFS, "templates/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range bare.FindAllString(string(b), -1) {
			if strings.Contains(m, "{{.QR}}") {
				continue
			}
			t.Errorf("%s: %q без {{url ...}}", e.Name(), m)
		}
	}
}

func prefixed(p *pEnv, base string) {
	p.srv.BasePath = base
	p.h = p.srv.Handler()
}

func TestBasePathPages(t *testing.T) {
	const base = "/azpanel/"
	p := portalEnv(t)
	prefixed(p, base)
	link := p.clientLink(t, ownClient)
	pages := []string{"/", "/monitor", "/clients/new", "/clients/" + ownClient, "/audit", "/users",
		"/users/" + "1", "/codes", "/codes/new", "/routing", "/settings/antizapret", "/settings/access",
		"/tasks", "/account", "/nonexistent"}
	for _, pg := range pages {
		r := httptest.NewRequest("GET", base[:len(base)-1]+pg, nil)
		if pg == "/" {
			r = httptest.NewRequest("GET", base, nil)
		}
		r.AddCookie(p.admin)
		rec := p.do(r)
		body := rec.Body.String()
		if len(body) == 0 {
			t.Errorf("%s: пустой ответ (%d)", pg, rec.Code)
		}
		for _, m := range attrRe.FindAllStringSubmatch(body, -1) {
			if !strings.HasPrefix(m[1], base) {
				t.Errorf("%s: ссылка без префикса: %s", pg, m[1])
			}
		}
	}
	// Портал и его инструкция.
	for _, pg := range []string{link, link + "/help"} {
		rec := p.pget(base[:len(base)-1] + pg)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", pg, rec.Code)
		}
		for _, m := range attrRe.FindAllStringSubmatch(rec.Body.String(), -1) {
			if !strings.HasPrefix(m[1], base) {
				t.Errorf("%s: ссылка без префикса: %s", pg, m[1])
			}
		}
	}
}

func TestBasePathRedirectsAndCookie(t *testing.T) {
	p := portalEnv(t)
	prefixed(p, "/azpanel/")
	// Без префикса — 404; «/azpanel» ведёт на «/azpanel/».
	if rec := p.pget("/login"); rec.Code != 404 {
		t.Fatalf("без префикса: %d", rec.Code)
	}
	rec := p.pget("/azpanel")
	if rec.Code != 301 || rec.Header().Get("Location") != "/azpanel/" {
		t.Fatalf("/azpanel: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Без входа — на страницу входа с префиксом.
	rec = p.pget("/azpanel/monitor")
	if rec.Code != 303 || rec.Header().Get("Location") != "/azpanel/login" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Вход: редирект и cookie с префиксом.
	rec = p.do(postForm("/azpanel/login", url.Values{"user": {"admin"}, "password": {testPassword}}))
	if rec.Code != 303 || rec.Header().Get("Location") != "/azpanel/" {
		t.Fatalf("вход: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var c *http.Cookie
	for _, x := range rec.Result().Cookies() {
		if x.Name == cookieName {
			c = x
		}
	}
	if c == nil || c.Path != "/azpanel/" {
		t.Fatalf("cookie: %+v", c)
	}
	// Ссылки портала: public_url + префикс.
	p.srv.PublicURL = "https://vpn.example.org"
	if got := p.srv.publicLink("/p/c_x"); got != "https://vpn.example.org/azpanel/p/c_x" {
		t.Fatal(got)
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	s := &Server{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}}
	cases := []struct {
		name, remote, xff, want string
	}{
		{"без прокси", "203.0.113.5:1000", "", "203.0.113.5"},
		{"недоверенный соседний адрес: XFF игнорируется", "203.0.113.5:1000", "1.2.3.4", "203.0.113.5"},
		{"доверенный, один адрес", "127.0.0.1:1000", "198.51.100.7", "198.51.100.7"},
		{"подделка слева: берётся правый недоверенный", "127.0.0.1:1000", "9.9.9.9, 198.51.100.7", "198.51.100.7"},
		{"доверенные справа пропускаются", "127.0.0.1:1000", "198.51.100.7, 127.0.0.1", "198.51.100.7"},
		{"только доверенные: адрес соединения", "127.0.0.1:1000", "127.0.0.1", "127.0.0.1"},
		{"нет заголовка", "[::1]:1000", "", "::1"},
		{"мусор в цепочке", "127.0.0.1:1000", "198.51.100.7, мусор", "127.0.0.1"},
		{"IPv4 в IPv6", "127.0.0.1:1000", "::ffff:198.51.100.7", "198.51.100.7"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.remoteHost(r); got != c.want {
			t.Errorf("%s: %q, нужно %q", c.name, got, c.want)
		}
	}
	// Несколько заголовков склеиваются.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Add("X-Forwarded-For", "9.9.9.9")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	if got := s.remoteHost(r); got != "198.51.100.7" {
		t.Errorf("два заголовка: %q", got)
	}
	// Без доверенных прокси XFF не читается вовсе.
	r.RemoteAddr = "127.0.0.1:1"
	if got := (&Server{}).remoteHost(r); got != "127.0.0.1" {
		t.Errorf("пустой список: %q", got)
	}
}

func TestForwardedProtoOnlyFromTrusted(t *testing.T) {
	s := &Server{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	mk := func(remote string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-Proto", "https")
		return r
	}
	if !s.isHTTPS(mk("127.0.0.1:1")) {
		t.Error("от доверенного должен учитываться")
	}
	if s.isHTTPS(mk("203.0.113.5:1")) {
		t.Error("от недоверенного не должен учитываться")
	}
}

// Ограничитель попыток входа и белый список видят настоящий адрес за прокси.
func TestLimiterUsesRealClientBehindProxy(t *testing.T) {
	e := newEnv(t, adminHash(t))
	e.srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for i := 0; i < 5; i++ {
		r := postForm("/login", url.Values{"user": {"admin"}, "password": {"неверный-пароль-1"}})
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		e.do(r)
	}
	r := postForm("/login", url.Values{"user": {"admin"}, "password": {testPassword}})
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if rec := e.do(r); rec.Code != 429 {
		t.Fatalf("тот же клиент за прокси должен быть заблокирован: %d", rec.Code)
	}
	r = postForm("/login", url.Values{"user": {"admin"}, "password": {testPassword}})
	r.Header.Set("X-Forwarded-For", "198.51.100.8")
	if rec := e.do(r); rec.Code != 303 {
		t.Fatalf("другой клиент за тем же прокси не должен страдать: %d", rec.Code)
	}
}

// Маршрутизация, настройки AntiZapret и задачи под префиксом.
func TestBasePathRoutingPages(t *testing.T) {
	const base = "/azpanel"
	e, c := routingEnv(t)
	e.srv.BasePath = base + "/"
	e.h = e.srv.Handler()
	e.node.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) { return nil, nil }
	e.node.TasksFn = func(context.Context) ([]nodeapi.Task, error) {
		return []nodeapi.Task{{ID: "t1", Kind: "apply_routing"}}, nil
	}
	for _, pg := range []string{"/routing", "/routing/files/include-hosts.txt", "/settings/antizapret", "/tasks"} {
		r := httptest.NewRequest("GET", base+pg, nil)
		r.AddCookie(c)
		rec := e.do(r)
		if rec.Code != 200 {
			t.Errorf("%s: %d", pg, rec.Code)
		}
		n := 0
		for _, m := range attrRe.FindAllStringSubmatch(rec.Body.String(), -1) {
			n++
			if !strings.HasPrefix(m[1], base+"/") {
				t.Errorf("%s: ссылка без префикса: %s", pg, m[1])
			}
		}
		if n == 0 {
			t.Errorf("%s: нет ссылок", pg)
		}
	}
}
