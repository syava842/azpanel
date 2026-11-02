package panel

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// url — адрес внутри панели с префиксом пути: части склеиваются как есть,
// впереди добавляется BasePath без хвостового «/». Путь «/» при префиксе
// «/x/» даёт «/x/». Годится и для шаблонов ({{url "/clients/" .Name}}),
// и для редиректов.
func (s *Server) url(parts ...any) string { return urlAt(s.BasePath, parts...) }

// urlAt — то же с явным префиксом: страница «перезапуск…» ведёт на адрес по
// новому base_path, который ещё не действует.
func urlAt(base string, parts ...any) string {
	var b strings.Builder
	for _, p := range parts {
		fmt.Fprint(&b, p)
	}
	return strings.TrimSuffix(base, "/") + b.String()
}

// cookiePath — Path cookie сессии: префикс пути либо «/».
func (s *Server) cookiePath() string {
	if s.BasePath == "" {
		return "/"
	}
	return s.BasePath
}

// redirect — перенаправление на адрес панели; префикс добавляется здесь.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to string, code int) {
	http.Redirect(w, r, s.url(to), code)
}

// stripBase снимает префикс пути. Запрос без префикса — 404; «/x» без
// хвостового «/» ведёт на «/x/».
func (s *Server) stripBase(next http.Handler) http.Handler {
	if s.BasePath == "" {
		return next
	}
	bare := strings.TrimSuffix(s.BasePath, "/")
	strip := http.StripPrefix(bare, next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == bare:
			http.Redirect(w, r, s.BasePath, http.StatusMovedPermanently)
		case strings.HasPrefix(r.URL.Path, s.BasePath):
			strip.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Server) trusted(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	for _, p := range s.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peerHost — адрес соседа по соединению (без порта).
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// remoteHost — адрес клиента. Если соединение пришло от доверенного прокси,
// берётся самый правый адрес X-Forwarded-For, не входящий в доверенные
// (левые записи клиент может подделать); иначе — адрес соединения.
func (s *Server) remoteHost(r *http.Request) string {
	host := peerHost(r)
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.trusted(peer) {
		return host
	}
	var chain []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		chain = append(chain, strings.Split(h, ",")...)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return host // мусор в цепочке: ему не верим
		}
		if !s.trusted(a) {
			return a.WithZone("").Unmap().String()
		}
	}
	return host
}

// isHTTPS: TLS на самом соединении либо X-Forwarded-Proto: https от
// доверенного прокси.
func (s *Server) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, err := netip.ParseAddr(peerHost(r))
	return err == nil && s.trusted(peer) && r.Header.Get("X-Forwarded-Proto") == "https"
}
