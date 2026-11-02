package panel

import (
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"
)

// AllowList — белый список адресов панели. Пустой список пускает всех.
// Меняется на ходу (страница «Доступ», возврат по таймеру).
type AllowList struct {
	mu   sync.RWMutex
	nets []netip.Prefix
}

func NewAllowList(nets []netip.Prefix) *AllowList { return &AllowList{nets: nets} }

func (a *AllowList) Set(nets []netip.Prefix) {
	a.mu.Lock()
	a.nets = nets
	a.mu.Unlock()
}

// Allows: пускать ли адрес. Нечитаемый адрес при непустом списке не пускается.
func (a *AllowList) Allows(host string) bool {
	if a == nil {
		return true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return allowsIn(a.nets, host)
}

func allowsIn(nets []netip.Prefix, host string) bool {
	if len(nets) == 0 {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.WithZone("").Unmap()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// allowGate — самый внешний обработчик (после заголовков): адрес вне белого
// списка получает 403 без подробностей, до входа и на всех маршрутах, кроме
// /healthz, портала (/p/, /dl/) и статики для его страниц. Адрес — remoteHost: за nginx это X-Forwarded-For
// доверенного прокси (panel.trusted_proxies).
func (s *Server) allowGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Путь чистится до проверки: /p/../clients не должен сойти за портал.
		// (Дальше ServeMux всё равно отвечает 301 на очищенный путь, но защита
		// не должна держаться на его поведении.)
		p := cleanURLPath(r.URL.Path)
		if p != "/healthz" && !isPortalPath(p) && !strings.HasPrefix(p, "/static/") && !s.Allow.Allows(s.remoteHost(r)) {
			http.Error(w, "доступ запрещён", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanURLPath — path.Clean с сохранением хвостового «/»: «/p/» остаётся
// «/p/», «/p/../x» становится «/x».
func cleanURLPath(p string) string {
	c := path.Clean("/" + p)
	if c != "/" && strings.HasSuffix(p, "/") {
		c += "/"
	}
	return c
}
