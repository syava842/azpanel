package panel

import (
	"net/http"
	"net/netip"
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
// /healthz. Адрес — remoteHost; за nginx это будет заголовок доверенного
// прокси (этап 2б).
func (s *Server) allowGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && !s.Allow.Allows(remoteHost(r)) {
			http.Error(w, "доступ запрещён", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
