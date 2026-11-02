package panel

import (
	"fmt"
	"net/http"
)

// access — кому открыт маршрут.
type access int

const (
	accPublic access = iota // без входа (сами решают, что проверять)
	accMFA                  // только сессия, ждущая код 2FA
	accAny                  // любой вошедший; клиентов ограничивает visibleClient
	accAdmin                // только администратор
)

// routes — таблица прав: каждый маршрут Handler() обязан быть здесь, иначе
// сборка маршрутов паникует, а тест прав падает.
var routes = map[string]access{
	"GET /healthz":    accPublic,
	"GET /static/":    accPublic,
	"GET /login":      accPublic,
	"POST /login":     accPublic,
	"POST /logout":    accPublic,
	"GET /login/2fa":  accMFA,
	"POST /login/2fa": accMFA,

	"GET /account":                  accAny,
	"GET /account/password":         accAny,
	"POST /account/password":        accAny,
	"GET /account/2fa":              accAny,
	"POST /account/2fa":             accAny,
	"POST /account/2fa/disable":     accAny,
	"POST /account/2fa/codes":       accAny,
	"POST /account/sessions/revoke": accAny,
	"POST /account/sessions/all":    accAny,
	"GET /account/once":             accAny,

	"GET /settings/access":          accAdmin,
	"POST /settings/access":         accAdmin,
	"POST /settings/access/confirm": accAdmin,

	"GET /users":                       accAdmin,
	"POST /users":                      accAdmin,
	"GET /users/{id}":                  accAdmin,
	"POST /users/{id}/role":            accAdmin,
	"POST /users/{id}/disabled":        accAdmin,
	"POST /users/{id}/password":        accAdmin,
	"POST /users/{id}/2fa/reset":       accAdmin,
	"POST /users/{id}/sessions/revoke": accAdmin,
	"POST /users/{id}/delete":          accAdmin,

	"GET /monitor":     accAdmin,
	"GET /audit":       accAdmin,
	"GET /clients/new": accAdmin,
	"POST /clients":    accAdmin,
	"GET /{$}":         accAny,
	"/":                accAny,

	"GET /clients/{name}": accAny,
	"GET /clients/{name}/profiles/{kind}/{variant}/{file}": accAny,
	"GET /clients/{name}/qr/{kind}/{variant}/{file}":       accAny,
	"POST /clients/{name}/renew":                           accAdmin,
	"POST /clients/{name}/limit":                           accAdmin,
	"POST /clients/{name}/card":                            accAdmin,
	"POST /clients/{name}/block":                           accAdmin,
	"POST /clients/{name}/delete":                          accAdmin,
	"POST /clients/{name}/owner":                           accAdmin,
}

// route регистрирует маршрут по таблице прав; маршрута нет в таблице — паника
// при сборке, а не открытая дверь.
func (s *Server) route(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	a, ok := routes[pattern]
	if !ok {
		panic(fmt.Sprintf("panel: маршрут %q не внесён в таблицу прав", pattern))
	}
	s.registered = append(s.registered, pattern)
	mux.Handle(pattern, s.require(a, h))
}

// require оборачивает обработчик проверкой права a. Не администратор на
// административном маршруте получает 403.
func (s *Server) require(a access, h http.HandlerFunc) http.Handler {
	switch a {
	case accPublic:
		return h
	case accMFA:
		return s.guard(h, guardMFA)
	case accAdmin:
		return s.protect(func(w http.ResponseWriter, r *http.Request) {
			if sess, _ := session(r); !sess.IsAdmin() {
				s.errorPage(w, r, http.StatusForbidden, "доступно только администратору")
				return
			}
			h(w, r)
		})
	}
	return s.protect(h)
}

// visibleClient: администратору видны все клиенты, пользователю — только
// свои (владелец). Чужой — «не найден», как несуществующий.
func (s *Server) visibleClient(r *http.Request, name string) bool {
	sess, ok := session(r)
	if !ok {
		return false
	}
	if sess.IsAdmin() {
		return true
	}
	if s.Store == nil {
		return false
	}
	owner, has, err := s.Store.OwnerOf(r.Context(), s.NodeID, name)
	if err != nil {
		s.Log.Warn("владелец клиента не прочитан", "client", name, "err", err)
		return false
	}
	return has && owner == sess.UserID
}

// ownedNames — имена клиентов пользователя на этом узле.
func (s *Server) ownedNames(r *http.Request, userID int64) (map[string]bool, error) {
	refs, err := s.Store.ClientsOf(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, x := range refs {
		if x.Node == s.NodeID {
			out[x.Name] = true
		}
	}
	return out, nil
}
