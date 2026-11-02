package panel

import (
	"fmt"
	"net/http"
	"strings"
)

// access — кому открыт маршрут.
type access int

const (
	accPublic access = iota // без входа (сами решают, что проверять)
	accPortal               // public-portal: без сессии панели, доступ по токену в адресе
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
	"POST /account/telegram":        accAny,
	"POST /account/telegram/unlink": accAny,

	"GET /settings":                 accAdmin,
	"POST /settings":                accAdmin,
	"POST /settings/apply":          accAdmin,
	"POST /settings/confirm":        accAdmin,
	"POST /settings/secrets":        accAdmin,
	"GET /settings/export":          accAdmin,
	"POST /settings/export":         accAdmin,
	"POST /settings/import":         accAdmin,
	"GET /settings/access":          accAdmin,
	"POST /settings/access":         accAdmin,
	"POST /settings/access/confirm": accAdmin,

	"GET /users":                         accAdmin,
	"POST /users":                        accAdmin,
	"GET /users/{id}":                    accAdmin,
	"POST /users/{id}/role":              accAdmin,
	"POST /users/{id}/disabled":          accAdmin,
	"POST /users/{id}/password":          accAdmin,
	"POST /users/{id}/2fa/reset":         accAdmin,
	"POST /users/{id}/sessions/revoke":   accAdmin,
	"POST /users/{id}/delete":            accAdmin,
	"POST /users/{id}/access":            accAdmin,
	"POST /users/{id}/portal":            accAdmin,
	"POST /users/{id}/telegram/unlink":   accAdmin,
	"GET /users/telegram":                accAdmin,
	"POST /users/telegram/backup-groups": accAdmin,
	"POST /users/telegram/unban":         accAdmin,

	"GET /codes":                       accAdmin,
	"GET /codes/new":                   accAdmin,
	"POST /codes":                      accAdmin,
	"POST /codes/download":             accAdmin,
	"POST /codes/{id}/revoke":          accAdmin,
	"POST /codes/batch/{batch}/revoke": accAdmin,

	"GET /monitor":     accAdmin,
	"GET /audit":       accAdmin,
	"GET /clients/new": accAdmin,
	"POST /clients":    accAdmin,

	"GET /routing":                       accAdmin,
	"GET /routing/files/{name}":          accAdmin,
	"POST /routing/files/{name}/add":     accAdmin,
	"POST /routing/files/{name}/remove":  accAdmin,
	"POST /routing/files/{name}/replace": accAdmin,
	"POST /routing/files/{name}/restore": accAdmin,
	"GET /settings/antizapret":           accAdmin,
	"POST /settings/antizapret":          accAdmin,
	"GET /tasks":                         accAdmin,
	"GET /tasks/{id}":                    accAdmin,
	"POST /tasks/start":                  accAdmin,

	"GET /nodes":               accAdmin,
	"GET /nodes/new":           accAdmin,
	"POST /nodes":              accAdmin,
	"GET /nodes/{id}":          accAdmin,
	"POST /nodes/{id}/probe":   accAdmin,
	"POST /nodes/{id}/connect": accAdmin,
	"POST /nodes/{id}/check":   accAdmin,
	"POST /nodes/{id}/delete":  accAdmin,

	"GET /groups":                            accAdmin,
	"POST /groups":                           accAdmin,
	"GET /groups/{id}":                       accAdmin,
	"POST /groups/{id}/verify":               accAdmin,
	"POST /groups/{id}/members":              accAdmin,
	"POST /groups/{id}/members/{nid}/remove": accAdmin,
	"POST /groups/{id}/align/{nid}":          accAdmin,
	"POST /groups/{id}/promote/{nid}":        accAdmin,
	"POST /groups/{id}/addrs":                accAdmin,
	"POST /groups/{id}/update":               accAdmin,
	"POST /groups/{id}/delete":               accAdmin,

	"GET /antizapret/update":          accAdmin,
	"POST /antizapret/update":         accAdmin,
	"POST /antizapret/update/restore": accAdmin,

	"GET /telemt":                      accAdmin,
	"POST /telemt/users":               accAdmin,
	"POST /telemt/users/{name}/delete": accAdmin,
	"POST /telemt/users/{name}/link":   accAdmin,
	"POST /telemt/restart":             accAdmin,
	"POST /telemt/update":              accAdmin,
	"POST /telemt/install":             accAdmin,

	"GET /update":        accAdmin,
	"POST /update":       accAdmin,
	"POST /update/check": accAdmin,

	"GET /proxy":              accAdmin,
	"POST /proxy":             accAdmin,
	"POST /proxy/{id}/delete": accAdmin,

	"GET /warp":          accAdmin,
	"POST /warp/domains": accAdmin,
	"POST /warp/ips":     accAdmin,
	"POST /warp/sync":    accAdmin,
	"POST /warp/update":  accAdmin,
	"POST /warp/install": accAdmin,

	"GET /{$}": accAny,
	"/":        accAny,

	"GET /clients/{name}": accAny,
	"GET /clients/{name}/profiles/{kind}/{variant}/{file}": accAny,
	"GET /clients/{name}/qr/{kind}/{variant}/{file}":       accAny,
	"POST /clients/{name}/renew":                           accAdmin,
	"POST /clients/{name}/limit":                           accAdmin,
	"POST /clients/{name}/card":                            accAdmin,
	"POST /clients/{name}/block":                           accAdmin,
	"POST /clients/{name}/delete":                          accAdmin,
	"POST /clients/{name}/owner":                           accAdmin,
	// «Продлить кодом»: администратор и владелец клиента (visibleClient)
	"POST /clients/{name}/redeem": accAny,
	"POST /clients/{name}/portal": accAdmin,
	"POST /clients/{name}/kinds":  accAdmin,
	"POST /clients/{name}/dl":     accAdmin,

	// Портал клиента и одноразовые ссылки: роль public-portal, без сессии.
	"GET /p/{token}":      accPortal,
	"GET /p/{token}/help": accPortal,
	"GET /p/{token}/profile/{name}/{kind}/{variant}/{file}": accPortal,
	"GET /p/{token}/qr/{name}/{kind}/{variant}/{file}":      accPortal,
	"POST /p/{token}/unlock":                                accPortal,
	"/p/":                                                   accPortal,
	"GET /dl/{token}":                                       accPortal,
	"POST /dl/{token}":                                      accPortal,
	"/dl/":                                                  accPortal,
}

// experimentalRoutes — маршруты отложенных возможностей (узлы, группы
// синхронизации, Telegram-бот, самообновление azpanel): регистрируются, только
// когда включён panel.experimental. Они остаются и в таблице прав.
var experimentalRoutes = func() map[string]bool {
	m := map[string]bool{}
	for p := range routes {
		_, path, ok := strings.Cut(p, " ")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(path, "/nodes"), strings.HasPrefix(path, "/groups"),
			strings.HasPrefix(path, "/users/telegram"), strings.HasPrefix(path, "/account/telegram"),
			path == "/users/{id}/telegram/unlink", path == "/clients/{name}/kinds",
			path == "/update", strings.HasPrefix(path, "/update/"):
			m[p] = true
		}
	}
	return m
}()

// route регистрирует маршрут по таблице прав; маршрута нет в таблице — паника
// при сборке, а не открытая дверь. Отложенный маршрут при выключенном
// panel.experimental не регистрируется вовсе.
func (s *Server) route(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	a, ok := routes[pattern]
	if !ok {
		panic(fmt.Sprintf("panel: маршрут %q не внесён в таблицу прав", pattern))
	}
	if experimentalRoutes[pattern] && !s.Experimental {
		return
	}
	s.registered = append(s.registered, pattern)
	mux.Handle(pattern, s.require(a, s.scoped(pattern, s.propagating(pattern, h))))
}

// require оборачивает обработчик проверкой права a. Не администратор на
// административном маршруте получает 403.
func (s *Server) require(a access, h http.HandlerFunc) http.Handler {
	switch a {
	case accPublic, accPortal:
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
	owner, has, err := s.Store.OwnerOf(r.Context(), s.nodeIDFor(r), name)
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
		if x.Node == s.nodeIDFor(r) {
			out[x.Name] = true
		}
	}
	return out, nil
}
