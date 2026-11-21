package panel

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Возврат после удаления клиента: туда, откуда пришли на его страницу, —
// в общий список, раздел OpenVPN или WireGuard, на страницу пользователя.

// backPages — страницы панели, на которые можно вернуться.
var backPages = map[string]bool{
	"/": true, "/clients": true,
	"/openvpn": true, "/openvpn/clients": true, "/openvpn/history": true, "/openvpn/stats": true,
	"/wireguard": true, "/wireguard/clients": true, "/wireguard/history": true, "/wireguard/stats": true,
}

var userPageRe = regexp.MustCompile(`^/users/[0-9]+$`)

// cleanBack проверяет адрес возврата: путь панели без префикса и, по
// желанию, запрос. Чужой хост, неизвестная страница, «//» — пусто.
func cleanBack(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Fragment != "" {
		return ""
	}
	if !backPages[u.Path] && !userPageRe.MatchString(u.Path) {
		return ""
	}
	if u.RawQuery == "" {
		return u.Path
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return u.Path
	}
	q.Del("msg") // уведомление прошлого действия не повторяется
	q.Del("n")
	if len(q) == 0 {
		return u.Path
	}
	return u.Path + "?" + q.Encode()
}

// backFrom — адрес возврата для страницы клиента: из формы (повторный
// показ после ошибки) или из Referer, если он указывает на эту же панель.
func (s *Server) backFrom(r *http.Request) string {
	if v := cleanBack(r.FormValue("back")); v != "" {
		return v
	}
	ref, err := url.Parse(r.Referer())
	if err != nil || ref.Host == "" || !strings.EqualFold(ref.Host, r.Host) {
		return ""
	}
	p := ref.Path
	if bare := strings.TrimSuffix(s.BasePath, "/"); bare != "" {
		if p != bare && !strings.HasPrefix(p, bare+"/") {
			return ""
		}
		p = strings.TrimPrefix(p, bare)
		if p == "" {
			p = "/"
		}
	}
	if ref.RawQuery != "" {
		p += "?" + ref.RawQuery
	}
	return cleanBack(p)
}

// withMsg добавляет уведомление к адресу, у которого уже может быть запрос.
func withMsg(to, code string) string {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	return to + sep + "msg=" + url.QueryEscape(code)
}
