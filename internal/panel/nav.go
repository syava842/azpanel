package panel

import "strings"

// navItem — пункт бокового меню. Match — префиксы путей, на которых пункт
// подсвечен; побеждает самый длинный (/settings/access — «Доступ», а не
// «Настройки»).
type navItem struct {
	Href, Label, Icon string
	Match             []string
	Active            bool
}

type navGroup struct {
	Title string
	Items []navItem
}

// nav собирает боковое меню для пути path (без base_path). Пользователь без
// роли администратора видит только клиентов.
func (s *Server) nav(path string, admin bool) []navGroup {
	clients := navItem{Href: "/", Label: "Клиенты", Icon: "users", Match: []string{"/clients/"}}
	if !admin {
		groups := []navGroup{{Items: []navItem{clients}}}
		markActive(groups, path)
		return groups
	}
	vpn := []navItem{
		clients,
		{Href: "/monitor", Label: "Сейчас", Icon: "activity"},
		{Href: "/routing", Label: "Маршрутизация", Icon: "route"},
		{Href: "/proxy", Label: "Прокси", Icon: "globe"},
	}
	if s.Experimental {
		vpn = append(vpn,
			navItem{Href: "/nodes", Label: "Узлы", Icon: "server"},
			navItem{Href: "/groups", Label: "Группы", Icon: "layers"})
	}
	services := []navItem{
		{Href: "/settings/antizapret", Label: "AntiZapret", Icon: "shield"},
		{Href: "/antizapret/update", Label: "Обновление AZ", Icon: "rotate"},
		{Href: "/telemt", Label: "telemt", Icon: "send"},
		{Href: "/warp", Label: "WARP", Icon: "cloud"},
	}
	system := []navItem{
		{Href: "/tasks", Label: "Задачи", Icon: "checks"},
		{Href: "/audit", Label: "Журнал", Icon: "file"},
		{Href: "/users", Label: "Пользователи", Icon: "user"},
		{Href: "/codes", Label: "Коды", Icon: "key"},
		{Href: "/settings", Label: "Настройки", Icon: "sliders"},
		{Href: "/settings/access", Label: "Доступ", Icon: "lock"},
	}
	if s.Experimental {
		system = append(system, navItem{Href: "/update", Label: "Обновление", Icon: "rotate"})
	}
	groups := []navGroup{{Title: "VPN", Items: vpn}, {Title: "Сервисы", Items: services}, {Title: "Система", Items: system}}
	markActive(groups, path)
	return groups
}

// markActive подсвечивает один пункт: «/» — только сама главная, остальные
// — по своему пути и Match, самый длинный префикс.
func markActive(groups []navGroup, path string) {
	bi, bj, best := -1, -1, 0
	for i := range groups {
		for j, it := range groups[i].Items {
			for _, p := range append([]string{it.Href}, it.Match...) {
				ok := path == p
				if p != "/" && !ok {
					ok = strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/")
				}
				if ok && len(p) > best {
					bi, bj, best = i, j, len(p)
				}
			}
		}
	}
	if bi >= 0 {
		groups[bi].Items[bj].Active = true
	}
}
