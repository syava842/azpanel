package panel

import "testing"

func activeLabel(groups []navGroup) string {
	label := ""
	for _, g := range groups {
		for _, it := range g.Items {
			if it.Active {
				if label != "" {
					return "два активных: " + label + ", " + it.Label
				}
				label = it.Label
			}
		}
	}
	return label
}

func TestNavActive(t *testing.T) {
	s := &Server{}
	for path, want := range map[string]string{
		"/":                    "Главная",
		"/monitor":             "Главная",
		"/openvpn/stats":       "OpenVPN",
		"/clients/ivan":        "OpenVPN",
		"/clients/new":         "OpenVPN",
		"/settings":            "Настройки",
		"/settings/export":     "Настройки",
		"/settings/access":     "Доступ",
		"/settings/antizapret": "AntiZapret",
		"/antizapret/update":   "Обновление AZ",
		"/users/3":             "Пользователи",
		"/codes/new":           "Коды",
		"/tasks/42":            "Задачи",
		"/account":             "",
		"/routingx":            "",
	} {
		if got := activeLabel(s.nav(path, true, false)); got != want {
			t.Errorf("%s: %q, ждали %q", path, got, want)
		}
	}
}

func TestNavRolesAndExperimental(t *testing.T) {
	s := &Server{}
	if g := s.nav("/", false, false); len(g) != 1 || len(g[0].Items) != 1 || g[0].Items[0].Label != "Клиенты" {
		t.Fatalf("меню не-администратора: %+v", g)
	}
	has := func(groups []navGroup, label string) bool {
		for _, g := range groups {
			for _, it := range g.Items {
				if it.Label == label {
					return true
				}
			}
		}
		return false
	}
	if has(s.nav("/", true, false), "Обновление") {
		t.Fatal("без experimental видно самообновление")
	}
	if !has(s.nav("/", true, false), "Узлы") || !has(s.nav("/", true, false), "Группы") {
		t.Fatal("без experimental нет узлов или групп — они не под флагом")
	}
	s.Experimental = true
	if !has(s.nav("/", true, false), "Узлы") || !has(s.nav("/", true, false), "Группы") || !has(s.nav("/", true, false), "Обновление") {
		t.Fatal("с experimental нет узлов, групп или самообновления")
	}
}

// WireGuard в меню — только когда на сервере есть его клиенты.
func TestNavWireGuardOnlyWhenUsed(t *testing.T) {
	s := &Server{}
	has := func(wg bool) bool {
		for _, g := range s.nav("/", true, wg) {
			for _, it := range g.Items {
				if it.Label == "WireGuard" {
					return true
				}
			}
		}
		return false
	}
	if has(false) || !has(true) {
		t.Fatalf("WireGuard: без клиентов %v, с клиентами %v", has(false), has(true))
	}
	if got := activeLabel(s.nav("/wireguard/clients", true, true)); got != "WireGuard" {
		t.Fatalf("активный: %q", got)
	}
}
