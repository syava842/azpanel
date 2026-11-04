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
		"/":                    "Клиенты",
		"/clients/ivan":        "Клиенты",
		"/clients/new":         "Клиенты",
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
		if got := activeLabel(s.nav(path, true)); got != want {
			t.Errorf("%s: %q, ждали %q", path, got, want)
		}
	}
}

func TestNavRolesAndExperimental(t *testing.T) {
	s := &Server{}
	if g := s.nav("/", false); len(g) != 1 || len(g[0].Items) != 1 || g[0].Items[0].Label != "Клиенты" {
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
	if has(s.nav("/", true), "Узлы") || has(s.nav("/", true), "Обновление") {
		t.Fatal("без experimental видны узлы или самообновление")
	}
	s.Experimental = true
	if !has(s.nav("/", true), "Узлы") || !has(s.nav("/", true), "Группы") || !has(s.nav("/", true), "Обновление") {
		t.Fatal("с experimental нет узлов, групп или самообновления")
	}
}
