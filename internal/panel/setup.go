package panel

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// Группы страницы «Настройки AntiZapret», в порядке показа.
const (
	grpLists    = "lists"
	grpProtect  = "protect"
	grpPorts    = "ports"
	grpHosts    = "hosts"
	grpReadonly = "readonly"
)

var groupTitles = []struct{ ID, Title, Note string }{
	{grpLists, "Маршрутизация списков", ""},
	{grpProtect, "Защита и прочее", ""},
	{grpPorts, "Резервные порты", ""},
	{grpHosts, "Адреса для профилей", ""},
	{grpReadonly, "Только чтение", "меняется переустановкой AntiZapret"},
}

// setupGroup раскладывает ключ по группе: порядок по смыслу, а не по
// таблице значений.
func setupGroup(e nodeapi.SetupEntry) string {
	if !e.Editable {
		return grpReadonly
	}
	k := e.Key
	switch {
	case strings.HasSuffix(k, "_INCLUDE") || strings.HasSuffix(k, "_ADBLOCK") || k == "ROUTE_ALL" || k == "CLEAR_HOSTS":
		return grpLists
	case strings.Contains(k, "_BACKUP"):
		return grpPorts
	case strings.HasSuffix(k, "_HOST"):
		return grpHosts
	}
	return grpProtect
}

// applyTexts — как вступает в силу ключ (для подписи в строке).
var applyTexts = map[string]string{
	nodeapi.ApplyDoall:     "после применения списков",
	nodeapi.ApplyRestart:   "после перезапуска antizapret",
	nodeapi.ApplyProfiles:  "после пересоздания профилей",
	nodeapi.ApplyReinstall: "меняется переустановкой AntiZapret",
}

type optionRow struct {
	Value string
	Label string // подпись, если отличается от значения
	Sel   bool
}

type setupRow struct {
	Key, Title, Hint, Kind, Value string
	Editable, Absent              bool
	Options                       []optionRow
	Min, Max                      int
	Apply                         string
}

type setupGroupView struct {
	ID, Title, Note string
	Rows            []setupRow
}

// nextActions — кнопки задач после сохранения; текст предупреждения — у
// тех, что прерывают работу.
var nextActions = []struct{ Kind, Button, Warn string }{
	{nodeapi.ApplyDoall, "Применить списки (doall.sh)", ""},
	{nodeapi.ApplyRestart, "Перезапустить antizapret", "VPN прервётся на несколько секунд."},
	{nodeapi.ApplyProfiles, "Пересоздать профили клиентов", "Профили клиентов будут пересозданы, старые файлы перестанут совпадать."},
}

type actionView struct{ Kind, Button, Warn string }

func formName(key string) string { return "v_" + key }

func buildSetupGroups(entries []nodeapi.SetupEntry, typed map[string]string) []setupGroupView {
	byID := map[string]*setupGroupView{}
	var out []*setupGroupView
	for _, g := range groupTitles {
		v := &setupGroupView{ID: g.ID, Title: g.Title, Note: g.Note}
		byID[g.ID] = v
		out = append(out, v)
	}
	for _, e := range entries {
		val := e.Value
		if t, ok := typed[e.Key]; ok {
			val = t
		}
		row := setupRow{Key: e.Key, Title: e.Title, Hint: e.Hint, Kind: e.Kind, Value: val, Editable: e.Editable,
			Absent: !e.Present, Min: e.Min, Max: e.Max}
		if row.Title == "" {
			row.Title = e.Key
		}
		var texts []string
		for _, a := range e.Apply {
			if t, ok := applyTexts[a]; ok {
				texts = append(texts, t)
			}
		}
		row.Apply = strings.Join(texts, ", ")
		opts := e.Options
		if e.Kind == "yn" {
			opts = []string{"y", "n"}
		}
		if e.Editable && len(opts) > 0 {
			// Текущее значение вне вариантов (пусто, «Y», «4», записано вручную)
			// — первый пункт: иначе браузер выбрал бы за человека первый вариант,
			// и форма молча поменяла бы ключ.
			if !contains(opts, e.Value) {
				o := optionRow{Value: e.Value, Sel: val == e.Value}
				if e.Value != "" {
					o.Label = e.Value + " (нестандартное)"
				}
				row.Options = append(row.Options, o)
			}
			for _, o := range opts {
				row.Options = append(row.Options, optionRow{Value: o, Sel: o == val})
			}
		}
		g := byID[setupGroup(e)]
		g.Rows = append(g.Rows, row)
	}
	res := make([]setupGroupView, 0, len(out))
	for _, g := range out {
		if len(g.Rows) > 0 {
			res = append(res, *g)
		}
	}
	return res
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// parseApply оставляет в параметре apply только известные способы, в
// порядке doall, restart, profiles и без повторов.
func parseApply(raw string) []actionView {
	want := map[string]bool{}
	for _, a := range strings.Split(raw, ",") {
		want[strings.TrimSpace(a)] = true
	}
	var out []actionView
	for _, a := range nextActions {
		if want[a.Kind] {
			out = append(out, actionView(a))
		}
	}
	return out
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	s.setupView(w, r, http.StatusOK, "", nil)
}

func (s *Server) setupView(w http.ResponseWriter, r *http.Request, status int, errText string, typed map[string]string) {
	entries, err := s.nodeFor(r).Setup(r.Context())
	if err != nil {
		st, tx := s.agentErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	data := map[string]any{"Groups": buildSetupGroups(entries, typed), "Next": parseApply(r.URL.Query().Get("apply"))}
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "setup", data)
}

// setupSave отправляет агенту только изменённые ключи. Задачи сами не
// запускаются: страница после сохранения предлагает их кнопками.
func (s *Server) setupSave(w http.ResponseWriter, r *http.Request) {
	entries, err := s.nodeFor(r).Setup(r.Context())
	if err != nil {
		st, tx := s.agentErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	typed := map[string]string{}
	changed := map[string]string{}
	var keys []string
	for _, e := range entries {
		if !e.Editable {
			continue
		}
		v, ok := r.PostForm[formName(e.Key)]
		if !ok {
			continue
		}
		val := strings.TrimSpace(v[0])
		typed[e.Key] = val
		if val != e.Value {
			changed[e.Key] = val
			keys = append(keys, e.Key)
		}
	}
	if len(changed) == 0 {
		s.redirectMsg(w, r, "/settings/antizapret", "setup_nochange")
		return
	}
	sort.Strings(keys)
	res, err := s.nodeFor(r).SetSetup(r.Context(), changed)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "setup_set", "keys", strings.Join(keys, ","), "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "setup_set", "setup", st, tx+" ("+strings.Join(keys, ",")+")")
		s.setupView(w, r, st, tx, typed)
		return
	}
	var before, after []string
	old := map[string]string{}
	for _, e := range entries {
		old[e.Key] = e.Value
	}
	for _, k := range keys {
		before = append(before, k+"="+old[k])
		after = append(after, k+"="+changed[k])
	}
	s.Log.Info("действие", "user", s.user(r), "op", "setup_set", "keys", strings.Join(keys, ","))
	s.audit(r, "setup_set", "setup", strings.Join(before, "; "), strings.Join(after, "; "))
	to := "/settings/antizapret"
	q := url.Values{"msg": {"setup_saved"}}
	if len(res.Apply) > 0 {
		q.Set("apply", strings.Join(res.Apply, ","))
	}
	s.redirect(w, r, to+"?"+q.Encode(), http.StatusSeeOther)
}
