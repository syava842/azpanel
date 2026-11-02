package panel

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/syava842/azpanel/internal/nodeapi"
)

var reCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// azMemory — что панель в последний раз видела у обновления AntiZapret. По
// нему ошибка связи при последнем известном running читается как
// «перезагрузка», а не как отказ.
type azMemory struct {
	mu     sync.Mutex
	status string
	phase  string
}

func (m *azMemory) set(status, phase string) {
	m.mu.Lock()
	m.status, m.phase = status, phase
	m.mu.Unlock()
}

func (m *azMemory) running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status == nodeapi.AZStatusRunning
}

type azCommitRow struct{ Short, SHA, Message, Date string }

func azCommitRows(cs []nodeapi.AZCommit) []azCommitRow {
	out := make([]azCommitRow, 0, len(cs))
	for _, c := range cs {
		d := c.Date
		out = append(out, azCommitRow{Short: shortSHA(c.SHA), SHA: c.SHA, Message: c.Message, Date: formatTime(&d)})
	}
	return out
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

type azBackupRow struct{ Name, Size, Time string }

type azStateView struct {
	Title, Status, Phase string
	Started, Finished    string
	From, Commit         string
	Failed, Running, OK  bool
	Reasons, Warnings    []string
	Notes                []string
	Services             []string
	Extras               []string
	TaskHref             string
	CanRestore           bool
	Backup               string
}

var azPhaseTexts = map[string]string{
	nodeapi.AZPhasePrepare: "подготовка: проверки, бэкап и setup.sh",
	nodeapi.AZPhaseReboot:  "сервер перезагружается",
	nodeapi.AZPhaseVerify:  "сервер поднялся, агент проверяет службы и клиентов",
}

func azStateRow(st nodeapi.AZUpdateState) azStateView {
	v := azStateView{Title: "Обновление", From: shortSHA(st.From), Commit: shortSHA(st.Commit), Backup: st.Backup,
		Reasons: st.Reasons, Warnings: st.Warnings, Notes: st.Notes, CanRestore: st.CanRestore}
	if st.Action == nodeapi.AZActionRestore {
		v.Title = "Восстановление из бэкапа"
	}
	switch st.Status {
	case nodeapi.AZStatusRunning:
		v.Running, v.Status = true, "идёт"
		v.Phase = azPhaseTexts[st.Phase]
	case nodeapi.AZStatusOK:
		v.OK, v.Status = true, "успешно"
	case nodeapi.AZStatusFailed:
		v.Failed, v.Status = true, "не удалось"
	}
	if !st.Started.IsZero() {
		t := st.Started
		v.Started = formatTime(&t)
	}
	v.Finished = formatTime(st.Finished)
	for _, sv := range st.Services {
		v.Services = append(v.Services, sv.Unit+": "+sv.State)
	}
	keys := make([]string, 0, len(st.Extras))
	for k := range st.Extras {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v.Extras = append(v.Extras, k+": "+st.Extras[k])
	}
	if st.TaskID != "" && reTaskID.MatchString(st.TaskID) {
		v.TaskHref = taskHref(st.TaskID)
	}
	return v
}

// azSetupRow — ключ setup, который меняется только переустановкой.
type azSetupRow struct {
	Key, Title, Value, Hint string
	Options                 []optionRow
}

func azReinstallRows(entries []nodeapi.SetupEntry, typed map[string]string) []azSetupRow {
	var out []azSetupRow
	for _, e := range entries {
		if !contains(e.Apply, nodeapi.ApplyReinstall) {
			continue
		}
		val := e.Value
		if t, ok := typed[e.Key]; ok {
			val = t
		}
		row := azSetupRow{Key: e.Key, Title: e.Title, Value: val, Hint: e.Hint}
		if row.Title == "" {
			row.Title = e.Key
		}
		opts := e.Options
		if e.Kind == "yn" {
			opts = []string{"y", "n"}
		}
		if len(opts) > 0 {
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
		out = append(out, row)
	}
	return out
}

func (s *Server) azUpdatePage(w http.ResponseWriter, r *http.Request) {
	s.azView(w, r, http.StatusOK, "", nil)
}

// azView собирает страницу: версия, проверки, состояние. Сбой одной части
// страницу не роняет — пишется текстом на своём месте.
func (s *Server) azView(w http.ResponseWriter, r *http.Request, status int, errText string, typed map[string]string) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	data := map[string]any{}
	if errText != "" {
		data["Error"] = errText
	}
	running := false
	stt, err := n.AZUpdateState(ctx)
	switch {
	case err == nil:
		s.az.set(stt.Status, stt.Phase)
		view := azStateRow(stt)
		running = view.Running
		if stt.Status != "" {
			data["State"] = view
		}
		bk := make([]azBackupRow, 0, len(stt.Backups))
		for _, b := range stt.Backups {
			t := b.Time
			bk = append(bk, azBackupRow{Name: b.Name, Size: humanBytes(uint64(max(b.Bytes, 0))), Time: formatTime(&t)})
		}
		data["Backups"] = bk
	case isNetErr(err) && s.az.running():
		data["Rebooting"], running = true, true
	default:
		_, tx := s.svcErr(err)
		data["StateErr"] = "состояние обновления недоступно: " + tx
	}
	data["Running"] = running
	if !running {
		if v, err := n.AZVersion(ctx); err != nil {
			_, tx := s.svcErr(err)
			data["VerErr"] = "версия недоступна: " + tx
		} else {
			data["Ver"] = v
			data["Behind"] = azCommitRows(v.Behind)
			if v.Latest != nil {
				data["LatestShort"], data["LatestSHA"] = shortSHA(v.Latest.SHA), v.Latest.SHA
			}
			if v.Current != "" {
				data["CurrentShort"] = shortSHA(v.Current)
			}
		}
		if pf, err := n.AZPreflight(ctx); err != nil {
			_, tx := s.svcErr(err)
			data["PreErr"] = "проверки недоступны: " + tx
		} else {
			data["Pre"] = pf
		}
		if entries, err := s.nodeFor(r).Setup(ctx); err == nil {
			data["Reinstall"] = azReinstallRows(entries, typed)
		}
	}
	s.render(w, r, status, "azupdate", data)
}

// azStart запускает обновление: только с подтверждением перезагрузки. Из
// формы берутся номер коммита, который администратор видел на странице, и
// изменённые ключи setup с применением reinstall.
func (s *Server) azStart(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	typed := map[string]string{}
	values := map[string]string{}
	var keys []string
	if entries, err := s.nodeFor(r).Setup(ctx); err == nil {
		for _, e := range entries {
			if !contains(e.Apply, nodeapi.ApplyReinstall) {
				continue
			}
			v, present := r.PostForm[formName(e.Key)]
			if !present {
				continue
			}
			val := strings.TrimSpace(v[0])
			typed[e.Key] = val
			if val != e.Value {
				values[e.Key] = val
				keys = append(keys, e.Key)
			}
		}
	}
	sort.Strings(keys)
	if !formConfirmed(r) {
		s.azView(w, r, http.StatusBadRequest, "Отметьте подтверждение: сервер будет перезагружен, VPN прервётся.", typed)
		return
	}
	commit := strings.TrimSpace(r.PostForm.Get("commit"))
	if commit != "" && !reCommit.MatchString(commit) {
		s.azView(w, r, http.StatusBadRequest, "Номер коммита должен быть 40 шестнадцатеричных знаков.", typed)
		return
	}
	target := commit
	if target == "" {
		target = "последний"
	}
	var changes []string
	for _, k := range keys {
		changes = append(changes, k+"="+values[k])
	}
	st, err := n.AZUpdate(ctx, nodeapi.AZUpdateRequest{Commit: commit, Values: values})
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "az_update", "commit", commit, "err", err)
		status, tx := s.svcErr(err)
		s.auditRefused(r, "az_update", target, status, tx)
		s.azView(w, r, status, tx, typed)
		return
	}
	s.az.set(st.Status, st.Phase)
	s.Log.Info("действие", "user", s.user(r), "op", "az_update", "commit", commit, "task", st.TaskID)
	s.audit(r, "az_update", target, "", strings.TrimSpace("запущено; "+strings.Join(changes, "; ")+" задача "+st.TaskID))
	s.redirectMsg(w, r, "/antizapret/update", "az_started")
}

// azRestore запускает восстановление из бэкапа, выбранного из списка агента.
func (s *Server) azRestore(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("backup"))
	if !formConfirmed(r) {
		s.azView(w, r, http.StatusBadRequest, "Отметьте подтверждение: сервер будет перезагружен, а клиенты и настройки заменены бэкапом.", nil)
		return
	}
	cur, err := n.AZUpdateState(r.Context())
	if err != nil {
		s.serviceRefused(w, r, "az_restore", name, err)
		return
	}
	found := false
	for _, b := range cur.Backups {
		found = found || b.Name == name
	}
	if !found {
		s.azView(w, r, http.StatusBadRequest, "Такого бэкапа на узле нет.", nil)
		return
	}
	st, err := n.AZRestore(r.Context(), name)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "az_restore", "backup", name, "err", err)
		status, tx := s.svcErr(err)
		s.auditRefused(r, "az_restore", name, status, tx)
		s.azView(w, r, status, tx, nil)
		return
	}
	s.az.set(st.Status, st.Phase)
	s.Log.Info("действие", "user", s.user(r), "op", "az_restore", "backup", name, "task", st.TaskID)
	s.audit(r, "az_restore", name, "", "запущено; задача "+st.TaskID)
	s.redirectMsg(w, r, "/antizapret/update", "az_restore_started")
}
