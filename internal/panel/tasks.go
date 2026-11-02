package panel

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/syava842/azpanel/internal/nodeapi"
)

var reTaskID = regexp.MustCompile(`^[0-9a-f]{12}$`)

// taskKinds — названия видов задач.
var taskKinds = map[string]string{
	"doall":    "Применение списков (doall.sh)",
	"restart":  "Перезапуск antizapret",
	"profiles": "Пересоздание профилей клиентов",
}

func taskKindTitle(kind string) string {
	if t, ok := taskKinds[kind]; ok {
		return t
	}
	return kind
}

func taskHref(id string) string { return "/tasks/" + id }

type taskRow struct {
	ID, Href, Kind   string
	Started, Ended   string
	Status           string
	Running, Failure bool
}

// newTaskRow: идёт — нет времени окончания; код 0 — успех; прерванная
// перезапуском агента задача кода выхода не имеет.
func newTaskRow(t nodeapi.Task) taskRow {
	row := taskRow{ID: t.ID, Href: taskHref(t.ID), Kind: taskKindTitle(t.Kind), Started: formatTime(&t.Started), Ended: "—"}
	switch {
	case t.Finished == nil:
		row.Running, row.Status = true, "идёт"
	case t.Interrupted && t.ExitCode == nil:
		row.Ended, row.Status, row.Failure = formatTime(t.Finished), "прервана перезапуском агента, итог неизвестен", true
	case t.ExitCode == nil:
		row.Ended, row.Status, row.Failure = formatTime(t.Finished), "завершена, код выхода неизвестен", true
	case *t.ExitCode == 0:
		row.Ended, row.Status = formatTime(t.Finished), "успешно (код 0)"
	default:
		row.Ended, row.Status, row.Failure = formatTime(t.Finished), "ошибка, код "+strconv.Itoa(*t.ExitCode), true
	}
	return row
}

func (s *Server) tasksPage(w http.ResponseWriter, r *http.Request) {
	list, err := s.Node.Tasks(r.Context())
	if err != nil {
		st, tx := s.agentErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	rows := make([]taskRow, 0, len(list))
	running := false
	for _, t := range list {
		row := newTaskRow(t)
		running = running || row.Running
		rows = append(rows, row)
	}
	s.render(w, r, http.StatusOK, "tasks", map[string]any{"Rows": rows, "Running": running})
}

func (s *Server) taskPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reTaskID.MatchString(id) {
		s.errorPage(w, r, http.StatusNotFound, "задача не найдена")
		return
	}
	d, err := s.Node.Task(r.Context(), id)
	if err != nil {
		st, tx := s.agentErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	row := newTaskRow(d.Task)
	s.render(w, r, http.StatusOK, "task", map[string]any{"Task": row, "Tail": d.Tail, "Running": row.Running, "Log": d.Log})
}

// taskStart запускает задачу и ведёт на её страницу. Вид — из закрытого
// списка; чужая задача уже идёт — 409 с текстом агента.
func (s *Server) taskStart(w http.ResponseWriter, r *http.Request) {
	kind := r.PostForm.Get("kind")
	var start func() (nodeapi.Task, error)
	switch kind {
	case "doall":
		start = func() (nodeapi.Task, error) { return s.Node.ApplyRouting(r.Context()) }
	case "restart":
		start = func() (nodeapi.Task, error) { return s.Node.RestartAntiZapret(r.Context()) }
	case "profiles":
		start = func() (nodeapi.Task, error) { return s.Node.RebuildProfiles(r.Context()) }
	default:
		s.errorPage(w, r, http.StatusBadRequest, "неизвестный вид задачи")
		return
	}
	t, err := start()
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "task_start", "kind", kind, "err", err)
		st, tx := s.agentErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "task_start", "kind", kind, "task", t.ID)
	s.audit(r, "task_start", kind, "", t.ID)
	http.Redirect(w, r, taskHref(t.ID), http.StatusSeeOther)
}
