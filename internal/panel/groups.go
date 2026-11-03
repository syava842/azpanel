package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

var reRemote = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$`)

func init() {
	for k, v := range map[string]string{
		"group_created":  "группа создана",
		"group_verified": "сверка выполнена",
		"group_deleted":  "группа удалена",
		"group_member":   "состав группы изменён",
		"group_promoted": "основной узел назначен",
		"group_addrs":    "адреса для клиентов сохранены",
		"job_started":    "операция запущена; ход виден ниже",
	} {
		msgTexts[k] = v
	}
}

// --- ход длинных операций группы ---

type jobStep struct {
	Text, State, Err string // State: run | ok | fail
}

type groupJob struct {
	mu       sync.Mutex
	Title    string
	Started  time.Time
	Finished time.Time
	Steps    []jobStep
	Running  bool
	Err      string
}

func (j *groupJob) begin(text string) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Steps = append(j.Steps, jobStep{Text: text, State: "run"})
	return len(j.Steps) - 1
}

func (j *groupJob) end(i int, err error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err != nil {
		j.Steps[i].State, j.Steps[i].Err = "fail", err.Error()
		return err
	}
	j.Steps[i].State = "ok"
	return nil
}

// step выполняет шаг f с записью в ход операции.
func (j *groupJob) step(text string, f func() error) error {
	return j.end(j.begin(text), f())
}

func (j *groupJob) snapshot() groupJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	return groupJob{Title: j.Title, Started: j.Started, Finished: j.Finished, Steps: append([]jobStep(nil), j.Steps...), Running: j.Running, Err: j.Err}
}

// startJob запускает операцию группы в фоне (в тестах hub.inline — на месте).
// Одна операция на группу; группа блокируется для копирования на время работы.
func (s *Server) startJob(g store.Group, title string, fn func(ctx context.Context, j *groupJob) error) error {
	rt := s.runtime(g.ID)
	s.hub.mu.Lock()
	if rt.job != nil && rt.job.Running {
		s.hub.mu.Unlock()
		return errors.New("в группе уже идёт операция: «" + rt.job.Title + "»")
	}
	j := &groupJob{Title: title, Started: s.now(), Running: true}
	rt.job = j
	s.hub.mu.Unlock()
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
		defer cancel()
		unlock := s.hub.groupMu.Lock(groupKey(g.ID))
		defer unlock()
		err := fn(ctx, j)
		j.mu.Lock()
		j.Running, j.Finished = false, s.now()
		if err != nil {
			j.Err = err.Error()
		}
		j.mu.Unlock()
		if err != nil {
			s.Log.Warn("операция группы не удалась", "group", g.Name, "op", title, "err", err)
			s.markGroup(g.ID, "«"+title+"» не удалось: "+err.Error())
			s.notifySyncMismatch(ctx, g, "операция «"+title+"» не удалась: "+err.Error())
		} else {
			s.markGroup(g.ID, "")
		}
	}
	if s.hub.inline {
		run()
	} else {
		go run()
	}
	return nil
}

// syncGroupLocked — копирование на реплики для вызова под замком группы.
func (s *Server) syncGroupLocked(ctx context.Context, g store.Group) error {
	primary, replicas, err := s.groupMembers(ctx, g.ID)
	if err != nil {
		return err
	}
	if primary.err != nil {
		return primary.err
	}
	var errs []error
	for _, m := range replicas {
		if m.err != nil {
			errs = append(errs, fmt.Errorf("«%s»: %w", m.name, m.err))
			continue
		}
		if _, err := pushToReplica(ctx, primary.c, m.c, false, false); err != nil {
			errs = append(errs, fmt.Errorf("«%s»: %w", m.name, err))
		}
	}
	return errors.Join(errs...)
}

// --- страницы ---

type groupRow struct {
	ID       int64
	Href     string
	Name     string
	Primary  string
	Replicas int
	State    string
	Bad      bool
}

func (s *Server) groupsPage(w http.ResponseWriter, r *http.Request) {
	s.groupsView(w, r, http.StatusOK, "", "")
}

func (s *Server) groupsView(w http.ResponseWriter, r *http.Request, status int, errText, typedName string) {
	ctx := r.Context()
	gs, err := s.Store.Groups(ctx)
	recs, err2 := s.nodeRecs(ctx)
	if err != nil || err2 != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "группы не прочитаны")
		return
	}
	rows := make([]groupRow, 0, len(gs))
	for _, g := range gs {
		row := groupRow{ID: g.ID, Href: "/groups/" + strconv.FormatInt(g.ID, 10), Name: g.Name, State: "не сверялась"}
		for _, n := range recs {
			if n.GroupID == g.ID && n.Kind == store.KindNode {
				if n.Role == store.RolePrimary {
					row.Primary = n.Name
				} else {
					row.Replicas++
				}
			}
		}
		rt := s.runtime(g.ID)
		s.hub.mu.Lock()
		switch {
		case rt.mark != "":
			row.State, row.Bad = "ошибка: "+rt.mark, true
		case rt.report != nil && rt.report.InSync():
			row.State = "реплики совпадают"
		case rt.report != nil:
			row.State, row.Bad = "есть расхождения", true
		}
		s.hub.mu.Unlock()
		rows = append(rows, row)
	}
	var free []store.NodeRec
	for _, n := range sortedNodes(recs, store.KindNode) {
		if n.GroupID == 0 && n.Connected() {
			free = append(free, n)
		}
	}
	s.render(w, r, status, "groups", map[string]any{"Rows": rows, "Free": free, "Error": errText, "Name": typedName})
}

func (s *Server) groupCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	pid, _ := strconv.ParseInt(r.PostForm.Get("primary"), 10, 64)
	if !reNodeName.MatchString(name) {
		s.groupsView(w, r, http.StatusBadRequest, "Имя группы: до 40 знаков — буквы, цифры, пробел, точка, дефис, подчёркивание.", name)
		return
	}
	rec, ok, _ := s.nodeRec(r.Context(), pid)
	if !ok || rec.Kind != store.KindNode || !rec.Connected() || rec.GroupID != 0 {
		s.groupsView(w, r, http.StatusBadRequest, "Выберите подключённый узел вне групп — он станет основным.", name)
		return
	}
	c, err := s.connect(rec)
	if err != nil {
		s.groupsView(w, r, http.StatusBadGateway, "Узел недоступен: "+err.Error(), name)
		return
	}
	sn, ok := c.syncer()
	if !ok {
		s.groupsView(w, r, http.StatusConflict, "Агент узла не умеет синхронизацию: обновите его.", name)
		return
	}
	// Роль на узле — раньше записи в базу: недоступный узел группы не создаёт.
	if err := sn.SetSyncRole(r.Context(), nodeapi.SyncRole{Role: nodeapi.RolePrimary, Group: name}); err != nil {
		s.groupsView(w, r, http.StatusBadGateway, "Роль на узле не назначена: "+connErrText(err), name)
		return
	}
	id, err := s.Store.AddGroup(r.Context(), name, rec.ID, s.now().Unix())
	if errors.Is(err, store.ErrNodeExists) {
		s.groupsView(w, r, http.StatusConflict, "Группа с таким именем уже есть.", name)
		return
	}
	if err != nil {
		s.groupsView(w, r, http.StatusInternalServerError, "Группа не создана: "+err.Error(), name)
		return
	}
	s.hubReload()
	s.Log.Info("действие", "user", s.user(r), "op", "group_create", "group", name)
	s.audit(r, "group_create", name, "", "основной «"+rec.Name+"»")
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(id, 10), "group_created")
}

// groupFromPath — группа по {id}; нет — 404.
func (s *Server) groupFromPath(w http.ResponseWriter, r *http.Request) (store.Group, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		g, ok, gerr := s.Store.GroupByID(r.Context(), id)
		if gerr != nil {
			s.errorPage(w, r, http.StatusInternalServerError, "группа не прочитана")
			return store.Group{}, false
		}
		if ok {
			return g, true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "группа не найдена")
	return store.Group{}, false
}

type memberRow struct {
	ID                  int64
	Name, Role, Status  string
	Primary, Replica    bool
	Online              bool
	Diffs               []string
	Missing, Extra      []string
	Err, RoleBad        string
	Reported, InSyncNow bool
}

func (s *Server) groupPage(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	s.groupView(w, r, http.StatusOK, g, "")
}

func (s *Server) groupView(w http.ResponseWriter, r *http.Request, status int, g store.Group, errText string) {
	ctx := r.Context()
	recs, err := s.nodeRecs(ctx)
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "узлы не прочитаны")
		return
	}
	var mine []store.NodeRec
	var free []store.NodeRec
	for _, n := range sortedNodes(recs, store.KindNode) {
		switch {
		case n.GroupID == g.ID:
			mine = append(mine, n)
		case n.GroupID == 0 && n.Connected():
			free = append(free, n)
		}
	}
	infos := s.checkNodes(ctx, mine)
	rt := s.runtime(g.ID)
	s.hub.mu.Lock()
	report := rt.report
	mark := rt.mark
	var job *groupJob
	if rt.job != nil {
		sn := rt.job.snapshot()
		job = &sn
	}
	s.hub.mu.Unlock()
	byName := map[string]replicaReport{}
	if report != nil {
		for _, rr := range report.Replicas {
			byName[rr.Name] = rr
		}
	}
	rows := make([]memberRow, 0, len(mine))
	for _, n := range mine {
		row := memberRow{ID: n.ID, Name: n.Name, Role: syncRoleText(n.Role), Primary: n.Role == store.RolePrimary, Replica: n.Role == store.RoleReplica}
		if e := infos[n.ID]; e.err != nil {
			row.Status = "нет связи: " + connErrText(e.err)
		} else {
			row.Status, row.Online = "связь есть", true
		}
		if rr, ok := byName[n.Name]; ok && n.Role == store.RoleReplica {
			row.Reported, row.InSyncNow = true, rr.InSync()
			for _, d := range rr.Diffs {
				row.Diffs = append(row.Diffs, d.Text())
			}
			row.Missing, row.Extra, row.Err, row.RoleBad = rr.ClientsMissing, rr.ClientsExtra, rr.Err, rr.RoleBad
		}
		rows = append(rows, row)
	}
	var remotes []string
	_ = json.Unmarshal([]byte(g.Remotes), &remotes)
	d := map[string]any{"Group": g, "Href": "/groups/" + strconv.FormatInt(g.ID, 10), "Members": rows, "Free": free,
		"Mark": mark, "Job": job, "Remotes": strings.Join(remotes, "\n"), "Error": errText}
	if report != nil {
		d["ReportAt"] = formatTime(&report.At)
		d["PrimaryErr"] = report.PrimaryErr
		d["InSync"] = report.InSync()
	}
	if job != nil && job.Running {
		d["Refresh"] = true
	}
	s.extendGroupView(ctx, g, recs, d)
	s.render(w, r, status, "group", d)
}

func (s *Server) groupVerify(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if _, err := s.verifyAndNotify(ctx, g); err != nil {
		s.groupView(w, r, http.StatusBadGateway, g, "Сверка не выполнена: "+err.Error())
		return
	}
	s.audit(r, "group_verify", g.Name, "", "")
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "group_verified")
}

// memberFromPath — участник группы {nid}.
func (s *Server) memberFromPath(w http.ResponseWriter, r *http.Request, g store.Group) (store.NodeRec, bool) {
	nid, _ := strconv.ParseInt(r.PathValue("nid"), 10, 64)
	rec, ok, _ := s.nodeRec(r.Context(), nid)
	if !ok || rec.GroupID != g.ID || rec.Kind != store.KindNode {
		s.errorPage(w, r, http.StatusNotFound, "узел не состоит в этой группе")
		return store.NodeRec{}, false
	}
	return rec, true
}

// groupAddMember добавляет реплику: роль на узле, затем запись.
func (s *Server) groupAddMember(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	nid, _ := strconv.ParseInt(r.PostForm.Get("node"), 10, 64)
	rec, ok, _ := s.nodeRec(r.Context(), nid)
	if !ok || rec.Kind != store.KindNode || !rec.Connected() || rec.GroupID != 0 {
		s.groupView(w, r, http.StatusBadRequest, g, "Выберите подключённый узел вне групп.")
		return
	}
	c, err := s.connect(rec)
	if err != nil {
		s.groupView(w, r, http.StatusBadGateway, g, "Узел недоступен: "+err.Error())
		return
	}
	sn, ok := c.syncer()
	if !ok {
		s.groupView(w, r, http.StatusConflict, g, "Агент узла не умеет синхронизацию: обновите его.")
		return
	}
	if err := sn.SetSyncRole(r.Context(), nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: g.Name}); err != nil {
		s.groupView(w, r, http.StatusBadGateway, g, "Роль на узле не назначена: "+connErrText(err))
		return
	}
	if err := s.Store.SetNodeGroup(r.Context(), rec.ID, g.ID, store.RoleReplica); err != nil {
		s.groupView(w, r, http.StatusInternalServerError, g, "Узел не добавлен: "+err.Error())
		return
	}
	s.hubReload()
	s.audit(r, "group_add_replica", g.Name, "", rec.Name)
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "group_member")
}

// groupRemoveMember выводит реплику из группы; роль на узле возвращается к
// основному (это обычный автономный узел).
func (s *Server) groupRemoveMember(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	rec, ok := s.memberFromPath(w, r, g)
	if !ok {
		return
	}
	if rec.Role == store.RolePrimary {
		s.groupView(w, r, http.StatusConflict, g, "Основной узел нельзя вывести: сначала назначьте другой основной.")
		return
	}
	if !formConfirmed(r) {
		s.groupView(w, r, http.StatusBadRequest, g, "Отметьте подтверждение.")
		return
	}
	s.resetRole(r.Context(), rec)
	if err := s.Store.SetNodeGroup(r.Context(), rec.ID, 0, ""); err != nil {
		s.groupView(w, r, http.StatusInternalServerError, g, "Узел не выведен: "+err.Error())
		return
	}
	s.hubReload()
	s.audit(r, "group_remove_replica", g.Name, "", rec.Name)
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "group_member")
}

// resetRole возвращает узлу автономную роль; недоступный узел пропускается:
// роль останется, пока он не вернётся (запись в базе уже снята).
func (s *Server) resetRole(ctx context.Context, rec store.NodeRec) {
	c, err := s.connect(rec)
	if err != nil {
		return
	}
	if sn, ok := c.syncer(); ok {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := sn.SetSyncRole(rctx, nodeapi.SyncRole{Role: nodeapi.RolePrimary}); err != nil {
			s.Log.Warn("роль узла не сброшена", "node", rec.Name, "err", err)
		}
	}
}

// groupAlign — «Выровнять» реплику: бэкап, полная замена набора, сверка.
func (s *Server) groupAlign(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	rec, ok := s.memberFromPath(w, r, g)
	if !ok {
		return
	}
	if rec.Role != store.RoleReplica {
		s.groupView(w, r, http.StatusConflict, g, "Выравнивается только реплика.")
		return
	}
	if !formConfirmed(r) {
		s.groupView(w, r, http.StatusBadRequest, g, "Отметьте подтверждение: набор файлов реплики будет заменён набором основного (перед этим делается бэкап реплики).")
		return
	}
	err := s.startJob(g, "Выровнять «"+rec.Name+"»", func(ctx context.Context, j *groupJob) error {
		return s.alignReplica(ctx, j, g, rec, r.PostForm.Get("force") == "1")
	})
	if err != nil {
		s.groupView(w, r, http.StatusConflict, g, err.Error())
		return
	}
	s.audit(r, "group_align", g.Name, "", rec.Name)
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "job_started")
}

func (s *Server) alignReplica(ctx context.Context, j *groupJob, g store.Group, rec store.NodeRec, force bool) error {
	primary, _, err := s.groupMembers(ctx, g.ID)
	if err != nil {
		return err
	}
	if primary.err != nil {
		return primary.err
	}
	rc, err := s.connect(rec)
	if err != nil {
		return err
	}
	bn, ok := rc.raw.(BackupNode)
	if !ok {
		return errors.New("агент реплики не умеет бэкап: обновите его")
	}
	if err := j.step("Бэкап реплики (client.sh 8)", func() error {
		t, err := bn.CreateBackup(ctx)
		if err != nil {
			return err
		}
		return waitTask(ctx, rc.node, t.ID)
	}); err != nil {
		return err
	}
	if err := j.step("Замена набора файлов реплики набором основного", func() error {
		_, err := pushToReplica(ctx, primary.c, rc, true, force)
		return err
	}); err != nil {
		return err
	}
	return j.step("Сверка", func() error {
		pm, err := primary.c.syncerMust().SyncManifest(ctx)
		if err != nil {
			return err
		}
		rm, err := rc.syncerMust().SyncManifest(ctx)
		if err != nil {
			return err
		}
		if _, diffs := diffManifests(pm, rm); len(diffs) > 0 {
			return fmt.Errorf("остались расхождения: %s", diffs[0].Text())
		}
		return nil
	})
}

func (c *conn) syncerMust() SyncNode {
	s, _ := c.syncer()
	return s
}

// groupPromote — «Назначить основным»: реплика становится основным, прежний
// основной — репликой (недоступный — выводится из группы).
func (s *Server) groupPromote(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	rec, ok := s.memberFromPath(w, r, g)
	if !ok {
		return
	}
	if rec.Role != store.RoleReplica {
		s.groupView(w, r, http.StatusConflict, g, "Основным можно назначить только реплику.")
		return
	}
	if !formConfirmed(r) {
		s.groupView(w, r, http.StatusBadRequest, g, "Отметьте подтверждение.")
		return
	}
	unlock := s.hub.groupMu.Lock(groupKey(g.ID))
	defer unlock()
	recs, _ := s.nodeRecs(r.Context())
	var old *store.NodeRec
	for i := range recs {
		if recs[i].GroupID == g.ID && recs[i].Role == store.RolePrimary && recs[i].Kind == store.KindNode {
			old = &recs[i]
		}
	}
	nc, err := s.connect(rec)
	if err != nil {
		s.groupView(w, r, http.StatusBadGateway, g, "Новый основной недоступен: "+err.Error())
		return
	}
	ns, ok := nc.syncer()
	if !ok {
		s.groupView(w, r, http.StatusConflict, g, "Агент узла не умеет синхронизацию: обновите его.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	oldReachable := false
	var os SyncNode
	if old != nil {
		if oc, err := s.connect(*old); err == nil {
			if os, ok = oc.syncer(); ok {
				// Прежний основной уходит в реплики первым: два основных не бывает.
				oldReachable = os.SetSyncRole(ctx, nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: g.Name}) == nil
			}
		}
	}
	if err := ns.SetSyncRole(ctx, nodeapi.SyncRole{Role: nodeapi.RolePrimary, Group: g.Name}); err != nil {
		if oldReachable { // откат: прежний основной остаётся основным
			_ = os.SetSyncRole(ctx, nodeapi.SyncRole{Role: nodeapi.RolePrimary, Group: g.Name})
		}
		s.groupView(w, r, http.StatusBadGateway, g, "Роль основного на узле не назначена: "+connErrText(err))
		return
	}
	roles := map[int64]string{rec.ID: store.RolePrimary}
	removed := ""
	if old != nil {
		if oldReachable {
			roles[old.ID] = store.RoleReplica
		} else {
			removed = old.Name
		}
	}
	if err := s.Store.SetNodeRoles(r.Context(), roles); err != nil {
		s.groupView(w, r, http.StatusInternalServerError, g, "Роли не записаны: "+err.Error())
		return
	}
	if removed != "" {
		_ = s.Store.SetNodeGroup(r.Context(), old.ID, 0, "")
	}
	s.hubReload()
	detail := "новый основной «" + rec.Name + "»"
	if removed != "" {
		detail += "; прежний «" + removed + "» недоступен и выведен из группы"
	}
	s.Log.Info("действие", "user", s.user(r), "op", "group_promote", "group", g.Name, "node", rec.Name)
	s.audit(r, "group_promote", g.Name, "", detail)
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "group_promoted")
}

// groupAddrs сохраняет адреса для клиентов: общий домен и список remote.
// Новый домен вписывается в OPENVPN_HOST и WIREGUARD_HOST основного,
// профили пересоздаются (client.sh 7) и расходятся по репликам.
func (s *Server) groupAddrs(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	domain := strings.TrimSpace(r.PostForm.Get("domain"))
	if domain != "" && !reDomain.MatchString(domain) {
		s.groupView(w, r, http.StatusBadRequest, g, "Домен: имя вида vpn.example.org.")
		return
	}
	var remotes []string
	for _, line := range strings.Split(r.PostForm.Get("remotes"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !reRemote.MatchString(line) {
			s.groupView(w, r, http.StatusBadRequest, g, "Адрес «"+line+"» не годится: «хост» или «хост:порт» по одному в строке.")
			return
		}
		remotes = append(remotes, line)
	}
	if len(remotes) > 8 {
		s.groupView(w, r, http.StatusBadRequest, g, "Не больше восьми адресов remote.")
		return
	}
	b, _ := json.Marshal(remotes)
	if remotes == nil {
		b = []byte("[]")
	}
	if err := s.Store.SetGroupAddrs(r.Context(), g.ID, domain, string(b)); err != nil {
		s.groupView(w, r, http.StatusInternalServerError, g, "Адреса не сохранены: "+err.Error())
		return
	}
	s.audit(r, "group_addrs", g.Name, g.Domain+" "+g.Remotes, domain+" "+string(b))
	if domain != "" && domain != g.Domain {
		err := s.startJob(g, "Домен «"+domain+"» в профилях", func(ctx context.Context, j *groupJob) error {
			return s.applyDomain(ctx, j, g, domain)
		})
		if err != nil {
			s.groupView(w, r, http.StatusConflict, g, err.Error())
			return
		}
		s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "job_started")
		return
	}
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "group_addrs")
}

func (s *Server) applyDomain(ctx context.Context, j *groupJob, g store.Group, domain string) error {
	primary, _, err := s.groupMembers(ctx, g.ID)
	if err != nil {
		return err
	}
	if primary.err != nil {
		return primary.err
	}
	if err := j.step("Домен в OPENVPN_HOST и WIREGUARD_HOST основного", func() error {
		_, err := primary.c.node.SetSetup(ctx, map[string]string{"OPENVPN_HOST": domain, "WIREGUARD_HOST": domain})
		return err
	}); err != nil {
		return err
	}
	if err := j.step("Пересоздание профилей (client.sh 7)", func() error {
		t, err := primary.c.node.RebuildProfiles(ctx)
		if err != nil {
			return err
		}
		return waitTask(ctx, primary.c.node, t.ID)
	}); err != nil {
		return err
	}
	return j.step("Копирование на реплики", func() error { return s.syncGroupLocked(ctx, g) })
}

// groupUpdateAZ — обновление AntiZapret по группе: реплики по одному, основной
// последним; следующий узел — только после успешного предыдущего.
func (s *Server) groupUpdateAZ(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	if !formConfirmed(r) {
		s.groupView(w, r, http.StatusBadRequest, g, "Отметьте подтверждение: серверы группы будут по очереди перезагружены, VPN на каждом прервётся.")
		return
	}
	err := s.startJob(g, "Обновление AntiZapret по группе", func(ctx context.Context, j *groupJob) error {
		return s.updateGroupAZ(ctx, j, g)
	})
	if err != nil {
		s.groupView(w, r, http.StatusConflict, g, err.Error())
		return
	}
	s.audit(r, "group_az_update", g.Name, "", "запущено")
	s.redirectMsg(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), "job_started")
}

func (s *Server) updateGroupAZ(ctx context.Context, j *groupJob, g store.Group) error {
	primary, replicas, err := s.groupMembers(ctx, g.ID)
	if err != nil {
		return err
	}
	order := append(append([]member(nil), replicas...), primary)
	for _, m := range order {
		if m.err != nil {
			return fmt.Errorf("«%s»: %w", m.name, m.err)
		}
		if m.c.svc == nil {
			return fmt.Errorf("«%s»: агент не умеет обновление AntiZapret", m.name)
		}
	}
	for _, m := range order {
		if err := j.step("«"+m.name+"»: обновление AntiZapret", func() error { return s.updateOneAZ(ctx, m) }); err != nil {
			return fmt.Errorf("остановлено на узле «%s»: %w", m.name, err)
		}
	}
	return nil
}

func (s *Server) updateOneAZ(ctx context.Context, m member) error {
	svc := m.c.svc
	pf, err := svc.AZPreflight(ctx)
	if err != nil {
		return fmt.Errorf("проверки: %w", err)
	}
	if !pf.OK {
		return fmt.Errorf("проверки не пройдены: %s", strings.Join(pf.Reasons, "; "))
	}
	st, err := svc.AZUpdate(ctx, nodeapi.AZUpdateRequest{})
	if err != nil {
		return err
	}
	deadline := time.Now().Add(azWaitMax)
	for {
		cur, err := svc.AZUpdateState(ctx)
		if err == nil && !cur.Started.Before(st.Started) && cur.Status != nodeapi.AZStatusRunning && cur.Status != "" {
			if cur.Status == nodeapi.AZStatusOK {
				return nil
			}
			return fmt.Errorf("обновление не удалось: %s", strings.Join(cur.Reasons, "; "))
		}
		// ошибка связи — обычное дело во время перезагрузки: ждём
		if time.Now().After(deadline) {
			return errors.New("обновление не завершилось за отведённое время")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(azPoll):
		}
	}
}

func (s *Server) groupDelete(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}
	if !formConfirmed(r) {
		s.groupView(w, r, http.StatusBadRequest, g, "Отметьте подтверждение.")
		return
	}
	recs, _ := s.nodeRecs(r.Context())
	for _, n := range recs {
		if n.GroupID == g.ID && n.Kind == store.KindNode {
			s.resetRole(r.Context(), n)
		}
	}
	if err := s.Store.DeleteGroup(r.Context(), g.ID); err != nil {
		s.groupView(w, r, http.StatusInternalServerError, g, "Группа не удалена: "+err.Error())
		return
	}
	s.hubReload()
	s.audit(r, "group_delete", g.Name, "", "")
	s.redirectMsg(w, r, "/groups", "group_deleted")
}

// --- адреса remote в профилях OpenVPN ---

// rewriteOvpn заменяет блок строк remote в .ovpn списком адресов группы по
// порядку. Порт и протокол берутся из адреса («хост:порт») или из первой
// исходной строки remote.
func rewriteOvpn(data []byte, remotes []string) []byte {
	if len(remotes) == 0 {
		return data
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	done := false
	var port, proto string
	for _, ln := range lines {
		f := strings.Fields(strings.TrimRight(ln, "\r"))
		cr := ""
		if strings.HasSuffix(ln, "\r") {
			cr = "\r"
		}
		if len(f) >= 2 && f[0] == "remote" {
			if !done {
				if len(f) >= 3 {
					port = f[2]
				}
				if len(f) >= 4 {
					proto = f[3]
				}
				for _, rm := range remotes {
					host, p := rm, port
					if h, pp, ok := strings.Cut(rm, ":"); ok {
						host, p = h, pp
					}
					line := "remote " + host
					if p != "" {
						line += " " + p
					}
					if proto != "" {
						line += " " + proto
					}
					out = append(out, line+cr)
				}
				done = true
			}
			continue
		}
		out = append(out, ln)
	}
	if !done {
		return data
	}
	return []byte(strings.Join(out, "\n"))
}

// groupRemotes — список remote группы узла.
// Группы — отложенная возможность: без panel.experimental оставшаяся в базе
// группа профили не переписывает (как и копирование на реплики).
func (s *Server) groupRemotes(ctx context.Context, nodeID int64) []string {
	if s.Store == nil || nodeID == 0 || !s.Experimental {
		return nil
	}
	rec, ok, err := s.nodeRec(ctx, nodeID)
	if err != nil || !ok || rec.GroupID == 0 {
		return nil
	}
	g, ok, err := s.Store.GroupByID(ctx, rec.GroupID)
	if err != nil || !ok {
		return nil
	}
	var remotes []string
	if json.Unmarshal([]byte(g.Remotes), &remotes) != nil {
		return nil
	}
	return remotes
}

// fixProfile подставляет адреса группы в скачиваемый .ovpn.
func (s *Server) fixProfile(ctx context.Context, nodeID int64, kind, file string, data []byte) []byte {
	if kind != nodeapi.KindOpenVPN || !bytes.Contains(data, []byte("remote ")) {
		return data
	}
	return rewriteOvpn(data, s.groupRemotes(ctx, nodeID))
}

// extendGroupView — место для данных страницы группы, которые добавляют
// другие разделы (прокси).
func (s *Server) extendGroupView(ctx context.Context, g store.Group, recs []store.NodeRec, d map[string]any) {
}
