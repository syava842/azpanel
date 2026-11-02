package panel

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/panel/bot"
	"github.com/syava842/azpanel/internal/store"
)

// SyncNode — синхронизация файлов у агента; *nodeapi.HTTPClient подходит.
type SyncNode interface {
	SyncManifest(ctx context.Context) (nodeapi.SyncManifest, error)
	SyncFile(ctx context.Context, path string) (io.ReadCloser, error)
	SyncApply(ctx context.Context, archive io.Reader, opts nodeapi.SyncApplyOpts) (nodeapi.Task, error)
	SyncRole(ctx context.Context) (nodeapi.SyncRole, error)
	SetSyncRole(ctx context.Context, r nodeapi.SyncRole) error
}

// BackupNode — бэкап узла (client.sh 8) задачей.
type BackupNode interface {
	CreateBackup(ctx context.Context) (nodeapi.Task, error)
}

var (
	_ SyncNode   = (*nodeapi.HTTPClient)(nil)
	_ BackupNode = (*nodeapi.HTTPClient)(nil)
)

var (
	taskPoll       = 2 * time.Second // как часто спрашиваем задачу агента
	taskWaitMax    = 30 * time.Minute
	azPoll         = 10 * time.Second
	azWaitMax      = 45 * time.Minute // обновление AntiZapret с перезагрузкой
	groupVerifyDur = 10 * time.Minute
)

func (c *conn) syncer() (SyncNode, bool) {
	s, ok := c.raw.(SyncNode)
	return s, ok
}

// member — участник группы: запись и подключение.
type member struct {
	c    *conn
	err  error // подключение не собрано
	name string
}

// groupMembers: основной и реплики группы. Основной один; нет основного —
// ошибка. Реплики по возрастанию id.
func (s *Server) groupMembers(ctx context.Context, gid int64) (primary member, replicas []member, err error) {
	recs, err := s.nodeRecs(ctx)
	if err != nil {
		return member{}, nil, err
	}
	have := false
	for _, rec := range recs {
		if rec.Kind != store.KindNode || rec.GroupID != gid {
			continue
		}
		m := member{name: rec.Name}
		m.c, m.err = s.connect(rec)
		switch rec.Role {
		case store.RolePrimary:
			primary, have = m, true
		case store.RoleReplica:
			replicas = append(replicas, m)
		}
	}
	if !have {
		return member{}, nil, errors.New("в группе нет основного узла")
	}
	return primary, replicas, nil
}

// fileDiff — расхождение одного файла набора.
type fileDiff struct {
	Path string
	Kind string // differs | missing | extra
}

func (d fileDiff) Text() string {
	switch d.Kind {
	case "missing":
		return d.Path + " — нет на реплике"
	case "extra":
		return d.Path + " — лишний на реплике"
	}
	return d.Path + " — содержимое отличается"
}

// diffManifests: что надо записать на реплику (из манифеста основного) и что
// лежит на реплике лишним.
func diffManifests(primary, replica nodeapi.SyncManifest) (push []nodeapi.SyncEntry, diffs []fileDiff) {
	have := map[string]nodeapi.SyncEntry{}
	for _, e := range replica.Files {
		have[e.Path] = e
	}
	seen := map[string]bool{}
	for _, e := range primary.Files {
		seen[e.Path] = true
		r, ok := have[e.Path]
		switch {
		case !ok:
			push, diffs = append(push, e), append(diffs, fileDiff{e.Path, "missing"})
		case r.SHA256 != e.SHA256 || r.Size != e.Size:
			push, diffs = append(push, e), append(diffs, fileDiff{e.Path, "differs"})
		}
	}
	for _, e := range replica.Files {
		if !seen[e.Path] {
			diffs = append(diffs, fileDiff{e.Path, "extra"})
		}
	}
	sort.SliceStable(diffs, func(i, j int) bool { return diffs[i].Path < diffs[j].Path })
	return push, diffs
}

// replicaReport — итог сверки одной реплики.
type replicaReport struct {
	Name  string
	ID    int64
	Err   string
	Diffs []fileDiff
	// ClientsMissing — клиенты основного, которых нет на реплике; ClientsExtra — наоборот.
	ClientsMissing, ClientsExtra []string
	RoleBad                      string
}

func (r replicaReport) InSync() bool {
	return r.Err == "" && len(r.Diffs) == 0 && len(r.ClientsMissing) == 0 && len(r.ClientsExtra) == 0 && r.RoleBad == ""
}

// groupReport — итог сверки группы.
type groupReport struct {
	At         time.Time
	PrimaryErr string
	Replicas   []replicaReport
}

func (g groupReport) InSync() bool {
	if g.PrimaryErr != "" {
		return false
	}
	for _, r := range g.Replicas {
		if !r.InSync() {
			return false
		}
	}
	return true
}

// signature — отпечаток расхождений: по нему уведомление не повторяется,
// пока картина не изменилась.
func (g groupReport) signature() string {
	var b strings.Builder
	b.WriteString(g.PrimaryErr)
	for _, r := range g.Replicas {
		b.WriteString("|" + r.Name + ":" + r.Err + r.RoleBad)
		for _, d := range r.Diffs {
			b.WriteString(";" + d.Kind + d.Path)
		}
		b.WriteString(";cm" + strings.Join(r.ClientsMissing, ","))
		b.WriteString(";ce" + strings.Join(r.ClientsExtra, ","))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

func clientNames(cs []nodeapi.Client) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.Name] = true
	}
	return out
}

func setDiff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// verifyGroup сверяет основной со всеми репликами: манифесты, список клиентов
// (запущенное состояние), роль на узле. Реплики опрашиваются параллельно.
func (s *Server) verifyGroup(ctx context.Context, g store.Group) (groupReport, error) {
	primary, replicas, err := s.groupMembers(ctx, g.ID)
	if err != nil {
		return groupReport{}, err
	}
	rep := groupReport{At: s.now(), Replicas: make([]replicaReport, len(replicas))}
	ps, ok := primary.syncerOrErr()
	if !ok {
		rep.PrimaryErr = "основной «" + primary.name + "»: " + primary.errText()
		return rep, nil
	}
	pm, err := ps.SyncManifest(ctx)
	if err != nil {
		rep.PrimaryErr = "основной «" + primary.name + "»: " + connErrText(err)
		return rep, nil
	}
	var pclients map[string]bool
	if cs, err := primary.c.node.Clients(ctx); err == nil {
		pclients = clientNames(cs)
	}
	var wg sync.WaitGroup
	for i, m := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := replicaReport{Name: m.name, ID: m.c.recID()}
			defer func() { rep.Replicas[i] = rr }()
			rs, ok := m.syncerOrErr()
			if !ok {
				rr.Err = m.errText()
				return
			}
			rm, err := rs.SyncManifest(ctx)
			if err != nil {
				rr.Err = connErrText(err)
				return
			}
			_, rr.Diffs = diffManifests(pm, rm)
			if role, err := rs.SyncRole(ctx); err == nil && role.Role != nodeapi.RoleReplica {
				rr.RoleBad = "на узле роль «" + role.Role + "», а в панели — реплика"
			}
			if pclients != nil {
				if cs, err := m.c.node.Clients(ctx); err == nil {
					rc := clientNames(cs)
					rr.ClientsMissing, rr.ClientsExtra = setDiff(pclients, rc), setDiff(rc, pclients)
				}
			}
		}()
	}
	wg.Wait()
	return rep, nil
}

func (c *conn) recID() int64 {
	if c == nil {
		return 0
	}
	return c.rec.ID
}

func (m member) syncerOrErr() (SyncNode, bool) {
	if m.err != nil || m.c == nil {
		return nil, false
	}
	return m.c.syncer()
}

func (m member) errText() string {
	if m.err != nil {
		return m.err.Error()
	}
	return "агент не умеет синхронизацию: обновите его"
}

// waitTask ждёт завершения задачи агента; ненулевой код — ошибка с хвостом журнала.
func waitTask(ctx context.Context, n Node, id string) error {
	if id == "" {
		return nil
	}
	deadline := time.Now().Add(taskWaitMax)
	for {
		d, err := n.Task(ctx, id)
		if err == nil && d.Finished != nil {
			switch {
			case d.TimedOut:
				return errors.New("задача остановлена по пределу времени")
			case d.ExitCode == nil:
				return errors.New("задача завершилась без кода выхода")
			case *d.ExitCode != 0:
				tail := strings.TrimSpace(d.Tail)
				if r := []rune(tail); len(r) > 300 {
					tail = "…" + string(r[len(r)-300:])
				}
				return fmt.Errorf("задача завершилась с кодом %d: %s", *d.ExitCode, tail)
			}
			return nil
		}
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return errors.New("задача не завершилась за отведённое время")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(taskPoll):
		}
	}
}

// buildArchive пишет в tar файлы entries, читая их у основного.
func buildArchive(ctx context.Context, src SyncNode, entries []nodeapi.SyncEntry, removals []string, w io.Writer) error {
	tw := tar.NewWriter(w)
	for _, e := range entries {
		rc, err := src.SyncFile(ctx, e.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Path, err)
		}
		err = nodeapi.WriteSyncEntry(tw, e, rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	if err := nodeapi.WriteSyncRemove(tw, removals); err != nil {
		return err
	}
	return tw.Close()
}

// needsDoall: изменились файлы, которые подхватывает только doall.
func needsDoall(p string) bool {
	return path.Base(p) == "setup" || strings.Contains(p, "/config/")
}

// pushResult — итог копирования на одну реплику.
type pushResult struct {
	Files   int
	Removed int
}

// pushToReplica копирует расхождения с основного на реплику. full — заменить
// набор целиком (с удалением лишнего); иначе только изменившиеся файлы, а
// лишние на реплике (удалённые на основном клиенты) удаляются списком в архиве.
func pushToReplica(ctx context.Context, primary, replica *conn, full bool) (pushResult, error) {
	ps, ok := primary.syncer()
	rs, ok2 := replica.syncer()
	if !ok || !ok2 {
		return pushResult{}, errors.New("агент не умеет синхронизацию: обновите его")
	}
	pm, err := ps.SyncManifest(ctx)
	if err != nil {
		return pushResult{}, fmt.Errorf("манифест основного: %w", err)
	}
	rm, err := rs.SyncManifest(ctx)
	if err != nil {
		return pushResult{}, fmt.Errorf("манифест реплики: %w", err)
	}
	push, _ := diffManifests(pm, rm)
	var removals []string
	for _, p := range nodeapi.SyncRemovals(pm, rm) {
		if path.Base(p) != "setup" { // setup агент не удаляет
			removals = append(removals, p)
		}
	}
	if len(push) == 0 && len(removals) == 0 && !full {
		return pushResult{}, nil
	}
	entries := push
	if full {
		entries = pm.Files
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(buildArchive(ctx, ps, entries, removals, pw)) }()
	task, err := rs.SyncApply(ctx, pr, nodeapi.SyncApplyOpts{})
	pr.CloseWithError(errors.New("приём завершён"))
	if err != nil {
		return pushResult{}, fmt.Errorf("реплика не приняла набор: %w", err)
	}
	if err := waitTask(ctx, replica.node, task.ID); err != nil {
		return pushResult{}, fmt.Errorf("запись набора на реплике: %w", err)
	}
	doall := false
	for _, e := range push {
		doall = doall || needsDoall(e.Path)
	}
	if full {
		doall = true
	}
	if doall {
		t, err := replica.node.ApplyRouting(ctx)
		if err != nil {
			return pushResult{}, fmt.Errorf("применение списков на реплике: %w", err)
		}
		if err := waitTask(ctx, replica.node, t.ID); err != nil {
			return pushResult{}, fmt.Errorf("применение списков на реплике: %w", err)
		}
	}
	// Сверка после записи: набор обязан совпасть.
	rm2, err := rs.SyncManifest(ctx)
	if err != nil {
		return pushResult{}, fmt.Errorf("сверка после записи: %w", err)
	}
	if _, left := diffManifests(pm, rm2); len(left) > 0 {
		return pushResult{}, fmt.Errorf("после записи остались расхождения: %s", left[0].Text())
	}
	return pushResult{Files: len(entries), Removed: len(removals)}, nil
}

// syncGroup копирует изменения основного на все реплики; ошибки по репликам
// собираются, остановки на первой нет. Группа блокируется на время работы.
func (s *Server) syncGroup(ctx context.Context, g store.Group) error {
	unlock := s.hub.groupMu.Lock(groupKey(g.ID))
	defer unlock()
	return s.syncGroupLocked(ctx, g)
}

func groupKey(id int64) string { return fmt.Sprintf("g%d", id) }

// syncAfterChange: изменение на выбранном узле, если он основной группы с
// репликами, уходит на реплики в фоне; ошибка помечает группу и шлёт sync_mismatch.
func (s *Server) syncAfterChange(c *conn, who string) {
	if c == nil || c.rec.Role != store.RolePrimary || c.rec.GroupID == 0 || s.Store == nil {
		return
	}
	gid := c.rec.GroupID
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		g, ok, err := s.Store.GroupByID(ctx, gid)
		if err != nil || !ok {
			return
		}
		if err := s.syncGroup(ctx, g); err != nil {
			s.Log.Warn("копирование на реплики не удалось", "group", g.Name, "err", err)
			s.markGroup(g.ID, "Копирование изменений на реплики не удалось: "+err.Error())
			s.notifySyncMismatch(ctx, g, "Копирование изменений основного узла на реплики не удалось: "+err.Error())
			return
		}
		s.markGroup(g.ID, "")
	}()
}

// statusRecorder запоминает код ответа обработчика.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// mutatingPattern: маршруты, после которых на узле меняются файлы набора.
var mutatingPattern = map[string]bool{
	"POST /clients":                      true,
	"POST /clients/{name}/renew":         true,
	"POST /clients/{name}/limit":         true,
	"POST /clients/{name}/block":         true,
	"POST /clients/{name}/delete":        true,
	"POST /clients/{name}/redeem":        true,
	"POST /routing/files/{name}/add":     true,
	"POST /routing/files/{name}/remove":  true,
	"POST /routing/files/{name}/replace": true,
	"POST /routing/files/{name}/restore": true,
	"POST /settings/antizapret":          true,
	"POST /tasks/start":                  true,
}

// propagating оборачивает изменяющий маршрут: успешный ответ запускает
// копирование на реплики.
func (s *Server) propagating(pattern string, h http.HandlerFunc) http.HandlerFunc {
	if !mutatingPattern[pattern] {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		h(rec, r)
		if rec.status != 0 && rec.status < 400 {
			s.syncAfterChange(selected(r), s.user(r))
		}
	}
}

// --- состояние групп в памяти: отметка ошибки и последняя сверка ---

type groupRuntime struct {
	report *groupReport
	mark   string
	job    *groupJob
}

func (s *Server) runtime(gid int64) *groupRuntime {
	h := &s.hub
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.groups == nil {
		h.groups = map[int64]*groupRuntime{}
	}
	rt := h.groups[gid]
	if rt == nil {
		rt = &groupRuntime{}
		h.groups[gid] = rt
	}
	return rt
}

func (s *Server) markGroup(gid int64, text string) {
	rt := s.runtime(gid)
	s.hub.mu.Lock()
	rt.mark = text
	s.hub.mu.Unlock()
}

// notifySyncMismatch кладёт sync_mismatch в очередь; повтор того же текста для
// группы, пока она не вернулась в порядок, не отправляется.
func (s *Server) notifySyncMismatch(ctx context.Context, g store.Group, text string) {
	s.notifyOnce(ctx, bot.KindSyncMismatch, "sync_mismatch:"+groupKey(g.ID), text, "Группа «"+g.Name+"»: "+text)
}

// notifyOnce: одно уведомление на значение sig под ключом meta.
func (s *Server) notifyOnce(ctx context.Context, kind, key, sig, text string) {
	if s.Store == nil {
		return
	}
	if v, found, err := s.Store.Meta(ctx, key); err == nil && found && v == sig {
		return
	}
	tg := s.Telegram
	if err := enqueueNotice(ctx, s.Store, &tg, s.now(), kind, text); err != nil {
		s.Log.Warn("уведомление не поставлено в очередь", "kind", kind, "err", err)
		return
	}
	if err := s.Store.SetMeta(ctx, key, sig); err != nil {
		s.Log.Warn("метка уведомления не записана", "key", key, "err", err)
	}
}

// verifyAndNotify — сверка группы с запоминанием итога и уведомлением.
func (s *Server) verifyAndNotify(ctx context.Context, g store.Group) (groupReport, error) {
	rep, err := s.verifyGroup(ctx, g)
	if err != nil {
		return rep, err
	}
	rt := s.runtime(g.ID)
	s.hub.mu.Lock()
	rt.report = &rep
	s.hub.mu.Unlock()
	key := "sync_mismatch:" + groupKey(g.ID)
	if rep.InSync() {
		_ = s.Store.ClearMeta(ctx, key)
		return rep, nil
	}
	s.notifyOnce(ctx, bot.KindSyncMismatch, key, rep.signature(), "Группа «"+g.Name+"»: "+rep.summary())
	return rep, nil
}

// summary — одна фраза о расхождениях для уведомления.
func (g groupReport) summary() string {
	if g.PrimaryErr != "" {
		return "расхождения не проверить: " + g.PrimaryErr + "."
	}
	var parts []string
	for _, r := range g.Replicas {
		switch {
		case r.Err != "":
			parts = append(parts, fmt.Sprintf("«%s» недоступна (%s)", r.Name, r.Err))
		case !r.InSync():
			parts = append(parts, fmt.Sprintf("«%s»: файлов с расхождениями %d, клиентов не хватает %d, лишних %d", r.Name, len(r.Diffs), len(r.ClientsMissing), len(r.ClientsExtra)))
		}
	}
	return "реплики расходятся с основным: " + strings.Join(parts, "; ") + ". Откройте раздел «Группы» и нажмите «Выровнять»."
}

// RunGroupWatch сверяет группы раз в groupVerifyDur и шлёт sync_mismatch;
// блокируется до отмены ctx.
func (s *Server) RunGroupWatch(ctx context.Context) {
	for {
		s.verifyAllGroups(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(groupVerifyDur):
		}
	}
}

func (s *Server) verifyAllGroups(ctx context.Context) {
	if s.Store == nil {
		return
	}
	gs, err := s.Store.Groups(ctx)
	if err != nil {
		return
	}
	for _, g := range gs {
		if ctx.Err() != nil {
			return
		}
		vctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if _, err := s.verifyAndNotify(vctx, g); err != nil {
			s.Log.Warn("сверка группы не удалась", "group", g.Name, "err", err)
		}
		cancel()
	}
}

// syncAfterLocal: изменение пришло не со страницы панели (бот), а на узле
// панели — если он основной группы, оно тоже уходит на реплики.
func (s *Server) syncAfterLocal() {
	if s.Store == nil {
		return
	}
	rec, ok, err := s.nodeRec(context.Background(), store.LocalNode)
	if err != nil || !ok {
		return
	}
	if c, err := s.connect(rec); err == nil {
		s.syncAfterChange(c, "бот")
	}
}
