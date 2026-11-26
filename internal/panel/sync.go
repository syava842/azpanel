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
	taskPoll    = 2 * time.Second // как часто спрашиваем задачу агента
	taskWaitMax = 30 * time.Minute
	azPoll      = 10 * time.Second
	azWaitMax   = 45 * time.Minute // обновление AntiZapret с перезагрузкой
	// groupVerifyDur — проход таймера групп: сверка и копирование расхождений
	// на реплики. 5 минут — столько живёт на основном изменение, сделанное мимо
	// страниц панели (client.sh, StatusOpenVPN, cron), прежде чем попасть на
	// запасной сервер; проход без расхождений — только манифесты и списки
	// клиентов, без записи и doall.
	groupVerifyDur = 5 * time.Minute
	// groupWatchMax — предел одного прохода по группе: копирование с doall
	// бывает долгим.
	groupWatchMax = 30 * time.Minute
	// syncBusyPause и syncBusyTries — ожидание узла, занятого задачей или
	// скриптом AntiZapret (nodeapi.ErrBusy): сверка после записи и
	// копирование после задачи повторяют попытку столько раз.
	syncBusyPause = 30 * time.Second
	syncBusyTries = 4
	// pushBackoffMax — сколько таймер не пишет на реплику, у которой после
	// записи осталось то же расхождение (одно уведомление вместо записи и
	// doall каждые 5 минут).
	pushBackoffMax = 6 * time.Hour
	// busyNoticeAfter — сколько узел группы может быть занят подряд
	// (nodeapi.ErrBusy), прежде чем об этом придёт уведомление: открытое и
	// брошенное меню client.sh держит автокопирование бесконечно.
	busyNoticeAfter = time.Hour
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
	id   int64
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
		m := member{name: rec.Name, id: rec.ID}
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
	// Want, Have — отпечатки у основного и у реплики (пусто — файла нет).
	Want, Have string
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
			push, diffs = append(push, e), append(diffs, fileDiff{Path: e.Path, Kind: "missing", Want: e.SHA256})
		case r.SHA256 != e.SHA256 || r.Size != e.Size:
			push, diffs = append(push, e), append(diffs, fileDiff{Path: e.Path, Kind: "differs", Want: e.SHA256, Have: r.SHA256})
		}
	}
	for _, e := range replica.Files {
		if !seen[e.Path] {
			diffs = append(diffs, fileDiff{Path: e.Path, Kind: "extra", Have: e.SHA256})
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
	Busy  bool // узел занят (nodeapi.ErrBusy): набор сейчас меняется
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
	At          time.Time
	PrimaryErr  string
	PrimaryBusy bool // основной занят (nodeapi.ErrBusy)
	Replicas    []replicaReport
	// primaryName — имя основного, для текста о занятом узле.
	primaryName string
}

// busyWho — какой узел занят: «Основной «X»» или «Реплика «Y»».
func (g groupReport) busyWho() string {
	if g.PrimaryBusy {
		return "Основной «" + g.primaryName + "»"
	}
	for _, r := range g.Replicas {
		if r.Busy {
			return "Реплика «" + r.Name + "»"
		}
	}
	return "Основной «" + g.primaryName + "»"
}

// busy: основной или реплика заняты задачей или скриптом AntiZapret — набор
// в промежуточном состоянии, сравнивать и копировать нечего до следующего
// прохода.
func (g groupReport) busy() bool {
	if g.PrimaryBusy {
		return true
	}
	for _, r := range g.Replicas {
		if r.Busy {
			return true
		}
	}
	return false
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

// clientNames — имена клиентов для сверки. Клиент без сертификата (NoCert, не
// WireGuard) в наборе файлов не лежит: он виден по живому сеансу OpenVPN или
// по limits.json, и на реплику копировать нечего. Такие в сверку не идут —
// иначе группа вечно «расходится», а подпись уведомления меняется с составом
// сеансов.
func clientNames(cs []nodeapi.Client) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		if c.NoCert && !c.WireGuard {
			continue
		}
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
	rep := groupReport{At: s.now(), Replicas: make([]replicaReport, len(replicas)), primaryName: primary.name}
	ps, ok := primary.syncerOrErr()
	if !ok {
		rep.PrimaryErr = "основной «" + primary.name + "»: " + primary.errText()
		return rep, nil
	}
	pm, err := ps.SyncManifest(ctx)
	if err != nil {
		rep.PrimaryErr = "основной «" + primary.name + "»: " + connErrText(err)
		rep.PrimaryBusy = errors.Is(err, nodeapi.ErrBusy)
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
				rr.Err, rr.Busy = connErrText(err), errors.Is(err, nodeapi.ErrBusy)
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

// needsDoall: изменились файлы, которые подхватывает только doall, — setup и
// списки config/*.txt (как SyncSet.needsApply агента). Профили, PKI, limits.json
// и прочее действуют сразу после записи: перезапуск служб для них делает сама
// задача sync-apply (unitsToRestart).
func needsDoall(p string) bool {
	if path.Base(p) == "setup" {
		return true
	}
	return path.Base(path.Dir(p)) == "config" && strings.HasSuffix(p, ".txt") && !strings.Contains(p, "/client/")
}

// pushResult — итог копирования на одну реплику.
type pushResult struct {
	Files   int
	Removed int
	// VerifyDeferred — набор записан, но сверка после записи не сделана:
	// реплика занята (только «Выровнять»).
	VerifyDeferred bool
}

// pushOpts — как копировать набор на реплику.
type pushOpts struct {
	// full — заменить набор целиком (с удалением лишнего), «Выровнять»;
	// иначе только изменившиеся файлы.
	full bool
	// force — разрешить удаление ключевых файлов (только «Выровнять»).
	force bool
	// guard — автоматическое копирование: если у реплики другие CA или ключи
	// сервера (identityDiffs), ничего не записывать и вернуть *identityError.
	guard bool
}

// identityError — у основного и реплики разная «личность» сервера; Paths —
// файлы, по которым это видно (пути, не содержимое).
type identityError struct{ Paths []string }

func (e *identityError) Error() string {
	return "у основного и реплики разные CA/ключи сервера: " + strings.Join(e.Paths, ", ")
}

// errLeftover — после записи у реплики остались расхождения.
var errLeftover = errors.New("после записи остались расхождения")

// manifestWhenFree — манифест узла; занятый узел (nodeapi.ErrBusy) ждём до
// syncBusyTries раз по syncBusyPause: задача записи на реплике кончилась, а
// перезапущенная служба ещё может гнать doall.
func manifestWhenFree(ctx context.Context, n SyncNode) (nodeapi.SyncManifest, error) {
	for i := 1; ; i++ {
		m, err := n.SyncManifest(ctx)
		if err == nil || !errors.Is(err, nodeapi.ErrBusy) || i >= syncBusyTries {
			return m, err
		}
		select {
		case <-ctx.Done():
			return m, ctx.Err()
		case <-time.After(syncBusyPause):
		}
	}
}

// pushToReplica копирует расхождения с основного на реплику (pushOpts);
// лишние на реплике файлы (удалённые на основном клиенты) удаляются списком в
// архиве. Основной или реплика заняты — ошибка с nodeapi.ErrBusy, ничего не
// записано.
func pushToReplica(ctx context.Context, primary, replica *conn, o pushOpts) (pushResult, error) {
	ps, ok := primary.syncer()
	rs, ok2 := replica.syncer()
	if !ok || !ok2 {
		return pushResult{}, errors.New("агент не умеет синхронизацию: обновите его")
	}
	// «Выровнять» (full) запущено человеком: занятый узел ждём, а не
	// отказываем; автокопирование пропускает проход (ErrBusy).
	manifest := func(n SyncNode) (nodeapi.SyncManifest, error) {
		if o.full {
			return manifestWhenFree(ctx, n)
		}
		return n.SyncManifest(ctx)
	}
	pm, err := manifest(ps)
	if err != nil {
		return pushResult{}, fmt.Errorf("манифест основного: %w", err)
	}
	rm, err := manifest(rs)
	if err != nil {
		return pushResult{}, fmt.Errorf("манифест реплики: %w", err)
	}
	push, diffs := diffManifests(pm, rm)
	if o.guard {
		paths, err := identityDiffs(ctx, ps, rs, diffs)
		if err != nil {
			return pushResult{}, fmt.Errorf("проверка CA и ключей сервера: %w", err)
		}
		if len(paths) > 0 {
			return pushResult{}, &identityError{Paths: paths}
		}
	}
	var removals []string
	for _, p := range nodeapi.SyncRemovals(pm, rm) {
		if path.Base(p) != "setup" { // setup агент не удаляет
			removals = append(removals, p)
		}
	}
	if len(push) == 0 && len(removals) == 0 && !o.full {
		return pushResult{}, nil
	}
	entries := push
	if o.full {
		entries = pm.Files
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(buildArchive(ctx, ps, entries, removals, pw)) }()
	task, err := rs.SyncApply(ctx, pr, nodeapi.SyncApplyOpts{Force: o.force})
	pr.CloseWithError(errors.New("приём завершён"))
	if err != nil {
		var ne *nodeapi.Error
		if errors.As(err, &ne) && ne.Status == http.StatusUnprocessableEntity {
			return pushResult{}, fmt.Errorf("агент отказал в удалении файлов (%s): проверьте основной; если удаление нужно, повторите «Выровнять» с отметкой «разрешить удаление ключевых файлов»", ne.Message)
		}
		return pushResult{}, fmt.Errorf("реплика не приняла набор: %w", err)
	}
	if err := waitTask(ctx, replica.node, task.ID); err != nil {
		return pushResult{}, fmt.Errorf("запись набора на реплике: %w", err)
	}
	doall := false
	for _, e := range push {
		doall = doall || needsDoall(e.Path)
	}
	for _, p := range removals { // удалённый список маршрутизации — тоже doall
		doall = doall || needsDoall(p)
	}
	if o.full {
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
	restart := o.full
	for _, e := range push {
		restart = restart || path.Base(e.Path) == "setup"
	}
	if restart {
		t, err := replica.node.RestartAntiZapret(ctx)
		if err != nil {
			return pushResult{}, fmt.Errorf("перезапуск AntiZapret на реплике: %w", err)
		}
		if err := waitTask(ctx, replica.node, t.ID); err != nil {
			return pushResult{}, fmt.Errorf("перезапуск AntiZapret на реплике: %w", err)
		}
	}
	// Сверка после записи: набор обязан совпасть.
	rm2, err := manifestWhenFree(ctx, rs)
	if err != nil && o.full && errors.Is(err, nodeapi.ErrBusy) {
		// Записано; реплика так и не освободилась — сверку сделает таймер.
		return pushResult{Files: len(entries), Removed: len(removals), VerifyDeferred: true}, nil
	}
	if err != nil {
		return pushResult{}, fmt.Errorf("сверка после записи: %w", err)
	}
	if _, left := diffManifests(pm, rm2); len(left) > 0 {
		return pushResult{}, fmt.Errorf("%w: %s", errLeftover, left[0].Text())
	}
	return pushResult{Files: len(entries), Removed: len(removals)}, nil
}

// syncGroup копирует изменения основного на все реплики; ошибки по репликам
// собираются, остановки на первой нет. Группа блокируется на время работы.
func (s *Server) syncGroup(ctx context.Context, g store.Group) pushOutcome {
	unlock := s.hub.groupMu.Lock(groupKey(g.ID))
	defer unlock()
	return s.pushReplicas(ctx, g, nil)
}

func groupKey(id int64) string { return fmt.Sprintf("g%d", id) }

// syncAfterChange: изменение на выбранном узле, если он основной группы с
// репликами, уходит на реплики в фоне; ошибка помечает группу и шлёт sync_mismatch.
func (s *Server) syncAfterChange(c *conn, who string) {
	if !s.groupPrimary(c) {
		return
	}
	gid := c.rec.GroupID
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		s.propagate(ctx, gid, 1)
	}()
}

// propagate копирует изменения основного группы gid на реплики и разбирает
// итог (afterChange). Узел занят (nodeapi.ErrBusy) — до tries попыток через
// syncBusyPause; не дождались — молча: расхождение скопирует таймер групп.
func (s *Server) propagate(ctx context.Context, gid int64, tries int) {
	g, ok, err := s.Store.GroupByID(ctx, gid)
	if err != nil || !ok {
		return
	}
	for i := 1; ; i++ {
		out := s.syncGroup(ctx, g)
		if !out.busy || len(out.errs) > 0 || len(out.identity) > 0 || i >= tries {
			s.afterChange(ctx, g, out)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(syncBusyPause):
		}
	}
}

// afterChange — итог копирования по событию: другая личность реплики или
// ошибка — отметка группы и уведомление; узел занят — молча (повторит
// таймер); иначе отметка снимается.
func (s *Server) afterChange(ctx context.Context, g store.Group, out pushOutcome) {
	switch {
	case len(out.identity) > 0 || len(out.errs) > 0:
		var r stopReason
		if len(out.errs) > 0 {
			err := errors.Join(out.errs...)
			s.Log.Warn("копирование на реплики не удалось", "group", g.Name, "err", err)
			r = stopReason{
				mark:   "Копирование изменений на реплики не удалось: " + err.Error(),
				notice: "Копирование изменений основного узла на реплики не удалось: " + err.Error(),
			}
			r.sig = r.notice
		}
		s.stopGroup(ctx, g, out.identity, r)
	case out.busy:
		s.Log.Info("узел группы занят, копирование оставлено таймеру", "group", g.Name)
	default:
		s.markGroup(g.ID, "")
	}
}

// stopReason — ошибка копирования для отметки группы (mark), уведомления
// (notice) и его подписи (sig); пусто — ошибок нет.
type stopReason struct{ mark, notice, sig string }

// stopGroup — отметка группы и одно уведомление о причинах остановки
// копирования: у реплик identity другие CA или ключи сервера и (или) ошибка
// копирования на другие реплики. Причины складываются: остановка по
// личности одной реплики не прячет ошибку другой.
func (s *Server) stopGroup(ctx context.Context, g store.Group, identity []string, r stopReason) {
	var marks, notices, sigs []string
	if len(identity) > 0 {
		t := identityText(identity)
		marks, notices, sigs = append(marks, t), append(notices, t), append(sigs, "identity:"+strings.Join(identity, ","))
	}
	if r.mark != "" {
		marks, notices, sigs = append(marks, r.mark), append(notices, r.notice), append(sigs, r.sig)
	}
	if len(marks) == 0 {
		return
	}
	s.markGroup(g.ID, strings.Join(marks, " "))
	s.notifyOnce(ctx, bot.KindSyncMismatch, "sync_mismatch:"+groupKey(g.ID), strings.Join(sigs, "|"), "Группа «"+g.Name+"»: "+strings.Join(notices, " "))
}

// groupPrimary: узел — основной группы (изменения на нём уходят на реплики).
func (s *Server) groupPrimary(c *conn) bool {
	return c != nil && c.rec.Role == store.RolePrimary && c.rec.GroupID != 0 && s.Store != nil
}

// syncAfterTask: задача на основном (doall, перезапуск, пересоздание
// профилей) меняет файлы набора по ходу работы, поэтому копирование — после
// её успешного завершения, а не после запуска: иначе на реплику уходит
// промежуточный config/*.txt. Неуспешная задача не копируется — расхождение
// найдёт таймер групп. Узел после задачи ещё занят (служба, перезапущенная
// задачей, гонит doall) — до syncBusyTries попыток через syncBusyPause, потом
// копирование остаётся таймеру.
func (s *Server) syncAfterTask(c *conn, id string) {
	if !s.groupPrimary(c) || id == "" {
		return
	}
	gid := c.rec.GroupID
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), taskWaitMax+30*time.Minute)
		defer cancel()
		if err := waitTask(ctx, c.node, id); err != nil {
			s.Log.Warn("задача на основном не завершилась успешно, копирование на реплики не запущено", "task", id, "err", err)
			return
		}
		s.propagate(ctx, gid, syncBusyTries)
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
// POST /tasks/start здесь нет: задача копируется по завершении (syncAfterTask).
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
	// backoff — реплики, у которых после записи по таймеру осталось
	// расхождение: подпись отличий и время записи.
	backoff map[int64]pushBackoff
	// busySince — с какого прохода таймера узел группы занят подряд;
	// busyMark — текст отметки о долгой занятости (снимается первым свободным
	// проходом).
	busySince time.Time
	busyMark  string
}

type pushBackoff struct {
	sig string
	at  time.Time
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
	s.reportAndNotify(ctx, g, rep)
	return rep, nil
}

// reportAndNotify запоминает итог сверки; расхождение — sync_mismatch (одно на
// одну картину), порядок — метка уведомления снимается.
func (s *Server) reportAndNotify(ctx context.Context, g store.Group, rep groupReport) {
	s.keepReport(g.ID, rep)
	key := "sync_mismatch:" + groupKey(g.ID)
	if rep.InSync() {
		_ = s.Store.ClearMeta(ctx, key)
		return
	}
	s.notifyOnce(ctx, bot.KindSyncMismatch, key, rep.signature(), "Группа «"+g.Name+"»: "+rep.summary())
}

func (s *Server) keepReport(gid int64, rep groupReport) {
	rt := s.runtime(gid)
	s.hub.mu.Lock()
	rt.report = &rep
	s.hub.mu.Unlock()
}

// diffSig — подпись набора отличий одной реплики: пути, виды и отпечатки с
// обеих сторон. Новое изменение на основном её меняет.
func diffSig(diffs []fileDiff) string {
	var b strings.Builder
	for _, d := range diffs {
		b.WriteString(d.Kind + "\x00" + d.Path + "\x00" + d.Want + "\x00" + d.Have + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// backedOff: на реплику r по таймеру уже писали, и осталось то же
// расхождение — не писать снова, пока подпись отличий та же и не прошло
// pushBackoffMax.
func (s *Server) backedOff(gid int64, r replicaReport) bool {
	rt := s.runtime(gid)
	now := s.now()
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	b, ok := rt.backoff[r.ID]
	return ok && b.sig == diffSig(r.Diffs) && now.Sub(b.at) < pushBackoffMax
}

// noteBackoff запоминает реплики, на которые писали, а расхождение осталось;
// совпавшие — забывает.
func (s *Server) noteBackoff(gid int64, written map[int64]bool, after groupReport) {
	rt := s.runtime(gid)
	now := s.now()
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	if rt.backoff == nil {
		rt.backoff = map[int64]pushBackoff{}
	}
	for _, r := range after.Replicas {
		switch {
		case r.Err == "" && len(r.Diffs) == 0:
			delete(rt.backoff, r.ID)
		case written[r.ID] && r.Err == "":
			rt.backoff[r.ID] = pushBackoff{sig: diffSig(r.Diffs), at: now}
		}
	}
}

// noteBusy — проход таймера застал узел who занятым. Занят подряд дольше
// busyNoticeAfter — отметка группы и одно уведомление.
func (s *Server) noteBusy(ctx context.Context, g store.Group, who string) {
	rt := s.runtime(g.ID)
	now := s.now()
	s.hub.mu.Lock()
	if rt.busySince.IsZero() {
		rt.busySince = now
	}
	long := now.Sub(rt.busySince) >= busyNoticeAfter
	s.hub.mu.Unlock()
	if !long {
		return
	}
	text := who + " занят больше часа (идёт задача или открыт client.sh/doall) — автокопирование ждёт."
	s.hub.mu.Lock()
	rt.mark, rt.busyMark = text, text
	s.hub.mu.Unlock()
	s.notifyOnce(ctx, bot.KindSyncMismatch, "sync_mismatch:"+groupKey(g.ID), "busy:"+who, "Группа «"+g.Name+"»: "+text)
}

// noteFree — проход застал узлы свободными: счёт занятости сначала,
// отметка о долгой занятости снимается.
func (s *Server) noteFree(gid int64) {
	rt := s.runtime(gid)
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	rt.busySince = time.Time{}
	if rt.busyMark != "" && rt.mark == rt.busyMark {
		rt.mark = ""
	}
	rt.busyMark = ""
}

// watchGroup — проход таймера по группе. Сверка; разошёлся набор файлов —
// копирование расхождений с основного на эти реплики тем же путём, что после
// изменения в панели (без force: защита от удаления ключевых файлов и
// массового удаления остаётся; реплика с другими CA или ключами сервера не
// трогается), и повторная сверка. Уведомление — только о том, что осталось
// после копирования, или об отказе копирования; одна и та же причина — одно
// уведомление. Группа занята операцией или копированием, узел занят задачей
// или скриптом AntiZapret — проход пропускается молча: итог проверит
// следующий. Реплика, на которую уже писали, а расхождение осталось то же, —
// не пишется снова до смены расхождения или pushBackoffMax.
func (s *Server) watchGroup(ctx context.Context, g store.Group) error {
	unlock, ok := s.hub.groupMu.TryLock(groupKey(g.ID))
	if !ok {
		return nil
	}
	defer unlock()
	rep, err := s.verifyGroup(ctx, g)
	if err != nil {
		return err
	}
	if rep.busy() {
		s.Log.Info("узел группы занят, проход таймера пропущен", "group", g.Name)
		s.noteBusy(ctx, g, rep.busyWho())
		return nil
	}
	s.noteFree(g.ID)
	only := map[int64]bool{}
	for _, r := range rep.Replicas {
		if r.Err == "" && len(r.Diffs) > 0 && !s.backedOff(g.ID, r) {
			only[r.ID] = true
		}
	}
	if rep.PrimaryErr != "" || len(only) == 0 {
		s.reportAndNotify(ctx, g, rep)
		return nil
	}
	out := s.pushReplicas(ctx, g, only)
	if out.busy && len(out.errs) == 0 && len(out.identity) == 0 {
		s.Log.Info("узел группы занят, копирование по таймеру отложено", "group", g.Name)
		s.noteBusy(ctx, g, rep.busyWho())
		return nil
	}
	again, err := s.verifyGroup(ctx, g)
	if err != nil {
		return err
	}
	s.noteBackoff(g.ID, out.written, again)
	// Остаток после записи — не ошибка копирования: о нём скажет сверка
	// (reportAndNotify), и та же картина на следующем проходе (запись
	// отложена отступом) нового уведомления не даст.
	var errs []error
	for _, e := range out.errs {
		if !errors.Is(e, errLeftover) {
			errs = append(errs, e)
		}
	}
	switch {
	case len(out.identity) > 0 || len(errs) > 0:
		s.keepReport(g.ID, again)
		var r stopReason
		if len(errs) > 0 {
			serr := errors.Join(errs...)
			s.Log.Warn("копирование на реплики по таймеру не удалось", "group", g.Name, "err", serr)
			r = stopReason{
				mark:   "Копирование на реплики по таймеру не удалось: " + serr.Error(),
				notice: "копирование изменений основного на реплики не удалось: " + serr.Error() + ". Откройте раздел «Группы».",
				sig:    "copy:" + serr.Error(),
			}
		}
		s.stopGroup(ctx, g, out.identity, r)
	default:
		s.markGroup(g.ID, "")
		s.reportAndNotify(ctx, g, again)
	}
	return nil
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

// RunGroupWatch раз в groupVerifyDur сверяет группы и копирует расхождения
// на реплики (watchGroup); блокируется до отмены ctx.
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
		vctx, cancel := context.WithTimeout(ctx, groupWatchMax)
		if err := s.watchGroup(vctx, g); err != nil {
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
