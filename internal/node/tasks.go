package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/nodeapi"
)

const (
	maxTasks      = 100      // сколько последних задач хранится в tasks.json
	maxTail       = 64 << 10 // хвост журнала в ответе по задаче
	taskLogMaxAge = 30 * 24 * time.Hour
	rotateEvery   = 24 * time.Hour
	// orphanGrace — запас сверх предела вида: дольше юнит жить не может
	// (RuntimeMaxSec), значит, ожидание дальше бессмысленно.
	orphanGrace = 10 * time.Minute
)

// Виды задач. Этапы 5, 10 и 11 добавят свои.
const (
	TaskDoall    = "doall"
	TaskRestart  = "restart"
	TaskProfiles = "profiles"
	// TaskAZUpdate — обновление AntiZapret: бэкап и setup.sh (переживает перезагрузку).
	TaskAZUpdate = "azupdate"
	// TaskAZRestore — восстановление из бэкапа: client.sh 9.
	TaskAZRestore = "azrestore"
	// TaskWarperResync — warper resync после обновления AntiZapret.
	TaskWarperResync = "warper-resync"
)

// DefaultTaskTimeouts — предел времени задачи по виду (RuntimeMaxSec юнита).
// Новый вид (этапы 5, 10, 11) добавляется сюда или в Tasks.Timeouts.
var DefaultTaskTimeouts = map[string]time.Duration{
	TaskDoall:    1800 * time.Second,
	TaskRestart:  300 * time.Second,
	TaskProfiles: 1800 * time.Second,
	// setup.sh обновляет систему и ставит пакеты; при недоступных зеркалах долго ждёт.
	TaskAZUpdate:     7200 * time.Second,
	TaskAZRestore:    3600 * time.Second,
	TaskWarperResync: 600 * time.Second,
}

// fallbackTaskTimeout — предел для вида, которого нет в таблице: задача без
// предела держала бы очередь, пока её не остановят вручную.
const fallbackTaskTimeout = 1800 * time.Second

// exitWrapper запускает команду и пишет её код выхода в файл. Всё передаётся
// позиционно ($1 — файл, дальше команда), в текст скрипта ничего не вставляется.
// Запись через временный файл и mv: читатель не увидит половину числа.
const exitWrapper = `f=$1; shift; "$@"; c=$?; echo "$c" > "$f.tmp" && mv -f "$f.tmp" "$f"; exit "$c"`

// Task — фоновая задача AntiZapret; тип общий с клиентом API.
type Task = nodeapi.Task

var taskKindRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// BusyError — задача уже идёт; вторую запустить нельзя.
type BusyError struct{ Task Task }

func (e *BusyError) Error() string {
	return fmt.Sprintf("уже идёт задача %s (%s)", e.Task.Kind, e.Task.ID)
}

// Tasks запускает долгие команды AntiZapret отдельным временным юнитом
// systemd-run: он живёт вне песочницы агента (ProtectSystem=strict не дал бы
// doall.sh писать в /etc/knot-resolver и sysctl) и переживает перезапуск
// агента. Одновременно идёт одна задача: doall, restart и profiles правят
// одни и те же файлы и службы.
type Tasks struct {
	Dir       string // рабочий каталог задач — каталог AntiZapret
	LogDir    string // журналы задач
	StatePath string // tasks.json
	Log       *slog.Logger
	Now       func() time.Time
	// Exec — запуск процесса; возвращает код выхода. Ошибка — только если
	// процесс не удалось запустить. nil — настоящий запуск. Подменяется в тестах.
	Exec func(ctx context.Context, name string, args ...string) (code int, out []byte, err error)
	// Active — работает ли юнит; nil — systemctl is-active. Ошибка — состояние
	// неизвестно (systemd занят, тайм-аут): задачу нельзя считать оконченной.
	Active func(ctx context.Context, unit string) (bool, error)
	// Result — итог юнита по systemctl show -p Result («timeout», «success»…);
	// пусто — неизвестно. nil — настоящий systemctl.
	Result func(ctx context.Context, unit string) string
	// Ctx — жизнь агента. Отменён — агент останавливается: клиент systemd-run
	// получил SIGTERM вместе с ним, а юнит задачи продолжает работать, поэтому
	// результат задачи не записывается; её подхватит следующий запуск (Load).
	Ctx context.Context
	// PollEvery — как часто проверять юнит задачи, оставшейся с прошлого запуска агента.
	PollEvery time.Duration
	// Timeouts — предел времени по виду задачи; nil — DefaultTaskTimeouts.
	Timeouts map[string]time.Duration
	// OnFinish вызывается (в отдельной горутине) после окончания любой задачи:
	// уборка файлов параметров, оставшихся от несостоявшихся запусков.
	OnFinish func()

	mu      sync.Mutex
	tasks   []Task // от старых к новым
	running string // id идущей задачи
}

func (t *Tasks) now() time.Time {
	if t.Now != nil {
		return t.Now().UTC()
	}
	return time.Now().UTC()
}

func (t *Tasks) logger() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Unit — имя временного юнита задачи.
func Unit(id string) string { return "azpanel-task-" + id }

// Load читает tasks.json. Задача, бывшая «идёт» при остановке агента,
// проверяется по юниту: работает — ждём её, нет — помечается прерванной.
// Испорченный файл откладывается в .bad, список начинается заново.
func (t *Tasks) Load() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, err := os.ReadFile(t.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []Task
	if err := json.Unmarshal(data, &list); err != nil {
		t.logger().Error("tasks.json испорчен — отложен, список задач начат заново", "err", err)
		return os.Rename(t.StatePath, t.StatePath+".bad")
	}
	if len(list) > maxTasks {
		list = list[len(list)-maxTasks:]
	}
	t.tasks = list
	changed := false
	for i := range t.tasks {
		tk := &t.tasks[i]
		if tk.Finished != nil {
			continue
		}
		changed = true
		// Задача могла кончиться, пока агент был остановлен: код — в файле.
		if code, ok := t.readExit(*tk); ok {
			now := t.now()
			tk.Finished = &now
			tk.ExitCode = &code
			continue
		}
		if t.running == "" && t.state(Unit(tk.ID)) != unitInactive { // неизвестное состояние — как «работает»
			t.running = tk.ID
			go t.waitOrphan(tk.ID)
			continue
		}
		now := t.now()
		tk.Finished = &now
		tk.Interrupted = true
	}
	if changed {
		t.saveLocked()
	}
	return nil
}

// Состояния юнита задачи.
type unitState int

const (
	unitInactive unitState = iota // юнита нет или он остановлен
	unitActive
	unitUnknown // systemctl не ответил: тайм-аут, сбой запуска
)

func (t *Tasks) context() context.Context {
	if t.Ctx != nil {
		return t.Ctx
	}
	return context.Background()
}

// state различает «остановлен» и «не удалось узнать»: ошибка опроса не должна
// закрывать идущую задачу.
func (t *Tasks) state(unit string) unitState {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var (
		active bool
		err    error
	)
	if t.Active != nil {
		active, err = t.Active(ctx, unit)
	} else {
		active, err = systemctlIsActive(ctx, unit)
	}
	switch {
	case err != nil:
		return unitUnknown
	case active:
		return unitActive
	}
	return unitInactive
}

// systemctlIsActive: код 0 — работает; 3 (inactive, failed) и 4 (юнита нет) —
// остановлен; всё остальное (не запустился, убит по тайм-ауту) — ошибка.
func systemctlIsActive(ctx context.Context, unit string) (bool, error) {
	err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run()
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ctx.Err() == nil && (ee.ExitCode() == 3 || ee.ExitCode() == 4) {
		return false, nil
	}
	return false, err
}

// unitResult — итог юнита; после --collect юнита уже может не быть.
func (t *Tasks) unitResult(unit string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if t.Result != nil {
		return t.Result(ctx, unit)
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "Result", "--value", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// timedOut: задача без файла .exit остановлена по пределу времени, если так
// говорит systemd либо она шла не меньше своего предела.
func (t *Tasks) timedOut(task Task) bool {
	if t.unitResult(Unit(task.ID)) == "timeout" {
		return true
	}
	return t.now().Sub(task.Started) >= t.timeout(task.Kind)
}

// exitPath — файл с кодом выхода задачи рядом с её журналом. Берётся из
// своего каталога по имени журнала, а не по пути из tasks.json.
func (t *Tasks) exitPath(task Task) string {
	return filepath.Join(t.LogDir, filepath.Base(task.Log)+".exit")
}

// readExit читает код выхода из файла обёртки. Нет файла или в нём не число —
// кода нет.
func (t *Tasks) readExit(task Task) (int, bool) {
	data, err := os.ReadFile(t.exitPath(task))
	if err != nil {
		return 0, false
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return code, true
}

func (t *Tasks) timeout(kind string) time.Duration {
	table := t.Timeouts
	if table == nil {
		table = DefaultTaskTimeouts
	}
	if d, ok := table[kind]; ok && d > 0 {
		return d
	}
	return fallbackTaskTimeout
}

// waitOrphan ждёт юнит задачи, у которой клиент systemd-run уже не с нами
// (агент перезапускался или оборвался D-Bus). Пока systemd не ответил или юнит
// работает — ждём. Код выхода берётся из файла обёртки; если файла нет, юнит
// убит по пределу времени (--collect уже убрал его результат) или сломан.
func (t *Tasks) waitOrphan(id string) {
	every := t.PollEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	for t.state(Unit(id)) != unitInactive {
		if task, ok := t.Get(id); ok && t.now().After(task.Started.Add(t.timeout(task.Kind)+orphanGrace)) {
			// Юнит не отвечает дольше любого мыслимого срока: состояние
			// неизвестно, очередь не должна висеть вечно.
			appendLog(task.Log, "юнит задачи не отвечает дольше предела времени — состояние неизвестно, задача закрыта без кода\n")
			t.logger().Warn("ожидание задачи прекращено: юнит не отвечает дольше предела", "id", id, "kind", task.Kind)
			t.finish(id, nil, true, false)
			return
		}
		select {
		case <-t.context().Done():
			return // агент останавливается: задачу подхватит следующий запуск
		case <-time.After(every):
		}
	}
	task, ok := t.Get(id)
	if ok {
		if code, ok := t.readExit(task); ok {
			t.finish(id, &code, false, false)
			return
		}
		if t.timedOut(task) {
			t.finish(id, nil, false, true)
			return
		}
	}
	t.finish(id, nil, true, false)
}

// StartOpts — окружение задачи сверх умолчаний systemd-run.
type StartOpts struct {
	// Env — пары KEY=VALUE для окружения юнита. В журнал и tasks.json не
	// попадают, но видны в systemctl show, пока юнит жив: секретов не передавать.
	Env []string
	// StdinFile — файл, который станет стандартным вводом команды; без него
	// ввод — /dev/null.
	StdinFile string
}

// Start запускает задачу в фоне. argv — команда и аргументы; запрет на
// одновременный запуск проверяется здесь, под тем же замком, что и
// регистрация задачи.
func (t *Tasks) Start(kind string, argv []string) (Task, error) {
	return t.StartWith(kind, argv, StartOpts{})
}

// StartWith — Start с окружением и вводом.
func (t *Tasks) StartWith(kind string, argv []string, opts StartOpts) (Task, error) {
	if !taskKindRe.MatchString(kind) || len(argv) == 0 {
		return Task{}, errors.New("неверный вид задачи или пустая команда")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.runningLocked(); ok {
		return Task{}, &BusyError{Task: cur}
	}
	id, err := newTaskID()
	if err != nil {
		return Task{}, err
	}
	started := t.now()
	if err := os.MkdirAll(t.LogDir, 0o750); err != nil {
		return Task{}, err
	}
	logPath := filepath.Join(t.LogDir, fmt.Sprintf("%s-%s-%s.log", started.Format("2006-01-02"), kind, id))
	header := fmt.Sprintf("== %s: задача %s (%s): %s ==\n", started.Format(time.RFC3339), kind, id, strings.Join(argv, " "))
	if err := os.WriteFile(logPath, []byte(header), 0o640); err != nil {
		return Task{}, err
	}
	task := Task{ID: id, Kind: kind, Started: started, Log: logPath}
	t.tasks = append(t.tasks, task)
	if len(t.tasks) > maxTasks {
		t.tasks = t.tasks[len(t.tasks)-maxTasks:]
	}
	t.running = id
	t.saveLocked()
	go t.run(task, argv, opts)
	return task, nil
}

func newTaskID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (t *Tasks) run(task Task, argv []string, opts StartOpts) {
	args := []string{
		"--unit=" + Unit(task.ID), "--collect", "--quiet", "--wait",
		"--property=StandardOutput=append:" + task.Log,
		"--property=StandardError=append:" + task.Log,
		"--property=RuntimeMaxSec=" + strconv.Itoa(int(t.timeout(task.Kind)/time.Second)),
		"--working-directory=" + t.Dir,
	}
	if opts.StdinFile != "" {
		args = append(args, "--property=StandardInput=file:"+opts.StdinFile)
	}
	for _, e := range opts.Env {
		args = append(args, "--setenv="+e)
	}
	args = append(args, "--", "/bin/sh", "-c", exitWrapper, "sh", t.exitPath(task))
	args = append(args, argv...)
	run := t.Exec
	if run == nil {
		run = execCommand
	}
	code, out, err := run(t.context(), "systemd-run", args...)
	if len(out) > 0 {
		appendLog(task.Log, string(out))
	}
	if t.context().Err() != nil {
		return // агент останавливается; юнит живёт дальше, итог запишет следующий запуск
	}
	if c, ok := t.readExit(task); ok {
		// Файл надёжнее: код самой команды, а не systemd-run.
		t.logger().Info("задача завершена", "id", task.ID, "kind", task.Kind, "exit_code", c)
		t.finish(task.ID, &c, false, false)
		return
	}
	if err != nil {
		appendLog(task.Log, "systemd-run не запущен: "+err.Error()+"\n")
		t.finish(task.ID, ptr(-1), false, false)
		return
	}
	// systemd-run вернулся, а кода команды нет. Юнит ещё жив (клиент убит
	// сигналом при остановке агента, оборван D-Bus) — ждём его, а не пишем
	// ложный код: иначе правило «одна задача» перестало бы действовать.
	if t.state(Unit(task.ID)) != unitInactive {
		t.logger().Warn("systemd-run вернулся, а юнит задачи ещё работает — ждём", "id", task.ID, "code", code)
		t.waitOrphan(task.ID)
		return
	}
	if t.timedOut(task) {
		appendLog(task.Log, "задача остановлена по пределу времени\n")
		t.logger().Warn("задача остановлена по пределу времени", "id", task.ID, "kind", task.Kind)
		t.finish(task.ID, nil, false, true)
		return
	}
	t.logger().Info("задача завершена", "id", task.ID, "kind", task.Kind, "exit_code", code)
	t.finish(task.ID, &code, false, false)
}

func ptr[T any](v T) *T { return &v }

func appendLog(path, s string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(s)
}

func execCommand(ctx context.Context, name string, args ...string) (int, []byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), out, nil
	}
	return 0, out, err
}

func (t *Tasks) finish(id string, code *int, interrupted, timedOut bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for i := range t.tasks {
		if t.tasks[i].ID == id {
			t.tasks[i].Finished = &now
			t.tasks[i].ExitCode = code
			t.tasks[i].Interrupted = interrupted
			t.tasks[i].TimedOut = timedOut
		}
	}
	if t.running == id {
		t.running = ""
	}
	t.saveLocked()
	if t.OnFinish != nil {
		go t.OnFinish()
	}
}

func (t *Tasks) runningLocked() (Task, bool) {
	if t.running == "" {
		return Task{}, false
	}
	for _, tk := range t.tasks {
		if tk.ID == t.running {
			return tk, true
		}
	}
	return Task{}, false
}

// Running — идущая задача, если есть.
func (t *Tasks) Running() (Task, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.runningLocked()
}

// List — задачи, новые сверху.
func (t *Tasks) List() []Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Task, 0, len(t.tasks))
	for i := len(t.tasks) - 1; i >= 0; i-- {
		out = append(out, t.tasks[i])
	}
	return out
}

// Get — задача по id.
func (t *Tasks) Get(id string) (Task, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tk := range t.tasks {
		if tk.ID == id {
			return tk, true
		}
	}
	return Task{}, false
}

// Tail — последние 64 КБ журнала задачи. Журнал берётся из своего каталога
// по имени файла, а не по пути из tasks.json.
func (t *Tasks) Tail(task Task) (string, error) {
	f, err := os.Open(filepath.Join(t.LogDir, filepath.Base(task.Log)))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil // журнал уже удалён ротацией
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := int64(0)
	if st.Size() > maxTail {
		off = st.Size() - maxTail
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	// Срез мог начаться посреди многобайтового символа.
	for len(buf) > 0 && !utf8.RuneStart(buf[0]) {
		buf = buf[1:]
	}
	return string(buf), nil
}

// Rotate удаляет журналы старше maxAge, кроме журнала идущей задачи.
func (t *Tasks) Rotate(maxAge time.Duration) {
	entries, err := os.ReadDir(t.LogDir)
	if err != nil {
		return
	}
	cur, busy := t.Running()
	cutoff := t.now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".log") || strings.HasSuffix(e.Name(), ".log.exit")) {
			continue
		}
		if busy && (e.Name() == filepath.Base(cur.Log) || e.Name() == filepath.Base(cur.Log)+".exit") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(t.LogDir, e.Name())); err == nil {
			t.logger().Info("журнал задачи удалён по возрасту", "file", e.Name())
		}
	}
}

// RunRotation чистит старые журналы сразу и затем раз в сутки.
func (t *Tasks) RunRotation(ctx context.Context) {
	t.Rotate(taskLogMaxAge)
	tk := time.NewTicker(rotateEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.Rotate(taskLogMaxAge)
		}
	}
}

// saveLocked пишет tasks.json; сбой записи не должен ронять задачу.
func (t *Tasks) saveLocked() {
	data, err := json.MarshalIndent(t.tasks, "", " ")
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(t.StatePath), 0o750); err == nil {
			err = fsutil.WriteFileAtomic(t.StatePath, data, 0o640)
		}
	}
	if err != nil {
		t.logger().Error("tasks.json не записан", "err", err)
	}
}

// busyDuring возвращает проверку для antizapret.Routing.Busy и SetupFile.Busy:
// пока идёт задача одного из видов kinds, запись отклоняется.
func busyDuring(t *Tasks, kinds ...string) func() error {
	return func() error {
		cur, ok := t.Running()
		if !ok {
			return nil
		}
		for _, k := range kinds {
			if cur.Kind == k {
				return &antizapret.BusyError{Reason: fmt.Sprintf("идёт задача %s — дождитесь её окончания и повторите", taskKindName(cur.Kind))}
			}
		}
		return nil
	}
}

func taskKindName(kind string) string {
	switch kind {
	case TaskDoall:
		return "doall (применение списков)"
	case TaskRestart:
		return "restart (перезапуск antizapret)"
	case TaskAZUpdate:
		return "azupdate (обновление AntiZapret)"
	case TaskAZRestore:
		return "azrestore (восстановление из бэкапа)"
	}
	return kind
}
