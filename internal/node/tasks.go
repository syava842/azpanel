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

	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/nodeapi"
)

const (
	maxTasks      = 100      // сколько последних задач хранится в tasks.json
	maxTail       = 64 << 10 // хвост журнала в ответе по задаче
	taskLogMaxAge = 30 * 24 * time.Hour
	rotateEvery   = 24 * time.Hour
)

// Виды задач. Этапы 5, 10 и 11 добавят свои.
const (
	TaskDoall    = "doall"
	TaskRestart  = "restart"
	TaskProfiles = "profiles"
)

// DefaultTaskTimeouts — предел времени задачи по виду (RuntimeMaxSec юнита).
// Новый вид (этапы 5, 10, 11) добавляется сюда или в Tasks.Timeouts.
var DefaultTaskTimeouts = map[string]time.Duration{
	TaskDoall:    1800 * time.Second,
	TaskRestart:  300 * time.Second,
	TaskProfiles: 1800 * time.Second,
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
	// Active — работает ли юнит; nil — systemctl is-active.
	Active func(ctx context.Context, unit string) bool
	// PollEvery — как часто проверять юнит задачи, оставшейся с прошлого запуска агента.
	PollEvery time.Duration
	// Timeouts — предел времени по виду задачи; nil — DefaultTaskTimeouts.
	Timeouts map[string]time.Duration

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
		if t.running == "" && t.isActive(Unit(tk.ID)) {
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

func (t *Tasks) isActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if t.Active != nil {
		return t.Active(ctx, unit)
	}
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
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

// waitOrphan ждёт юнит задачи, начатой до перезапуска агента. Код выхода
// берётся из файла обёртки; если файла нет (юнит убит по пределу времени или
// сломан), код неизвестен — --collect уже убрал юнит вместе с результатом.
func (t *Tasks) waitOrphan(id string) {
	every := t.PollEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	for t.isActive(Unit(id)) {
		time.Sleep(every)
	}
	if task, ok := t.Get(id); ok {
		if code, ok := t.readExit(task); ok {
			t.finish(id, &code, false)
			return
		}
	}
	t.finish(id, nil, true)
}

// Start запускает задачу в фоне. argv — команда и аргументы; запрет на
// одновременный запуск проверяется здесь, под тем же замком, что и
// регистрация задачи.
func (t *Tasks) Start(kind string, argv []string) (Task, error) {
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
	go t.run(task, argv)
	return task, nil
}

func newTaskID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (t *Tasks) run(task Task, argv []string) {
	args := []string{
		"--unit=" + Unit(task.ID), "--collect", "--quiet", "--wait",
		"--property=StandardOutput=append:" + task.Log,
		"--property=StandardError=append:" + task.Log,
		"--property=RuntimeMaxSec=" + strconv.Itoa(int(t.timeout(task.Kind)/time.Second)),
		"--working-directory=" + t.Dir,
		"--", "/bin/sh", "-c", exitWrapper, "sh", t.exitPath(task),
	}
	args = append(args, argv...)
	run := t.Exec
	if run == nil {
		run = execCommand
	}
	// Контекст не отменяется: ожидание кончается вместе с процессом агента.
	code, out, err := run(context.Background(), "systemd-run", args...)
	if len(out) > 0 {
		appendLog(task.Log, string(out))
	}
	if err != nil {
		appendLog(task.Log, "systemd-run не запущен: "+err.Error()+"\n")
		code = -1
	} else if c, ok := t.readExit(task); ok {
		code = c // файл надёжнее: код самой команды, а не systemd-run
	}
	t.logger().Info("задача завершена", "id", task.ID, "kind", task.Kind, "exit_code", code)
	t.finish(task.ID, &code, false)
}

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

func (t *Tasks) finish(id string, code *int, interrupted bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for i := range t.tasks {
		if t.tasks[i].ID == id {
			t.tasks[i].Finished = &now
			t.tasks[i].ExitCode = code
			t.tasks[i].Interrupted = interrupted
		}
	}
	if t.running == id {
		t.running = ""
	}
	t.saveLocked()
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
