package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
)

// unitFake — управляемое состояние юнита для Tasks.Active.
type unitFake struct {
	mu     sync.Mutex
	active bool
	err    error
}

func (u *unitFake) set(active bool, err error) {
	u.mu.Lock()
	u.active, u.err = active, err
	u.mu.Unlock()
}

func (u *unitFake) fn(context.Context, string) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.active, u.err
}

// immediateTasks — systemd-run возвращается сразу (как клиент, убитый SIGTERM),
// юнитом управляет unitFake.
func immediateTasks(t *testing.T, code int, u *unitFake) *Tasks {
	t.Helper()
	root := t.TempDir()
	return &Tasks{
		Dir: "/root/antizapret", LogDir: filepath.Join(root, "log"), StatePath: filepath.Join(root, "tasks.json"),
		Exec:      func(context.Context, string, ...string) (int, []byte, error) { return code, nil, nil },
		Active:    u.fn,
		Result:    func(context.Context, string) string { return "" },
		Now:       time.Now,
		PollEvery: 5 * time.Millisecond,
	}
}

func stillRunning(t *testing.T, tk *Tasks, id string) {
	t.Helper()
	time.Sleep(60 * time.Millisecond)
	cur, ok := tk.Running()
	if !ok || cur.ID != id {
		t.Fatalf("задача %s должна идти, Running=%+v %v", id, cur, ok)
	}
	if got, _ := tk.Get(id); got.Finished != nil {
		t.Fatalf("задача записана оконченной: %+v", got)
	}
}

// I1: systemd-run убит вместе с агентом (код 143), а юнит работает — задача
// остаётся идущей, вторая получает BusyError, итог берётся из .exit.
func TestTasksClientDiedUnitAliveKeepsTaskRunning(t *testing.T) {
	u := &unitFake{active: true}
	tk := immediateTasks(t, 143, u)
	task, err := tk.Start(TaskDoall, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	stillRunning(t, tk, task.ID)
	_, err = tk.Start(TaskRestart, []string{"y"})
	var busy *BusyError
	if !errors.As(err, &busy) || busy.Task.ID != task.ID {
		t.Fatalf("ожидалась BusyError, получено %v", err)
	}
	// Юнит закончил и оставил код.
	os.WriteFile(task.Log+".exit", []byte("7\n"), 0o640)
	u.set(false, nil)
	got := waitFinished(t, tk, task.ID)
	if got.ExitCode == nil || *got.ExitCode != 7 || got.Interrupted || got.TimedOut {
		t.Fatalf("%+v", got)
	}
	if _, ok := tk.Running(); ok {
		t.Fatal("после окончания задача всё ещё идёт")
	}
}

// Агент останавливается (Ctx отменён): ложный итог не пишется, после
// перезапуска Load подхватывает живой юнит.
func TestTasksAgentShutdownWritesNoResult(t *testing.T) {
	u := &unitFake{active: true}
	tk := immediateTasks(t, 143, u)
	ctx, cancel := context.WithCancel(context.Background())
	tk.Ctx = ctx
	cancel()
	task, err := tk.Start(TaskDoall, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if got, _ := tk.Get(task.ID); got.Finished != nil {
		t.Fatalf("при остановке агента итог записан: %+v", got)
	}
	// Новый запуск агента: юнит ещё работает — задача ждётся, потом закрывается кодом из файла.
	again := &Tasks{LogDir: tk.LogDir, StatePath: tk.StatePath, Active: u.fn, PollEvery: 5 * time.Millisecond,
		Result: func(context.Context, string) string { return "" }}
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	if cur, ok := again.Running(); !ok || cur.ID != task.ID {
		t.Fatalf("после перезапуска задача должна идти: %+v %v", cur, ok)
	}
	os.WriteFile(task.Log+".exit", []byte("0\n"), 0o640)
	u.set(false, nil)
	got := waitFinished(t, again, task.ID)
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("%+v", got)
	}
}

// M5: systemctl не ответил (тайм-аут) — это «неизвестно», задача не закрывается.
func TestTasksActiveErrorIsUnknownNotStopped(t *testing.T) {
	u := &unitFake{err: errors.New("тайм-аут systemctl")}
	tk := immediateTasks(t, 1, u)
	task, _ := tk.Start(TaskProfiles, []string{"x"})
	stillRunning(t, tk, task.ID)
	os.WriteFile(task.Log+".exit", []byte("0\n"), 0o640)
	u.set(false, nil)
	got := waitFinished(t, tk, task.ID)
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestTasksLoadUnknownStateWaits(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tasks.json")
	os.WriteFile(state, []byte(`[{"id":"eeeeeeeeeeee","kind":"doall","started":"`+recentStart+`","log":"/x/e.log"}]`), 0o640)
	u := &unitFake{err: errors.New("systemd занят")}
	tk := &Tasks{LogDir: root, StatePath: state, Active: u.fn, PollEvery: 5 * time.Millisecond,
		Result: func(context.Context, string) string { return "" }}
	if err := tk.Load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := tk.Running(); !ok {
		t.Fatal("при неизвестном состоянии задачу нельзя помечать прерванной")
	}
	u.set(false, nil)
	got := waitFinished(t, tk, "eeeeeeeeeeee")
	if !got.Interrupted {
		t.Fatalf("юнит остановлен без .exit — прервана: %+v", got)
	}
}

// M6: нет .exit, юнит остановлен, systemd говорит timeout — «превышено время».
func TestTasksTimedOutBySystemdResult(t *testing.T) {
	u := &unitFake{}
	tk := immediateTasks(t, 1, u)
	tk.Result = func(context.Context, string) string { return "timeout" }
	task, _ := tk.Start(TaskDoall, []string{"x"})
	got := waitFinished(t, tk, task.ID)
	if !got.TimedOut || got.ExitCode != nil || got.Interrupted {
		t.Fatalf("%+v", got)
	}
}

// Результата systemd нет (--collect убрал юнит): по пределу времени.
func TestTasksTimedOutByElapsedLimit(t *testing.T) {
	u := &unitFake{active: true}
	tk := immediateTasks(t, 1, u)
	tk.Timeouts = map[string]time.Duration{TaskRestart: 50 * time.Millisecond}
	task, _ := tk.Start(TaskRestart, []string{"x"})
	stillRunning(t, tk, task.ID)
	u.set(false, nil)
	got := waitFinished(t, tk, task.ID)
	if !got.TimedOut || got.ExitCode != nil {
		t.Fatalf("%+v", got)
	}
}

// Обычная ошибка команды — не «превышено время».
func TestTasksPlainFailureIsNotTimeout(t *testing.T) {
	u := &unitFake{}
	tk := immediateTasks(t, 1, u)
	task, _ := tk.Start(TaskDoall, []string{"x"})
	got := waitFinished(t, tk, task.ID)
	if got.TimedOut || got.ExitCode == nil || *got.ExitCode != 1 {
		t.Fatalf("%+v", got)
	}
}

// I2: пока идёт doall, правка списков отклоняется кодом 409 и файл не тронут.
func TestAPIRoutingWritesRefusedDuringDoall(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	f := newFakeExec()
	tk := newTasks(t, f)
	e.api.Tasks = tk
	e.api.Routing.Busy = busyDuring(tk, TaskDoall)
	ctx := context.Background()

	stamp, err := e.api.Routing.Backups.Save("include-hosts.txt", []byte("old.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	task, err := tk.Start(TaskDoall, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.PatchRouting(ctx, "include-hosts.txt", patchAdd("b.example.com")); status(err) != 409 || !strings.Contains(err.Error(), "doall") {
		t.Fatalf("PATCH: %v", err)
	}
	if _, err := e.client.ReplaceRouting(ctx, "include-hosts.txt", "b.example.com\n", ""); status(err) != 409 {
		t.Fatalf("PUT: %v", err)
	}
	if _, err := e.client.RestoreRouting(ctx, "include-hosts.txt", stamp); status(err) != 409 {
		t.Fatalf("restore: %v", err)
	}
	if got := readCfg(t, e, "include-hosts.txt"); got != "a.example.com\n" {
		t.Fatalf("файл тронут: %q", got)
	}
	f.done()
	waitFinished(t, tk, task.ID)
	res, err := e.client.PatchRouting(ctx, "include-hosts.txt", patchAdd("b.example.com"))
	if err != nil || !res.Applied {
		t.Fatalf("после doall правка должна проходить: %+v %v", res, err)
	}
}

// Профили не трогают списки: правка во время profiles разрешена.
func TestAPIRoutingAllowedDuringProfiles(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	f := newFakeExec()
	tk := newTasks(t, f)
	e.api.Tasks = tk
	e.api.Routing.Busy = busyDuring(tk, TaskDoall)
	task, _ := tk.Start(TaskProfiles, []string{"x"})
	res, err := e.client.PatchRouting(context.Background(), "include-hosts.txt", patchAdd("b.example.com"))
	if err != nil || !res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	f.done()
	waitFinished(t, tk, task.ID)
}

// I2 для setup: 409, пока идёт doall или restart.
func TestAPISetupRefusedDuringDoallAndRestart(t *testing.T) {
	for _, kind := range []string{TaskDoall, TaskRestart} {
		e, p := setupEnv(t)
		f := newFakeExec()
		tk := newTasks(t, f)
		e.api.Tasks = tk
		e.api.Setup.Busy = busyDuring(tk, TaskDoall, TaskRestart)
		task, _ := tk.Start(kind, []string{"x"})
		_, err := e.client.SetSetup(context.Background(), map[string]string{"ROUTE_ALL": "y"})
		if status(err) != 409 || !strings.Contains(err.Error(), kind) {
			t.Fatalf("%s: %v", kind, err)
		}
		if b, _ := os.ReadFile(p); string(b) != apiSetup {
			t.Fatalf("%s: setup тронут", kind)
		}
		f.done()
		waitFinished(t, tk, task.ID)
		if _, err := e.client.SetSetup(context.Background(), map[string]string{"ROUTE_ALL": "y"}); err != nil {
			t.Fatalf("%s: после задачи запись должна проходить: %v", kind, err)
		}
	}
}

// I4: /raw отдаёт файл как есть, PUT с base_sha256 при расхождении — 409.
func TestAPIRoutingRawAndBaseSHA(t *testing.T) {
	orig := "# заметка\n\nexample.com\n"
	e := routingEnv(t, map[string]string{"include-hosts.txt": orig, "big-hosts.txt": strings.Repeat("a.example.com\n", antizapret.MaxReplaceBytes/14+10)})
	ctx := context.Background()
	raw, err := e.client.RoutingRaw(ctx, "include-hosts.txt")
	if err != nil || raw.Content != orig || raw.SHA256 != antizapret.SHA256([]byte(orig)) || raw.Name != "include-hosts.txt" {
		t.Fatalf("%+v %v", raw, err)
	}
	if _, err := e.client.RoutingRaw(ctx, "big-hosts.txt"); status(err) != 413 {
		t.Fatalf("большой файл: %v", err)
	}
	if _, err := e.client.RoutingRaw(ctx, "nope.txt"); status(err) != 404 {
		t.Fatalf("нет файла: %v", err)
	}
	// Другой администратор успел дописать строку.
	if _, err := e.client.PatchRouting(ctx, "include-hosts.txt", patchAdd("new.example.com")); err != nil {
		t.Fatal(err)
	}
	before := readCfg(t, e, "include-hosts.txt")
	if _, err := e.client.ReplaceRouting(ctx, "include-hosts.txt", "x.example.com\n", raw.SHA256); status(err) != 409 {
		t.Fatalf("ожидался 409: %v", err)
	}
	if readCfg(t, e, "include-hosts.txt") != before {
		t.Fatal("файл изменён при расхождении")
	}
	fresh, _ := e.client.RoutingRaw(ctx, "include-hosts.txt")
	if res, err := e.client.ReplaceRouting(ctx, "include-hosts.txt", fresh.Content, fresh.SHA256); err != nil || !res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	// Сохранение без правок не теряет комментарии.
	if got := readCfg(t, e, "include-hosts.txt"); got != before {
		t.Fatalf("комментарии потеряны:\n%q\nбыло\n%q", got, before)
	}
}

func patchAdd(lines ...string) nodeapi.RoutingPatch { return nodeapi.RoutingPatch{Add: lines} }
