package node

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// fakeExec — подмена systemd-run: ждёт release и возвращает заданный код.
type fakeExec struct {
	mu      sync.Mutex
	calls   [][]string
	release chan struct{}
	code    int
	out     string
}

func newFakeExec() *fakeExec { return &fakeExec{release: make(chan struct{})} }

func (f *fakeExec) exec(_ context.Context, name string, args ...string) (int, []byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{name}, args...))
	f.mu.Unlock()
	<-f.release
	return f.code, []byte(f.out), nil
}

func (f *fakeExec) done() { close(f.release) }

func newTasks(t *testing.T, f *fakeExec) *Tasks {
	t.Helper()
	root := t.TempDir()
	return &Tasks{
		Dir: "/root/antizapret", LogDir: filepath.Join(root, "log", "tasks"),
		StatePath: filepath.Join(root, "data", "tasks.json"),
		Exec:      f.exec, Now: time.Now, PollEvery: 5 * time.Millisecond,
		// Юнитов в тестах нет: после возврата Exec задача считается оконченной.
		Active: func(context.Context, string) (bool, error) { return false, nil },
		Result: func(context.Context, string) string { return "" },
	}
}

func waitFinished(t *testing.T, tk *Tasks, id string) Task {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := tk.Get(id); ok && got.Finished != nil {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("задача не закончилась")
	return Task{}
}

func TestTasksSecondTaskIsBusy(t *testing.T) {
	f := newFakeExec()
	tk := newTasks(t, f)
	first, err := tk.Start(TaskDoall, []string{"/root/antizapret/doall.sh"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tk.Start(TaskRestart, []string{"systemctl", "restart", "antizapret"})
	busy, ok := err.(*BusyError)
	if !ok || busy.Task.ID != first.ID || !strings.Contains(err.Error(), "уже идёт задача doall") {
		t.Fatalf("ожидалась BusyError про doall, получено %v", err)
	}
	f.done()
	waitFinished(t, tk, first.ID)
	// После окончания следующая задача принимается.
	second, err := tk.Start(TaskRestart, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	waitFinished(t, tk, second.ID)
}

func TestTasksExitCodeAndSystemdRunArgv(t *testing.T) {
	f := newFakeExec()
	f.code, f.out = 3, "systemd-run сообщает\n"
	tk := newTasks(t, f)
	task, err := tk.Start(TaskDoall, []string{"/root/antizapret/doall.sh", "x"})
	if err != nil {
		t.Fatal(err)
	}
	f.done()
	got := waitFinished(t, tk, task.ID)
	if got.ExitCode == nil || *got.ExitCode != 3 || got.Finished == nil || got.Finished.Before(got.Started) || got.Interrupted {
		t.Fatalf("%+v", got)
	}
	want := []string{
		"systemd-run", "--unit=azpanel-task-" + task.ID, "--collect", "--quiet", "--wait",
		"--property=StandardOutput=append:" + task.Log, "--property=StandardError=append:" + task.Log,
		"--property=RuntimeMaxSec=1800",
		"--working-directory=/root/antizapret", "--", "/bin/sh", "-c", exitWrapper, "sh", task.Log + ".exit",
		"/root/antizapret/doall.sh", "x",
	}
	if strings.Join(f.calls[0], "\n") != strings.Join(want, "\n") {
		t.Fatalf("argv:\n%v\nожидалось:\n%v", f.calls[0], want)
	}
	if !strings.HasSuffix(filepath.Base(task.Log), "-doall-"+task.ID+".log") || len(task.ID) != 12 {
		t.Fatalf("журнал %q, id %q", task.Log, task.ID)
	}
	log, _ := os.ReadFile(task.Log)
	if !strings.Contains(string(log), "doall.sh x") || !strings.Contains(string(log), "systemd-run сообщает") {
		t.Fatalf("журнал: %q", log)
	}
}

func TestTasksExecFailureIsRecorded(t *testing.T) {
	root := t.TempDir()
	tk := &Tasks{
		Dir: "/x", LogDir: filepath.Join(root, "l"), StatePath: filepath.Join(root, "tasks.json"),
		Exec: func(context.Context, string, ...string) (int, []byte, error) {
			return 0, nil, os.ErrNotExist
		},
	}
	task, err := tk.Start(TaskDoall, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	got := waitFinished(t, tk, task.ID)
	if got.ExitCode == nil || *got.ExitCode != -1 {
		t.Fatalf("%+v", got)
	}
}

func TestTasksStateSurvivesNewInstance(t *testing.T) {
	f := newFakeExec()
	f.code = 0
	tk := newTasks(t, f)
	a, _ := tk.Start(TaskDoall, []string{"a"})
	f.done()
	waitFinished(t, tk, a.ID)

	again := &Tasks{LogDir: tk.LogDir, StatePath: tk.StatePath}
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	list := again.List()
	if len(list) != 1 || list[0].ID != a.ID || list[0].ExitCode == nil || *list[0].ExitCode != 0 || list[0].Kind != TaskDoall {
		t.Fatalf("%+v", list)
	}
}

func TestTasksListNewestFirstAndCapped(t *testing.T) {
	root := t.TempDir()
	tk := &Tasks{
		Dir: "/x", LogDir: filepath.Join(root, "l"), StatePath: filepath.Join(root, "tasks.json"),
		Exec:   func(context.Context, string, ...string) (int, []byte, error) { return 0, nil, nil },
		Active: func(context.Context, string) (bool, error) { return false, nil },
	}
	var ids []string
	for i := 0; i < maxTasks+5; i++ {
		var task Task
		var err error
		for { // предыдущая ещё может идти
			task, err = tk.Start(TaskDoall, []string{"x"})
			if err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		ids = append(ids, task.ID)
		waitFinished(t, tk, task.ID)
	}
	list := tk.List()
	if len(list) != maxTasks || list[0].ID != ids[len(ids)-1] {
		t.Fatalf("задач %d, первая %v", len(list), list[0].ID)
	}
	again := &Tasks{StatePath: tk.StatePath}
	again.Load()
	if len(again.List()) != maxTasks {
		t.Fatalf("после перезапуска %d", len(again.List()))
	}
}

func TestTasksInterruptedWhenUnitGone(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tasks.json")
	os.WriteFile(state, []byte(`[{"id":"aaaaaaaaaaaa","kind":"doall","started":"2026-11-02T10:00:00Z","log":"/x/a.log"}]`), 0o640)
	tk := &Tasks{
		LogDir: root, StatePath: state,
		Active: func(context.Context, string) (bool, error) { return false, nil },
	}
	if err := tk.Load(); err != nil {
		t.Fatal(err)
	}
	got, _ := tk.Get("aaaaaaaaaaaa")
	if got.Finished == nil || !got.Interrupted || got.ExitCode != nil {
		t.Fatalf("%+v", got)
	}
	if _, busy := tk.Running(); busy {
		t.Fatal("прерванная задача не должна занимать очередь")
	}
	// И после следующего чтения состояние сохранено.
	again := &Tasks{StatePath: state}
	again.Load()
	if g, _ := again.Get("aaaaaaaaaaaa"); !g.Interrupted {
		t.Fatalf("%+v", g)
	}
}

func TestTasksOrphanWaitedWhileUnitActive(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tasks.json")
	os.WriteFile(state, []byte(`[{"id":"bbbbbbbbbbbb","kind":"profiles","started":"2026-11-02T10:00:00Z","log":"/x/b.log"}]`), 0o640)
	var mu sync.Mutex
	active := true
	tk := &Tasks{
		LogDir: root, StatePath: state, PollEvery: 5 * time.Millisecond,
		Active: func(_ context.Context, unit string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			return active && unit == "azpanel-task-bbbbbbbbbbbb", nil
		},
		Exec: func(context.Context, string, ...string) (int, []byte, error) { return 0, nil, nil },
	}
	if err := tk.Load(); err != nil {
		t.Fatal(err)
	}
	if cur, busy := tk.Running(); !busy || cur.ID != "bbbbbbbbbbbb" {
		t.Fatal("задача должна считаться идущей")
	}
	if _, err := tk.Start(TaskDoall, []string{"x"}); err == nil {
		t.Fatal("вторая задача при идущей должна отклоняться")
	}
	mu.Lock()
	active = false
	mu.Unlock()
	got := waitFinished(t, tk, "bbbbbbbbbbbb")
	if !got.Interrupted || got.ExitCode != nil {
		t.Fatalf("%+v", got)
	}
	if _, busy := tk.Running(); busy {
		t.Fatal("очередь должна освободиться")
	}
}

func TestTasksCorruptStateSetAside(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tasks.json")
	os.WriteFile(state, []byte("{не json"), 0o640)
	tk := &Tasks{LogDir: root, StatePath: state}
	if err := tk.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state + ".bad"); err != nil || len(tk.List()) != 0 {
		t.Fatalf("испорченный файл не отложен: %v", err)
	}
}

func TestTasksTailCapped(t *testing.T) {
	root := t.TempDir()
	tk := &Tasks{LogDir: root}
	// Кириллица: 64 КБ почти наверняка попадают посреди символа.
	body := strings.Repeat("строка журнала\n", 20000)
	path := filepath.Join(root, "x.log")
	os.WriteFile(path, []byte(body), 0o640)
	tail, err := tk.Tail(Task{Log: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) > maxTail || len(tail) < maxTail-4 || !strings.HasSuffix(tail, "строка журнала\n") {
		t.Fatalf("хвост %d байт", len(tail))
	}
	if strings.ContainsRune(tail, '�') {
		t.Fatal("хвост начинается с обрезанного символа")
	}
	short, _ := tk.Tail(Task{Log: filepath.Join(root, "нет.log")})
	if short != "" {
		t.Fatal("удалённый журнал — пустой хвост")
	}
}

func TestTasksRotateByAge(t *testing.T) {
	root := t.TempDir()
	tk := &Tasks{LogDir: root, Now: time.Now}
	old := filepath.Join(root, "2026-09-01-doall-aaaaaaaaaaaa.log")
	fresh := filepath.Join(root, "2026-11-01-doall-bbbbbbbbbbbb.log")
	other := filepath.Join(root, "notes.txt")
	for _, p := range []string{old, fresh, other} {
		os.WriteFile(p, []byte("x"), 0o640)
	}
	ago := time.Now().Add(-31 * 24 * time.Hour)
	os.Chtimes(old, ago, ago)
	os.Chtimes(other, ago, ago)
	tk.Rotate(taskLogMaxAge)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("старый журнал должен быть удалён")
	}
	for _, p := range []string{fresh, other} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s не должен удаляться: %v", p, err)
		}
	}
}

func TestTasksRotateKeepsRunningLog(t *testing.T) {
	f := newFakeExec()
	tk := newTasks(t, f)
	task, _ := tk.Start(TaskDoall, []string{"x"})
	ago := time.Now().Add(-40 * 24 * time.Hour)
	os.Chtimes(task.Log, ago, ago)
	tk.Rotate(taskLogMaxAge)
	if _, err := os.Stat(task.Log); err != nil {
		t.Fatal("журнал идущей задачи удалён")
	}
	f.done()
	waitFinished(t, tk, task.ID)
}

// --- API ---

func tasksEnv(t *testing.T) (apiEnv, *fakeExec, *Tasks) {
	t.Helper()
	e := newAPI(t)
	f := newFakeExec()
	tk := newTasks(t, f)
	tk.Dir = e.api.AntiZapretDir
	e.api.Tasks = tk
	return e, f, tk
}

func TestAPITaskStartAndConflict(t *testing.T) {
	e, f, tk := tasksEnv(t)
	ctx := context.Background()
	az := e.api.AntiZapretDir

	task, err := e.client.ApplyRouting(ctx)
	if err != nil || task.Kind != TaskDoall || len(task.ID) != 12 || task.Finished != nil {
		t.Fatalf("%+v, %v", task, err)
	}
	if _, err := e.client.RestartAntiZapret(ctx); status(err) != 409 || !strings.Contains(err.Error(), "уже идёт задача doall") {
		t.Fatalf("restart при идущей: %v", err)
	}
	if _, err := e.client.ApplyRouting(ctx); status(err) != 409 {
		t.Fatalf("doall при идущей: %v", err)
	}
	if _, err := e.client.RebuildProfiles(ctx); status(err) != 409 {
		t.Fatalf("profiles при идущей: %v", err)
	}
	list, err := e.client.Tasks(ctx)
	if err != nil || len(list) != 1 || list[0].ID != task.ID {
		t.Fatalf("%+v, %v", list, err)
	}
	f.done()
	waitFinished(t, tk, task.ID)

	d, err := e.client.Task(ctx, task.ID)
	if err != nil || d.ExitCode == nil || *d.ExitCode != 0 || !strings.Contains(d.Tail, "doall.sh") {
		t.Fatalf("%+v, %v", d, err)
	}
	if got := f.calls[0][len(f.calls[0])-1]; got != filepath.Join(az, "doall.sh") {
		t.Fatalf("команда doall: %v", f.calls[0])
	}
	for _, id := range []string{"нет", "000000000000", "../x"} {
		if _, err := e.client.Task(ctx, id); status(err) != 404 {
			t.Fatalf("задача %q: %v", id, err)
		}
	}
}

func TestAPITaskCommands(t *testing.T) {
	cases := []struct {
		name string
		call func(*nodeapi.HTTPClient) (nodeapi.Task, error)
		kind string
		tail []string
	}{
		{"restart", func(c *nodeapi.HTTPClient) (nodeapi.Task, error) { return c.RestartAntiZapret(context.Background()) },
			TaskRestart, []string{"systemctl", "restart", "antizapret"}},
		{"profiles", func(c *nodeapi.HTTPClient) (nodeapi.Task, error) { return c.RebuildProfiles(context.Background()) },
			TaskProfiles, []string{"client.sh", "7"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, f, tk := tasksEnv(t)
			task, err := c.call(e.client)
			if err != nil || task.Kind != c.kind {
				t.Fatalf("%+v, %v", task, err)
			}
			f.done()
			waitFinished(t, tk, task.ID)
			got := f.calls[0]
			n := len(c.tail)
			if filepath.Base(got[len(got)-n]) != c.tail[0] || strings.Join(got[len(got)-n+1:], " ") != strings.Join(c.tail[1:], " ") {
				t.Fatalf("команда: %v", got)
			}
		})
	}
}

func TestAPIProfilesTaskBlocksClientOps(t *testing.T) {
	e, f, tk := tasksEnv(t)
	ctx := context.Background()
	task, err := e.client.RebuildProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindWireGuard}); status(err) != 409 {
		t.Fatalf("создание: %v", err)
	}
	if _, err := e.client.Renew(ctx, "alice", 30); status(err) != 409 {
		t.Fatalf("продление: %v", err)
	}
	if _, err := e.client.DeleteClient(ctx, nodeapi.KindOpenVPN, "alice"); status(err) != 409 {
		t.Fatalf("удаление: %v", err)
	}
	if len(*e.calls) != 0 {
		t.Fatalf("client.sh не должен запускаться: %v", *e.calls)
	}
	// Лимиты и блокировки client.sh не трогают.
	if err := e.client.SetLimit(ctx, "alice", 2); err != nil {
		t.Fatalf("лимит: %v", err)
	}
	f.done()
	waitFinished(t, tk, task.ID)
	if _, err := e.client.Renew(ctx, "alice", 30); err != nil {
		t.Fatalf("после задачи продление должно работать: %v", err)
	}
}

func TestAPIClientOpBlocksProfilesTask(t *testing.T) {
	e, _, _ := tasksEnv(t)
	release := make(chan struct{})
	entered := make(chan struct{})
	e.api.ClientSh.Run = func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		close(entered)
		<-release
		return []byte("ok"), nil
	}
	e.api.ClientSh.Timeout = 5 * time.Second
	done := make(chan error, 1)
	go func() {
		_, err := e.client.Renew(context.Background(), "alice", 30)
		done <- err
	}()
	<-entered
	if _, err := e.client.RebuildProfiles(context.Background()); status(err) != 409 || !strings.Contains(err.Error(), "операция над клиентом") {
		t.Fatalf("profiles во время client.sh: %v", err)
	}
	// doall от client.sh не зависит.
	if _, err := e.client.ApplyRouting(context.Background()); err != nil {
		t.Fatalf("doall: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAPITasksRequireToken(t *testing.T) {
	e, _, _ := tasksEnv(t)
	bad := nodeapi.New(e.srv.URL, "wrong")
	if _, err := bad.Tasks(context.Background()); status(err) != 401 {
		t.Fatalf("%v", err)
	}
	if _, err := bad.ApplyRouting(context.Background()); status(err) != 401 {
		t.Fatalf("%v", err)
	}
}

// --- предел времени и код выхода в файле ---

func TestTasksRuntimeMaxSecByKind(t *testing.T) {
	for kind, want := range map[string]string{
		TaskDoall: "1800", TaskRestart: "300", TaskProfiles: "1800", "novyj-vid": "1800",
	} {
		f := newFakeExec()
		tk := newTasks(t, f)
		task, err := tk.Start(kind, []string{"x"})
		if err != nil {
			t.Fatal(err)
		}
		f.done()
		waitFinished(t, tk, task.ID)
		if !strings.Contains(strings.Join(f.calls[0], " "), "--property=RuntimeMaxSec="+want+" ") {
			t.Fatalf("%s: ожидался RuntimeMaxSec=%s, получено %v", kind, want, f.calls[0])
		}
	}
	// Настраиваемая таблица.
	f := newFakeExec()
	tk := newTasks(t, f)
	tk.Timeouts = map[string]time.Duration{"update": 7200 * time.Second}
	task, _ := tk.Start("update", []string{"x"})
	f.done()
	waitFinished(t, tk, task.ID)
	if !strings.Contains(strings.Join(f.calls[0], " "), "RuntimeMaxSec=7200 ") {
		t.Fatalf("%v", f.calls[0])
	}
}

func TestTasksExitFileOverridesSystemdRunCode(t *testing.T) {
	f := newFakeExec()
	f.code = 1 // systemd-run мог сообщить другое
	tk := newTasks(t, f)
	task, _ := tk.Start(TaskDoall, []string{"x"})
	os.MkdirAll(tk.LogDir, 0o750)
	os.WriteFile(task.Log+".exit", []byte("5\n"), 0o640)
	f.done()
	got := waitFinished(t, tk, task.ID)
	if got.ExitCode == nil || *got.ExitCode != 5 {
		t.Fatalf("%+v", got)
	}
}

func TestTasksOrphanExitCodeFromFile(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tasks.json")
	os.WriteFile(state, []byte(`[{"id":"cccccccccccc","kind":"doall","started":"2026-11-02T10:00:00Z","log":"/x/c.log"}]`), 0o640)
	var mu sync.Mutex
	active := true
	tk := &Tasks{
		LogDir: root, StatePath: state, PollEvery: 5 * time.Millisecond,
		Active: func(context.Context, string) (bool, error) { mu.Lock(); defer mu.Unlock(); return active, nil },
	}
	if err := tk.Load(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "c.log.exit"), []byte("0\n"), 0o640)
	mu.Lock()
	active = false
	mu.Unlock()
	got := waitFinished(t, tk, "cccccccccccc")
	if got.Interrupted || got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestTasksLoadFinishedWhileAgentDown(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tasks.json")
	os.WriteFile(state, []byte(`[{"id":"dddddddddddd","kind":"restart","started":"2026-11-02T10:00:00Z","log":"/x/d.log"}]`), 0o640)
	os.WriteFile(filepath.Join(root, "d.log.exit"), []byte("2\n"), 0o640)
	tk := &Tasks{LogDir: root, StatePath: state, Active: func(context.Context, string) (bool, error) { return false, nil }}
	if err := tk.Load(); err != nil {
		t.Fatal(err)
	}
	got, _ := tk.Get("dddddddddddd")
	if got.Finished == nil || got.Interrupted || got.ExitCode == nil || *got.ExitCode != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestTasksRotateRemovesExitFiles(t *testing.T) {
	root := t.TempDir()
	tk := &Tasks{LogDir: root, Now: time.Now}
	old := filepath.Join(root, "2026-09-01-doall-aaaaaaaaaaaa.log.exit")
	os.WriteFile(old, []byte("0\n"), 0o640)
	ago := time.Now().Add(-31 * 24 * time.Hour)
	os.Chtimes(old, ago, ago)
	tk.Rotate(taskLogMaxAge)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("старый файл кода выхода должен быть удалён")
	}
}

// Обёртка на настоящем sh: код выхода пишется в файл, аргументы с кавычками и
// пробелами доходят как есть и ничего не исполняют.
func TestExitWrapperRealShell(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh не найден")
	}
	dir := t.TempDir()
	exitFile := filepath.Join(dir, "t.log.exit")
	marker := filepath.Join(dir, "pwned")
	evil := "a b'; touch " + marker + "; '"
	out, err := exec.Command(shell, "-c", exitWrapper, "sh", exitFile, "sh", "-c", `echo "$1"; exit 7`, "x", evil).CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("ожидался код 7: %v %s", err, out)
	}
	if strings.TrimSpace(string(out)) != evil {
		t.Fatalf("аргумент искажён: %q", out)
	}
	data, _ := os.ReadFile(exitFile)
	if strings.TrimSpace(string(data)) != "7" {
		t.Fatalf("файл кода: %q", data)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("инъекция сработала")
	}
	if _, err := os.Stat(exitFile + ".tmp"); err == nil {
		t.Fatal("временный файл остался")
	}
}
