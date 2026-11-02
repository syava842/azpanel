package node

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Скрипты задач обновления исполняются в настоящем sh на временных каталогах
// с подменными client.sh и setup.sh: текстовой проверки мало — ошибка в
// ls/rm/cp/mkfifo осталась бы незамеченной до боевого обновления.

type scriptEnv struct {
	t       *testing.T
	dir     string // «/root/antizapret»
	rootDir string // «/root»
	keep    string // «/opt/azpanel/backup»
	work    string
	u       *AZUpdater
}

func newScriptEnv(t *testing.T) *scriptEnv {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("скрипты задач исполняются только на Linux")
	}
	for _, tool := range []string{"sh", "bash", "tar", "gzip", "mkfifo", "cat", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("нет " + tool)
		}
	}
	root := t.TempDir()
	e := &scriptEnv{t: t, rootDir: filepath.Join(root, "root"), keep: filepath.Join(root, "backup"), work: filepath.Join(root, "work")}
	e.dir = filepath.Join(e.rootDir, "antizapret")
	for _, d := range []string{e.dir, e.keep, e.work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.u = &AZUpdater{Dir: e.dir, GuardEvery: time.Second, GuardTicks: 2}
	return e
}

func (e *scriptEnv) write(path, body string) {
	e.t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

// clientSh — подменный client.sh: «8» делает настоящий tar.gz, «9» пишет метку.
func (e *scriptEnv) clientSh() {
	e.write(filepath.Join(e.dir, "client.sh"), `#!/bin/bash
echo "client.sh $* stdin=$(cat | wc -c)" >> "`+filepath.Join(e.work, "calls")+`"
case "$1" in
8) mkdir -p /tmp/azb.$$ && echo cfg > /tmp/azb.$$/c && tar -czf "`+e.dir+`/backup-test.tar.gz" -C /tmp/azb.$$ c && rm -rf /tmp/azb.$$ ;;
9) echo "Configuration and clients restored from backup" ;;
esac
`)
}

func (e *scriptEnv) calls() string {
	b, _ := os.ReadFile(filepath.Join(e.work, "calls"))
	return string(b)
}

func (e *scriptEnv) run(argv []string, timeout time.Duration) (string, int) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.WaitDelay = 2 * time.Second // внуки (sleep сторожа) держат канал вывода
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		e.t.Fatalf("скрипт не завершился за %v:\n%s", timeout, out)
	}
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	return string(out), code
}

func (e *scriptEnv) answers() string {
	p := filepath.Join(e.work, "stdin")
	e.write(p, "1380\nvpn.example.com\n\n")
	return p
}

func (e *scriptEnv) updateArgv(setup string) []string {
	rootCopy := filepath.Join(e.rootDir, "backup-azpanel-2026-11-02-101500.tar.gz")
	keepCopy := filepath.Join(e.keep, "backup-azpanel-2026-11-02-101500.tar.gz")
	return e.u.setupArgv(azUpdateScript, "azupdate", rootCopy, keepCopy, setup, e.answers())
}

func TestAZUpdateScriptRunsInSh(t *testing.T) {
	e := newScriptEnv(t)
	e.clientSh()
	// Старая копия прошлой попытки в /root должна исчезнуть, чужой файл остаться.
	e.write(filepath.Join(e.rootDir, "backup-azpanel-2026-10-01-000000.tar.gz"), "old")
	e.write(filepath.Join(e.rootDir, "keep-me.txt"), "x")
	setup := filepath.Join(e.work, "setup.sh")
	e.write(setup, `#!/bin/bash
read -r mtu; read -r ovpn; read -r wg
echo "setup получил: mtu=$mtu ovpn=$ovpn wg=[$wg] env=$OPENVPN_PATCH"
ls /root-nonexistent >/dev/null 2>&1
echo "AntiZapret VPN + full VPN installed successfully!"
`)
	argv := e.updateArgv(setup)
	out, code := e.run(append([]string{"env", "OPENVPN_PATCH=3"}, argv...), 20*time.Second)
	if code != 0 {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if !strings.Contains(out, "setup получил: mtu=1380 ovpn=vpn.example.com wg=[] env=3") || !strings.Contains(out, "installed successfully") {
		t.Fatalf("ответы setup.sh не дошли:\n%s", out)
	}
	name := "backup-azpanel-2026-11-02-101500.tar.gz"
	for _, p := range []string{filepath.Join(e.keep, name), filepath.Join(e.rootDir, name)} {
		if st, err := os.Stat(p); err != nil || st.Size() == 0 || st.Mode().Perm() != 0o600 {
			t.Errorf("копия бэкапа %s: %v %v", p, st, err)
		}
	}
	if _, err := os.Stat(filepath.Join(e.rootDir, "backup-azpanel-2026-10-01-000000.tar.gz")); err == nil {
		t.Error("старая копия прошлой попытки осталась в /root")
	}
	if _, err := os.Stat(filepath.Join(e.rootDir, "keep-me.txt")); err != nil {
		t.Error("чужой файл в /root удалён")
	}
	// client.sh 8 не должен читать общий стандартный ввод юнита.
	if c := e.calls(); !strings.Contains(c, "client.sh 8 stdin=0") {
		t.Errorf("client.sh 8 унаследовал стандартный ввод: %q", c)
	}
}

func TestAZUpdateScriptPropagatesSetupExitCode(t *testing.T) {
	e := newScriptEnv(t)
	e.clientSh()
	setup := filepath.Join(e.work, "setup.sh")
	e.write(setup, "#!/bin/bash\nread -r a; read -r b; read -r c\necho 'Error: Low disk space!'\nexit 8\n")
	out, code := e.run(e.updateArgv(setup), 20*time.Second)
	if code != 8 || !strings.Contains(out, "Low disk space") {
		t.Fatalf("код %d, ждали 8:\n%s", code, out)
	}
}

func TestAZUpdateScriptStopsBeforeSetupWhenBackupBroken(t *testing.T) {
	e := newScriptEnv(t)
	// client.sh 8 «сделал» не tar.gz: setup.sh запускаться не должен.
	e.write(filepath.Join(e.dir, "client.sh"), "#!/bin/bash\necho нет > \""+e.dir+"/backup-test.tar.gz\"\n")
	setup := filepath.Join(e.work, "setup.sh")
	e.write(setup, "#!/bin/bash\ntouch \""+filepath.Join(e.work, "setup-ran")+"\"\n")
	_, code := e.run(e.updateArgv(setup), 20*time.Second)
	if code == 0 {
		t.Fatal("битый бэкап не остановил скрипт")
	}
	if _, err := os.Stat(filepath.Join(e.work, "setup-ran")); err == nil {
		t.Fatal("setup.sh запущен после неудавшегося бэкапа")
	}
}

// Лишний вопрос setup.sh: ввод не закрыт, читатель виден по /proc и прерывается,
// а не крутится до предела времени задачи.
func TestAZUpdateScriptStopsWhenSetupAsksMoreThanAnswered(t *testing.T) {
	e := newScriptEnv(t)
	switch runtime.GOARCH {
	case "amd64", "arm64":
	default:
		t.Skip("сторож ввода работает на x86_64 и aarch64")
	}
	// /proc/<pid>/syscall чужого процесса читается только с правом ptrace
	// (в боевой задаче агент выполняется от root; в контейнере без SYS_PTRACE нет).
	probe := exec.Command("sleep", "5")
	if err := probe.Start(); err != nil {
		t.Skip("sleep не запущен: " + err.Error())
	}
	defer func() { probe.Process.Kill(); probe.Wait() }()
	if _, err := os.ReadFile("/proc/" + strconv.Itoa(probe.Process.Pid) + "/syscall"); err != nil {
		t.Skip("/proc/<pid>/syscall чужого процесса не читается: " + err.Error())
	}
	e.clientSh()
	setup := filepath.Join(e.work, "setup.sh")
	e.write(setup, `#!/bin/bash
read -r a; read -r b; read -r c
echo "первые три вопроса получили ответы"
until [[ "$NEW_QUESTION" =~ (y|n) ]]; do
	read -r NEW_QUESTION || sleep 0.1
done
echo "сюда не дойти"
`)
	start := time.Now()
	out, code := e.run(e.updateArgv(setup), 30*time.Second)
	if code != 12 || !strings.Contains(out, "первые три вопроса получили ответы") || strings.Contains(out, "сюда не дойти") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if !strings.Contains(out, "ждёт ответа на вопрос, которого нет во вводе") {
		t.Fatalf("нет сообщения сторожа:\n%s", out)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("сторож сработал слишком поздно: %v", d)
	}
	// Сторож не должен принимать за зависание обычную долгую работу setup.sh.
	e2 := newScriptEnv(t)
	e2.clientSh()
	slow := filepath.Join(e2.work, "setup.sh")
	e2.write(slow, "#!/bin/bash\nread -r a; read -r b; read -r c\nsleep 5\necho 'installed successfully'\n")
	out, code = e2.run(e2.updateArgv(slow), 30*time.Second)
	if code != 0 || !strings.Contains(out, "installed successfully") {
		t.Fatalf("долгая работа прервана сторожем: код %d\n%s", code, out)
	}
}

func TestAZRetryScriptRunsInSh(t *testing.T) {
	e := newScriptEnv(t)
	e.clientSh()
	name := "backup-azpanel-2026-11-02-101500.tar.gz"
	// Бэкап в /opt/azpanel/backup — настоящий tar.gz.
	src := filepath.Join(e.work, "src")
	os.MkdirAll(src, 0o755)
	e.write(filepath.Join(src, "c"), "cfg")
	if out, err := exec.Command("tar", "-czf", filepath.Join(e.keep, name), "-C", src, "c").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v %s", err, out)
	}
	setup := filepath.Join(e.work, "setup.sh")
	e.write(setup, "#!/bin/bash\nread -r a; read -r b; read -r c\nls \""+e.rootDir+"\"/backup-azpanel-*.tar.gz\necho 'installed successfully'\n")
	argv := e.u.setupArgv(azRetryScript, "azretry", filepath.Join(e.rootDir, name), filepath.Join(e.keep, name), setup, e.answers())
	out, code := e.run(argv, 20*time.Second)
	if code != 0 || !strings.Contains(out, name) || !strings.Contains(out, "installed successfully") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if c := e.calls(); c != "" {
		t.Fatalf("повтор вызвал client.sh: %q", c)
	}
	// Без бэкапа (или с битым) повтор не стартует.
	os.WriteFile(filepath.Join(e.keep, name), []byte("не tar"), 0o600)
	if _, code := e.run(argv, 20*time.Second); code == 0 {
		t.Fatal("повтор с битым бэкапом выполнен")
	}
}

func TestAZRestoreScriptRunsInSh(t *testing.T) {
	e := newScriptEnv(t)
	e.clientSh()
	name := "backup-azpanel-2026-11-02-101500.tar.gz"
	keepCopy := filepath.Join(e.keep, name)
	e.write(keepCopy, "tgz")
	e.write(filepath.Join(e.rootDir, "backup-azpanel-2026-10-01-000000.tar.gz"), "old")
	out, code := e.run([]string{"/bin/sh", "-c", azRestoreScript, "azrestore", keepCopy, e.rootDir, e.dir}, 20*time.Second)
	if code != 0 || !strings.Contains(out, "restored from backup") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if b, err := os.ReadFile(filepath.Join(e.rootDir, name)); err != nil || string(b) != "tgz" {
		t.Fatalf("бэкап не скопирован в /root: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(e.rootDir, "backup-azpanel-2026-10-01-000000.tar.gz")); err == nil {
		t.Error("старая копия осталась")
	}
	if !strings.Contains(e.calls(), "client.sh 9") {
		t.Errorf("client.sh 9 не вызван: %q", e.calls())
	}
	// Нет бэкапа — client.sh 9 не вызывается.
	os.Remove(keepCopy)
	os.Remove(filepath.Join(e.work, "calls"))
	if _, code := e.run([]string{"/bin/sh", "-c", azRestoreScript, "azrestore", keepCopy, e.rootDir, e.dir}, 20*time.Second); code == 0 || e.calls() != "" {
		t.Fatal("без бэкапа восстановление выполнено")
	}
}
