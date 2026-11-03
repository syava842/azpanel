package node

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const (
	azHead    = "2d2d298057ced91fa4b8cc587288b1527703c451"
	azOldMain = "1111111111111111111111111111111111111111" // старый коммит main (compare: behind)
	azForkSHA = "2222222222222222222222222222222222222222" // коммит из форка (compare: diverged)
)

// azSetupMap — setup сервера со всеми ключами, которые спрашивает setup.sh.
func azSetupMap() map[string]string {
	return map[string]string{
		"SETUP_DATE": "2026-10-01T10:00:00+03:00", "MTU": "1380", "WARP_MTU": "1300",
		"OPENVPN_UDP_ENABLE": "y", "OPENVPN_TCP_ENABLE": "n", "WIREGUARD_ENABLE": "y",
		"OPENVPN_PATCH": "2", "OPENVPN_DCO": "y", "ANTIZAPRET_WARP": "4", "VPN_WARP": "2",
		"WARP_PROTECTION": "y", "ANTIZAPRET_DNS": "1", "VPN_DNS": "1", "DNS_WARP": "n",
		"ANTIZAPRET_ADBLOCK": "y", "VPN_ADBLOCK": "n", "ALTERNATIVE_CLIENT_IP": "n",
		"ALTERNATIVE_FAKE_IP": "y", "OPENVPN_BACKUP_UDP": "y", "OPENVPN_BACKUP_TCP": "n",
		"WIREGUARD_BACKUP": "y", "OPENVPN_DUPLICATE": "y", "OPENVPN_LOG": "n",
		"SSH_PROTECTION": "y", "ATTACK_PROTECTION": "y", "SCAN_PROTECTION": "y",
		"TORRENT_GUARD": "y", "RESTRICT_FORWARD": "y", "CLIENT_ISOLATION": "y",
		"OPENVPN_HOST": "vpn.example.com", "WIREGUARD_HOST": "",
		"ROUTE_ALL": "n", "CLOUDFLARE_INCLUDE": "y", "TELEGRAM_INCLUDE": "y", "WHATSAPP_INCLUDE": "y",
		"ANTIZAPRET_WARP_PRIVATE_KEY": "SECRETKEY", "RECONNECT_WARP": "y", "TXQUEUELEN": "5000",
	}
}

func writeSetupMap(t *testing.T, path string, m map[string]string) {
	t.Helper()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + m[k] + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o640); err != nil {
		t.Fatal(err)
	}
}

// azExec — подмена systemd-run: пишет вызовы, «выполняет» задачу сразу (или
// после hold) и дописывает в её журнал заданный вывод.
type azExec struct {
	mu     sync.Mutex
	calls  [][]string
	hold   chan struct{} // не nil: задача azupdate ждёт закрытия
	codes  map[string]int
	output map[string]string
}

func (x *azExec) exec(_ context.Context, name string, args ...string) (int, []byte, error) {
	x.mu.Lock()
	x.calls = append(x.calls, append([]string{name}, args...))
	hold := x.hold
	x.mu.Unlock()
	kind := ""
	for _, a := range args {
		switch a {
		case "azupdate", "azrestore", "azretry":
			kind = a
		case "resync":
			kind = "resync"
		}
	}
	if (kind == "azupdate" || kind == "azretry") && hold != nil {
		<-hold
	}
	for _, a := range args {
		if p, ok := strings.CutPrefix(a, "--property=StandardOutput=append:"); ok {
			appendLog(p, x.output[kind])
		}
	}
	return x.codes[kind], nil, nil
}

func (x *azExec) callsFor(kind string) [][]string {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out [][]string
	for _, c := range x.calls {
		for _, a := range c {
			if a == kind {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

type azEnv struct {
	t       *testing.T
	u       *AZUpdater
	ex      *azExec
	root    string
	dir     string // каталог AntiZapret
	rootDir string // «/root»
	data    string
	backup  string
	pki     string
	boot    time.Time
	svcMu   sync.Mutex
	svcs    []sysinfo.Service
	exists  map[string]bool
	reboots atomic.Int32
	cancel  context.CancelFunc
	gh      *httptest.Server
}

func azServices(active ...string) []sysinfo.Service {
	all := []string{"openvpn-server@antizapret-udp", "openvpn-server@vpn-udp", "openvpn-server@antizapret-tcp", "openvpn-server@vpn-tcp", "kresd@1", "kresd@2", "wg-quick@antizapret", "wg-quick@vpn", "azpanel-node"}
	on := map[string]bool{}
	for _, a := range active {
		on[a] = true
	}
	var out []sysinfo.Service
	for _, s := range all {
		st := "inactive"
		if on[s] {
			st = "active"
		}
		out = append(out, sysinfo.Service{Unit: s, State: st})
	}
	return out
}

func (e *azEnv) setServices(s []sysinfo.Service) {
	e.svcMu.Lock()
	e.svcs = s
	e.svcMu.Unlock()
}

var azHealthy = []string{"openvpn-server@antizapret-udp", "openvpn-server@vpn-udp", "kresd@1", "kresd@2", "wg-quick@antizapret", "wg-quick@vpn", "azpanel-node"}

// newAZ собирает обновлятель с подставными системными вызовами.
func newAZ(t *testing.T) *azEnv {
	t.Helper()
	root := t.TempDir()
	e := &azEnv{t: t, root: root, exists: map[string]bool{}, boot: time.Now().Add(-48 * time.Hour)}
	e.dir = filepath.Join(root, "root", "antizapret")
	e.rootDir = filepath.Join(root, "root")
	e.data = filepath.Join(root, "data")
	e.backup = filepath.Join(root, "backup")
	e.pki = filepath.Join(root, "pki")
	for _, d := range []string{e.dir, e.data, e.backup, filepath.Join(e.pki, "issued"), filepath.Join(root, "wg")} {
		os.MkdirAll(d, 0o755)
	}
	writeSetupMap(t, filepath.Join(e.dir, "setup"), azSetupMap())
	for _, n := range antizapret.VersionScripts {
		os.WriteFile(filepath.Join(e.dir, n), []byte("#!/bin/bash\n# "+n+"\n"), 0o755)
	}
	for _, c := range []string{"alice", "bob"} {
		os.WriteFile(filepath.Join(e.pki, "issued", c+".crt"), []byte("не PEM"), 0o644)
	}
	e.svcs = azServices(azHealthy...)

	e.ex = &azExec{codes: map[string]int{}, output: map[string]string{
		"azupdate":  "== setup.sh ==\nAntiZapret VPN + full VPN installed successfully!\n",
		"azretry":   "== setup.sh ==\nInstallation, please wait...\nAntiZapret VPN + full VPN installed successfully!\n",
		"azrestore": "Configuration and clients restored from backup\n",
	}}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	t.Cleanup(cancel)
	tasks := &Tasks{
		Dir: e.dir, LogDir: filepath.Join(root, "log", "tasks"), StatePath: filepath.Join(e.data, "tasks.json"),
		Exec: e.ex.exec, Now: time.Now, PollEvery: 5 * time.Millisecond, Ctx: ctx,
		Active: func(context.Context, string) (bool, error) { return false, nil },
		Result: func(context.Context, string) string { return "" },
	}

	// Поддельный GitHub: коммиты и содержимое каталога скриптов (хеши — локальные).
	hashes, _ := antizapret.LocalScriptHashes(e.dir)
	e.gh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits"):
			json.NewEncoder(w).Encode([]map[string]any{{"sha": azHead, "commit": map[string]any{"message": "Update parse.sh", "committer": map[string]any{"date": "2026-11-02T07:30:30Z"}}}})
		case strings.Contains(r.URL.Path, "/compare/"+azOldMain+"..."):
			json.NewEncoder(w).Encode(map[string]string{"status": "behind"})
		case strings.Contains(r.URL.Path, "/compare/"+azForkSHA+"..."):
			json.NewEncoder(w).Encode(map[string]string{"status": "diverged"})
		case strings.Contains(r.URL.Path, "/contents/"):
			var out []map[string]any
			for n, h := range hashes {
				out = append(out, map[string]any{"name": n, "sha": h, "type": "file"})
			}
			json.NewEncoder(w).Encode(out)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(e.gh.Close)
	gh := &antizapret.GitHub{BaseURL: e.gh.URL}

	e.u = &AZUpdater{
		Tasks: tasks, GitHub: gh,
		Record: antizapret.InstalledFile{Path: filepath.Join(e.data, "antizapret.json")},
		Dir:    e.dir, RootDir: e.rootDir, DataDir: e.data, BackupDir: e.backup,
		Inventory:  antizapret.Inventory{PKI: e.pki, WireGuardDir: filepath.Join(root, "wg")},
		EnsureHook: func() (bool, error) { return false, nil },
		Services: func(context.Context) ([]sysinfo.Service, error) {
			e.svcMu.Lock()
			defer e.svcMu.Unlock()
			return append([]sysinfo.Service(nil), e.svcs...), nil
		},
		Free:   func(string) (uint64, error) { return 10 << 30, nil },
		Procs:  func() ([]string, error) { return []string{"bash", "azpanel"}, nil },
		Exists: func(p string) bool { return e.exists[p] },
		Download: func(_ context.Context, sha, dest string) error {
			// Настоящий setup.sh из testdata: после скачивания агент сверяет его вопросы с таблицей.
			data, err := os.ReadFile(filepath.Join("..", "antizapret", "testdata", "setup.sh"))
			if err != nil {
				return err
			}
			return os.WriteFile(dest, append(data, []byte("\n# commit "+sha+"\n")...), 0o700)
		},
		BootTime:    func() (time.Time, error) { return e.boot, nil },
		Reboot:      func(context.Context) error { e.reboots.Add(1); return nil },
		Exec:        func(context.Context, string, ...string) ([]byte, error) { return []byte("active\n"), nil },
		RebootGrace: 40 * time.Millisecond, VerifyWait: 300 * time.Millisecond, VerifyEvery: 10 * time.Millisecond, PollEvery: 5 * time.Millisecond,
		Version: nil,
	}
	e.u.Version = &antizapret.VersionService{GitHub: gh, Dir: e.dir, Record: e.u.Record}
	return e
}

// reboot имитирует перезагрузку: новый экземпляр агента с теми же файлами и
// временем загрузки после начала обновления.
func (e *azEnv) reboot() *AZUpdater {
	e.t.Helper()
	e.cancel() // «старый» агент остановлен
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.t.Cleanup(cancel)
	st := e.u.State()
	tasks := &Tasks{
		Dir: e.dir, LogDir: e.u.Tasks.LogDir, StatePath: e.u.Tasks.StatePath,
		Exec: e.ex.exec, Now: time.Now, PollEvery: 5 * time.Millisecond, Ctx: ctx,
		Active: func(context.Context, string) (bool, error) { return false, nil },
		Result: func(context.Context, string) string { return "" },
	}
	if err := tasks.Load(); err != nil {
		e.t.Fatal(err)
	}
	n := e.u.cloneConfig()
	n.Tasks = tasks
	n.BootTime = func() (time.Time, error) { return st.Started.Add(time.Hour), nil }
	e.u = n
	if err := e.u.Load(); err != nil {
		e.t.Fatal(err)
	}
	return e.u
}

func (e *azEnv) waitStatus(want string) nodeapi.AZUpdateState {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := e.u.State(); st.Status == want {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("итог не стал %q: %+v", want, e.u.State())
	return nodeapi.AZUpdateState{}
}

func (e *azEnv) waitPhase(want string) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e.u.State().Phase == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("этап не стал %q: %+v", want, e.u.State())
}

// startAndReboot запускает обновление, ждёт «reboot» и поднимает новый агент.
func (e *azEnv) startAndReboot() nodeapi.AZUpdateState {
	e.t.Helper()
	e.ex.hold = make(chan struct{})
	st, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{})
	if err != nil {
		e.t.Fatal(err)
	}
	// Сервер ушёл в перезагрузку, пока юнит работал: итога задачи нет вовсе.
	e.reboot()
	close(e.ex.hold)
	e.u.Resume()
	return st
}

func TestAZPreflightEachReason(t *testing.T) {
	cases := map[string]struct {
		mutate func(e *azEnv)
		want   string
	}{
		"мало места на /": {func(e *azEnv) {
			e.u.Free = func(p string) (uint64, error) {
				if p == "/" {
					return 1 << 30, nil
				}
				return 10 << 30, nil
			}
		}, "на / свободно 1.0 ГБ"},
		"мало места на /root": {func(e *azEnv) {
			e.u.Free = func(p string) (uint64, error) {
				if p == e.rootDir {
					return 100 << 20, nil
				}
				return 10 << 30, nil
			}
		}, "свободно 0.1 ГБ"},
		"нужна перезагрузка": {func(e *azEnv) { e.exists["/var/run/reboot-required"] = true }, "reboot-required"},
		"apt":                {func(e *azEnv) { e.u.Procs = func() ([]string, error) { return []string{"apt"}, nil } }, "работает apt"},
		"apt-get":            {func(e *azEnv) { e.u.Procs = func() ([]string, error) { return []string{"apt-get"}, nil } }, "работает apt-get"},
		"dpkg":               {func(e *azEnv) { e.u.Procs = func() ([]string, error) { return []string{"dpkg"}, nil } }, "работает dpkg"},
		"unattended-upgrade": {func(e *azEnv) {
			e.u.Procs = func() ([]string, error) { return []string{"unattended-upgrade-shutdown", "unattended-upgrade"}, nil }
		}, "работает unattended-upgrade —"},
		"чужой бэкап": {func(e *azEnv) {
			os.WriteFile(filepath.Join(e.rootDir, "backup-old.tar.gz"), []byte("x"), 0o600)
		}, "чужие backup*.tar.gz (backup-old.tar.gz)"},
		"значение, которое setup.sh не примет": {func(e *azEnv) {
			m := azSetupMap()
			m["OPENVPN_PATCH"] = "9"
			writeSetupMap(t, filepath.Join(e.dir, "setup"), m)
		}, "OPENVPN_PATCH"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newAZ(t)
			c.mutate(e)
			p := e.u.Preflight()
			if p.OK || !strings.Contains(strings.Join(p.Reasons, "|"), c.want) {
				t.Fatalf("ожидалась причина %q: %+v", c.want, p)
			}
			_, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{})
			var pre *PreflightError
			if !errors.As(err, &pre) {
				t.Fatalf("Start должен отказать: %v", err)
			}
			if len(e.ex.callsFor("azupdate")) != 0 {
				t.Fatal("задача запущена несмотря на отказ")
			}
			if e.u.Active() {
				t.Fatal("после отказа состояние не должно быть «идёт»")
			}
		})
	}
	e := newAZ(t)
	os.WriteFile(filepath.Join(e.rootDir, "backup-azpanel-2026-10-01-000000.tar.gz"), []byte("x"), 0o600)
	if p := e.u.Preflight(); !p.OK {
		t.Fatalf("свои старые бэкапы не должны мешать: %+v", p)
	}
}

func TestAZStartBuildsTaskWithEnvAndStdin(t *testing.T) {
	e := newAZ(t)
	e.ex.hold = make(chan struct{})
	defer close(e.ex.hold)
	st, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{Values: map[string]string{"OPENVPN_PATCH": "3"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != nodeapi.AZStatusRunning || st.Phase != nodeapi.AZPhasePrepare || st.Commit != azHead || st.Action != nodeapi.AZActionUpdate {
		t.Fatalf("%+v", st)
	}
	if strings.Join(st.Clients, ",") != "alice,bob" || !strings.HasPrefix(st.Backup, "backup-azpanel-") || st.Started.IsZero() || st.TaskID == "" {
		t.Fatalf("состояние: %+v", st)
	}
	var call []string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && call == nil {
		if c := e.ex.callsFor("azupdate"); len(c) > 0 {
			call = c[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	if call == nil {
		t.Fatal("systemd-run не вызван")
	}
	joined := strings.Join(call, "\n")
	for _, want := range []string{
		"RuntimeMaxSec=7200",
		filepath.Join(e.data, "azupdate", "stdin"), // файл ответов — позиционный аргумент, не StandardInput
		"--setenv=OPENVPN_PATCH=3", "--setenv=WARP_MTU=1300", "--setenv=OPENVPN_UDP_ENABLE=y", "--setenv=HOME=/root",
		filepath.Join(e.data, "azupdate", "setup.sh"),
		filepath.Join(e.rootDir, st.Backup), filepath.Join(e.backup, st.Backup),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("в вызове systemd-run нет %q:\n%s", want, joined)
		}
	}
	for _, bad := range []string{"SETUP_DATE", "SECRETKEY", "PRIVATE_KEY", "--setenv=MTU", "--setenv=OPENVPN_HOST", "--setenv=TXQUEUELEN"} {
		if strings.Contains(joined, bad) {
			t.Errorf("в вызове systemd-run лишнее %q", bad)
		}
	}
	in, err := os.ReadFile(filepath.Join(e.data, "azupdate", "stdin"))
	if err != nil || string(in) != "1380\nvpn.example.com\n\n" {
		t.Fatalf("ввод setup.sh: %q %v", in, err)
	}
	setupSh, _ := os.ReadFile(filepath.Join(e.data, "azupdate", "setup.sh"))
	if !strings.Contains(string(setupSh), azHead) {
		t.Fatalf("setup.sh не из архива коммита: %q", setupSh)
	}
	// azupdate.json: коммит, время, бэкап, клиенты.
	raw, err := os.ReadFile(filepath.Join(e.data, "azupdate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	json.Unmarshal(raw, &f)
	if f["commit"] != azHead || f["backup"] != st.Backup || f["started"] == nil || len(f["clients"].([]any)) != 2 || f["status"] != "running" {
		t.Fatalf("azupdate.json: %s", raw)
	}
	// Скрипт задачи: сначала client.sh 8, затем setup.sh; положение копий.
	if !strings.Contains(azUpdateScript, `"$dir/client.sh" 8 </dev/null`) || !strings.Contains(azUpdateScript, `/bin/bash "$setup" < "$fifo"`) {
		t.Fatal("скрипт обновления не делает client.sh 8 и setup.sh")
	}
	// Пока идёт, вторую задачу и второе обновление не принимает.
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err == nil {
		t.Fatal("второе обновление принято")
	} else {
		var pre *PreflightError
		if !errors.As(err, &pre) || !pre.Busy {
			t.Fatalf("ожидалось «уже идёт»: %v", err)
		}
	}
}

func TestAZStartRefusals(t *testing.T) {
	e := newAZ(t)
	e.ex.hold = make(chan struct{})
	if _, err := e.u.Tasks.Start(TaskDoall, []string{"doall.sh"}); err != nil {
		t.Fatal(err)
	}
	_, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{})
	var busy *BusyError
	if !errors.As(err, &busy) {
		t.Fatalf("при идущей задаче нужна BusyError: %v", err)
	}
	close(e.ex.hold)

	e = newAZ(t)
	var pre *PreflightError
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{Commit: "не sha"}); !errors.As(err, &pre) || !pre.BadRequest {
		t.Fatalf("кривой коммит: %v", err)
	}
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{Values: map[string]string{"TXQUEUELEN": "1"}}); err == nil {
		t.Fatal("ключ, которого setup.sh не спрашивает, принят")
	}
	e.u.Download = func(context.Context, string, string) error { return errors.New("нет сети") }
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err == nil || !strings.Contains(err.Error(), "нет сети") {
		t.Fatalf("сбой загрузки: %v", err)
	}
	if e.u.Active() {
		t.Fatal("после отказа состояние «идёт»")
	}
}

// Главный путь: обновление, перезагрузка, новый экземпляр агента считает итог.
func TestAZAfterRebootOK(t *testing.T) {
	e := newAZ(t)
	e.exists[e.u.warperVersion()] = true
	e.exists[e.u.telemtBin()] = true
	e.exists[e.u.telemtConfig()] = true
	hooks := 0
	e.u.EnsureHook = func() (bool, error) { hooks++; return true, nil }
	st := e.startAndReboot()

	got := e.waitStatus(nodeapi.AZStatusOK)
	if len(got.Reasons) != 0 || got.Commit != azHead || got.Finished == nil {
		t.Fatalf("итог: %+v", got)
	}
	if hooks == 0 {
		t.Fatal("хук не поставлен после загрузки")
	}
	if got.Extras["warper"] != "resync выполнен" || got.Extras["telemt"] != "active" {
		t.Fatalf("сопутствующие службы: %+v", got.Extras)
	}
	if len(e.ex.callsFor("resync")) != 1 {
		t.Fatalf("warper resync не запущен: %v", e.ex.callsFor("resync"))
	}
	if len(got.Services) == 0 {
		t.Fatal("в итоге нет состояния служб")
	}
	rec, _ := e.u.Record.Read()
	if rec.Commit != azHead {
		t.Fatalf("коммит не записан в antizapret.json: %+v", rec)
	}
	// Итог пережил ещё один запуск агента и не пересчитывается.
	e.reboot()
	e.u.Resume()
	if again := e.u.State(); again.Status != nodeapi.AZStatusOK || again.TaskID != st.TaskID {
		t.Fatalf("после повторного запуска: %+v", again)
	}
	if e.u.Active() {
		t.Fatal("после итога состояние «идёт»")
	}
}

func TestAZMissingClientIsFailure(t *testing.T) {
	e := newAZ(t)
	e.ex.hold = make(chan struct{})
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	// «Во время установки» клиент bob пропал.
	os.Remove(filepath.Join(e.pki, "issued", "bob.crt"))
	e.reboot()
	close(e.ex.hold)
	e.u.Resume()
	got := e.waitStatus(nodeapi.AZStatusFailed)
	if !strings.Contains(strings.Join(got.Reasons, "|"), "пропали клиенты: bob") {
		t.Fatalf("причины: %v", got.Reasons)
	}
	rec, _ := e.u.Record.Read()
	if rec.Commit != "" {
		t.Fatal("при провале коммит записывать нельзя")
	}
}

func TestAZServicesChecked(t *testing.T) {
	setup := azSetupMap()
	healthy := azServices(azHealthy...)
	if r := badServices(setup, healthy); len(r) != 0 {
		t.Fatalf("здоровая система: %v", r)
	}
	// TCP отключён — его юниты неактивны и это нормально; UDP упал — это провал.
	down := azServices("openvpn-server@vpn-udp", "kresd@1", "kresd@2", "wg-quick@antizapret", "wg-quick@vpn")
	if r := badServices(setup, down); len(r) != 1 || !strings.Contains(r[0], "openvpn-server@antizapret-udp") {
		t.Fatalf("упал antizapret-udp: %v", r)
	}
	// kresd и WireGuard.
	if r := badServices(setup, azServices("openvpn-server@antizapret-udp", "openvpn-server@vpn-udp", "kresd@1")); len(r) != 3 {
		t.Fatalf("kresd@2 и два wg-quick: %v", r)
	}
	setup["WIREGUARD_ENABLE"] = "n"
	setup["OPENVPN_TCP_ENABLE"] = "y"
	r := badServices(setup, azServices("openvpn-server@antizapret-udp", "openvpn-server@vpn-udp", "kresd@1", "kresd@2"))
	if len(r) != 2 {
		t.Fatalf("WG выключен, TCP включён: %v", r)
	}
	if r := badServices(setup, []sysinfo.Service{{Unit: "openvpn-server@antizapret-udp", State: "active"}}); len(r) != 1 || !strings.Contains(r[0], "kresd") {
		t.Fatalf("без kresd: %v", r)
	}
}

func TestAZServicesWaitedFor(t *testing.T) {
	e := newAZ(t)
	e.setServices(azServices("azpanel-node")) // сразу после загрузки ничего не поднялось
	go func() {
		time.Sleep(60 * time.Millisecond)
		e.setServices(azServices(azHealthy...))
	}()
	e.startAndReboot()
	e.waitStatus(nodeapi.AZStatusOK) // дождался, пока службы поднимутся
}

func TestAZServiceDownFailsAfterWait(t *testing.T) {
	e := newAZ(t)
	e.setServices(azServices("kresd@1", "kresd@2", "wg-quick@antizapret", "wg-quick@vpn"))
	st := e.startAndReboot()
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600) // его кладёт скрипт задачи
	got := e.waitStatus(nodeapi.AZStatusFailed)
	if !strings.Contains(strings.Join(got.Reasons, "|"), "openvpn-server@antizapret-udp: inactive") || len(got.Services) == 0 {
		t.Fatalf("%+v", got)
	}
	if !got.CanRestore {
		t.Fatal("после провала должна быть доступна кнопка восстановления: бэкап есть")
	}
}

// Сервер перезагрузился раньше, чем setup.sh дошёл до конца: по журналу видно.
func TestAZSetupShNotFinishedIsFailure(t *testing.T) {
	e := newAZ(t)
	e.ex.output["azupdate"] = "== setup.sh ==\nInstallation, please wait...\n"
	e.startAndReboot()
	// Строка «Installation, please wait...» есть, «installed successfully» нет:
	// службы остановлены, конфигурация стёрта — это failed_late.
	got := e.waitStatus(nodeapi.AZStatusFailedLate)
	if !strings.Contains(strings.Join(got.Reasons, "|"), "не дошёл до конца") {
		t.Fatalf("%v", got.Reasons)
	}
}

// Сервер перезагрузился, а в журнале нет даже начала установки: ничего не тронуто.
func TestAZSetupShRebootBeforeInstallIsPlainFailure(t *testing.T) {
	e := newAZ(t)
	e.ex.output["azupdate"] = "== setup.sh ==\n"
	e.startAndReboot()
	got := e.waitStatus(nodeapi.AZStatusFailed)
	os.WriteFile(filepath.Join(e.backup, got.Backup), []byte("tgz"), 0o600)
	if st := e.u.State(); st.CanRestore || st.CanRetry {
		t.Fatalf("установка не начиналась — действий быть не должно: %+v", st)
	}
}

func TestAZTaskFailureWithoutReboot(t *testing.T) {
	e := newAZ(t)
	e.ex.codes["azupdate"] = 8
	e.ex.output["azupdate"] = "Error: Low disk space! You need 2GB of free space!\n"
	// Бэкап «сделан» скриптом: файл в каталоге бэкапов.
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	st := e.waitStatus(nodeapi.AZStatusFailed)
	if !strings.Contains(strings.Join(st.Reasons, "|"), "завершилась с кодом 8") || !strings.Contains(strings.Join(st.Reasons, "|"), "Low disk space") {
		t.Fatalf("%v", st.Reasons)
	}
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)
	// Отказ проверок setup.sh (код 8) до остановки служб: ничего не тронуто,
	// «восстановить» перезагрузило бы рабочий сервер без нужды.
	if s := e.u.State(); s.CanRestore || s.CanRetry {
		t.Fatalf("ранний отказ не должен предлагать восстановление и повтор: %+v", s)
	}
	if e.u.Active() {
		t.Fatal("после провала состояние «идёт»")
	}
}

func TestAZRebootFallbackWhenScriptDidNotReboot(t *testing.T) {
	e := newAZ(t)
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	// Задача завершилась с 0, а сервер всё ещё работает: агент перезагружает сам.
	e.waitPhase(nodeapi.AZPhaseReboot)
	deadline := time.Now().Add(2 * time.Second)
	for e.reboots.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.reboots.Load() != 1 {
		t.Fatalf("перезагрузок: %d", e.reboots.Load())
	}
	got := e.waitStatus(nodeapi.AZStatusFailed)
	if !strings.Contains(strings.Join(got.Reasons, "|"), "не перезагрузился") {
		t.Fatalf("%v", got.Reasons)
	}
}

func TestAZResumeWhileTaskStillRunning(t *testing.T) {
	e := newAZ(t)
	e.ex.hold = make(chan struct{})
	st, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// Агент перезапустился, перезагрузки не было (BootTime до начала): ждёт задачу.
	n := e.u.cloneConfig()
	n.BootTime = func() (time.Time, error) { return st.Started.Add(-time.Hour), nil }
	if err := n.Load(); err != nil {
		t.Fatal(err)
	}
	if !n.Active() {
		t.Fatal("состояние «идёт» не прочитано")
	}
	n.Resume()
	close(e.ex.hold)
	// Старый экземпляр в этом тесте продолжает смотреть за задачей и дойдёт до
	// ожидания перезагрузки; нас интересует, что Resume не считает итог рано.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n.State().Phase == nodeapi.AZPhaseReboot {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := n.State(); got.Status == nodeapi.AZStatusOK {
		t.Fatalf("итог посчитан без перезагрузки: %+v", got)
	}
}

func TestAZResetKeysWarning(t *testing.T) {
	e := newAZ(t)
	e.ex.hold = make(chan struct{})
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{Values: map[string]string{"CLIENT_ISOLATION": "n"}}); err != nil {
		t.Fatal(err)
	}
	// setup.sh после установки: RECONNECT_WARP сброшен в n, TXQUEUELEN — в 10000,
	// CLIENT_ISOLATION изменён по просьбе, остальное — как было.
	m := azSetupMap()
	m["RECONNECT_WARP"], m["TXQUEUELEN"], m["CLIENT_ISOLATION"] = "n", "10000", "n"
	writeSetupMap(t, filepath.Join(e.dir, "setup"), m)
	e.reboot()
	close(e.ex.hold)
	e.u.Resume()
	got := e.waitStatus(nodeapi.AZStatusOK)
	all := strings.Join(got.Warnings, "|")
	if !strings.Contains(all, "RECONNECT_WARP") || !strings.Contains(all, "TXQUEUELEN") || strings.Contains(all, "CLIENT_ISOLATION") {
		t.Fatalf("замечания: %v", got.Warnings)
	}
}

func TestAZDownloadAndExtract(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	add("AntiZapret-VPN-"+azHead+"/README.md", "readme")
	add("AntiZapret-VPN-"+azHead+"/setup/setup.sh", "не тот файл")
	add("AntiZapret-VPN-"+azHead+"/setup.sh", "#!/bin/bash\necho настоящий\n")
	tw.Close()
	gz.Close()
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		w.Write(buf.Bytes())
	}))
	defer srv.Close()
	u := &AZUpdater{ArchiveBase: srv.URL}
	dest := filepath.Join(t.TempDir(), "setup.sh")
	if err := u.downloadSetupSh(context.Background(), azHead, dest); err != nil {
		t.Fatal(err)
	}
	if asked != "/GubernievS/AntiZapret-VPN/archive/"+azHead+".tar.gz" {
		t.Fatalf("запрошено %q", asked)
	}
	data, _ := os.ReadFile(dest)
	if !strings.Contains(string(data), "настоящий") {
		t.Fatalf("setup.sh: %q", data)
	}
	if err := u.downloadSetupSh(context.Background(), "../../etc", dest); err == nil {
		t.Fatal("кривой коммит принят")
	}
	if err := extractSetupSh(strings.NewReader("не gzip"), dest); err == nil {
		t.Fatal("мусор принят")
	}
	// Архив без setup.sh.
	buf.Reset()
	gz = gzip.NewWriter(&buf)
	tw = tar.NewWriter(gz)
	add("root/README.md", "x")
	tw.Close()
	gz.Close()
	if err := extractSetupSh(&buf, dest); err == nil || !strings.Contains(err.Error(), "нет setup.sh") {
		t.Fatalf("архив без setup.sh: %v", err)
	}
	// 404.
	srv404 := httptest.NewServer(http.NotFoundHandler())
	defer srv404.Close()
	u.ArchiveBase = srv404.URL
	if err := u.downloadSetupSh(context.Background(), azHead, dest); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
}

func TestAZRestoreFlow(t *testing.T) {
	e := newAZ(t)
	name := "backup-azpanel-2026-11-02-101500.tar.gz"
	os.WriteFile(filepath.Join(e.backup, name), []byte("tgz"), 0o600)

	for _, bad := range []string{"", "../etc/passwd", "backup-azpanel-x.tar.gz", "backup-azpanel-2026-11-02-999999.tar.gz"} {
		if _, err := e.u.Restore(context.Background(), bad); err == nil {
			t.Errorf("бэкап %q принят", bad)
		}
	}
	os.WriteFile(filepath.Join(e.rootDir, "backup-чужой.tar.gz"), []byte("x"), 0o600)
	if _, err := e.u.Restore(context.Background(), name); err == nil {
		t.Fatal("с чужим backup*.tar.gz в /root восстановление должно отказать")
	}
	os.Remove(filepath.Join(e.rootDir, "backup-чужой.tar.gz"))

	e.ex.hold = make(chan struct{})
	st, err := e.u.Restore(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	if st.Action != nodeapi.AZActionRestore || st.Status != nodeapi.AZStatusRunning || st.Backup != name {
		t.Fatalf("%+v", st)
	}
	deadline := time.Now().Add(2 * time.Second)
	var call []string
	for time.Now().Before(deadline) && call == nil {
		if c := e.ex.callsFor("azrestore"); len(c) > 0 {
			call = c[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	joined := strings.Join(call, "\n")
	if !strings.Contains(joined, "RuntimeMaxSec=3600") || !strings.Contains(joined, filepath.Join(e.backup, name)) {
		t.Fatalf("вызов: %s", joined)
	}
	if !strings.Contains(azRestoreScript, `exec "$dir/client.sh" 9`) {
		t.Fatal("скрипт не вызывает client.sh 9")
	}
	e.reboot()
	e.u.Resume()
	got := e.waitStatus(nodeapi.AZStatusOK)
	if got.Action != nodeapi.AZActionRestore {
		t.Fatalf("%+v", got)
	}
	rec, _ := e.u.Record.Read()
	if rec.Commit != "" {
		t.Fatal("восстановление не должно записывать версию")
	}
	close(e.ex.hold)
}

func TestAZBackupsPrunedAndListed(t *testing.T) {
	e := newAZ(t)
	for i := 1; i <= 7; i++ {
		os.WriteFile(filepath.Join(e.backup, fmt.Sprintf("backup-azpanel-2026-10-0%d-120000.tar.gz", i)), []byte("x"), 0o600)
	}
	os.WriteFile(filepath.Join(e.backup, "other.tar.gz"), []byte("x"), 0o600)
	if l := e.u.ListBackups(); len(l) != 7 || l[0].Name != "backup-azpanel-2026-10-07-120000.tar.gz" {
		t.Fatalf("%+v", l)
	}
	e.u.pruneBackups()
	l := e.u.ListBackups()
	if len(l) != azKeepBackups || l[len(l)-1].Name != "backup-azpanel-2026-10-03-120000.tar.gz" {
		t.Fatalf("после очистки: %+v", l)
	}
	if _, err := os.Stat(filepath.Join(e.backup, "other.tar.gz")); err != nil {
		t.Fatal("чужой файл удалён")
	}
}

func TestAZScriptsShape(t *testing.T) {
	// Обёртка задач передаёт скрипт и аргументы позиционно: ничего не вставляется в текст.
	for _, s := range []string{azUpdateScript, azRestoreScript} {
		if strings.Contains(s, "%s") || strings.Contains(s, "${") && !strings.Contains(s, "$(") {
			t.Fatalf("в тексте скрипта подстановка: %s", s)
		}
	}
	if !strings.HasPrefix(azUpdateScript, "set -e") || !strings.HasPrefix(azRestoreScript, "set -e") {
		t.Fatal("скрипт должен падать на первой ошибке: без этого setup.sh запустился бы после неудавшегося бэкапа")
	}
	i8, iSetup := strings.Index(azUpdateScript, "client.sh\" 8"), strings.Index(azUpdateScript, "/bin/bash")
	if i8 < 0 || iSetup < i8 {
		t.Fatal("бэкап должен идти до setup.sh")
	}
}

// --- API ---

func TestAZAPIEndpointsAndGating(t *testing.T) {
	e := newAPI(t)
	az := newAZ(t)
	e.api.AZ = az.u
	e.api.AZVersion = az.u.Version
	e.api.Tasks = az.u.Tasks
	ctx := context.Background()

	v, err := e.client.AZVersion(ctx)
	if err != nil || v.Latest == nil || v.Latest.SHA != azHead || v.Current == "" || !v.UpToDate {
		t.Fatalf("версия: %+v %v", v, err)
	}
	p, err := e.client.AZPreflight(ctx)
	if err != nil || !p.OK {
		t.Fatalf("проверки: %+v %v", p, err)
	}
	if _, err := e.client.AZRestore(ctx, "backup-azpanel-x"); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("кривой бэкап: %v", err)
	}
	az.ex.hold = make(chan struct{})
	st, err := e.client.AZUpdate(ctx, nodeapi.AZUpdateRequest{})
	if err != nil || st.Status != nodeapi.AZStatusRunning {
		t.Fatalf("запуск: %+v %v", st, err)
	}
	if _, err := e.client.AZUpdate(ctx, nodeapi.AZUpdateRequest{}); status(err) != http.StatusConflict {
		t.Fatalf("второй запуск: %v", err)
	}
	// Пока идёт, клиентов и задачи не принимаются.
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "carol", Kind: nodeapi.KindOpenVPN}); status(err) != http.StatusConflict {
		t.Fatalf("создание клиента во время обновления: %v", err)
	}
	if _, err := e.client.RestartAntiZapret(ctx); status(err) != http.StatusConflict {
		t.Fatalf("перезапуск во время обновления: %v", err)
	}
	if err := azBusy(az.u)(); err == nil {
		t.Fatal("списки и setup во время обновления должны быть закрыты")
	}
	got, err := e.client.AZUpdateState(ctx)
	if err != nil || got.Status != nodeapi.AZStatusRunning || got.TaskID != st.TaskID {
		t.Fatalf("состояние: %+v %v", got, err)
	}
	close(az.ex.hold)
}

// cloneConfig — новый экземпляр с теми же настройками и пустым состоянием:
// «агент после перезапуска».
func (u *AZUpdater) cloneConfig() *AZUpdater {
	return &AZUpdater{
		Tasks: u.Tasks, GitHub: u.GitHub, Version: u.Version, Record: u.Record, Dir: u.Dir, RootDir: u.RootDir,
		DataDir: u.DataDir, BackupDir: u.BackupDir, Inventory: u.Inventory, EnsureHook: u.EnsureHook,
		Services: u.Services, Log: u.Log, Now: u.Now, Free: u.Free, Procs: u.Procs, Exists: u.Exists,
		Download: u.Download, BootTime: u.BootTime, Reboot: u.Reboot, Exec: u.Exec,
		Gate: u.Gate, GuardEvery: u.GuardEvery, GuardTicks: u.GuardTicks,
		ArchiveBase: u.ArchiveBase, HTTP: u.HTTP, WarperVersion: u.WarperVersion, WarperBin: u.WarperBin,
		TelemtBin: u.TelemtBin, TelemtConfig: u.TelemtConfig,
		RebootGrace: u.RebootGrace, VerifyWait: u.VerifyWait, VerifyEvery: u.VerifyEvery, PollEvery: u.PollEvery,
	}
}

// Постоянный unattended-upgrade-shutdown --wait-for-signal не мешает запуску.
func TestAZPreflightIgnoresUnattendedShutdown(t *testing.T) {
	e := newAZ(t)
	e.u.Procs = func() ([]string, error) { return []string{"unattended-upgrade-shutdown", "python3"}, nil }
	if p := e.u.Preflight(); !p.OK {
		t.Fatalf("отказ из-за unattended-upgrade-shutdown: %+v", p)
	}
}

func TestProcNameResolvesTruncatedComm(t *testing.T) {
	for _, c := range []struct {
		comm, cmdline, want string
	}{
		{"unattended-upgr", "/usr/bin/python3\x00/usr/share/unattended-upgrades/unattended-upgrade-shutdown\x00--wait-for-signal\x00", "unattended-upgrade-shutdown"},
		{"unattended-upgr", "/usr/bin/python3\x00/usr/bin/unattended-upgrade\x00", "unattended-upgrade"},
		{"unattended-upgr", "", "unattended-upgr"},
		{"dpkg", "/usr/bin/dpkg-other\x00", "dpkg"},
	} {
		if got := procName(c.comm, []byte(c.cmdline)); got != c.want {
			t.Errorf("procName(%q, %q) = %q, ожидалось %q", c.comm, c.cmdline, got, c.want)
		}
	}
}
