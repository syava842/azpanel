package node

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const (
	azMinFree      = 2 << 30 // свободного места в «/» и «/root» — как требует setup.sh
	azKeepBackups  = 5       // сколько бэкапов обновлений хранится в /opt/azpanel/backup
	azBackupPrefix = "backup-azpanel-"
	azStateName    = "azupdate.json"

	// Строки, по которым в журнале задачи видно, что скрипт дошёл до конца.
	azUpdateDoneMarker  = "installed successfully"
	azRestoreDoneMarker = "restored from backup"
)

var (
	azSHARe        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	azBackupNameRe = regexp.MustCompile(`^backup-azpanel-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}\.tar\.gz$`)
)

// azUpdateScript — задача обновления. Идёт вне песочницы агента (запись в /root
// агенту недоступна). Всё передаётся позиционно:
// $1 каталог AntiZapret, $2 копия в /root, $3 копия в /opt/azpanel/backup,
// $4 setup.sh из архива коммита. Стандартный ввод юнита — файл с ответами
// setup.sh (MTU, адреса серверов), окружение — остальные ответы.
//
// Свои старые /root/backup-azpanel-*.tar.gz (от неудавшегося обновления)
// убираются: их копии лежат в /opt/azpanel/backup, а setup.sh распаковывает
// только один /root/backup*.tar.gz и удаляет все.
const azUpdateScript = `set -e
dir=$1; rootcopy=$2; keepcopy=$3; setup=$4
echo "== бэкап: client.sh 8 =="
"$dir/client.sh" 8
src=$(ls -t "$dir"/backup-*.tar.gz | head -n 1)
[ -s "$src" ]
tar -tzf "$src" >/dev/null
mkdir -p "$(dirname "$keepcopy")"
cp -f "$src" "$keepcopy"
chmod 600 "$keepcopy"
rm -f "$(dirname "$rootcopy")"/backup-azpanel-*.tar.gz
cp -f "$src" "$rootcopy"
chmod 600 "$rootcopy"
echo "== setup.sh =="
exec /bin/bash "$setup"`

// azRestoreScript: $1 бэкап в /opt/azpanel/backup, $2 каталог /root, $3 каталог
// AntiZapret. client.sh 9 сам распаковывает /root/backup*.tar.gz, удаляет его
// и перезагружает сервер.
const azRestoreScript = `set -e
keep=$1; rootdir=$2; dir=$3
[ -s "$keep" ]
rm -f "$rootdir"/backup-azpanel-*.tar.gz
cp -f "$keep" "$rootdir/$(basename "$keep")"
chmod 600 "$rootdir/$(basename "$keep")"
exec "$dir/client.sh" 9`

// PreflightError — проверки перед запуском не пройдены.
type PreflightError struct {
	Reasons []string
	Busy    bool // обновление уже идёт — это 409, а не отказ проверок
}

func (e *PreflightError) Error() string {
	return "обновление не начато: " + antizapret.JoinReasons(e.Reasons)
}

// azFile — содержимое data/azupdate.json: состояние для панели и то, что нужно
// только агенту.
type azFile struct {
	nodeapi.AZUpdateState
	// SetupExpected — значения ключей setup, которые должны быть после установки
	// (без секретов): расхождение — setup.sh сбросил ключ.
	SetupExpected map[string]string `json:"setup_expected,omitempty"`
}

// AZUpdater обновляет AntiZapret: проверки, бэкап, setup.sh задачей, проверка
// после перезагрузки и восстановление из бэкапа. Состояние лежит в
// data/azupdate.json и переживает перезагрузку: итог считается при следующем
// запуске агента (Resume).
type AZUpdater struct {
	Tasks     *Tasks
	GitHub    *antizapret.GitHub
	Version   *antizapret.VersionService // пусто — «с какого коммита» не определяется
	Record    antizapret.InstalledFile
	Dir       string // /root/antizapret
	RootDir   string // /root
	DataDir   string // /opt/azpanel/data
	BackupDir string // /opt/azpanel/backup
	Inventory antizapret.Inventory
	// EnsureHook ставит хук лимита в скрипты OpenVPN (setup.sh стирает /etc/openvpn/server).
	EnsureHook func() (bool, error)
	// Services — состояние служб (sysinfo.Services по найденным юнитам).
	Services func(ctx context.Context) ([]sysinfo.Service, error)
	Log      *slog.Logger
	Now      func() time.Time

	// Подменяются в тестах; nil — настоящие.
	Free     func(path string) (uint64, error)
	Procs    func() ([]string, error)                                               // имена процессов (/proc/*/comm)
	Exists   func(path string) bool                                                 // существует ли путь
	Download func(ctx context.Context, sha, dest string) error                      // кладёт setup.sh коммита в dest
	BootTime func() (time.Time, error)                                              // время загрузки системы
	Reboot   func(ctx context.Context) error                                        // systemctl reboot
	Exec     func(ctx context.Context, name string, args ...string) ([]byte, error) // короткие команды (systemctl is-active)

	// ArchiveBase — откуда качать архив коммита; пусто — https://github.com.
	ArchiveBase string
	HTTP        *http.Client

	// Пути сопутствующих служб.
	WarperVersion string // пусто — /root/warper/version
	WarperBin     string // пусто — warper
	TelemtBin     string // пусто — /usr/local/bin/telemt
	TelemtConfig  string // пусто — /etc/telemt/config.toml

	// Сроки: 0 — умолчания (пять минут на остановку, десять на подъём служб).
	RebootGrace time.Duration
	VerifyWait  time.Duration
	VerifyEvery time.Duration
	PollEvery   time.Duration

	// startMu не пускает два запуска одновременно: сеть и скачивание идут вне mu,
	// чтобы Active и State не ждали GitHub.
	startMu sync.Mutex
	mu      sync.Mutex
	state   azFile
}

func (u *AZUpdater) now() time.Time {
	if u.Now != nil {
		return u.Now().UTC()
	}
	return time.Now().UTC()
}

func (u *AZUpdater) logger() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (u *AZUpdater) ctx() context.Context { return u.Tasks.context() }

func (u *AZUpdater) dur(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

func (u *AZUpdater) statePath() string { return filepath.Join(u.DataDir, azStateName) }

func (u *AZUpdater) workDir() string { return filepath.Join(u.DataDir, "azupdate") }

func (u *AZUpdater) exists(p string) bool {
	if u.Exists != nil {
		return u.Exists(p)
	}
	_, err := os.Stat(p)
	return err == nil
}

// --- состояние ---

// Load читает azupdate.json при старте агента.
func (u *AZUpdater) Load() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	data, err := os.ReadFile(u.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f azFile
	if err := json.Unmarshal(data, &f); err != nil {
		u.logger().Error("azupdate.json испорчен — отложен", "err", err)
		return os.Rename(u.statePath(), u.statePath()+".bad")
	}
	u.state = f
	return nil
}

// saveLocked пишет azupdate.json; сбой записи состояния — повод остановить
// обновление, поэтому ошибка возвращается.
func (u *AZUpdater) saveLocked() error {
	data, err := json.MarshalIndent(u.state, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(u.DataDir, 0o750); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(u.statePath(), data, 0o640)
}

// Active — идёт обновление или восстановление: клиентов, списки и setup в это
// время не правят.
func (u *AZUpdater) Active() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state.Status == nodeapi.AZStatusRunning
}

// State — состояние для панели со списком бэкапов.
func (u *AZUpdater) State() nodeapi.AZUpdateState {
	u.mu.Lock()
	st := u.state.AZUpdateState
	u.mu.Unlock()
	st.Backups = u.ListBackups()
	st.CanRestore = st.Status == nodeapi.AZStatusFailed && st.Backup != "" && u.backupExists(st.Backup)
	return st
}

func (u *AZUpdater) backupExists(name string) bool {
	if !azBackupNameRe.MatchString(name) {
		return false
	}
	_, err := os.Stat(filepath.Join(u.BackupDir, name))
	return err == nil
}

// ListBackups — бэкапы обновлений, новые сверху.
func (u *AZUpdater) ListBackups() []nodeapi.AZBackup {
	entries, err := os.ReadDir(u.BackupDir)
	out := []nodeapi.AZBackup{}
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !azBackupNameRe.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, nodeapi.AZBackup{Name: e.Name(), Bytes: info.Size(), Time: info.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

func (u *AZUpdater) pruneBackups() {
	list := u.ListBackups()
	for i := azKeepBackups; i < len(list); i++ {
		if err := os.Remove(filepath.Join(u.BackupDir, list[i].Name)); err == nil {
			u.logger().Info("старый бэкап обновления удалён", "file", list[i].Name)
		}
	}
}

// --- проверки ---

var aptProcs = []string{"apt", "apt-get", "dpkg"}

// isAptProc: имя из /proc/*/comm обрезано до 15 знаков («unattended-upgr»).
func isAptProc(comm string) bool {
	for _, p := range aptProcs {
		if comm == p {
			return true
		}
	}
	return strings.HasPrefix(comm, "unattended-upgr")
}

func listProcNames() ([]string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue // процесс уже завершился
		}
		out = append(out, strings.TrimSpace(string(b)))
	}
	return out, nil
}

func (u *AZUpdater) freeBytes(p string) (uint64, error) {
	if u.Free != nil {
		return u.Free(p)
	}
	d, err := sysinfo.DiskUsage(p)
	return d.FreeBytes, err
}

// foreignBackups — чужие /root/backup*.tar.gz: setup.sh распакует только
// один из них и удалит все.
func (u *AZUpdater) foreignBackups() []string {
	list, _ := filepath.Glob(filepath.Join(u.RootDir, "backup*.tar.gz"))
	var out []string
	for _, f := range list {
		if !strings.HasPrefix(filepath.Base(f), azBackupPrefix) {
			out = append(out, f)
		}
	}
	return out
}

// preflight — проверки, общие для обновления и восстановления.
func (u *AZUpdater) preflight(needSpace bool) []string {
	var reasons []string
	if needSpace {
		for _, p := range []string{"/", u.RootDir} {
			free, err := u.freeBytes(p)
			switch {
			case err != nil:
				reasons = append(reasons, fmt.Sprintf("место на %s не проверено: %v", p, err))
			case free < azMinFree:
				reasons = append(reasons, fmt.Sprintf("на %s свободно %.1f ГБ, нужно не меньше 2", p, float64(free)/(1<<30)))
			}
		}
		if u.exists("/var/run/reboot-required") {
			reasons = append(reasons, "серверу нужна перезагрузка (есть /var/run/reboot-required) — setup.sh откажется работать")
		}
		procs := u.Procs
		if procs == nil {
			procs = listProcNames
		}
		names, err := procs()
		if err != nil {
			reasons = append(reasons, "список процессов не прочитан: "+err.Error())
		}
		seen := map[string]bool{}
		for _, n := range names {
			if isAptProc(n) && !seen[n] {
				seen[n] = true
				reasons = append(reasons, fmt.Sprintf("работает %s — дождитесь окончания обновления пакетов", n))
			}
		}
	}
	if f := u.foreignBackups(); len(f) > 0 {
		reasons = append(reasons, fmt.Sprintf("в %s лежат чужие backup*.tar.gz (%s): setup.sh и client.sh 9 удалят их — уберите или переименуйте", u.RootDir, strings.Join(baseNames(f), ", ")))
	}
	return reasons
}

func baseNames(list []string) []string {
	out := make([]string, len(list))
	for i, f := range list {
		out[i] = filepath.Base(f)
	}
	return out
}

func (u *AZUpdater) readSetup() (map[string]string, error) {
	return antizapret.ReadSetup(filepath.Join(u.Dir, "setup"))
}

// Preflight — можно ли обновлять сейчас; ничего не запускает.
func (u *AZUpdater) Preflight() nodeapi.AZPreflight {
	res := nodeapi.AZPreflight{Reasons: []string{}}
	if u.Active() {
		res.Reasons = append(res.Reasons, "обновление или восстановление уже идёт")
	}
	if t, ok := u.Tasks.Running(); ok {
		res.Reasons = append(res.Reasons, fmt.Sprintf("идёт задача %s", t.Kind))
	}
	res.Reasons = append(res.Reasons, u.preflight(true)...)
	setup, err := u.readSetup()
	if err != nil {
		res.Reasons = append(res.Reasons, "setup не прочитан: "+err.Error())
	} else {
		plan := antizapret.PlanSetupSh(setup, nil)
		res.Reasons = append(res.Reasons, plan.Problems...)
		res.Notes = plan.Notes
	}
	res.OK = len(res.Reasons) == 0
	return res
}

// --- запуск обновления ---

// Start запускает обновление. Ошибки: *BusyError (идёт задача),
// *PreflightError (проверки не пройдены), прочие — внутренние.
func (u *AZUpdater) Start(ctx context.Context, req nodeapi.AZUpdateRequest) (nodeapi.AZUpdateState, error) {
	u.startMu.Lock()
	defer u.startMu.Unlock()
	if u.Active() {
		return nodeapi.AZUpdateState{}, &PreflightError{Busy: true, Reasons: []string{"обновление или восстановление уже идёт"}}
	}
	if t, ok := u.Tasks.Running(); ok {
		return nodeapi.AZUpdateState{}, &BusyError{Task: t}
	}
	reasons := u.preflight(true)
	setup, err := u.readSetup()
	if err != nil {
		return nodeapi.AZUpdateState{}, &PreflightError{Reasons: append(reasons, "setup не прочитан: "+err.Error())}
	}
	plan := antizapret.PlanSetupSh(setup, req.Values)
	reasons = append(reasons, plan.Problems...)

	sha := req.Commit
	if sha == "" {
		commits, err := u.GitHub.Commits(ctx)
		if err != nil || len(commits) == 0 {
			if err == nil {
				err = errors.New("пустая история")
			}
			reasons = append(reasons, "последний коммит не определён: "+err.Error())
		} else {
			sha = commits[0].SHA
		}
	} else if !azSHARe.MatchString(sha) {
		reasons = append(reasons, "коммит — 40 шестнадцатеричных знаков")
	}
	if len(reasons) > 0 {
		return nodeapi.AZUpdateState{}, &PreflightError{Reasons: reasons}
	}

	work := u.workDir()
	if err := os.RemoveAll(work); err != nil {
		return nodeapi.AZUpdateState{}, err
	}
	if err := os.MkdirAll(work, 0o750); err != nil {
		return nodeapi.AZUpdateState{}, err
	}
	setupSh := filepath.Join(work, "setup.sh")
	download := u.Download
	if download == nil {
		download = u.downloadSetupSh
	}
	if err := download(ctx, sha, setupSh); err != nil {
		return nodeapi.AZUpdateState{}, &PreflightError{Reasons: []string{"setup.sh коммита не получен: " + err.Error()}}
	}
	stdin := filepath.Join(work, "stdin")
	if err := os.WriteFile(stdin, []byte(plan.Stdin), 0o600); err != nil {
		return nodeapi.AZUpdateState{}, err
	}

	clients, err := u.clientNames()
	if err != nil {
		return nodeapi.AZUpdateState{}, fmt.Errorf("состав клиентов не прочитан: %w", err)
	}
	from := u.currentCommit(ctx)
	started := u.now()
	name := azBackupPrefix + started.Format("2006-01-02-150405") + ".tar.gz"
	rootCopy := filepath.Join(u.RootDir, name)
	keepCopy := filepath.Join(u.BackupDir, name)

	st := azFile{
		AZUpdateState: nodeapi.AZUpdateState{
			Action: nodeapi.AZActionUpdate, Status: nodeapi.AZStatusRunning, Phase: nodeapi.AZPhasePrepare,
			Commit: sha, From: from, Started: started, Backup: name, Clients: clients, Notes: plan.Notes,
		},
		SetupExpected: expectedSetup(setup, plan),
	}
	argv := []string{"/bin/sh", "-c", azUpdateScript, "azupdate", u.Dir, rootCopy, keepCopy, setupSh}
	out, err := u.begin(st, TaskAZUpdate, argv, StartOpts{Env: append([]string{"HOME=/root"}, plan.Env...), StdinFile: stdin})
	if err == nil {
		u.logger().Info("обновление AntiZapret запущено", "commit", sha, "from", from, "task", out.TaskID, "backup", name)
	}
	return out, err
}

// begin записывает состояние «идёт», запускает задачу и ставит наблюдателя.
// Не вышло запустить — прежнее состояние возвращается.
func (u *AZUpdater) begin(st azFile, kind string, argv []string, opts StartOpts) (nodeapi.AZUpdateState, error) {
	u.mu.Lock()
	prev := u.state
	u.state = st
	if err := u.saveLocked(); err != nil {
		u.state = prev
		u.mu.Unlock()
		return nodeapi.AZUpdateState{}, err
	}
	u.mu.Unlock()
	task, err := u.Tasks.StartWith(kind, argv, opts)
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		u.state = prev
		u.saveLocked()
		return nodeapi.AZUpdateState{}, err
	}
	u.state.TaskID = task.ID
	u.saveLocked()
	go u.watch(task.ID)
	return u.state.AZUpdateState, nil
}

// expectedSetup — что должно оказаться в setup после установки: ответы на
// вопросы setup.sh и ключи, которые он не перезаписывает жёстко и должен
// сохранить (RECONNECT_WARP, CLEAR_HOSTS, TXQUEUELEN — setup.sh их сбрасывает).
func expectedSetup(setup map[string]string, plan antizapret.SetupShPlan) map[string]string {
	exp := map[string]string{}
	for _, k := range []string{"RECONNECT_WARP", "CLEAR_HOSTS", "TXQUEUELEN"} {
		if v, ok := setup[k]; ok {
			exp[k] = v
		}
	}
	for _, e := range plan.Env {
		k, v, _ := strings.Cut(e, "=")
		exp[k] = v
	}
	lines := strings.Split(strings.TrimRight(plan.Stdin, "\n"), "\n")
	for i, k := range []string{"MTU", "OPENVPN_HOST", "WIREGUARD_HOST"} {
		if i < len(lines) {
			exp[k] = lines[i]
		}
	}
	return exp
}

func (u *AZUpdater) clientNames() ([]string, error) {
	list, err := u.Inventory.Clients()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list))
	for _, c := range list {
		names = append(names, c.Name)
	}
	return names, nil
}

func (u *AZUpdater) currentCommit(ctx context.Context) string {
	if u.Version == nil {
		return ""
	}
	return u.Version.Get(ctx).Current
}

// Restore восстанавливает конфигурацию и клиентов из бэкапа (client.sh 9
// задачей; он сам перезагружает сервер).
func (u *AZUpdater) Restore(ctx context.Context, backup string) (nodeapi.AZUpdateState, error) {
	u.startMu.Lock()
	defer u.startMu.Unlock()
	if u.Active() {
		return nodeapi.AZUpdateState{}, &PreflightError{Busy: true, Reasons: []string{"обновление или восстановление уже идёт"}}
	}
	if t, ok := u.Tasks.Running(); ok {
		return nodeapi.AZUpdateState{}, &BusyError{Task: t}
	}
	if !azBackupNameRe.MatchString(backup) || !u.backupExists(backup) {
		return nodeapi.AZUpdateState{}, &PreflightError{Reasons: []string{"такого бэкапа нет в " + u.BackupDir}}
	}
	if reasons := u.preflight(false); len(reasons) > 0 {
		return nodeapi.AZUpdateState{}, &PreflightError{Reasons: reasons}
	}
	// Клиенты, которые должны быть после восстановления: список до обновления,
	// если он известен, иначе нынешний.
	u.mu.Lock()
	prevState := u.state
	u.mu.Unlock()
	clients := prevState.Clients
	if len(clients) == 0 {
		var err error
		if clients, err = u.clientNames(); err != nil {
			return nodeapi.AZUpdateState{}, fmt.Errorf("состав клиентов не прочитан: %w", err)
		}
	}
	st := azFile{AZUpdateState: nodeapi.AZUpdateState{
		Action: nodeapi.AZActionRestore, Status: nodeapi.AZStatusRunning, Phase: nodeapi.AZPhasePrepare,
		Started: u.now(), Backup: backup, Clients: clients, Commit: prevState.Commit, From: prevState.From,
	}}
	argv := []string{"/bin/sh", "-c", azRestoreScript, "azrestore", filepath.Join(u.BackupDir, backup), u.RootDir, u.Dir}
	out, err := u.begin(st, TaskAZRestore, argv, StartOpts{})
	if err == nil {
		u.logger().Info("восстановление AntiZapret из бэкапа запущено", "backup", backup, "task", out.TaskID)
	}
	return out, err
}

// --- загрузка setup.sh ---

// downloadSetupSh качает архив коммита и берёт из него setup.sh. Остальное из
// архива не нужно: setup.sh сам клонирует репозиторий (см. setupsh.go в antizapret).
func (u *AZUpdater) downloadSetupSh(ctx context.Context, sha, dest string) error {
	if !azSHARe.MatchString(sha) {
		return errors.New("неверный коммит")
	}
	base := strings.TrimRight(u.ArchiveBase, "/")
	if base == "" {
		base = "https://github.com"
	}
	url := fmt.Sprintf("%s/%s/archive/%s.tar.gz", base, antizapret.UpstreamRepo, sha)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "azpanel")
	cl := u.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub ответил %d на %s", resp.StatusCode, url)
	}
	return extractSetupSh(io.LimitReader(resp.Body, 256<<20), dest)
}

// extractSetupSh достаёт из tar.gz файл «<корень>/setup.sh» и пишет в dest.
func extractSetupSh(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("архив не gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("в архиве нет setup.sh")
		}
		if err != nil {
			return fmt.Errorf("архив повреждён: %w", err)
		}
		parts := strings.Split(path.Clean(h.Name), "/")
		if h.Typeflag != tar.TypeReg || len(parts) != 2 || parts[1] != "setup.sh" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 4<<20))
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(data), "#!/bin/bash") {
			return errors.New("setup.sh из архива не похож на скрипт bash")
		}
		return os.WriteFile(dest, data, 0o700)
	}
}

// --- ход задачи ---

func (u *AZUpdater) pollEvery() time.Duration { return u.dur(u.PollEvery, 2*time.Second) }

// sleep ждёт d или остановки агента; false — агент останавливается.
func (u *AZUpdater) sleep(d time.Duration) bool {
	select {
	case <-u.ctx().Done():
		return false
	case <-time.After(d):
		return true
	}
}

// watch ждёт окончания задачи и решает, что дальше.
func (u *AZUpdater) watch(taskID string) {
	for {
		t, ok := u.Tasks.Get(taskID)
		if !ok {
			u.finish(nodeapi.AZStatusFailed, []string{"задача " + taskID + " не найдена в списке задач"}, nil)
			return
		}
		if t.Finished != nil {
			u.afterTask(t)
			return
		}
		if !u.sleep(u.pollEvery()) {
			return // агент останавливается; продолжит Resume
		}
	}
}

func (u *AZUpdater) afterTask(t Task) {
	if t.ExitCode != nil && *t.ExitCode == 0 {
		// Скрипт отработал и перезагрузил сервер: до выключения агент ещё жив.
		u.setPhase(nodeapi.AZPhaseReboot)
		u.waitReboot()
		return
	}
	var how string
	switch {
	case t.TimedOut:
		how = "остановлена по пределу времени"
	case t.Interrupted:
		how = "прервана, код выхода неизвестен"
	case t.ExitCode != nil:
		how = "завершилась с кодом " + strconv.Itoa(*t.ExitCode)
	default:
		how = "завершилась без кода выхода"
	}
	reasons := []string{fmt.Sprintf("задача %s %s (журнал задачи %s)", t.Kind, how, t.ID)}
	if tail, err := u.Tasks.Tail(t); err == nil {
		reasons = append(reasons, lastLines(tail, 3)...)
	}
	u.finish(nodeapi.AZStatusFailed, reasons, nil)
}

var ansiEsc = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// lastLines — последние n непустых строк без цветовых кодов.
func lastLines(s string, n int) []string {
	s = ansiEsc.ReplaceAllString(s, "")
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// waitReboot: скрипт сам вызвал reboot, и агента остановят вместе с системой.
// Если сервер не ушёл на перезагрузку за отведённое время — перезагружает агент.
func (u *AZUpdater) waitReboot() {
	grace := u.dur(u.RebootGrace, 5*time.Minute)
	if !u.sleep(grace) {
		return
	}
	u.logger().Warn("задача завершилась успешно, а сервер не перезагружается — перезагружаю сам")
	reboot := u.Reboot
	if reboot == nil {
		reboot = systemctlReboot
	}
	if err := reboot(u.ctx()); err != nil {
		u.finish(nodeapi.AZStatusFailed, []string{"установка завершена, но перезагрузить сервер не удалось: " + err.Error()}, nil)
		return
	}
	if !u.sleep(grace) {
		return
	}
	u.finish(nodeapi.AZStatusFailed, []string{"установка завершена, но сервер не перезагрузился"}, nil)
}

func systemctlReboot(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "systemctl", "reboot").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (u *AZUpdater) setPhase(phase string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state.Status != nodeapi.AZStatusRunning {
		return
	}
	u.state.Phase = phase
	if err := u.saveLocked(); err != nil {
		u.logger().Error("azupdate.json не записан", "err", err)
	}
}

// finish записывает итог. mutate вносит дополнительные поля под замком.
func (u *AZUpdater) finish(status string, reasons []string, mutate func(*azFile)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state.Status != nodeapi.AZStatusRunning {
		return
	}
	now := u.now()
	u.state.Status = status
	u.state.Phase = ""
	u.state.Finished = &now
	u.state.Reasons = reasons
	if mutate != nil {
		mutate(&u.state)
	}
	if err := u.saveLocked(); err != nil {
		u.logger().Error("azupdate.json не записан", "err", err)
	}
	u.logger().Info("обновление AntiZapret закончено", "action", u.state.Action, "status", status, "reasons", reasons)
}

// --- после перезагрузки ---

// Resume вызывается при старте агента: незаконченное обновление либо
// продолжается (задача ещё идёт), либо проверяется после перезагрузки.
func (u *AZUpdater) Resume() {
	u.mu.Lock()
	st := u.state
	u.mu.Unlock()
	if st.Status != nodeapi.AZStatusRunning {
		return
	}
	boot := u.BootTime
	if boot == nil {
		boot = procBootTime
	}
	if b, err := boot(); err == nil && b.After(st.Started) {
		u.logger().Info("после перезагрузки найдено незаконченное обновление — проверяю", "action", st.Action, "started", st.Started)
		go u.verifyLoop()
		return
	}
	t, ok := u.Tasks.Get(st.TaskID)
	switch {
	case !ok:
		u.finish(nodeapi.AZStatusFailed, []string{"задача " + st.TaskID + " не найдена в списке задач"}, nil)
	case t.Finished != nil:
		go u.afterTask(t)
	default:
		go u.watch(st.TaskID)
	}
}

// procBootTime — время загрузки системы из btime в /proc/stat.
func procBootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(n, 0).UTC(), nil
		}
	}
	return time.Time{}, errors.New("в /proc/stat нет btime")
}

// verifyLoop ждёт, пока службы поднимутся, и записывает итог.
func (u *AZUpdater) verifyLoop() {
	u.setPhase(nodeapi.AZPhaseVerify)
	u.mu.Lock()
	st := u.state
	u.mu.Unlock()

	// Дошёл ли скрипт до конца: иначе сервер перезагрузился по другой причине.
	if reason := u.unfinishedReason(st); reason != "" {
		u.ensureHook()
		svcs, _ := u.Services(u.ctx())
		u.finish(nodeapi.AZStatusFailed, []string{reason}, func(f *azFile) { f.Services = svcs })
		return
	}

	wait := u.dur(u.VerifyWait, 10*time.Minute)
	every := u.dur(u.VerifyEvery, 15*time.Second)
	deadline := time.Now().Add(wait)
	for {
		u.ensureHook()
		reasons, svcs := u.check(u.ctx(), st)
		if len(reasons) == 0 {
			u.complete(st, svcs)
			return
		}
		if time.Now().After(deadline) {
			u.finish(nodeapi.AZStatusFailed, reasons, func(f *azFile) { f.Services = svcs })
			return
		}
		if !u.sleep(every) {
			return
		}
	}
}

func (u *AZUpdater) ensureHook() {
	if u.EnsureHook == nil {
		return
	}
	if changed, err := u.EnsureHook(); err != nil {
		u.logger().Error("хук лимита не установлен", "err", err)
	} else if changed {
		u.logger().Info("хук лимита установлен после обновления")
	}
}

// unfinishedReason — причина, если журнал задачи есть, а завершающей строки в
// нём нет. Журнала нет (удалён ротацией) — не причина.
func (u *AZUpdater) unfinishedReason(st azFile) string {
	t, ok := u.Tasks.Get(st.TaskID)
	if !ok {
		return ""
	}
	if _, err := os.Stat(filepath.Join(u.Tasks.LogDir, filepath.Base(t.Log))); err != nil {
		return ""
	}
	tail, err := u.Tasks.Tail(t)
	if err != nil {
		return ""
	}
	marker := azUpdateDoneMarker
	script := "setup.sh"
	if st.Action == nodeapi.AZActionRestore {
		marker, script = azRestoreDoneMarker, "client.sh 9"
	}
	if strings.Contains(tail, marker) {
		return ""
	}
	return fmt.Sprintf("сервер перезагрузился, а %s не дошёл до конца (в журнале задачи %s нет сообщения «%s»)", script, t.ID, marker)
}

// check сверяет состояние с ожидаемым: службы и клиенты.
func (u *AZUpdater) check(ctx context.Context, st azFile) (reasons []string, svcs []sysinfo.Service) {
	setup, err := u.readSetup()
	if err != nil {
		return []string{"setup не прочитан: " + err.Error()}, nil
	}
	svcs, err = u.Services(ctx)
	if err != nil {
		return []string{"состояние служб не получено: " + err.Error()}, nil
	}
	reasons = append(reasons, badServices(setup, svcs)...)
	now, err := u.clientNames()
	if err != nil {
		reasons = append(reasons, "состав клиентов не прочитан: "+err.Error())
	} else if missing := missingNames(st.Clients, now); len(missing) > 0 {
		reasons = append(reasons, "пропали клиенты: "+strings.Join(missing, ", "))
	}
	return reasons, svcs
}

// badServices — службы, которые по setup должны работать, а не работают.
func badServices(setup map[string]string, svcs []sysinfo.Service) []string {
	var reasons []string
	kresd := 0
	for _, s := range svcs {
		var need bool
		switch {
		case strings.HasPrefix(s.Unit, "openvpn-server@"):
			if strings.HasSuffix(s.Unit, "-udp") {
				need = setup["OPENVPN_UDP_ENABLE"] == "y"
			} else {
				need = setup["OPENVPN_TCP_ENABLE"] == "y"
			}
		case strings.HasPrefix(s.Unit, "kresd@"):
			kresd++
			need = true
		case strings.HasPrefix(s.Unit, "wg-quick@"):
			need = setup["WIREGUARD_ENABLE"] == "y"
		}
		if need && s.State != "active" {
			reasons = append(reasons, fmt.Sprintf("служба %s: %s", s.Unit, s.State))
		}
	}
	if kresd == 0 {
		reasons = append(reasons, "службы kresd@* не найдены")
	}
	return reasons
}

func missingNames(before, now []string) []string {
	have := map[string]bool{}
	for _, n := range now {
		have[n] = true
	}
	var out []string
	for _, n := range before {
		if !have[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// complete — проверка прошла: сопутствующие службы, сброшенные ключи, итог.
func (u *AZUpdater) complete(st azFile, svcs []sysinfo.Service) {
	extras := map[string]string{}
	var warnings []string

	if u.warperPresent() {
		msg, warn := u.warperResync()
		extras["warper"] = msg
		warnings = append(warnings, warn...)
	}
	if u.exists(u.telemtBin()) && u.exists(u.telemtConfig()) {
		state := u.unitState("telemt")
		extras["telemt"] = state
		if state != "active" {
			warnings = append(warnings, "telemt после обновления: "+state)
		}
	}
	var note string
	if st.Action == nodeapi.AZActionUpdate {
		warnings = append(warnings, u.resetKeys(st)...)
		note = u.recordInstalled(st)
	}
	u.finish(nodeapi.AZStatusOK, nil, func(f *azFile) {
		f.Services = svcs
		f.Extras = extras
		f.Warnings = warnings
		if note != "" {
			f.Notes = append(f.Notes, note)
		}
	})
	u.pruneBackups()
}

// resetKeys — ключи setup, которые после установки не совпали с ожидаемыми.
func (u *AZUpdater) resetKeys(st azFile) []string {
	now, err := u.readSetup()
	if err != nil {
		return nil
	}
	var out []string
	keys := make([]string, 0, len(st.SetupExpected))
	for k := range st.SetupExpected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if want, got := st.SetupExpected[k], now[k]; want != got {
			out = append(out, fmt.Sprintf("ключ %s в setup: ожидалось «%s», стало «%s» (setup.sh сбросил или не принял значение)", k, want, got))
		}
	}
	return out
}

// recordInstalled записывает коммит в data/antizapret.json. setup.sh клонирует
// main сам, поэтому по хешам скриптов проверяется, какой коммит встал на
// самом деле; расхождение с запрошенным — в пометке.
func (u *AZUpdater) recordInstalled(st azFile) string {
	commit, note := st.Commit, ""
	if u.GitHub != nil {
		if local, err := antizapret.LocalScriptHashes(u.Dir); err == nil {
			if sha, found, err := u.GitHub.FindCommit(u.ctx(), local); err == nil && found && sha != st.Commit {
				note = fmt.Sprintf("setup.sh поставил main на момент своего запуска: коммит %s вместо запрошенного %s", sha, st.Commit)
				commit = sha
			}
		}
	}
	if err := u.Record.Write(u.Dir, commit, u.now()); err != nil {
		u.logger().Error("antizapret.json не записан", "err", err)
	}
	return note
}

func (u *AZUpdater) warperVersion() string {
	return u.pathOr(u.WarperVersion, "/root/warper/version")
}
func (u *AZUpdater) telemtBin() string    { return u.pathOr(u.TelemtBin, "/usr/local/bin/telemt") }
func (u *AZUpdater) telemtConfig() string { return u.pathOr(u.TelemtConfig, "/etc/telemt/config.toml") }

func (u *AZUpdater) pathOr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (u *AZUpdater) warperPresent() bool { return u.exists(u.warperVersion()) }

// warperResync запускает «warper resync» задачей и ждёт её. Сбой — замечание,
// не провал обновления: AntiZapret при этом работает.
func (u *AZUpdater) warperResync() (string, []string) {
	bin := u.pathOr(u.WarperBin, "warper")
	var t Task
	var err error
	for i := 0; i < 5; i++ {
		t, err = u.Tasks.Start(TaskWarperResync, []string{bin, "resync"})
		var busy *BusyError
		if !errors.As(err, &busy) {
			break
		}
		if !u.sleep(u.pollEvery()) {
			return "", nil
		}
	}
	if err != nil {
		return "не запущен", []string{"warper resync не запущен: " + err.Error()}
	}
	deadline := time.Now().Add(u.dur(u.VerifyWait, 10*time.Minute))
	for time.Now().Before(deadline) {
		got, ok := u.Tasks.Get(t.ID)
		if ok && got.Finished != nil {
			if got.ExitCode != nil && *got.ExitCode == 0 {
				return "resync выполнен", nil
			}
			return "resync не удался", []string{fmt.Sprintf("warper resync не удался (журнал задачи %s)", t.ID)}
		}
		if !u.sleep(u.pollEvery()) {
			return "", nil
		}
	}
	return "resync не закончился", []string{"warper resync не закончился за отведённое время"}
}

func (u *AZUpdater) unitState(unit string) string {
	run := u.Exec
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).Output()
		}
	}
	out, _ := run(u.ctx(), "systemctl", "is-active", unit) // код выхода не важен: состояние в выводе
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return "unknown"
}
