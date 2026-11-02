package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/fsutil"
)

const (
	maxBinary = 128 << 20
	dbName    = "azpanel.db"
	// ResultName — итог последнего обновления в data/update/: по нему панель
	// после перезапуска шлёт уведомление update_result.
	ResultName = "result.json"
)

var archiveRe = regexp.MustCompile(`^azpanel_(\d+\.\d+\.\d+)_linux_(amd64|arm64)\.tar\.gz$`)

// Check — проверка живости после перезапуска (/healthz панели, /v1/info
// агента с новой версией newVersion). Ошибка — ещё не готово, проверка
// повторится до HealthWait.
type Check func(ctx context.Context, newVersion string) error

// Input — то, что получено из релиза: архив, суммы и подпись как опубликованы.
type Input struct {
	Name    string // имя архива, как в SHA256SUMS
	Archive []byte
	Sums    []byte
	Sig     []byte
	Answers map[string]string // ответы на вопросы миграции конфига
}

// Result — итог обновления; он же лежит в data/update/result.json.
type Result struct {
	OK     bool      `json:"ok"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason,omitempty"` // почему откатили
	Backup string    `json:"backup,omitempty"`
	Time   time.Time `json:"time"`
}

// Env — окружение обновления на этом хосте. Всё, что трогает систему (службы,
// база, проверки), задаётся полями: тесты подставляют поддельные.
type Env struct {
	Root    string // корень установки (/opt/azpanel)
	Version string // текущая версия
	Pub     ed25519.PublicKey
	Arch    string   // пусто — runtime.GOARCH
	Units   []string // службы этого хоста, перезапускаются в этом порядке
	// Migrate — миграции конфига; nil — config.Migrate.
	Migrate func(data []byte, answers map[string]string) ([]byte, []config.Question, error)
	// BackupDB пишет согласованный снимок базы src в dst (VACUUM INTO).
	// nil — базу не снимать.
	BackupDB func(ctx context.Context, src, dst string) error
	// Systemctl — запуск systemctl; nil — настоящий.
	Systemctl  func(ctx context.Context, args ...string) error
	Checks     []Check
	HealthWait time.Duration // 0 — 30 с
	HealthEach time.Duration // 0 — 1 с
	Now        func() time.Time
	Log        io.Writer
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) logf(format string, a ...any) {
	if e.Log != nil {
		fmt.Fprintf(e.Log, format+"\n", a...)
	}
}

func (e *Env) p(parts ...string) string { return filepath.Join(append([]string{e.Root}, parts...)...) }

// ResultPath — файл итога.
func (e *Env) ResultPath() string { return e.p("data", "update", ResultName) }

// ReadResult читает итог последнего обновления; нет файла — (nil, nil).
func ReadResult(root string) (*Result, error) {
	data, err := os.ReadFile(filepath.Join(root, "data", "update", ResultName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Prepare проверяет подпись и сумму, версию и архитектуру и достаёт бинарник.
// Ничего не пишет на диск: отказ здесь не меняет систему. Агент вызывает его
// сам до запуска задачи, а Apply — ещё раз перед заменой.
func (e *Env) Prepare(in Input) (newVersion string, binary []byte, err error) {
	if IsDev(e.Version) {
		return "", nil, errors.New("сборка dev обновлений не ставит")
	}
	if err := Verify(e.Pub, in.Sums, in.Sig, in.Name, in.Archive); err != nil {
		return "", nil, err
	}
	m := archiveRe.FindStringSubmatch(in.Name)
	if m == nil {
		return "", nil, fmt.Errorf("имя архива %q не вида azpanel_x.y.z_linux_<arch>.tar.gz", in.Name)
	}
	arch := e.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if m[2] != arch {
		return "", nil, fmt.Errorf("архив для %s, а хост %s", m[2], arch)
	}
	newer, err := Newer(e.Version, m[1])
	if err != nil {
		return "", nil, err
	}
	if !newer {
		return "", nil, fmt.Errorf("версия %s не новее установленной %s", m[1], e.Version)
	}
	bin, err := extractBinary(in.Archive)
	if err != nil {
		return "", nil, err
	}
	return m[1], bin, nil
}

func extractBinary(archive []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("архив не открыт: %w", err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("в архиве нет файла azpanel")
		}
		if err != nil {
			return nil, fmt.Errorf("архив повреждён: %w", err)
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != "azpanel" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxBinary+1))
		if err != nil {
			return nil, fmt.Errorf("архив повреждён: %w", err)
		}
		if len(data) > maxBinary {
			return nil, errors.New("бинарник в архиве слишком велик")
		}
		if !bytes.HasPrefix(data, []byte("\x7fELF")) {
			return nil, errors.New("azpanel в архиве не исполняемый файл Linux")
		}
		return data, nil
	}
}

// Apply ставит обновление. До записи на диск идут проверки (подпись,
// миграция конфига): отказ или вопрос без ответа (*config.QuestionsError)
// ничего не меняют. Дальше — бэкап, замена, перезапуск, проверка; не
// прошла — откат из бэкапа и ошибка с причиной. Итог пишется в result.json.
func (e *Env) Apply(ctx context.Context, in Input) (res Result, err error) {
	res = Result{From: e.Version}
	p, err := e.plan(in)
	if err != nil {
		return res, err
	}
	newVer, bin, oldCfg, newCfg := p.version, p.binary, p.oldCfg, p.newCfg
	cfgPath := e.p("etc", "config.toml")
	res.To = newVer
	e.logf("Проверено: %s, подпись верна", in.Name)

	binary := e.p("bin", "azpanel")
	prev := binary + ".prev"
	staged := binary + ".new"
	backup, err := e.backup(ctx)
	if err != nil {
		return res, fmt.Errorf("бэкап не создан, обновление не начато: %w", err)
	}
	res.Backup = backup
	e.logf("Бэкап: %s", backup)

	defer func() {
		os.Remove(staged)
		res.Time = e.now().UTC()
		res.OK = err == nil
		if err != nil {
			res.Reason = err.Error()
		}
		if werr := e.writeResult(res); werr != nil {
			e.logf("итог обновления не записан: %v", werr)
		}
	}()

	if err = copyFile(binary, prev); err != nil {
		return res, fmt.Errorf("копия текущего бинарника не сделана, обновление не начато: %w", err)
	}
	if err = fsutil.WriteFileAtomic(staged, bin, 0o755); err != nil {
		return res, fmt.Errorf("новый бинарник не записан, обновление не начато: %w", err)
	}
	// С этого места система меняется: любая ошибка ведёт к откату.
	fail := func(cause error) (Result, error) {
		e.logf("Ошибка: %v. Откат.", cause)
		if rerr := e.rollback(ctx, backup, prev); rerr != nil {
			err = fmt.Errorf("%w; ОТКАТ НЕ УДАЛСЯ: %v (бэкап: %s)", cause, rerr, backup)
		} else {
			err = fmt.Errorf("обновление откатено: %w", cause)
		}
		return res, err
	}
	if !bytes.Equal(newCfg, oldCfg) {
		if werr := fsutil.WriteFileKeepMeta(cfgPath, newCfg); werr != nil {
			return fail(fmt.Errorf("config.toml не записан: %w", werr))
		}
		e.logf("Конфиг приведён к новой версии")
	}
	if rerr := os.Rename(staged, binary); rerr != nil {
		return fail(fmt.Errorf("бинарник не заменён: %w", rerr))
	}
	if rerr := e.units(ctx, "restart"); rerr != nil {
		return fail(rerr)
	}
	e.logf("Службы перезапущены, жду проверки (до %s)", e.healthWait())
	if herr := e.waitHealthy(ctx, newVer); herr != nil {
		return fail(herr)
	}
	e.logf("Готово: %s -> %s", e.Version, newVer)
	return res, nil
}

func (e *Env) healthWait() time.Duration {
	if e.HealthWait > 0 {
		return e.HealthWait
	}
	return 30 * time.Second
}

func (e *Env) waitHealthy(ctx context.Context, newVer string) error {
	each := e.HealthEach
	if each <= 0 {
		each = time.Second
	}
	deadline := time.Now().Add(e.healthWait())
	for {
		var last error
		for _, c := range e.Checks {
			if last = c(ctx, newVer); last != nil {
				break
			}
		}
		if last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("новая версия не ответила за %s: %w", e.healthWait(), last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(each):
		}
	}
}

// units выполняет systemctl <verb> для служб хоста; stop — в обратном порядке.
func (e *Env) units(ctx context.Context, verb string) error {
	sc := e.Systemctl
	if sc == nil {
		sc = runSystemctl
	}
	list := append([]string(nil), e.Units...)
	if verb == "stop" {
		for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
			list[i], list[j] = list[j], list[i]
		}
	}
	var errs []error
	for _, u := range list {
		if err := sc(ctx, verb, u); err != nil {
			errs = append(errs, fmt.Errorf("systemctl %s %s: %w", verb, u, err))
		}
	}
	return errors.Join(errs...)
}

// rollback возвращает бинарник, etc/ и data/ и запускает службы.
func (e *Env) rollback(ctx context.Context, backup, prev string) error {
	var errs []error
	// Откат не должен зависеть от отмены контекста задачи.
	ctx = context.WithoutCancel(ctx)
	if err := e.units(ctx, "stop"); err != nil {
		errs = append(errs, err)
	}
	tmp := e.p("bin", "azpanel.rollback")
	if err := copyFile(prev, tmp); err != nil {
		errs = append(errs, fmt.Errorf("azpanel.prev: %w", err))
	} else if err := os.Rename(tmp, e.p("bin", "azpanel")); err != nil {
		errs = append(errs, err)
	}
	os.Remove(e.p("data", dbName+"-wal"))
	os.Remove(e.p("data", dbName+"-shm"))
	if err := e.restoreBackup(backup); err != nil {
		errs = append(errs, err)
	}
	if err := e.units(ctx, "start"); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (e *Env) writeResult(r Result) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.ResultPath()), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(e.ResultPath(), data, 0o600)
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(dst, data, info.Mode().Perm())
}

// skipInBackup — что в бэкап не входит: файлы самой базы (вместо них снимок),
// каталоги параметров задач и итога обновления.
func skipInBackup(rel string) bool {
	switch rel {
	case "data/update", "data/params", "data/" + dbName + "-wal", "data/" + dbName + "-shm":
		return true
	}
	return false
}

// backup пишет backup/update-<версия>-<дата>.tar.gz с etc/ и data/. База —
// снимок VACUUM INTO, а не копия живого файла.
func (e *Env) backup(ctx context.Context) (string, error) {
	dir := e.p("backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("update-%s-%s.tar.gz", e.Version, e.now().UTC().Format("20060102-150405"))
	dest := filepath.Join(dir, name)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	snap := ""
	if e.BackupDB != nil {
		db := e.p("data", dbName)
		if _, err := os.Stat(db); err == nil {
			snap = filepath.Join(dir, ".snapshot-"+dbName)
			os.Remove(snap) // VACUUM INTO не пишет поверх существующего файла
			defer os.Remove(snap)
			if err := e.BackupDB(ctx, db, snap); err != nil {
				return "", fmt.Errorf("снимок базы: %w", err)
			}
		}
	}
	for _, top := range []string{"etc", "data"} {
		root := e.p(top)
		if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(e.Root, path)
			rel = filepath.ToSlash(rel)
			if skipInBackup(rel) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return nil
			}
			src := path
			if rel == "data/"+dbName && snap != "" {
				src = snap
			}
			return addToTar(tw, rel, src, info)
		})
		if err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(dest, buf.Bytes(), 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

func addToTar(tw *tar.Writer, rel, src string, info fs.FileInfo) error {
	h, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	h.Name = rel
	if info.IsDir() {
		h.Name += "/"
		return tw.WriteHeader(h)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	h.Size = int64(len(data))
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

// restoreBackup разворачивает бэкап поверх etc/ и data/.
func (e *Env) restoreBackup(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(h.Name))
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return fmt.Errorf("в бэкапе недопустимый путь %q", h.Name)
		}
		dst := filepath.Join(e.Root, clean)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			data, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := fsutil.WriteFileAtomic(dst, data, fs.FileMode(h.Mode).Perm()); err != nil {
				return err
			}
		}
	}
}

type plan struct {
	version        string
	binary         []byte
	oldCfg, newCfg []byte
}

// plan делает все проверки без записи на диск: подпись, версия, миграция конфига.
func (e *Env) plan(in Input) (plan, error) {
	var p plan
	var err error
	if p.version, p.binary, err = e.Prepare(in); err != nil {
		return p, err
	}
	if p.oldCfg, err = os.ReadFile(e.p("etc", "config.toml")); err != nil {
		return p, fmt.Errorf("config.toml не прочитан: %w", err)
	}
	migrate := e.Migrate
	if migrate == nil {
		migrate = config.Migrate
	}
	if p.newCfg, _, err = migrate(p.oldCfg, in.Answers); err != nil {
		return p, err
	}
	return p, nil
}

// Preflight — всё, что проверяет Apply до первой записи: подпись, версия,
// архитектура, миграция конфига. Вопросы без ответа приходят как
// *config.QuestionsError. Агент вызывает его при приёме, чтобы отказать
// запросом, а не упавшей задачей.
func (e *Env) Preflight(in Input) (newVersion string, err error) {
	p, err := e.plan(in)
	return p.version, err
}
