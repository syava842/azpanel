package telemt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/syava842/azpanel/internal/fsutil"
)

// RestoreDelay — пауза после возврата к прежнему бинарнику перед проверкой.
const restoreDelay = 5 * time.Second

// verify проверяет службу после перезапуска: active, NRestarts не вырос,
// ссылки в журнале (если telemt их печатает) совпадают с конфигом.
func (e *Env) verify(ctx context.Context, since time.Time, baseline int) error {
	e.sleep(e.settle())
	active, restarts, err := e.UnitState(ctx)
	if err != nil {
		return fmt.Errorf("состояние службы не прочитано: %w", err)
	}
	if active != "active" {
		return fmt.Errorf("служба не в состоянии active (сейчас: %s)", active)
	}
	if restarts > baseline {
		return fmt.Errorf("служба перезапускалась сама (NRestarts %d → %d) — она падает", baseline, restarts)
	}
	doc, err := e.ReadConfig()
	if err != nil {
		return err
	}
	journal, err := e.Journal(ctx, since)
	if err != nil {
		e.logf("журнал службы не прочитан (%v) — сверка ссылки пропущена", err)
		return nil
	}
	found, err := CheckJournal(journal, doc.Users(), doc.TLSDomain())
	if err != nil {
		return err
	}
	if found {
		e.logf("ссылка в журнале совпала с конфигом")
	} else {
		e.logf("ссылки в журнале не видно (log_level silent?) — сверка по журналу пропущена")
	}
	return nil
}

// restart перезапускает службу и проверяет её. baseline читается до перезапуска.
func (e *Env) restart(ctx context.Context) error {
	_, baseline, err := e.UnitState(ctx)
	if err != nil {
		return fmt.Errorf("состояние службы не прочитано: %w", err)
	}
	since := e.now()
	if out, err := e.run(ctx, "systemctl", "restart", e.unit()); err != nil {
		return fmt.Errorf("перезапуск не удался: %w (%s)", err, firstLine(string(out)))
	}
	return e.verify(ctx, since, baseline)
}

// Restart — перезапуск telemt с проверкой.
func (e *Env) Restart(ctx context.Context) error {
	e.logf("перезапускаю %s", e.unit())
	if err := e.restart(ctx); err != nil {
		return err
	}
	e.logf("служба работает")
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// Update обновляет бинарник до последнего релиза: прежний сохраняется как
// <бинарник>.prev, конфиг не трогается. Не прошла проверка после перезапуска —
// возврат к прежнему бинарнику. Нечего обновлять — nil.
func (e *Env) Update(ctx context.Context, force bool) error {
	cur, err := e.Version(ctx)
	if err != nil {
		return fmt.Errorf("версия установленного telemt не определена: %w", err)
	}
	rel, err := e.LatestRelease(ctx)
	if err != nil {
		return err
	}
	e.logf("установлена %s, последняя %s", cur, rel.Version())
	if !force && CompareVersions(cur, rel.Version()) >= 0 {
		e.logf("обновление не нужно")
		return nil
	}
	bin := e.binary()
	staged := bin + ".new"
	defer os.Remove(staged)
	if err := e.fetchBinary(ctx, rel, staged); err != nil {
		return err
	}
	if out, err := e.run(ctx, staged, "--version"); err != nil || versionRe.FindString(string(out)) == "" {
		return fmt.Errorf("скачанный бинарник не запускается: %v", err)
	}
	prev := bin + ".prev"
	if err := copyFile(bin, prev, 0o755); err != nil {
		return fmt.Errorf("прежний бинарник не сохранён: %w", err)
	}
	e.logf("прежний бинарник сохранён в %s", prev)
	if err := os.Rename(staged, bin); err != nil {
		return fmt.Errorf("бинарник не заменён: %w", err)
	}
	if err := e.restart(ctx); err != nil {
		e.logf("проверка не прошла: %v — возвращаю прежний бинарник", err)
		return e.rollback(ctx, prev, err)
	}
	e.logf("telemt обновлён до %s", rel.Version())
	return nil
}

// rollback возвращает прежний бинарник и проверяет, что служба поднялась.
func (e *Env) rollback(ctx context.Context, prev string, cause error) error {
	if err := copyFile(prev, e.binary(), 0o755); err != nil {
		return fmt.Errorf("%w; откат не удался: %v", cause, err)
	}
	if out, err := e.run(ctx, "systemctl", "restart", e.unit()); err != nil {
		return fmt.Errorf("%w; откат: перезапуск не удался: %v (%s)", cause, err, firstLine(string(out)))
	}
	e.sleep(restoreDelay)
	if active, _, err := e.UnitState(ctx); err != nil || active != "active" {
		return fmt.Errorf("%w; после отката служба не active", cause)
	}
	return fmt.Errorf("обновление откачено: %w", cause)
}

// ApplyParams — правка пользователей. Секрет для add — готовые 32 hex.
type ApplyParams struct {
	Op     string `json:"op"` // add | remove | restart
	Name   string `json:"name,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// Apply правит [access.users] (add, remove) и перезапускает telemt с проверкой.
// Не прошла проверка — прежний конфиг возвращается и служба перезапускается.
func (e *Env) Apply(ctx context.Context, p ApplyParams) error {
	if p.Op == "restart" {
		return e.Restart(ctx)
	}
	data, err := os.ReadFile(e.config())
	if err != nil {
		return err
	}
	doc, err := ParseConfig(data)
	if err != nil {
		return err
	}
	switch p.Op {
	case "add":
		err = doc.AddUser(p.Name, p.Secret)
	case "remove":
		if us := doc.Users(); len(us) == 1 && us[0].Name == p.Name {
			return errors.New("нельзя удалить последнего пользователя: telemt без пользователей не запустится")
		}
		err = doc.RemoveUser(p.Name)
	default:
		return fmt.Errorf("неизвестная операция %q", p.Op)
	}
	if err != nil {
		return err
	}
	st, err := os.Stat(e.config())
	if err != nil {
		return err
	}
	backup := e.config() + ".bak-" + e.now().Format("20060102-150405")
	if err := fsutil.WriteFileAtomic(backup, data, st.Mode().Perm()); err != nil {
		return fmt.Errorf("копия конфига не сохранена: %w", err)
	}
	if err := fsutil.WriteFileAtomic(e.config(), doc.Bytes(), st.Mode().Perm()); err != nil {
		return err
	}
	e.pruneConfigBackups(keepConfigBackups)
	e.logf("конфиг обновлён (копия: %s), перезапускаю", backup)
	if err := e.restart(ctx); err != nil {
		e.logf("проверка не прошла: %v — возвращаю прежний конфиг", err)
		if werr := fsutil.WriteFileAtomic(e.config(), data, st.Mode().Perm()); werr != nil {
			return fmt.Errorf("%w; конфиг не возвращён: %v", err, werr)
		}
		_, _ = e.run(ctx, "systemctl", "restart", e.unit())
		return fmt.Errorf("правка откачена: %w", err)
	}
	e.logf("служба работает")
	return nil
}

// InstallParams — ответы на вопросы установки.
type InstallParams struct {
	Port           int    `json:"port"`
	Domain         string `json:"domain"`
	Secret         string `json:"secret,omitempty"` // пусто — сгенерировать
	User           string `json:"user,omitempty"`   // имя первого пользователя; по умолчанию user
	MaxConnections int    `json:"max_connections,omitempty"`
	BufDivisor     int    `json:"buf_divisor,omitempty"`
	SkipDomainDNS  bool   `json:"skip_domain_dns,omitempty"`
}

// Defaults — значения установщика: 4000 соединений при делителе 16 рассчитаны
// на 1 ГБ памяти.
func (p *InstallParams) Defaults() {
	if p.Port == 0 {
		p.Port = 902
	}
	if p.User == "" {
		p.User = "user"
	}
	if p.MaxConnections == 0 {
		p.MaxConnections = 4000
	}
	if p.BufDivisor == 0 {
		p.BufDivisor = 16
	}
}

// Validate проверяет ответы до любых действий на узле.
func (p InstallParams) Validate() error {
	switch {
	case p.Port < 1 || p.Port > 65535:
		return errors.New("порт вне диапазона 1–65535")
	case !ValidDomain(p.Domain):
		return errors.New("домен маскировки выглядит неправильно")
	case p.Secret != "" && !ValidSecret(p.Secret):
		return errors.New("секрет должен быть ровно 32 hex-символа")
	case !ValidUserName(p.User):
		return errors.New("имя пользователя: 1–32 символа a-z, A-Z, 0-9, _ и -")
	case p.MaxConnections < 1 || p.MaxConnections > 1_000_000:
		return errors.New("max_connections вне диапазона 1–1000000")
	case p.BufDivisor < 1 || p.BufDivisor > 1024:
		return errors.New("делитель буферов вне диапазона 1–1024")
	}
	return nil
}

// NewSecret — случайный секрет, 32 hex.
func NewSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Install ставит telemt на пустой узел: бинарник с проверкой суммы,
// «telemt --init», настройка конфига, запуск и проверка.
func (e *Env) Install(ctx context.Context, p InstallParams) error {
	p.Defaults()
	if err := p.Validate(); err != nil {
		return err
	}
	if e.Installed() {
		return errors.New("telemt уже установлен — используйте обновление")
	}
	if err := e.CheckPort(p.Port); err != nil {
		return err
	}
	if !p.SkipDomainDNS {
		lookup := e.LookupHost
		if lookup == nil {
			lookup = func(ctx context.Context, h string) ([]string, error) { return netResolver(ctx, h) }
		}
		if _, err := lookup(ctx, p.Domain); err != nil {
			return fmt.Errorf("домен %s не резолвится: %w", p.Domain, err)
		}
	}
	if p.Secret == "" {
		s, err := NewSecret()
		if err != nil {
			return err
		}
		p.Secret = s
		e.logf("сгенерирован новый секрет")
	}
	rel, err := e.LatestRelease(ctx)
	if err != nil {
		return err
	}
	bin := e.binary()
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		return err
	}
	staged := bin + ".new"
	defer os.Remove(staged)
	if err := e.fetchBinary(ctx, rel, staged); err != nil {
		return err
	}
	if err := os.Rename(staged, bin); err != nil {
		return err
	}
	// Бинарника и конфига до установки не было (Installed() проверена выше):
	// при сбое убираем свои следы, иначе повтор упрётся в «уже установлен».
	done, started := false, false
	defer func() {
		if done {
			return
		}
		e.logf("установка не удалась — убираю бинарник и конфиг")
		if started {
			_, _ = e.run(context.WithoutCancel(ctx), "systemctl", "disable", "--now", e.unit())
		}
		os.Remove(bin)
		os.Remove(e.config())
	}()
	if v, err := e.Version(ctx); err != nil {
		return fmt.Errorf("установленный бинарник не запускается: %w", err)
	} else {
		e.logf("установлен %s версии %s", bin, v)
	}
	dir := filepath.Dir(e.config())
	// Настоящий секрет в аргументы дочернего процесса не попадает: argv виден в
	// /proc/<pid>/cmdline любому пользователю узла и в тексте ошибки. --init
	// получает одноразовый секрет, а настоящий ставит tuneConfig правкой конфига.
	tmpSecret, err := NewSecret()
	if err != nil {
		return err
	}
	if out, err := e.run(ctx, bin, "--init", "--port", strconv.Itoa(p.Port), "--domain", p.Domain,
		"--secret", tmpSecret, "--user", p.User, "--config-dir", dir, "--no-start"); err != nil {
		return fmt.Errorf("telemt --init завершился с ошибкой: %s (%s)", RedactSecrets(err.Error()), RedactSecrets(firstLine(string(out))))
	}
	if err := e.tuneConfig(p); err != nil {
		return err
	}
	if e.StateDir != "" {
		if err := os.MkdirAll(e.StateDir, 0o755); err != nil {
			return err
		}
	}
	if out, err := e.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w (%s)", err, firstLine(string(out)))
	}
	// Счётчик перезапусков до запуска: юнит мог существовать раньше, и ноль в
	// качестве точки отсчёта дал бы ложный провал.
	baseline := 0
	if _, n, err := e.UnitState(ctx); err == nil {
		baseline = n
	}
	since := e.now()
	started = true
	if out, err := e.run(ctx, "systemctl", "enable", "--now", e.unit()); err != nil {
		return fmt.Errorf("служба не запустилась: %w (%s)", err, firstLine(string(out)))
	}
	if err := e.verify(ctx, since, baseline); err != nil {
		return err
	}
	if err := e.CheckPortListening(ctx, p.Port); err != nil {
		return err
	}
	done = true
	e.logf("telemt установлен: порт %d, домен %s", p.Port, p.Domain)
	return nil
}

// CheckPortListening — после запуска порт занят самим telemt.
func (e *Env) CheckPortListening(ctx context.Context, port int) error {
	if e.CheckPort(port) == nil {
		return fmt.Errorf("порт %d не слушается", port)
	}
	return nil
}

// tuneConfig задаёт тюнинг установщика: тихий журнал, малые буферы, без
// IPv6, STUN, телеметрии и WEB-API.
func (e *Env) tuneConfig(p InstallParams) error {
	data, err := os.ReadFile(e.config())
	if err != nil {
		return fmt.Errorf("telemt --init не создал конфиг: %w", err)
	}
	doc, err := ParseConfig(data)
	if err != nil {
		return err
	}
	// Секрет первого пользователя: --init записал одноразовый, ставим настоящий.
	if err := doc.RemoveUser(p.User); err != nil {
		return fmt.Errorf("пользователь %s в конфиге после --init: %w", p.User, err)
	}
	if err := doc.AddUser(p.User, p.Secret); err != nil {
		return err
	}
	sets := []struct{ section, key, raw string }{
		{"general", "beobachten", "false"},
		{"general", "log_level", `"silent"`},
		{"general", "direct_relay_copy_buf_c2s_bytes", strconv.Itoa(65536 / p.BufDivisor)},
		{"general", "direct_relay_copy_buf_s2c_bytes", strconv.Itoa(262144 / p.BufDivisor)},
		{"general", "crypto_pending_buffer", strconv.Itoa(262144 / p.BufDivisor)},
		{"network", "stun_use", "false"},
		{"network", "ipv6", "false"},
		{"server", "max_connections", strconv.Itoa(p.MaxConnections)},
		{"censorship", "unknown_sni_action", `"mask"`},
		{"general.telemetry", "core_enabled", "false"},
		{"general.telemetry", "user_enabled", "false"},
		{"timeouts", "client_keepalive", "15"},
		{"timeouts", "client_ack", "60"},
		{"server.api", "enabled", "false"},
	}
	for _, s := range sets {
		if err := doc.Set(s.section, s.key, s.raw); err != nil {
			return fmt.Errorf("[%s] %s: %w", s.section, s.key, err)
		}
	}
	if err := doc.DisableIPv6Listener(); err != nil {
		return err
	}
	st, err := os.Stat(e.config())
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(e.config(), doc.Bytes(), st.Mode().Perm())
}

// keepConfigBackups — сколько копий config.toml.bak-* хранится: в каждой полные
// секреты пользователей, копить их без предела незачем.
const keepConfigBackups = 5

// pruneConfigBackups оставляет n последних копий конфига (имя несёт время).
func (e *Env) pruneConfigBackups(n int) {
	list, err := filepath.Glob(e.config() + ".bak-*")
	if err != nil || len(list) <= n {
		return
	}
	sort.Strings(list)
	for _, f := range list[:len(list)-n] {
		if err := os.Remove(f); err == nil {
			e.logf("старая копия конфига удалена: %s", filepath.Base(f))
		}
	}
}
