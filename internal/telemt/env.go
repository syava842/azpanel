package telemt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner запускает внешнюю команду и возвращает её вывод (stdout вместе со
// stderr). Ненулевой код выхода — ошибка, вывод при этом тоже возвращается.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner — настоящий запуск процесса.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w", name, RedactSecrets(strings.Join(args, " ")), err)
	}
	return out, nil
}

// Env — всё, что нужно telemt-операциям: пути, запуск команд, сеть, часы.
// Нулевые поля заменяются умолчаниями (NewEnv); в тестах подменяются.
type Env struct {
	Binary string // /usr/local/bin/telemt
	Config string // /etc/telemt/config.toml
	Unit   string // telemt
	// StateDir — каталог данных telemt (/var/lib/telemt), создаётся при установке.
	StateDir string

	Run     Runner
	HTTP    *http.Client
	APIBase string // https://api.github.com
	// Arch и Libc выбирают архив релиза; пусто — по машине (x86_64/aarch64, gnu).
	Arch, Libc string
	// Settle — сколько ждать после перезапуска, прежде чем проверять службу.
	Settle time.Duration
	Sleep  func(time.Duration)
	Now    func() time.Time
	// PortFree проверяет, что порт свободен; nil — попытка слушать TCP.
	PortFree func(port int) error
	// LookupHost проверяет, что домен маскировки резолвится; nil — net.LookupHost.
	LookupHost func(ctx context.Context, host string) ([]string, error)
	Log        io.Writer // журнал задачи; nil — никуда
}

// NewEnv — окружение с настоящими путями узла.
func NewEnv() *Env {
	return &Env{Binary: DefaultBinary, Config: DefaultConfig, Unit: DefaultUnit, StateDir: "/var/lib/telemt"}
}

func (e *Env) binary() string { return orStr(e.Binary, DefaultBinary) }
func (e *Env) config() string { return orStr(e.Config, DefaultConfig) }
func (e *Env) unit() string   { return orStr(e.Unit, DefaultUnit) }

func orStr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func (e *Env) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if e.Run != nil {
		return e.Run(ctx, name, args...)
	}
	return ExecRunner(ctx, name, args...)
}

func (e *Env) sleep(d time.Duration) {
	if e.Sleep != nil {
		e.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) settle() time.Duration {
	if e.Settle > 0 {
		return e.Settle
	}
	return 15 * time.Second
}

func (e *Env) logf(format string, a ...any) {
	if e.Log != nil {
		fmt.Fprint(e.Log, RedactSecrets(fmt.Sprintf(format, a...))+"\n")
	}
}

// ReadConfig читает и разбирает config.toml.
func (e *Env) ReadConfig() (*Doc, error) {
	data, err := os.ReadFile(e.config())
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// queryTimeout — предел опросов (telemt --version, systemctl show, journalctl):
// зависшая команда не должна подвешивать GET /v1/telemt и задачи.
const queryTimeout = 10 * time.Second

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// Version — версия установленного бинарника (из «telemt --version»).
func (e *Env) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := e.run(ctx, e.binary(), "--version")
	if err != nil {
		return "", err
	}
	v := versionRe.FindString(string(out))
	if v == "" {
		return "", fmt.Errorf("в выводе telemt --version нет номера версии: %q", firstLine(string(out)))
	}
	return v, nil
}

var secretLikeRe = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)

// RedactSecrets затирает в тексте 32-значные hex-секреты: текст уходит в
// журнал задачи и в ответы панели. Ошибка не должна нести секрет, даже если
// команду запустили с ним в аргументах.
func RedactSecrets(s string) string {
	return secretLikeRe.ReplaceAllString(s, "********")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// UnitState — ActiveState и NRestarts службы.
func (e *Env) UnitState(ctx context.Context) (active string, restarts int, err error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := e.run(ctx, "systemctl", "show", e.unit(), "-p", "ActiveState", "-p", "NRestarts")
	if err != nil {
		return "", 0, err
	}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		switch {
		case !ok:
		case k == "ActiveState":
			active = v
		case k == "NRestarts":
			restarts, _ = strconv.Atoi(v)
		}
	}
	if active == "" {
		return "", 0, errors.New("systemctl show не вернул ActiveState")
	}
	return active, restarts, nil
}

// Journal — журнал службы с указанного момента.
func (e *Env) Journal(ctx context.Context, since time.Time) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := e.run(ctx, "journalctl", "-u", e.unit(), "--no-pager", "--since", since.Local().Format("2006-01-02 15:04:05"))
	return string(out), err
}

// UserInfo — пользователь для показа: секрет только маской.
type UserInfo struct {
	Name         string `json:"name"`
	SecretMasked string `json:"secret_masked"`
}

// Status — состояние telemt для панели. Секретов не содержит.
type Status struct {
	Installed   bool   `json:"installed"`
	Version     string `json:"version,omitempty"`
	ActiveState string `json:"active_state,omitempty"`
	NRestarts   int    `json:"n_restarts"`
	// RestartsGrewAt — когда агент заметил рост NRestarts; панель сравнивает
	// с тем, что видела раньше, и поднимает ошибку и уведомление.
	RestartsGrewAt *time.Time `json:"restarts_grew_at,omitempty"`
	Port           int        `json:"port,omitempty"`
	Domain         string     `json:"domain,omitempty"`
	Users          []UserInfo `json:"users"`
	Error          string     `json:"error,omitempty"` // что не удалось прочитать
}

// Installed — есть и бинарник, и конфиг.
func (e *Env) Installed() bool {
	_, err1 := os.Stat(e.binary())
	_, err2 := os.Stat(e.config())
	return err1 == nil && err2 == nil
}

// Status собирает состояние. Сбой отдельной части не обрывает ответ: он
// попадает в Error, остальное заполнено.
func (e *Env) Status(ctx context.Context) Status {
	st := Status{Users: []UserInfo{}}
	if !e.Installed() {
		return st
	}
	st.Installed = true
	var errs []string
	if v, err := e.Version(ctx); err != nil {
		errs = append(errs, "версия: "+err.Error())
	} else {
		st.Version = v
	}
	if a, n, err := e.UnitState(ctx); err != nil {
		errs = append(errs, "служба: "+err.Error())
	} else {
		st.ActiveState, st.NRestarts = a, n
	}
	if doc, err := e.ReadConfig(); err != nil {
		errs = append(errs, "конфиг: "+err.Error())
	} else {
		st.Port, st.Domain = doc.Port(), doc.TLSDomain()
		for _, u := range doc.Users() {
			st.Users = append(st.Users, UserInfo{Name: u.Name, SecretMasked: MaskSecret(u.Secret)})
		}
	}
	st.Error = strings.Join(errs, "; ")
	return st
}

// LinkInfo — ссылки пользователя; единственное место, где секрет виден целиком.
type LinkInfo struct {
	Name    string `json:"name"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
	Link    string `json:"link"`
	WebLink string `json:"web_link"`
}

// UserLink собирает ссылку пользователя. server — адрес, который увидит
// клиент Telegram; пусто — берётся адрес из ссылки в журнале telemt.
func (e *Env) UserLink(ctx context.Context, name, server string) (LinkInfo, error) {
	doc, err := e.ReadConfig()
	if err != nil {
		return LinkInfo{}, err
	}
	var user *User
	for _, u := range doc.Users() {
		if u.Name == name {
			u := u
			user = &u
		}
	}
	if user == nil {
		return LinkInfo{}, fmt.Errorf("пользователя %q нет", name)
	}
	domain, port := doc.TLSDomain(), doc.Port()
	if domain == "" || port == 0 {
		return LinkInfo{}, errors.New("в конфиге нет tls_domain или порта")
	}
	if server == "" {
		j, _ := e.Journal(ctx, e.now().Add(-30*24*time.Hour))
		for _, k := range JournalLinks(j) {
			if k.Server != "" {
				server = k.Server
			}
		}
	}
	if server == "" {
		return LinkInfo{}, errors.New("адрес сервера не указан и не виден в журнале telemt")
	}
	return LinkInfo{
		Name: name, Server: server, Port: port,
		Link:    Link(server, port, user.Secret, domain),
		WebLink: WebLink(server, port, user.Secret, domain),
	}, nil
}

// Watcher замечает рост NRestarts между опросами: Restart=always прячет
// падающую службу, а счётчик перезапусков растёт.
type Watcher struct {
	mu   sync.Mutex
	last int
	seen bool
	grew *time.Time
}

// Observe принимает очередное значение NRestarts и возвращает момент
// последнего замеченного роста (nil — роста не было).
func (w *Watcher) Observe(n int, now time.Time) *time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen && n > w.last {
		t := now
		w.grew = &t
	}
	w.last, w.seen = n, true
	return w.grew
}

// CheckPort — порт свободен для прослушивания TCP.
func (e *Env) CheckPort(port int) error {
	if e.PortFree != nil {
		return e.PortFree(port)
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("порт %d занят: %w", port, err)
	}
	return ln.Close()
}

// BusyPorts — какие из портов заняты (80, 443, 504, 508 бывают заняты OpenVPN и nginx).
func (e *Env) BusyPorts(ports ...int) map[int]bool {
	out := map[int]bool{}
	for _, p := range ports {
		out[p] = e.CheckPort(p) != nil
	}
	return out
}

func netResolver(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}
