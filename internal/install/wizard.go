package install

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

// ErrNotYet — тип установки, которого в этой версии ещё нет.
var ErrNotYet = errors.New("этот тип установки появится в следующей версии")

// ErrAdminExists — CreateAdmin: такой логин уже занят.
var ErrAdminExists = errors.New("администратор с таким логином уже есть")

// Host — всё, что мастер читает из системы и меняет в ней. Каждое действие
// — поле-функция: в тестах подменяется, и видно, что до подтверждения не
// вызвано ни одно изменяющее.
type Host struct {
	// Чтение.
	Geteuid     func() int
	ReadFile    func(path string) ([]byte, error)
	Stat        func(path string) (fs.FileInfo, error)
	HasSystemd  func() bool
	PortBusy    func(port int) bool
	Port80Owner func() string // "" — свободен, "nginx" или имя процесса
	Fetch       func(url string) (string, error)
	// CertNotAfter — срок сертификата (nil — не проверять).
	CertNotAfter func(file string) (time.Time, error)
	// Resolve — адреса домена (nil — не проверять, куда он указывает).
	Resolve     func(host string) ([]string, error)
	AdminExists func(login string) bool
	LoadConfig  func() (config.Config, error)

	// Изменения.
	MkLayout        func() error
	CopyBinary      func() error
	WriteConfig     func(config.Config) error
	EnsureNodeToken func() error
	WriteSecrets    func(kv map[string]string) error
	WriteInstallEnv func(data []byte) error
	WriteUnit       func(name, content string) error
	InstallHook     func() error
	Systemctl       func(args ...string) error
	WaitAgent       func() error
	WaitPanel       func(url string) error
	CreateAdmin     func(login, password string, mustChange bool) error
	OpenFirewall    func(port int) error
}

// Wizard — мастер установки (azpanel install).
type Wizard struct {
	In          *bufio.Reader
	Out         io.Writer
	Interactive bool
	// ReadSecret — ввод без эха; nil — строка из In.
	ReadSecret func() (string, error)
	Getenv     func(string) string
	Flags      map[string]string // ключ ответа → значение из флагов
	Host       Host
	Nginx      *Nginx
	TLS        *TLS
	// Установка с --yes: подтверждение не спрашивается.
	AssumeYes bool
	// Experimental — спрашивать про отложенные возможности (Telegram-бота,
	// п. 9); пока выключено, вопрос не задаётся, а ответы о Telegram
	// игнорируются.
	Experimental bool

	AntiZapretDir string
	ScriptsDir    string
	// NewPassword — генератор пароля; nil — настоящий.
	NewPassword func() (string, error)
}

type step struct {
	name string
	do   func() error
}

// Mode-слова для вывода.
var modeTitles = []struct{ mode, title string }{
	{ModePanelNode, "azpanel (AntiZapret на этом же сервере)"},
	{ModeNode, "только управление AntiZapret (для azpanel на другом сервере)"},
	{ModeProxy, "только прокси-агент"},
	{ModePanel, "только веб-интерфейс azpanel"},
}

func modeTitle(mode string) string {
	for _, m := range modeTitles {
		if m.mode == mode {
			return m.title
		}
	}
	return mode
}

func (w *Wizard) printf(format string, a ...any) { fmt.Fprintf(w.Out, format, a...) }

// Run — весь мастер: вопросы, итог, подтверждение, применение.
func (w *Wizard) Run() error {
	a, set, err := w.preset()
	if err != nil {
		return err
	}
	if !w.Interactive {
		if miss := a.Missing(set); len(miss) > 0 {
			return errors.New("не хватает обязательных ответов:\n  " + strings.Join(miss, "\n  "))
		}
	}
	if !w.Experimental {
		a.Telegram, a.TelegramToken, a.TelegramChat = false, "", 0 // бот отложен: ответы о нём не берутся
	}
	if a.Mode != ModePanelNode {
		return fmt.Errorf("%w: «%s». Ничего не изменено", ErrNotYet, modeTitle(a.Mode))
	}
	if err := w.preflight(a); err != nil {
		return err
	}
	servers, _ := FindServers(w.Nginx.dir())
	if a.Address == "" {
		if ip, err := ExternalIP(w.Host.Fetch); err == nil {
			a.Address = ip
			if w.Interactive {
				w.printf("Внешний IP сервера: %s\n", ip)
			}
		} else if w.Interactive {
			w.printf("Внешний IP определить не удалось (%v).\n", err)
		}
	}
	if w.Interactive {
		// IP спрашивается, только если определить его не удалось.
		if a.Address == "" {
			if err := w.askKey(&a, KeyAddress, "Внешний IP сервера", ""); err != nil {
				return err
			}
		}
		for _, ask := range []func(*Answers) error{w.askDomain, w.askHTTPS} {
			if err := ask(&a); err != nil {
				return err
			}
		}
		if err := w.askAccess(&a, servers); err != nil {
			return err
		}
	}
	p, err := w.plan(&a, servers)
	if err != nil {
		return err
	}
	if w.Interactive {
		if len(p.bakFiles) > 0 {
			if p.moveBak, err = w.yesno("Перенести их в "+w.Nginx.backupDir(), true); err != nil {
				return err
			}
		}
		if err := w.askAdmin(&a, p); err != nil {
			return err
		}
		if err := w.askExtras(&a); err != nil {
			return err
		}
		// Пароль и токен могли появиться только сейчас.
		if err := a.Problem(); err != nil {
			return err
		}
	}
	if err := p.finish(&a); err != nil {
		return err
	}
	w.summary(a, p)
	if w.Interactive && !w.AssumeYes {
		ok, err := w.yesno("Применить? Сейчас на сервере ничего не изменено", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("установка отменена, ничего не изменено")
		}
	}
	var done []string
	for _, s := range p.steps {
		w.printf("→ %s\n", s.name)
		if err := s.do(); err != nil {
			w.printf("\nУстановка прервана на шаге «%s». Уже выполнено: %s.\n", s.name, doneList(done))
			w.printf("Исправьте причину и повторите azpanel install (шаги идемпотентны) или уберите сделанное: azpanel uninstall.\n")
			return fmt.Errorf("%s: %w", s.name, err)
		}
		done = append(done, s.name)
	}
	w.report(a, p)
	return nil
}

// preset: умолчания, поверх install.env, поверх окружения и флагов.
func (w *Wizard) preset() (Answers, []string, error) {
	a := DefaultAnswers(paths.Backup())
	var set []string
	if data, err := w.Host.ReadFile(filepath.Join(paths.Etc(), "install.env")); err == nil {
		kv, err := ParseEnvFile(data)
		if err != nil {
			return a, nil, err
		}
		s, err := a.Overlay(kv)
		if err != nil {
			return a, nil, fmt.Errorf("install.env: %w", err)
		}
		set = append(set, s...)
	}
	env := map[string]string{}
	for _, k := range AnswerKeys {
		if v := w.Getenv(EnvName(k)); v != "" {
			env[k] = v
		}
	}
	s, err := a.Overlay(env)
	if err != nil {
		return a, nil, err
	}
	set = append(set, s...)
	s, err = a.Overlay(w.Flags)
	if err != nil {
		return a, nil, err
	}
	return a, append(set, s...), nil
}

// ------------------------------------------------------------------ проверки

// CheckOS проверяет содержимое /etc/os-release: Ubuntu 24.04+ или Debian 13+.
func CheckOS(osRelease string) error {
	kv := map[string]string{}
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	major, minor := 0, 0
	majS, minS, _ := strings.Cut(kv["VERSION_ID"], ".")
	major, _ = strconv.Atoi(majS)
	minor, _ = strconv.Atoi(minS)
	switch kv["ID"] {
	case "ubuntu":
		if major > 24 || major == 24 && minor >= 4 {
			return nil
		}
	case "debian":
		if major >= 13 {
			return nil
		}
	default:
		return fmt.Errorf("система %q не поддерживается: нужна Ubuntu 24.04+ или Debian 13+", kv["ID"])
	}
	return fmt.Errorf("версия %s %s не поддерживается: нужна Ubuntu 24.04+ или Debian 13+", kv["ID"], kv["VERSION_ID"])
}

func (w *Wizard) preflight(a Answers) error {
	var errs []error
	if w.Host.Geteuid() != 0 {
		errs = append(errs, errors.New("нужны права root: запустите от root"))
	}
	if data, err := w.Host.ReadFile("/etc/os-release"); err != nil {
		errs = append(errs, fmt.Errorf("/etc/os-release: %w", err))
	} else if err := CheckOS(string(data)); err != nil {
		errs = append(errs, err)
	}
	if !w.Host.HasSystemd() {
		errs = append(errs, errors.New("нужен systemd"))
	}
	if a.Mode == ModePanelNode || a.Mode == ModeNode {
		if _, err := w.Host.Stat(filepath.Join(w.AntiZapretDir, "client.sh")); err != nil {
			errs = append(errs, fmt.Errorf("AntiZapret не найден: нет %s", filepath.Join(w.AntiZapretDir, "client.sh")))
		}
		if _, err := w.Host.Stat(w.ScriptsDir); err != nil {
			errs = append(errs, fmt.Errorf("нет каталога скриптов OpenVPN %s", w.ScriptsDir))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("проверки не пройдены, ничего не изменено:\n  %w", joinLines(errs))
	}
	return nil
}

type linesError []error

func (l linesError) Error() string {
	parts := make([]string, len(l))
	for i, e := range l {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "\n  ")
}

func joinLines(errs []error) error { return linesError(errs) }

// ipSources — источники внешнего IP; верен ответ большинства.
var ipSources = []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://ipv4.icanhazip.com"}

// ExternalIP спрашивает три источника по HTTPS и берёт ответ, совпавший у
// двух из них.
func ExternalIP(fetch func(url string) (string, error)) (string, error) {
	votes := map[string]int{}
	for _, u := range ipSources {
		body, err := fetch(u)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(body))
		if err != nil {
			continue
		}
		votes[ip.String()]++
	}
	for ip, n := range votes {
		if n >= 2 {
			return ip, nil
		}
	}
	return "", errors.New("источники не дали общего ответа")
}

// ------------------------------------------------------------------- вопросы

func (w *Wizard) readLine() (string, error) {
	line, err := w.In.ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("ввод закончился, ничего не изменено")
	}
	return strings.TrimSpace(line), nil
}

// ask задаёт вопрос; Enter принимает умолчание.
func (w *Wizard) ask(label, def string) (string, error) {
	if def != "" {
		w.printf("%s [%s]: ", label, def)
	} else {
		w.printf("%s: ", label)
	}
	v, err := w.readLine()
	if err != nil {
		return "", err
	}
	if v == "" {
		v = def
	}
	return v, nil
}

// askKey спрашивает, пока ответ не пройдёт проверку ключа. Пустой ответ
// при пустом умолчании оставляет ответ незаданным.
func (w *Wizard) askKey(a *Answers, key, label, def string) error {
	for {
		v, err := w.ask(label, def)
		if err != nil {
			return err
		}
		if v == "" {
			return nil
		}
		if err := a.set(key, v); err != nil {
			w.printf("  %v\n", err)
			continue
		}
		return nil
	}
}

func (w *Wizard) yesno(label string, def bool) (bool, error) {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	for {
		w.printf("%s [%s]: ", label, d)
		v, err := w.readLine()
		if err != nil {
			return false, err
		}
		if v == "" {
			return def, nil
		}
		if b, err := parseBool(v); err == nil {
			return b, nil
		}
		w.printf("  нужно да или нет\n")
	}
}

// choose печатает пронумерованные варианты и возвращает индекс.
func (w *Wizard) choose(label string, options []string, def int) (int, error) {
	w.printf("%s\n", label)
	for i, o := range options {
		w.printf("  %d) %s\n", i+1, o)
	}
	for {
		v, err := w.ask("Выбор", strconv.Itoa(def+1))
		if err != nil {
			return 0, err
		}
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		w.printf("  введите число от 1 до %d\n", len(options))
	}
}

func (w *Wizard) secret(label string) (string, error) {
	w.printf("%s: ", label)
	if w.ReadSecret != nil {
		v, err := w.ReadSecret()
		w.printf("\n")
		return strings.TrimRight(v, "\r\n"), err
	}
	return w.readLine()
}

// Вопросы мастера: домен, HTTPS, как открывать (по порту — и порт),
// администратор. Всё остальное — умолчания: они видны в итоге и меняются
// потом в «Настройках» или переменными AZPANEL_*.

// askPort — порт своего сайта azpanel (только «по порту»). Занятый порт не
// принимается: на нём уже чей-то сайт или служба; свой сайт azpanel от
// прошлой установки не в счёт.
func (w *Wizard) askPort(a *Answers) error {
	for {
		v, err := w.ask("   Порт azpanel", strconv.Itoa(a.Port))
		if err != nil {
			return err
		}
		n, err := atoiRange(strings.TrimSpace(v), 1, 65535)
		if err != nil {
			w.printf("  %v\n", err)
			continue
		}
		if w.Host.PortBusy(n) && !w.ownSiteOn(n) {
			w.printf("  порт %d занят, выберите другой\n", n)
			continue
		}
		a.Port = n
		return nil
	}
}

// ownSiteOn — порт занят своим же сайтом azpanel от прошлой установки.
func (w *Wizard) ownSiteOn(port int) bool {
	if _, err := w.Host.Stat(path.Join(w.Nginx.dir(), ownPortLink)); err != nil {
		return false
	}
	servers, _ := FindServers(w.Nginx.dir())
	for _, s := range servers {
		if isOwnSite(s) && s.ListensOn(port) {
			return true
		}
	}
	return false
}

// isOwnSite — server из своего файла azpanel (sites-available/azpanel).
func isOwnSite(s NginxServer) bool {
	return path.Base(filepath.ToSlash(s.File)) == path.Base(ownPortFile)
}

// askDomain — вопрос 1. Домен, указывающий на другой сервер, не принимается:
// ссылки по нему сюда не попадут.
func (w *Wizard) askDomain(a *Answers) error {
	label := "1. Домен (пусто — по IP)"
	if a.Address != "" {
		label = "1. Домен (пусто — по IP " + a.Address + ")"
	}
	if a.Domain != "" {
		label += ", «-» — без домена"
	}
	for {
		v, err := w.ask(label, a.Domain)
		if err != nil {
			return err
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || v == "-" {
			a.Domain = ""
			return nil
		}
		if !domainRe.MatchString(v) {
			w.printf("  %q: неверное доменное имя\n", v)
			continue
		}
		a.Domain = v
		if ips := w.domainElsewhere(a); len(ips) > 0 {
			w.printf("  Домен %s указывает на %s, а не на этот сервер (%s): ссылки по нему сюда не попадут.\n  Введите другой или оставьте пустым — тогда по IP.\n",
				v, strings.Join(ips, ", "), a.Address)
			a.Domain = ""
			continue
		}
		return nil
	}
}

// askHTTPS — вопрос 2.
func (w *Wizard) askHTTPS(a *Answers) error {
	var err error
	if a.HTTPS, err = w.yesno("2. Включить HTTPS", a.HTTPS); err != nil {
		return err
	}
	if !a.HTTPS {
		w.printf("  Без HTTPS логин и пароль идут по сети открытым текстом, браузер пометит страницу «Не защищено».\n")
	}
	return nil
}

// scheme — http или https по ответу.
func (a Answers) scheme() string {
	if a.HTTPS {
		return "https"
	}
	return "http"
}

// host — по чему открывать azpanel: домен, иначе внешний IP.
func (a Answers) host() string {
	if a.Domain != "" {
		return a.Domain
	}
	return a.Address
}

// siteCandidates — сайты nginx, в которые можно встроить раздел /azpanel/:
// не свой сайт azpanel; для HTTPS — с ssl, без — с портом без ssl; с
// доменом — с этим доменом в server_name.
func siteCandidates(servers []NginxServer, a Answers) []NginxServer {
	var out []NginxServer
	for _, s := range servers {
		if isOwnSite(s) || sitePort(s, a.HTTPS) == 0 || (a.Domain != "" && !s.NamedFor(a.Domain)) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// sitePort — порт сайта, по которому откроется раздел: для HTTPS — с ssl
// (443, если он есть), без — без ssl (80, если есть); 0 — такого нет.
func sitePort(s NginxServer, https bool) int {
	std, found := 80, 0
	if https {
		std = 443
	}
	for _, p := range s.Ports() {
		if s.SSLOn(p) != https {
			continue
		}
		if p == std {
			return p
		}
		if found == 0 {
			found = p
		}
	}
	return found
}

// siteFor — сайт для раздела /azpanel/: заданный (NGINX_FILE), иначе из
// подходящих — на стандартном порту, потом default_server.
func siteFor(servers []NginxServer, a Answers) (NginxServer, bool) {
	best, score := NginxServer{}, -1
	for _, s := range siteCandidates(servers, a) {
		if a.NginxFile != "" {
			if s.File == a.NginxFile {
				return s, true
			}
			continue
		}
		p := sitePort(s, a.HTTPS)
		n := 0
		if p == 443 || p == 80 {
			n += 2
		}
		if s.defaultServer(p) {
			n++
		}
		if n > score {
			best, score = s, n
		}
	}
	return best, score >= 0
}

// siteURL — адрес раздела /azpanel/ в сайте s.
func siteURL(s NginxServer, a Answers) string {
	return publicURL(a.scheme(), a.host(), sitePort(s, a.HTTPS)) + DefaultBasePath
}

// askAccess — вопрос 3: либо по порту (свой сайт azpanel, корень адреса),
// либо по пути — разделом /azpanel/ одного из ваших сайтов nginx. Вместе
// не бывает. По порту следом спрашивается порт.
func (w *Wizard) askAccess(a *Answers, servers []NginxServer) error {
	sites := siteCandidates(servers, *a)
	opts := []string{fmt.Sprintf("по порту: %s://%s:<порт>/ — свой сайт azpanel, порт спрошу следующим (по умолчанию %d)",
		a.scheme(), bracketHost(a.host()), DefaultPort)}
	def := 0
	for i, s := range sites {
		opts = append(opts, fmt.Sprintf("по пути: %s — раздел вашего сайта %s", siteURL(s, *a), s.File))
		if a.Access == AccessPath && (a.NginxFile == s.File || (a.NginxFile == "" && def == 0)) {
			def = i + 1
		}
	}
	if len(sites) == 0 {
		w.printf("  По пути (/azpanel/) — некуда: в nginx нет сайта%s с %s.\n", forDomain(a.Domain), a.scheme())
	}
	i, err := w.choose("3. Как открывать azpanel", opts, def)
	if err != nil {
		return err
	}
	if i == 0 {
		a.Access, a.NginxFile = AccessPort, ""
		return w.askPort(a)
	}
	a.Access, a.NginxFile = AccessPath, sites[i-1].File
	return nil
}

func forDomain(d string) string {
	if d == "" {
		return ""
	}
	return " с именем " + d
}

func bracketHost(h string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

func (w *Wizard) generatePassword() (string, error) {
	if w.NewPassword != nil {
		return w.NewPassword()
	}
	return GeneratePassword()
}

// askAdmin — вопрос 4. Сгенерированный пароль панель попросит сменить при
// первом входе, свой — нет.
func (w *Wizard) askAdmin(a *Answers, p *plan) error {
	w.printf("4. Администратор\n")
	if err := w.askKey(a, KeyAdmin, "Логин", a.Admin); err != nil {
		return err
	}
	if w.Host.AdminExists(a.Admin) {
		p.adminExists = true
		w.printf("  Пользователь %s уже есть: пароль не меняется (сменить — команда azpanel)\n", a.Admin)
		return nil
	}
	p.adminExists = false
	for {
		pw, err := w.secret("Пароль (Enter — сгенерировать)")
		if err != nil {
			return err
		}
		if pw == "" {
			if pw, err = w.generatePassword(); err != nil {
				return err
			}
			a.AdminPassword, a.MustChange = pw, true
			p.generated = true
			w.printf("  Пароль: %s\n  Запишите его: он будет показан ещё раз в конце и нигде не сохраняется.\n", pw)
			return nil
		}
		if err := ValidatePassword(a.Admin, pw); err != nil {
			w.printf("  %v\n", err)
			continue
		}
		again, err := w.secret("Повторите пароль")
		if err != nil {
			return err
		}
		if again != pw {
			w.printf("  пароли не совпадают\n")
			continue
		}
		a.AdminPassword, a.MustChange = pw, false
		return nil
	}
}

// askExtras — Telegram, только пока он включён (panel.experimental).
func (w *Wizard) askExtras(a *Answers) error {
	if !w.Experimental {
		return nil
	}
	var err error
	w.printf("Telegram (необязательно; потом меняется в «Настройках»)\n")
	if a.Telegram, err = w.yesno("Включить бота", a.Telegram); err != nil {
		return err
	}
	if a.Telegram {
		for a.TelegramToken == "" {
			t, err := w.secret("Токен бота")
			if err != nil {
				return err
			}
			a.TelegramToken = t
		}
		if err := w.askKey(a, KeyTgChat, "ID чата для уведомлений", chatDef(a.TelegramChat)); err != nil {
			return err
		}
	}
	return nil
}

func chatDef(id int64) string {
	if id == 0 {
		return ""
	}
	return strconv.FormatInt(id, 10)
}

// firewallPorts — какие порты открыть в файрволе и у хостера.
func firewallPorts(a Answers, p *plan) []string {
	switch {
	case a.Access == AccessPort:
		return []string{fmt.Sprintf("Откройте TCP %d: по нему открывается azpanel.", a.Port)}
	case a.Access == AccessPath:
		return []string{"Новых портов открывать не нужно: azpanel — раздел вашего сайта."}
	}
	return []string{"azpanel слушает только 127.0.0.1: открывать нечего."}
}

// GeneratePassword — 16 знаков: буквы и цифры, обязательно и те и другие.
func GeneratePassword() (string, error) {
	const letters = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
	const digits = "23456789"
	pick := func(set string) (byte, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return 0, err
		}
		return set[n.Int64()], nil
	}
	for {
		b := make([]byte, 16)
		for i := range b {
			c, err := pick(letters + digits)
			if err != nil {
				return "", err
			}
			b[i] = c
		}
		if s := string(b); strings.ContainsAny(s, letters) && strings.ContainsAny(s, digits) {
			return s, nil
		}
	}
}

// -------------------------------------------------------------------- план

type plan struct {
	steps       []step
	lines       []string // что будет создано и изменено
	server      NginxServer
	acme        ACMEPlan
	cfg         config.Config
	url         string
	adminExists bool
	generated   bool
	listen      string
	needCert    bool // свой сайт с HTTPS: сертификат выпускается шагом установки
	// bakFiles — копии *.bak-* в sites-enabled (nginx читает их как конфиги);
	// moveBak — перенести их в каталог копий мастера.
	bakFiles []string
	moveBak  bool
	// dropOld — прежняя раскладка в nginx не совпадает с новой: строка
	// include в прежнем сайте (dropFile) и свой сайт azpanel убираются до
	// новой.
	dropOld  bool
	dropFile string
	// finishFn достраивает конфиг и шаги по ответам, полученным после plan.
	finishFn func(a *Answers, p *plan) error
}

func (p *plan) finish(a *Answers) error { return p.finishFn(a, p) }

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// publicURL — внешний адрес azpanel без пути: стандартный порт схемы (443
// для https, 80 для http) не пишется, адрес IPv6 берётся в скобки.
func publicURL(scheme, host string, port int) string {
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return scheme + "://" + bracketHost(host)
	}
	return scheme + "://" + hostPort(host, port)
}

// domainElsewhere — домен указывает не на этот сервер: возвращает адреса,
// на которые он ведёт. Пусто — совпал, не разрешился или проверить нечем.
func (w *Wizard) domainElsewhere(a *Answers) []string {
	if a.Domain == "" || a.Address == "" || w.Host.Resolve == nil {
		return nil
	}
	ips, err := w.Host.Resolve(a.Domain)
	if err != nil || len(ips) == 0 {
		return nil
	}
	for _, ip := range ips {
		if ip == a.Address {
			return nil
		}
	}
	return ips
}

// plan проверяет ответы и собирает шаги применения. Изменяющих вызовов не
// делает: только чтение системы.
func (w *Wizard) plan(a *Answers, servers []NginxServer) (*plan, error) {
	p := &plan{}
	prevFile := a.NginxFile // из install.env прошлой установки
	if err := a.Problem(); err != nil && !w.Interactive {
		return nil, err
	}
	cfg, err := w.Host.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("текущий конфиг: %w", err)
	}
	p.listen = cfg.Panel.Listen
	if a.Access == AccessPath || a.Access == AccessPort {
		cfg.Panel.BasePath, cfg.Panel.PublicURL = "", ""
	}
	host := a.Domain
	if host == "" {
		host = a.Address
	}

	switch a.Access {
	case AccessPath:
		cfg.Panel.BasePath = DefaultBasePath
		s, ok := siteFor(servers, *a)
		if !ok {
			if a.NginxFile != "" {
				return nil, fmt.Errorf("в nginx нет сайта %s%s с %s для раздела %s: откройте azpanel по порту (AZPANEL_ACCESS=port)", a.NginxFile, forDomain(a.Domain), a.scheme(), DefaultBasePath)
			}
			return nil, fmt.Errorf("в nginx нет сайта%s с %s для раздела %s: откройте azpanel по порту (AZPANEL_ACCESS=port)", forDomain(a.Domain), a.scheme(), DefaultBasePath)
		}
		// Раздел в существующем сайте: сертификат и порт — его.
		p.server = s
		a.NginxFile = s.File
		a.TLS, a.CertPath, a.KeyPath = "", "", ""
		cfg.Panel.PublicURL = publicURL(a.scheme(), host, sitePort(s, a.HTTPS))
		p.lines = append(p.lines,
			fmt.Sprintf("nginx: раздел %s в вашем сайте %s (server_name %s): одна строка include, фрагмент %s; копия файла в %s; после nginx -t — reload",
				DefaultBasePath, s.File, strings.Join(s.ServerName, " "), SnippetPath, w.Nginx.backupDir()))
		if a.HTTPS {
			p.lines = append(p.lines, w.siteCertNotes(s, *a)...)
		}
		p.url = cfg.Panel.PublicURL + DefaultBasePath
	case AccessPort:
		if _, err := w.Host.Stat(path.Join(w.Nginx.dir(), ownPortLink)); err != nil && w.Host.PortBusy(a.Port) {
			return nil, fmt.Errorf("порт %d занят: выберите другой", a.Port)
		}
		a.NginxFile = ""
		cfg.Panel.PublicURL = publicURL(a.scheme(), host, a.Port)
		p.url = cfg.Panel.PublicURL + "/"
		p.lines = append(p.lines,
			fmt.Sprintf("nginx: свой сайт azpanel на порту %d (%s, ссылка в sites-enabled); ваши сайты не меняются; после nginx -t — reload", a.Port, path.Join(w.Nginx.dir(), ownPortFile)))
		if a.HTTPS {
			if err := w.planCert(a, p, servers); err != nil {
				return nil, err
			}
		} else {
			a.TLS, a.CertPath, a.KeyPath = "", "", ""
		}
	default:
		a.Access = AccessLocal
		// public_url и base_path, заданные в «Настройках», повторная
		// установка в режиме local не стирает.
		p.url = "http://" + cfg.Panel.Listen + normalizeBase(cfg.Panel.BasePath)
		p.lines = append(p.lines, "azpanel слушает только "+cfg.Panel.Listen+" (доступ через SSH-туннель), nginx не меняется")
	}

	if a.Access == AccessPath || a.Access == AccessPort {
		if ips := w.domainElsewhere(a); len(ips) > 0 {
			p.lines = append(p.lines, fmt.Sprintf(
				"ВНИМАНИЕ: домен %s указывает на %s, а не на этот сервер (%s): azpanel и ссылки портала по нему сюда не попадут. Оставьте домен пустым — будет использован IP",
				a.Domain, strings.Join(ips, ", "), a.Address))
		}
		p.bakFiles = w.Nginx.OldBackups()
		if len(p.bakFiles) > 0 {
			w.printf("Внимание: в %s лежат копии конфигов, которые nginx читает как рабочие (дубли server-блоков):\n", path.Join(w.Nginx.dir(), "sites-enabled"))
			for _, f := range p.bakFiles {
				w.printf("  %s\n", f)
			}
			if !w.Interactive {
				w.printf("Перенесите их вручную в %s (в неинтерактивном режиме мастер их не трогает).\n", w.Nginx.backupDir())
			}
		}
	}
	if _, err := w.Nginx.ReadFile(prevFile); err == nil && prevFile != "" && prevFile != a.NginxFile {
		p.dropOld, p.dropFile = true, prevFile
		p.lines = append(p.lines, fmt.Sprintf("nginx: раздел %s убирается из прежнего сайта %s (строка include)", DefaultBasePath, prevFile))
	}
	// По пути свой сайт azpanel не нужен: прежний (в том числе с разделом
	// /azpanel/ на своём порту от старых версий) снимается.
	if _, err := w.Host.Stat(path.Join(w.Nginx.dir(), ownPortLink)); err == nil && a.Access == AccessPath {
		p.dropOld = true
		p.lines = append(p.lines, "nginx: свой сайт azpanel от прошлой установки убирается — теперь azpanel раздел вашего сайта")
	}
	p.cfg = cfg
	p.adminExists = w.Host.AdminExists(a.Admin)
	p.finishFn = w.buildSteps
	if !w.Interactive {
		w.fillAdminPassword(a, p)
		if p.generated || a.AdminPassword != "" {
			if err := w.checkPassword(a, p); err != nil {
				return nil, err
			}
		}
		if err := a.Problem(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (w *Wizard) fillAdminPassword(a *Answers, p *plan) {
	if p.adminExists || a.AdminPassword != "" {
		return
	}
	pw, err := w.generatePassword()
	if err == nil {
		a.AdminPassword, p.generated = pw, true
	}
}

func (w *Wizard) checkPassword(a *Answers, p *plan) error {
	if p.generated || p.adminExists {
		return nil
	}
	return ValidatePassword(a.Admin, a.AdminPassword)
}

// planCert выбирает сертификат для своего сайта azpanel и проверяет всё,
// что для него нужно, без изменений: свой (AZPANEL_TLS=own) — как задан;
// домен — существующий Let's Encrypt или новый; IP — самоподписанный.
func (w *Wizard) planCert(a *Answers, p *plan, servers []NginxServer) error {
	p.needCert = true
	if a.TLS != TLSOwn {
		switch {
		case a.Domain == "":
			a.TLS = TLSSelfSigned
		default:
			if _, _, ok := w.TLS.ExistingLetsEncrypt(a.Domain); ok {
				a.TLS = TLSExisting
			} else {
				a.TLS = TLSLetsEncrypt
			}
		}
	}
	switch a.TLS {
	case TLSExisting:
		cert, key, ok := w.TLS.ExistingLetsEncrypt(a.Domain)
		if !ok {
			return fmt.Errorf("нет сертификата Let's Encrypt для %q в %s", a.Domain, LetsEncryptDir)
		}
		a.CertPath, a.KeyPath = cert, key
		p.lines = append(p.lines, "HTTPS: существующий сертификат "+cert)
	case TLSOwn:
		for _, f := range []string{a.CertPath, a.KeyPath} {
			if _, err := w.Host.Stat(f); err != nil {
				return fmt.Errorf("файл сертификата %q не найден", f)
			}
		}
		p.lines = append(p.lines, "HTTPS: свой сертификат "+a.CertPath)
	case TLSLetsEncrypt:
		if a.Domain == "" {
			return errors.New("для Let's Encrypt нужен домен")
		}
		plan, err := PlanACME(servers, a.Domain, w.Host.Port80Owner())
		if err != nil {
			return err
		}
		p.acme = plan
		p.lines = append(p.lines, "HTTPS: certbot выпустит сертификат Let's Encrypt для "+a.Domain)
	case TLSSelfSigned:
		p.lines = append(p.lines, "HTTPS: самоподписанный сертификат на "+a.host()+" ("+filepath.Join(paths.Etc(), "tls")+"): браузер покажет предупреждение — с доменом будет Let's Encrypt")
	}
	return nil
}

// buildSteps собирает порядок применения: каталоги, бинарник, конфиг,
// секреты, юниты, хук, сертификат, nginx, пользователь, запуск.
func (w *Wizard) buildSteps(a *Answers, p *plan) error {
	if a.Telegram {
		t := &p.cfg.Telegram
		t.Enabled = true
		t.NotifyChats = []int64{a.TelegramChat}
		t.BackupEveryDays = a.BackupEveryDays
		if a.BackupEveryDays > 0 {
			t.BackupChats = []int64{a.TelegramChat}
		}
	}
	if err := p.cfg.Validate(); err != nil {
		return fmt.Errorf("конфиг по ответам неверен: %w", err)
	}
	h := w.Host
	add := func(name string, do func() error) { p.steps = append(p.steps, step{name, do}) }
	add("каталоги", h.MkLayout)
	add("бинарник", h.CopyBinary)
	add("конфиг", func() error { return h.WriteConfig(p.cfg) })
	add("секреты", func() error {
		if err := h.EnsureNodeToken(); err != nil {
			return fmt.Errorf("токен узла: %w", err)
		}
		if a.Telegram && a.TelegramToken != "" {
			return h.WriteSecrets(map[string]string{secrets.TelegramBotToken: a.TelegramToken})
		}
		return nil
	})
	add("юниты", func() error {
		if err := h.WriteUnit(nodeUnitName, NodeUnit(paths.Binary())); err != nil {
			return err
		}
		return h.WriteUnit(panelUnitName, PanelUnit(paths.Binary()))
	})
	add("хук лимита", h.InstallHook)
	if p.needCert {
		add("сертификат", func() error { return w.issueCert(a, p) })
	}
	if p.dropOld {
		add("nginx: прежняя раскладка", func() error { return w.Nginx.Disable(p.dropFile) })
	}
	if p.moveBak {
		add("перенос копий .bak из sites-enabled", func() error { return w.Nginx.MoveBackups(p.bakFiles) })
	}
	switch {
	case a.Access == AccessPath:
		add("nginx", func() error { return w.Nginx.Enable(p.server, DefaultBasePath, p.listen) })
	case a.Access == AccessPort:
		add("nginx", func() error {
			return w.Nginx.EnableOwnPort(a.Port, a.CertPath, a.KeyPath, a.Domain, "", p.listen)
		})
	}
	if !p.adminExists {
		add("администратор в базе", func() error {
			err := h.CreateAdmin(a.Admin, a.AdminPassword, a.MustChange)
			if errors.Is(err, ErrAdminExists) {
				p.adminExists = true
				return nil
			}
			return err
		})
	}
	add("ответы (install.env)", func() error { return h.WriteInstallEnv(a.EnvFile()) })
	add("запуск", func() error {
		for _, args := range [][]string{{"daemon-reload"}, {"enable", "azpanel-node"}, {"enable", "azpanel-panel"}, {"restart", "azpanel-node"}} {
			if err := h.Systemctl(args...); err != nil {
				return err
			}
		}
		if err := h.WaitAgent(); err != nil {
			return fmt.Errorf("агент не ответил: %w; журнал — %s", err, filepath.Join(paths.Log(), "node.log"))
		}
		if err := h.Systemctl("restart", "azpanel-panel"); err != nil {
			return err
		}
		base := p.cfg.Panel.BasePath
		if base == "" {
			base = "/"
		}
		if err := h.WaitPanel("http://" + p.listen + base + "healthz"); err != nil {
			return fmt.Errorf("azpanel не ответила на /healthz: %w; журнал — %s", err, filepath.Join(paths.Log(), "panel.log"))
		}
		return nil
	})
	if a.Firewall && a.Access == AccessPort {
		add("файрвол", func() error { return h.OpenFirewall(a.Port) })
	}
	return nil
}

func (w *Wizard) issueCert(a *Answers, p *plan) error {
	switch a.TLS {
	case TLSSelfSigned:
		var hosts []string
		for _, h := range []string{a.Domain, a.Address} {
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			hosts = []string{"localhost"}
		}
		cert, key, err := w.TLS.SelfSigned(hosts, filepath.Join(paths.Etc(), "tls"))
		if err != nil {
			return err
		}
		a.CertPath, a.KeyPath = cert, key
	case TLSLetsEncrypt:
		cert, key, err := w.TLS.IssueLetsEncrypt(p.acme, a.Domain, a.Email)
		if err != nil {
			return err
		}
		a.CertPath, a.KeyPath = cert, key
	}
	return nil
}

// ------------------------------------------------------------------- вывод

// siteCertNotes — предупреждения о сертификате сайта, в который встаёт
// раздел /azpanel/: истёк или выписан на домен, а открывать будут по IP.
func (w *Wizard) siteCertNotes(s NginxServer, a Answers) []string {
	var notes []string
	if s.SSLCertificate != "" && w.Host.CertNotAfter != nil {
		if end, err := w.Host.CertNotAfter(s.SSLCertificate); err == nil && end.Before(time.Now()) {
			notes = append(notes, fmt.Sprintf("ВНИМАНИЕ: сертификат сайта (%s) истёк %s: браузер покажет предупреждение и не предложит сохранить пароль",
				s.SSLCertificate, end.UTC().Format("2006-01-02")))
		}
	}
	if a.Domain == "" {
		notes = append(notes, "HTTPS — сертификат вашего сайта: он выписан на имя сайта, а открывать azpanel вы будете по IP, поэтому браузер покажет предупреждение")
	} else {
		notes = append(notes, "HTTPS — сертификат вашего сайта")
	}
	return notes
}

func (w *Wizard) summary(a Answers, p *plan) {
	w.printf("\nИтог\n")
	w.printf("  azpanel в %s\n", paths.Root())
	w.printf("  службы azpanel-node и azpanel-panel (%s), хук лимита в %s\n", w.unitDirNote(), w.ScriptsDir)
	for _, l := range p.lines {
		w.printf("  %s\n", l)
	}
	switch {
	case p.adminExists:
		w.printf("  администратор %s уже есть: не меняется\n", a.Admin)
	default:
		w.printf("  администратор %s (смена пароля при первом входе: %s)\n", a.Admin, yn(a.MustChange))
		// Свой пароль не печатается нигде; созданный показан на шаге
		// вопросов (интерактивно) или здесь, и ещё раз в конце.
		if p.generated && !w.Interactive {
			w.printf("  пароль администратора (создан): %s\n", a.AdminPassword)
		}
	}
	if a.Telegram {
		w.printf("  Telegram-бот включён, чат %d\n", a.TelegramChat)
	}
	w.printf("  бэкапы AntiZapret: раз в %d дн., хранить %d (меняется в «Настройках»)\n", a.BackupEveryDays, a.BackupKeep)
	w.printf("  ответы без секретов — %s (при переустановке подставятся сами)\n", filepath.Join(paths.Etc(), "install.env"))
	if a.Firewall {
		w.printf("  правило iptables для TCP %d\n", a.Port)
	}
	w.printf("  адрес azpanel после установки: %s\n\n", p.url)
}

func doneList(done []string) string {
	if len(done) == 0 {
		return "ничего"
	}
	return strings.Join(done, "; ")
}

func (w *Wizard) unitDirNote() string { return "/etc/systemd/system" }

func yn(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}

func (w *Wizard) report(a Answers, p *plan) {
	w.printf("\nГотово.\n  Адрес:  %s\n", p.url)
	if !p.adminExists {
		w.printf("  Логин:  %s\n", a.Admin)
		if p.generated {
			w.printf("  Пароль: %s (при первом входе попросит сменить)\n", a.AdminPassword)
		}
	}
	if a.Access == AccessLocal {
		w.printf("Открыть — SSH-туннелем с вашего компьютера:\n  ssh -L 8080:%s root@<сервер>\n  затем http://127.0.0.1:8080\n", p.listen)
	}
	for _, l := range firewallPorts(a, p) {
		w.printf("%s\n", l)
	}
	w.printf("Проверка установки: azpanel doctor\n")
	w.printf("Пароли, администраторы, обновление — меню: azpanel\n")
}
