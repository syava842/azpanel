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
	{ModePanelNode, "панель + узел (AntiZapret на этом же сервере)"},
	{ModeNode, "только узел (подключить к панели на другом сервере)"},
	{ModeProxy, "только прокси-агент"},
	{ModePanel, "только панель"},
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
	} else {
		if err := w.askMode(&a); err != nil {
			return err
		}
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
		if err := w.askAddress(&a); err != nil {
			return err
		}
		if err := w.askAccess(&a, servers); err != nil {
			return err
		}
		if err := w.askTLS(&a); err != nil {
			return err
		}
	}
	p, err := w.plan(&a, servers)
	if err != nil {
		return err
	}
	if w.Interactive {
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
	for _, s := range p.steps {
		w.printf("→ %s\n", s.name)
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
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

func (w *Wizard) askMode(a *Answers) error {
	def := 0
	titles := make([]string, len(modeTitles))
	for i, m := range modeTitles {
		titles[i] = m.title
		if m.mode == a.Mode {
			def = i
		}
	}
	i, err := w.choose("1. Что ставим", titles, def)
	if err != nil {
		return err
	}
	a.Mode = modeTitles[i].mode
	return nil
}

func (w *Wizard) askAddress(a *Answers) error {
	w.printf("3. Адрес сервера\n")
	if err := w.askKey(a, KeyAddress, "Внешний IP", a.Address); err != nil {
		return err
	}
	return w.askKey(a, KeyDomain, "Домен (пусто — только IP)", a.Domain)
}

// pathCandidates — server-блоки, в которые можно встроить панель: с ssl и,
// если домен задан, с этим доменом.
func pathCandidates(servers []NginxServer, domain string) []NginxServer {
	var out []NginxServer
	for _, s := range servers {
		if s.SSL() && (domain == "" || s.NamedFor(domain)) {
			out = append(out, s)
		}
	}
	return out
}

func serverTitle(s NginxServer) string {
	return fmt.Sprintf("%s (server_name %s, порт %v)", s.File, strings.Join(s.ServerName, " "), s.Ports())
}

func (w *Wizard) askAccess(a *Answers, servers []NginxServer) error {
	cands := pathCandidates(servers, a.Domain)
	var opts, vals []string
	if len(cands) > 0 {
		opts = append(opts, "путь "+DefaultBasePath+" в найденном nginx")
		vals = append(vals, AccessPath)
	}
	opts = append(opts, fmt.Sprintf("отдельный порт HTTPS (по умолчанию %d)", DefaultPort), "только 127.0.0.1 (доступ через SSH-туннель)")
	vals = append(vals, AccessPort, AccessLocal)
	// Без предустановки: найденный nginx предлагается, иначе — только
	// 127.0.0.1, наружу ничего не открываем.
	def := len(vals) - 1
	if a.Access == "" && len(cands) > 0 {
		def = 0
	}
	for i, v := range vals {
		if v == a.Access {
			def = i
		}
	}
	i, err := w.choose("4. Как открыть панель", opts, def)
	if err != nil {
		return err
	}
	a.Access = vals[i]
	switch a.Access {
	case AccessPath:
		pick := 0
		if len(cands) > 1 {
			titles := make([]string, len(cands))
			for j, c := range cands {
				titles[j] = serverTitle(c)
			}
			if pick, err = w.choose("Какой server-блок", titles, 0); err != nil {
				return err
			}
		}
		a.NginxFile = cands[pick].File
		if a.Domain == "" {
			for _, n := range cands[pick].ServerName {
				if n != "_" && domainRe.MatchString(n) {
					a.Domain = strings.ToLower(n)
					break
				}
			}
		}
	case AccessPort:
		return w.askKey(a, KeyPort, "Порт HTTPS", strconv.Itoa(a.Port))
	}
	return nil
}

func (w *Wizard) askTLS(a *Answers) error {
	switch a.Access {
	case AccessLocal:
		return nil
	case AccessPath:
		w.printf("5. HTTPS: сертификат берётся у выбранного server-блока nginx\n")
		return nil
	}
	_, _, haveLE := w.TLS.ExistingLetsEncrypt(a.Domain)
	var opts, vals []string
	if haveLE {
		opts = append(opts, "существующий сертификат Let's Encrypt для "+a.Domain)
		vals = append(vals, TLSExisting)
	}
	opts = append(opts, "Let's Encrypt для домена (нужен свободный TCP 80)", "свой сертификат (пути к fullchain и key)", "самоподписанный")
	vals = append(vals, TLSLetsEncrypt, TLSOwn, TLSSelfSigned)
	def := 0
	for i, v := range vals {
		if v == a.TLS {
			def = i
		}
	}
	if a.TLS == "" && !haveLE && a.Domain == "" {
		def = len(vals) - 1 // без домена Let's Encrypt не выпустить
	}
	i, err := w.choose("5. HTTPS", opts, def)
	if err != nil {
		return err
	}
	a.TLS = vals[i]
	switch a.TLS {
	case TLSLetsEncrypt:
		if a.Domain == "" {
			if err := w.askKey(a, KeyDomain, "Домен", ""); err != nil {
				return err
			}
		}
		return w.askKey(a, KeyEmail, "Почта для Let's Encrypt", a.Email)
	case TLSOwn:
		if err := w.askKey(a, KeyCert, "Путь к fullchain", a.CertPath); err != nil {
			return err
		}
		return w.askKey(a, KeyKey, "Путь к закрытому ключу", a.KeyPath)
	}
	return nil
}

func (w *Wizard) generatePassword() (string, error) {
	if w.NewPassword != nil {
		return w.NewPassword()
	}
	return GeneratePassword()
}

func (w *Wizard) askAdmin(a *Answers, p *plan) error {
	w.printf("6. Администратор\n")
	if err := w.askKey(a, KeyAdmin, "Логин", a.Admin); err != nil {
		return err
	}
	if w.Host.AdminExists(a.Admin) {
		p.adminExists = true
		w.printf("  Пользователь %s уже есть в панели: пароль не меняется (сброс — azpanel user reset %s)\n", a.Admin, a.Admin)
		return nil
	}
	p.adminExists = false
	for {
		pw, err := w.secret("Пароль (Enter — создать 16 символов)")
		if err != nil {
			return err
		}
		if pw == "" {
			if pw, err = w.generatePassword(); err != nil {
				return err
			}
			a.AdminPassword = pw
			w.printf("  Пароль администратора: %s\n  Запишите его: он будет показан ещё раз в итоге и нигде не сохраняется.\n", pw)
			break
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
		a.AdminPassword = pw
		break
	}
	var err error
	a.MustChange, err = w.yesno("Требовать смену пароля при первом входе", a.MustChange)
	return err
}

func (w *Wizard) askExtras(a *Answers) error {
	w.printf("9. Telegram (необязательно; потом меняется в «Настройках»)\n")
	var err error
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
	w.printf("10. Бэкапы\n")
	if err := w.askKey(a, KeyBackupDir, "Каталог", a.BackupDir); err != nil {
		return err
	}
	if err := w.askKey(a, KeyBackupDay, "Автобэкап раз в N дней (0 — выкл.)", strconv.Itoa(a.BackupEveryDays)); err != nil {
		return err
	}
	if err := w.askKey(a, KeyBackupKp, "Сколько копий хранить", strconv.Itoa(a.BackupKeep)); err != nil {
		return err
	}
	w.printf("11. Файрвол: правила не меняются\n")
	for _, line := range firewallPorts(*a) {
		w.printf("  %s\n", line)
	}
	if a.Access == AccessPort {
		a.Firewall, err = w.yesno(fmt.Sprintf("Добавить правило iptables для TCP %d", a.Port), a.Firewall)
		return err
	}
	a.Firewall = false
	return nil
}

func chatDef(id int64) string {
	if id == 0 {
		return ""
	}
	return strconv.FormatInt(id, 10)
}

func firewallPorts(a Answers) []string {
	switch a.Access {
	case AccessPort:
		return []string{fmt.Sprintf("Откройте TCP %d: панель.", a.Port)}
	case AccessPath:
		return []string{"Новых портов открывать не нужно: панель за вашим nginx."}
	}
	return []string{"Панель слушает только 127.0.0.1: открывать нечего."}
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
	// finishFn достраивает конфиг и шаги по ответам, полученным после plan.
	finishFn func(a *Answers, p *plan) error
}

func (p *plan) finish(a *Answers) error { return p.finishFn(a, p) }

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// plan проверяет ответы и собирает шаги применения. Изменяющих вызовов не
// делает: только чтение системы.
func (w *Wizard) plan(a *Answers, servers []NginxServer) (*plan, error) {
	p := &plan{}
	if err := a.Problem(); err != nil && !w.Interactive {
		return nil, err
	}
	cfg, err := w.Host.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("текущий конфиг: %w", err)
	}
	p.listen = cfg.Panel.Listen
	cfg.Panel.BasePath, cfg.Panel.PublicURL = "", ""
	host := a.Domain
	if host == "" {
		host = a.Address
	}

	switch a.Access {
	case AccessPath:
		cands := pathCandidates(servers, a.Domain)
		if a.NginxFile != "" {
			var one []NginxServer
			for _, c := range cands {
				if c.File == a.NginxFile {
					one = append(one, c)
				}
			}
			cands = one
		}
		if len(cands) == 0 {
			return nil, fmt.Errorf("в nginx (%s) нет server-блока с ssl для домена %q: выберите отдельный порт или 127.0.0.1", w.Nginx.dir(), a.Domain)
		}
		// Предпочитаем 443.
		p.server = cands[0]
		for _, c := range cands {
			if c.ListensOn(443) {
				p.server = c
				break
			}
		}
		a.NginxFile = p.server.File
		if a.TLS == "" {
			a.TLS = TLSExisting
		}
		a.CertPath = p.server.SSLCertificate
		cfg.Panel.BasePath = DefaultBasePath
		cfg.Panel.PublicURL = "https://" + a.Domain
		p.url = "https://" + a.Domain + DefaultBasePath
		p.lines = append(p.lines,
			fmt.Sprintf("nginx: в %s (блок %s) одна строка include; фрагмент %s; копия %s.bak-ГГГГММДД; после nginx -t — reload",
				p.server.File, strings.Join(p.server.ServerName, " "), SnippetPath, filepath.Base(p.server.File)))
	case AccessPort:
		if a.TLS == "" {
			return nil, errors.New("не выбран тип HTTPS")
		}
		if _, err := w.Host.Stat(path.Join(w.Nginx.dir(), ownPortLink)); err != nil && w.Host.PortBusy(a.Port) {
			return nil, fmt.Errorf("порт %d занят: выберите другой", a.Port)
		}
		pub := hostPort(host, a.Port)
		cfg.Panel.PublicURL = "https://" + pub
		p.url = "https://" + pub + "/"
		p.lines = append(p.lines,
			fmt.Sprintf("nginx: отдельный server на порту %d (%s, ссылка в sites-enabled), фрагмент %s; после nginx -t — reload", a.Port, path.Join(w.Nginx.dir(), ownPortFile), SnippetPath))
		if err := w.planCert(a, p, servers); err != nil {
			return nil, err
		}
	default:
		a.Access = AccessLocal
		p.url = "http://" + cfg.Panel.Listen + "/"
		p.lines = append(p.lines, "панель слушает только "+cfg.Panel.Listen+" (доступ через SSH-туннель), nginx не меняется")
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

// planCert проверяет всё, что нужно сертификату выбранного типа, без изменений.
func (w *Wizard) planCert(a *Answers, p *plan, servers []NginxServer) error {
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
		if a.Domain == "" || a.Email == "" {
			return errors.New("для Let's Encrypt нужны домен и почта")
		}
		plan, err := PlanACME(servers, a.Domain, w.Host.Port80Owner())
		if err != nil {
			return err
		}
		p.acme = plan
		p.lines = append(p.lines, "HTTPS: certbot выпустит сертификат Let's Encrypt для "+a.Domain)
	case TLSSelfSigned:
		p.lines = append(p.lines, "HTTPS: самоподписанный сертификат в "+filepath.Join(paths.Etc(), "tls"))
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
	if a.Access == AccessPort {
		add("сертификат", func() error { return w.issueCert(a, p) })
	}
	switch a.Access {
	case AccessPath:
		add("nginx", func() error { return w.Nginx.Enable(p.server, DefaultBasePath, p.listen) })
	case AccessPort:
		add("nginx", func() error {
			name := a.Domain
			return w.Nginx.EnableOwnPort(a.Port, a.CertPath, a.KeyPath, name, "", p.listen)
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
			return fmt.Errorf("панель не ответила на /healthz: %w; журнал — %s", err, filepath.Join(paths.Log(), "panel.log"))
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

func (w *Wizard) summary(a Answers, p *plan) {
	w.printf("\n12. Итог. Будет установлено: %s\n", modeTitle(a.Mode))
	w.printf("  каталоги, бинарник и конфиг в %s\n", paths.Root())
	w.printf("  службы azpanel-node и azpanel-panel (%s), хук лимита в %s\n", w.unitDirNote(), w.ScriptsDir)
	for _, l := range p.lines {
		w.printf("  %s\n", l)
	}
	switch {
	case p.adminExists:
		w.printf("  администратор %s уже есть: не меняется\n", a.Admin)
	default:
		w.printf("  администратор %s (смена пароля при первом входе: %s)\n", a.Admin, yn(a.MustChange))
		if a.AdminPassword != "" {
			w.printf("  пароль администратора: %s\n", a.AdminPassword)
		}
	}
	if a.Telegram {
		w.printf("  Telegram-бот включён, чат %d\n", a.TelegramChat)
	}
	w.printf("  ответы без секретов — %s\n", filepath.Join(paths.Etc(), "install.env"))
	if a.Firewall {
		w.printf("  правило iptables для TCP %d\n", a.Port)
	}
	w.printf("  адрес панели после установки: %s\n\n", p.url)
}

func (w *Wizard) unitDirNote() string { return "/etc/systemd/system" }

func yn(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}

func (w *Wizard) report(a Answers, p *plan) {
	w.printf("\nГотово. Панель: %s\n", p.url)
	if !p.adminExists {
		w.printf("Администратор: %s", a.Admin)
		if a.AdminPassword != "" {
			w.printf(", пароль: %s", a.AdminPassword)
		}
		w.printf("\n")
	}
	if a.Access == AccessLocal {
		w.printf("Открыть — SSH-туннелем с вашего компьютера:\n  ssh -L 8080:%s root@<сервер>\n  затем http://127.0.0.1:8080\n", p.listen)
	}
	for _, l := range firewallPorts(a) {
		w.printf("%s\n", l)
	}
	w.printf("Проверка установки: azpanel doctor\n")
}
