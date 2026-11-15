package install

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/syava842/azpanel/internal/secrets"
)

// Типы установки. Мастер их не спрашивает (обычная установка — panel+node);
// остальные задаются только AZPANEL_MODE.
const (
	ModePanelNode = "panel+node"
	ModeNode      = "node"
	ModeProxy     = "proxy"
	ModePanel     = "panel"
)

// Как открывать azpanel: по имени (раздел /azpanel/ в nginx) или по порту.
// local — только 127.0.0.1, задаётся только AZPANEL_ACCESS.
const (
	AccessPath  = "path"
	AccessPort  = "port"
	AccessLocal = "local"
)

// Сертификат при HTTPS. Мастер выбирает его сам: свой сайт в nginx — его
// сертификат; домен — существующий или новый Let's Encrypt; IP —
// самоподписанный. own — только через AZPANEL_TLS с путями к файлам.
const (
	TLSExisting    = "existing"
	TLSLetsEncrypt = "letsencrypt"
	TLSOwn         = "own"
	TLSSelfSigned  = "selfsigned"
)

const (
	// DefaultBasePath — префикс панели в чужом nginx.
	DefaultBasePath = "/azpanel/"
	DefaultPort     = 8443
	defaultAdmin    = "admin"
)

// Answers — ответы мастера. Секреты (пароль администратора, токен бота) в
// install.env не попадают.
type Answers struct {
	Mode      string
	Address   string // внешний IP сервера
	Domain    string
	Access    string
	NginxFile string // файл с server-блоком для AccessPath
	Port      int    // порт для AccessPort
	HTTPS     bool
	TLS       string
	CertPath  string // свой сертификат или найденный
	KeyPath   string
	Email     string // для Let's Encrypt

	Admin         string
	AdminPassword string // секрет
	MustChange    bool

	Telegram      bool
	TelegramToken string // секрет
	TelegramChat  int64

	BackupDir       string
	BackupEveryDays int
	BackupKeep      int

	Firewall bool
}

// Ключи ответов: переменная окружения AZPANEL_<ключ>.
const (
	KeyMode      = "MODE"
	KeyAddress   = "ADDRESS"
	KeyDomain    = "DOMAIN"
	KeyAccess    = "ACCESS"
	KeyNginxFile = "NGINX_FILE"
	KeyPort      = "PORT"
	KeyHTTPS     = "HTTPS"
	KeyTLS       = "TLS"
	KeyCert      = "CERT"
	KeyKey       = "KEY"
	KeyEmail     = "EMAIL"
	KeyAdmin     = "ADMIN"
	KeyAdminPass = "ADMIN_PASSWORD"
	KeyMustChg   = "MUST_CHANGE"
	KeyTelegram  = "TELEGRAM"
	KeyTgToken   = "TELEGRAM_TOKEN"
	KeyTgChat    = "TELEGRAM_CHAT"
	KeyBackupDir = "BACKUP_DIR"
	KeyBackupDay = "BACKUP_DAYS"
	KeyBackupKp  = "BACKUP_KEEP"
	KeyFirewall  = "FIREWALL"
)

// AnswerKeys — все ключи в порядке вопросов.
var AnswerKeys = []string{KeyMode, KeyAddress, KeyPort, KeyDomain, KeyHTTPS, KeyAccess, KeyNginxFile, KeyTLS, KeyCert, KeyKey,
	KeyEmail, KeyAdmin, KeyAdminPass, KeyMustChg, KeyTelegram, KeyTgToken, KeyTgChat, KeyBackupDir, KeyBackupDay,
	KeyBackupKp, KeyFirewall}

// secretKeys не пишутся в install.env.
var secretKeys = map[string]bool{KeyAdminPass: true, KeyTgToken: true}

// EnvName — имя переменной окружения для ключа.
func EnvName(key string) string { return "AZPANEL_" + key }

// DefaultAnswers — умолчания мастера.
func DefaultAnswers(backupDir string) Answers {
	return Answers{
		Mode: ModePanelNode, Access: AccessPath, Port: DefaultPort, HTTPS: true,
		Admin: defaultAdmin, MustChange: true,
		BackupDir: backupDir, BackupEveryDays: 1, BackupKeep: 14,
	}
}

// Overlay накладывает значения (ключ → текст) на ответы. Пустой текст
// ключа игнорируется. Возвращает ключи, которые были заданы.
func (a *Answers) Overlay(kv map[string]string) (set []string, err error) {
	var errs []error
	for _, k := range AnswerKeys {
		v, ok := kv[k]
		v = strings.TrimSpace(v)
		if !ok || v == "" {
			continue
		}
		if err := a.set(k, v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvName(k), err))
			continue
		}
		set = append(set, k)
	}
	return set, errors.Join(errs...)
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "y", "yes", "1", "true", "д", "да":
		return true, nil
	case "n", "no", "0", "false", "н", "нет":
		return false, nil
	}
	return false, fmt.Errorf("%q: нужно да или нет", v)
}

func oneOf(v string, allowed ...string) (string, error) {
	v = strings.ToLower(v)
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", fmt.Errorf("%q: допустимо %s", v, strings.Join(allowed, ", "))
}

func atoiRange(v string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%q: нужно число %d..%d", v, lo, hi)
	}
	return n, nil
}

// checkNginxPath: путь идёт в директиву nginx и в install.env, поэтому ни
// пробелов, ни знаков, которые закончат директиву или откроют блок, ни кавычек.
func checkNginxPath(v string) error {
	if !strings.HasPrefix(v, "/") {
		return fmt.Errorf("%q: нужен абсолютный путь", v)
	}
	if strings.ContainsAny(v, " \t\r\n;{}\"'`$#\\") {
		return fmt.Errorf("%q: в пути не должно быть пробелов и знаков ; { } кавычек $ # \\", v)
	}
	return nil
}

func (a *Answers) set(key, v string) (err error) {
	switch key {
	case KeyMode:
		a.Mode, err = oneOf(v, ModePanelNode, ModeNode, ModeProxy, ModePanel)
	case KeyAddress:
		ip, perr := netip.ParseAddr(v)
		if perr != nil {
			return fmt.Errorf("%q: нужен IP-адрес", v)
		}
		a.Address = ip.String()
	case KeyDomain:
		if !domainRe.MatchString(v) {
			return fmt.Errorf("%q: неверное доменное имя", v)
		}
		a.Domain = strings.ToLower(v)
	case KeyAccess:
		a.Access, err = oneOf(v, AccessPath, AccessPort, AccessLocal)
	case KeyNginxFile:
		a.NginxFile = v
	case KeyPort:
		a.Port, err = atoiRange(v, 1, 65535)
	case KeyHTTPS:
		a.HTTPS, err = parseBool(v)
	case KeyTLS:
		a.TLS, err = oneOf(v, TLSExisting, TLSLetsEncrypt, TLSOwn, TLSSelfSigned)
	case KeyCert, KeyKey:
		if err := checkNginxPath(v); err != nil {
			return err
		}
		if key == KeyCert {
			a.CertPath = v
		} else {
			a.KeyPath = v
		}
	case KeyEmail:
		if !strings.Contains(v, "@") || strings.ContainsAny(v, " \t\r\n") {
			return fmt.Errorf("%q: неверный адрес почты", v)
		}
		a.Email = v
	case KeyAdmin:
		v = strings.ToLower(v)
		if !loginRe.MatchString(v) {
			return errors.New("логин: 3-32 знака, строчные латинские буквы, цифры и _ . -")
		}
		a.Admin = v
	case KeyAdminPass:
		a.AdminPassword = v
	case KeyMustChg:
		a.MustChange, err = parseBool(v)
	case KeyTelegram:
		a.Telegram, err = parseBool(v)
	case KeyTgToken:
		a.TelegramToken = v
	case KeyTgChat:
		n, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil || n == 0 {
			return fmt.Errorf("%q: нужен числовой ID чата", v)
		}
		a.TelegramChat = n
	case KeyBackupDir:
		if !strings.HasPrefix(v, "/") && !filepath.IsAbs(v) {
			return fmt.Errorf("%q: нужен абсолютный путь", v)
		}
		a.BackupDir = v
	case KeyBackupDay:
		a.BackupEveryDays, err = atoiRange(v, 0, 365)
	case KeyBackupKp:
		a.BackupKeep, err = atoiRange(v, 1, 1000)
	case KeyFirewall:
		a.Firewall, err = parseBool(v)
	}
	return err
}

var (
	loginRe  = regexp.MustCompile(`^[a-z0-9_.-]{3,32}$`)
	domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// Values — ответы как ключ → текст; withSecrets добавляет секреты.
func (a Answers) Values(withSecrets bool) map[string]string {
	yn := func(b bool) string {
		if b {
			return "y"
		}
		return "n"
	}
	m := map[string]string{
		KeyMode: a.Mode, KeyAddress: a.Address, KeyDomain: a.Domain, KeyAccess: a.Access,
		KeyNginxFile: a.NginxFile, KeyTLS: a.TLS, KeyCert: a.CertPath, KeyKey: a.KeyPath, KeyEmail: a.Email,
		KeyHTTPS: yn(a.HTTPS), KeyAdmin: a.Admin, KeyMustChg: yn(a.MustChange),
		KeyBackupDir: a.BackupDir, KeyBackupDay: strconv.Itoa(a.BackupEveryDays),
		KeyBackupKp: strconv.Itoa(a.BackupKeep), KeyFirewall: yn(a.Firewall),
	}
	if a.Port != 0 {
		m[KeyPort] = strconv.Itoa(a.Port)
	}
	if a.Telegram {
		m[KeyTelegram] = "y"
	}
	if a.TelegramChat != 0 {
		m[KeyTgChat] = strconv.FormatInt(a.TelegramChat, 10)
	}
	if withSecrets {
		m[KeyAdminPass], m[KeyTgToken] = a.AdminPassword, a.TelegramToken
	}
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	return m
}

// EnvFile — содержимое install.env: ответы без секретов.
func (a Answers) EnvFile() []byte { return secrets.Marshal(a.Values(false)) }

// ParseEnvFile читает install.env.
func ParseEnvFile(data []byte) (map[string]string, error) {
	m, err := secrets.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("install.env: %w", err)
	}
	for k := range secretKeys {
		delete(m, k) // секретам в этом файле не место
	}
	return m, nil
}

// Missing — чего не хватает для установки без вопросов: обязательные
// ответы без умолчания. set — ключи, заданные из окружения, флагов или
// install.env.
func (a Answers) Missing(set []string) []string {
	has := map[string]bool{}
	for _, k := range set {
		has[k] = true
	}
	var miss []string
	need := func(key, why string) {
		if !has[key] {
			miss = append(miss, fmt.Sprintf("%s — %s", EnvName(key), why))
		}
	}
	// Всё остальное имеет умолчания: путь /azpanel/, HTTPS, домен — нет
	// (тогда IP), сертификат мастер выбирает сам.
	if a.HTTPS && a.TLS == TLSOwn {
		need(KeyCert, "путь к fullchain")
		need(KeyKey, "путь к закрытому ключу")
	}
	if a.HTTPS && a.TLS == TLSLetsEncrypt && a.Domain == "" {
		need(KeyDomain, "домен для Let's Encrypt")
	}
	return miss
}

// Problem возвращает первое нарушение согласованности ответов.
func (a Answers) Problem() error {
	if a.Telegram && a.TelegramToken == "" {
		return errors.New("Telegram включён, но токена нет (" + EnvName(KeyTgToken) + ")")
	}
	if a.Telegram && a.TelegramChat == 0 {
		return errors.New("Telegram включён, но нет ID чата (" + EnvName(KeyTgChat) + ")")
	}
	if (a.Access == AccessPath || a.Access == AccessPort) && a.Domain == "" && a.Address == "" {
		return errors.New("не задан ни домен, ни внешний IP сервера (" + EnvName(KeyDomain) + " или " + EnvName(KeyAddress) + ")")
	}
	return nil
}

// ValidatePassword — правила пароля администратора (как в панели, этап 6):
// от 10 символов, не длиннее 72 байт, буквы и цифры, не равен логину.
// ValidLogin — логин пользователя панели: 3-32 знака, строчные латинские
// буквы, цифры и _ . - (как в форме «Новый пользователь»).
func ValidLogin(login string) bool { return loginRe.MatchString(login) }

func ValidatePassword(login, pw string) error {
	if utf8.RuneCountInString(pw) < 10 {
		return errors.New("пароль короче 10 символов")
	}
	if len(pw) > 72 {
		return errors.New("пароль длиннее 72 байт")
	}
	var letter, digit bool
	for _, r := range pw {
		letter = letter || unicode.IsLetter(r)
		digit = digit || unicode.IsDigit(r)
	}
	if !letter || !digit {
		return errors.New("в пароле нужны и буквы, и цифры")
	}
	if strings.EqualFold(pw, login) {
		return errors.New("пароль не должен совпадать с логином")
	}
	return nil
}
