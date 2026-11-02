// Package config — /opt/azpanel/etc/config.toml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/syava842/azpanel/internal/fsutil"
)

// CurrentVersion — версия структуры конфига, которую знает этот бинарник.
// 2 — API агента, пути AntiZapret, раздел [panel].
const CurrentVersion = 2

type Config struct {
	ConfigVersion int      `toml:"config_version"`
	Node          Node     `toml:"node"`
	Panel         Panel    `toml:"panel"`
	Log           Log      `toml:"log"`
	Telegram      Telegram `toml:"telegram"`
	Proxy         Proxy    `toml:"proxy"`
}

type Node struct {
	OpenVPNSocketDir  string `toml:"openvpn_socket_dir"`
	OpenVPNScriptsDir string `toml:"openvpn_scripts_dir"`
	PollSeconds       int    `toml:"poll_seconds"`
	QueryTimeoutMs    int    `toml:"query_timeout_ms"`
	APIListen         string `toml:"api_listen"` // пусто — API выключен
	AntiZapretDir     string `toml:"antizapret_dir"`
	EasyRSAPKI        string `toml:"easyrsa_pki"`
	WireGuardDir      string `toml:"wireguard_dir"`
	ClientShTimeoutS  int    `toml:"client_sh_timeout_seconds"`
	// ListenTLS — внешний порт агента по TLS (адрес:порт); пусто — выключен.
	// Сертификат — etc/tls/node.{crt,key}, создаётся при первом старте; пускает
	// только адреса из AllowIPs, и список обязателен.
	ListenTLS string   `toml:"listen_tls"`
	AllowIPs  []string `toml:"allow_ips"`
	// AmneziaWGDir и KnotResolverDir — каталоги набора синхронизации; пусто —
	// у AmneziaWG нет каталога на узле, и он пропускается.
	AmneziaWGDir    string `toml:"amneziawg_dir"`
	KnotResolverDir string `toml:"knot_resolver_dir"`
}

type Panel struct {
	Listen         string `toml:"listen"`
	NodeURL        string `toml:"node_url"`
	CollectSeconds int    `toml:"collect_seconds"`
	HistoryDays    int    `toml:"history_days"`
	SessionHours   int    `toml:"session_hours"`
	// RequireAdmin2FA — администратор без двухфакторной проверки после
	// входа обязан её включить, пока не включит, дальше не пускают.
	RequireAdmin2FA bool `toml:"require_admin_2fa"`
	// AllowIPs — белый список адресов панели: IP или CIDR; пусто — без
	// ограничения.
	AllowIPs []string `toml:"allow_ips"`
	// PublicURL — внешний адрес панели для ссылок портала и одноразовых
	// ссылок (https://vpn.example.org); пусто — ссылки относительные.
	PublicURL string `toml:"public_url"`
	// BasePath — префикс пути, под которым панель стоит за nginx: пусто или
	// «/x/» (с обеими косыми). Панель снимает его с запроса сама.
	BasePath string `toml:"base_path"`
	// TrustedProxies — адреса прокси (IP или CIDR), чьим X-Forwarded-For и
	// X-Forwarded-Proto панель верит.
	TrustedProxies []string `toml:"trusted_proxies"`
}

type Log struct {
	MaxSizeMB int `toml:"max_size_mb"`
	Keep      int `toml:"keep"`
}

// TelegramNotifyKinds — виды уведомлений бота, которые можно включить.
var TelegramNotifyKinds = []string{
	"node_down", "load_high", "reboot", "sync_mismatch", "hook_error",
	"limit_denials", "antizapret_update", "update_result", "cert_expiring", "access_expiring",
}

// Telegram — настройки бота. Токен сюда не входит: он в secrets.env.
type Telegram struct {
	Enabled bool `toml:"enabled"`
	// Strangers — как вести себя с непривязанными: closed — молчать,
	// request — принимать заявки.
	Strangers   string  `toml:"strangers"`
	NotifyChats []int64 `toml:"notify_chats"`
	// Notify — включённые виды уведомлений (TelegramNotifyKinds).
	Notify []string `toml:"notify"`
	// Пороги нагрузки, проценты; держаться должны LoadMinutes минут.
	CPUPercent  int `toml:"cpu_percent"`
	MemPercent  int `toml:"mem_percent"`
	DiskPercent int `toml:"disk_percent"`
	LoadMinutes int `toml:"load_minutes"`
	// SummaryAt — время сводки «ЧЧ:ММ» по UTC; пусто — выкл.
	SummaryAt string `toml:"summary_at"`
	// BackupEveryDays — периодичность бэкапа в чат; 0 — выкл.
	BackupEveryDays int     `toml:"backup_every_days"`
	BackupChats     []int64 `toml:"backup_chats"`
}

func Default() Config {
	return Config{
		ConfigVersion: CurrentVersion,
		Node: Node{
			OpenVPNSocketDir:  "/run/openvpn-server",
			OpenVPNScriptsDir: "/etc/openvpn/server/scripts",
			PollSeconds:       5,
			QueryTimeoutMs:    1000,
			APIListen:         "127.0.0.1:9100",
			AntiZapretDir:     "/root/antizapret",
			EasyRSAPKI:        "/etc/openvpn/easyrsa3/pki",
			WireGuardDir:      "/etc/wireguard",
			ClientShTimeoutS:  120,
			AmneziaWGDir:      "/etc/amnezia/amneziawg",
			KnotResolverDir:   "/etc/knot-resolver",
		},
		Panel: Panel{
			Listen:         "127.0.0.1:8080",
			NodeURL:        "http://127.0.0.1:9100",
			CollectSeconds: 60,
			HistoryDays:    30,
			SessionHours:   168,
			TrustedProxies: []string{"127.0.0.1/32", "::1/128"},
		},
		Log:   Log{MaxSizeMB: 10, Keep: 5},
		Proxy: defaultProxy(),
		Telegram: Telegram{
			Strangers:   "closed",
			Notify:      slices.Clone(TelegramNotifyKinds),
			CPUPercent:  90,
			MemPercent:  90,
			DiskPercent: 90,
			LoadMinutes: 5,
			SummaryAt:   "09:00",
		},
	}
}

// Load читает конфиг поверх умолчаний; нет файла — умолчания. При ошибке
// вместе с ней возвращаются умолчания.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return Default(), err
	}
	return loadMigrated(data, path)
}

// loadMigrated поднимает файл до текущей версии (в памяти, файл не
// переписывается) и читает его поверх умолчаний. Вопросы миграции без
// ответов возвращаются как *QuestionsError.
func loadMigrated(data []byte, path string) (Config, error) {
	c := Default()
	data, _, err := Migrate(data, nil)
	if err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c Config) Validate() error {
	n, p := c.Node, c.Panel
	switch {
	case n.OpenVPNSocketDir == "":
		return errors.New("node.openvpn_socket_dir пуст")
	case n.OpenVPNScriptsDir == "":
		return errors.New("node.openvpn_scripts_dir пуст")
	case n.PollSeconds < 1 || n.PollSeconds > 60:
		return fmt.Errorf("node.poll_seconds = %d, нужно 1..60", n.PollSeconds)
	case n.QueryTimeoutMs < 100 || n.QueryTimeoutMs > 5000:
		return fmt.Errorf("node.query_timeout_ms = %d, нужно 100..5000", n.QueryTimeoutMs)
	case n.APIListen != "" && !loopbackAddr(n.APIListen):
		return fmt.Errorf("node.api_listen = %q: нужен 127.0.0.1:порт, [::1]:порт или пусто", n.APIListen)
	case n.ListenTLS != "" && !tlsAddr(n.ListenTLS):
		return fmt.Errorf("node.listen_tls = %q: нужен адрес:порт (например 0.0.0.0:9100)", n.ListenTLS)
	case n.ListenTLS != "" && n.ListenTLS == n.APIListen:
		return errors.New("node.listen_tls и node.api_listen не могут совпадать")
	case n.ListenTLS != "" && len(n.AllowIPs) == 0:
		return errors.New("node.allow_ips пуст: при node.listen_tls нужен белый список адресов панели")
	case allowErr(n.AllowIPs) != nil:
		return fmt.Errorf("node.allow_ips: %w", allowErr(n.AllowIPs))
	case n.AntiZapretDir == "" || n.EasyRSAPKI == "" || n.WireGuardDir == "":
		return errors.New("node.antizapret_dir, node.easyrsa_pki и node.wireguard_dir не могут быть пустыми")
	case n.ClientShTimeoutS < 10 || n.ClientShTimeoutS > 600:
		return fmt.Errorf("node.client_sh_timeout_seconds = %d, нужно 10..600", n.ClientShTimeoutS)
	case !loopbackAddr(p.Listen):
		return fmt.Errorf("panel.listen = %q: нужен 127.0.0.1:порт или [::1]:порт", p.Listen)
	case !strings.HasPrefix(p.NodeURL, "http://") && !strings.HasPrefix(p.NodeURL, "https://"):
		return fmt.Errorf("panel.node_url = %q: нужен адрес http:// или https://", p.NodeURL)
	case p.CollectSeconds < 10 || p.CollectSeconds > 600:
		return fmt.Errorf("panel.collect_seconds = %d, нужно 10..600", p.CollectSeconds)
	case p.HistoryDays < 1 || p.HistoryDays > 365:
		return fmt.Errorf("panel.history_days = %d, нужно 1..365", p.HistoryDays)
	case p.SessionHours < 1 || p.SessionHours > 720:
		return fmt.Errorf("panel.session_hours = %d, нужно 1..720", p.SessionHours)
	case allowErr(p.AllowIPs) != nil:
		return fmt.Errorf("panel.allow_ips: %w", allowErr(p.AllowIPs))
	case publicURLErr(p.PublicURL) != nil:
		return fmt.Errorf("panel.public_url: %w", publicURLErr(p.PublicURL))
	case basePathErr(p.BasePath) != nil:
		return fmt.Errorf("panel.base_path: %w", basePathErr(p.BasePath))
	case trustedErr(p.TrustedProxies) != nil:
		return fmt.Errorf("panel.trusted_proxies: %w", trustedErr(p.TrustedProxies))
	case c.Log.MaxSizeMB < 1 || c.Log.MaxSizeMB > 1000:
		return fmt.Errorf("log.max_size_mb = %d, нужно 1..1000", c.Log.MaxSizeMB)
	case c.Log.Keep < 1 || c.Log.Keep > 100:
		return fmt.Errorf("log.keep = %d, нужно 1..100", c.Log.Keep)
	}
	if err := c.Telegram.validate(); err != nil {
		return err
	}
	return c.Proxy.validate()
}

func (g Telegram) validate() error {
	switch {
	case g.Strangers != "closed" && g.Strangers != "request":
		return fmt.Errorf("telegram.strangers = %q, нужно closed или request", g.Strangers)
	case g.CPUPercent < 1 || g.CPUPercent > 100:
		return fmt.Errorf("telegram.cpu_percent = %d, нужно 1..100", g.CPUPercent)
	case g.MemPercent < 1 || g.MemPercent > 100:
		return fmt.Errorf("telegram.mem_percent = %d, нужно 1..100", g.MemPercent)
	case g.DiskPercent < 1 || g.DiskPercent > 100:
		return fmt.Errorf("telegram.disk_percent = %d, нужно 1..100", g.DiskPercent)
	case g.LoadMinutes < 1 || g.LoadMinutes > 1440:
		return fmt.Errorf("telegram.load_minutes = %d, нужно 1..1440", g.LoadMinutes)
	case g.SummaryAt != "" && !validClock(g.SummaryAt):
		return fmt.Errorf("telegram.summary_at = %q, нужно ЧЧ:ММ (00:00..23:59) или пусто", g.SummaryAt)
	case g.BackupEveryDays < 0 || g.BackupEveryDays > 365:
		return fmt.Errorf("telegram.backup_every_days = %d, нужно 0..365", g.BackupEveryDays)
	}
	for _, k := range g.Notify {
		if !slices.Contains(TelegramNotifyKinds, k) {
			return fmt.Errorf("telegram.notify: неизвестный вид %q", k)
		}
	}
	if slices.Contains(g.NotifyChats, 0) {
		return errors.New("telegram.notify_chats: ID чата не может быть 0")
	}
	if slices.Contains(g.BackupChats, 0) {
		return errors.New("telegram.backup_chats: ID чата не может быть 0")
	}
	return nil
}

// validClock — «ЧЧ:ММ» ровно в пять символов.
func validClock(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	t, err := time.Parse("15:04", s)
	return err == nil && t.Format("15:04") == s
}

// loopbackAddr — «адрес:порт» на петлевом интерфейсе. В этом этапе ни API
// агента, ни панель наружу не слушают: наружу — nginx и TLS (этапы 2б и 4).
func loopbackAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.Addr().IsLoopback() && ap.Port() != 0
}

// tlsAddr — «IP:порт» для внешнего порта агента (не обязательно петлевой).
func tlsAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.Port() != 0
}

func Save(path string, c Config) error {
	data, err := Marshal(c)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o600)
}

// Marshal проверяет конфиг и кодирует его в TOML.
func Marshal(c Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse читает конфиг из байт (файл импорта) поверх умолчаний, с миграцией.
func Parse(data []byte) (Config, error) { return loadMigrated(data, "импорт") }

func allowErr(list []string) error {
	_, err := ParseAllowIPs(list)
	return err
}

// ParseAllowIPs разбирает белый список: каждая запись — IP или CIDR.
// Одиночный адрес становится префиксом /32 (/128). Пусто — без ограничения.
func ParseAllowIPs(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, raw := range list {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, errors.New("пустая запись")
		}
		if strings.Contains(v, "/") {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("%q: неверная сеть", v)
			}
			if p.Addr().Is4In6() && p.Bits() < 96 {
				// Иначе префикс не помещается в IPv4 и запись молча ничего не пускала бы.
				return nil, fmt.Errorf("%q: сеть IPv4 внутри IPv6 должна быть не короче /96; запишите её как IPv4 (например 10.0.0.0/8)", v)
			}
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), unmapBits(p)).Masked())
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("%q: неверный адрес", v)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// unmapBits: длина префикса IPv4-в-IPv6 (::ffff:a.b.c.d/N) пересчитывается в IPv4.
func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return p.Bits() - 96
	}
	return p.Bits()
}

// publicURLErr проверяет panel.public_url: пусто либо http(s)://хост[:порт][/путь]
// без учётных данных, запроса и фрагмента.
func publicURLErr(v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	switch {
	case err != nil || strings.ContainsAny(v, " \t\r\n"):
		return fmt.Errorf("%q: неверный адрес", v)
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("%q: нужен адрес http:// или https://", v)
	case u.Host == "" || u.Hostname() == "":
		return fmt.Errorf("%q: не указан хост", v)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(v, "?") || strings.Contains(v, "#"):
		return fmt.Errorf("%q: без учётных данных, запроса и фрагмента", v)
	}
	return nil
}

func trustedErr(list []string) error {
	_, err := ParseAllowIPs(list)
	return err
}

// ParseTrustedProxies разбирает panel.trusted_proxies (как белый список).
func ParseTrustedProxies(list []string) ([]netip.Prefix, error) { return ParseAllowIPs(list) }

// basePathErr проверяет panel.base_path: пусто либо «/x/», «/a/b/»: начинается
// и кончается косой чертой, сегменты из латиницы, цифр и «._~-».
func basePathErr(v string) error {
	if v == "" {
		return nil
	}
	if len(v) < 3 || v[0] != '/' || v[len(v)-1] != '/' {
		return fmt.Errorf("%q: нужен вид /имя/ (с косой чертой в начале и в конце) или пусто", v)
	}
	for _, seg := range strings.Split(v[1:len(v)-1], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%q: пустой или недопустимый сегмент пути", v)
		}
		for _, r := range seg {
			ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~-", r)
			if !ok {
				return fmt.Errorf("%q: допустимы латиница, цифры и . _ ~ -", v)
			}
		}
	}
	return nil
}
