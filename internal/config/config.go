// Package config — /opt/azpanel/etc/config.toml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/syava842/azpanel/internal/fsutil"
)

// CurrentVersion — версия структуры конфига, которую знает этот бинарник.
// 2 — API агента, пути AntiZapret, раздел [panel].
const CurrentVersion = 2

type Config struct {
	ConfigVersion int   `toml:"config_version"`
	Node          Node  `toml:"node"`
	Panel         Panel `toml:"panel"`
	Log           Log   `toml:"log"`
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
}

type Log struct {
	MaxSizeMB int `toml:"max_size_mb"`
	Keep      int `toml:"keep"`
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
		},
		Panel: Panel{
			Listen:         "127.0.0.1:8080",
			NodeURL:        "http://127.0.0.1:9100",
			CollectSeconds: 60,
			HistoryDays:    30,
			SessionHours:   168,
		},
		Log: Log{MaxSizeMB: 10, Keep: 5},
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
	if _, err := toml.Decode(string(data), &c); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	if c.ConfigVersion > CurrentVersion {
		return Default(), fmt.Errorf("%s: config_version %d новее, чем знает эта версия azpanel (%d)", path, c.ConfigVersion, CurrentVersion)
	}
	// Версия 2 только добавила ключи, умолчания для них уже подставлены
	// разбором поверх Default. Миграции с переименованием ключей появятся
	// вместе с самообновлением (план 2в).
	if c.ConfigVersion < CurrentVersion {
		c.ConfigVersion = CurrentVersion
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
	case c.Log.MaxSizeMB < 1 || c.Log.MaxSizeMB > 1000:
		return fmt.Errorf("log.max_size_mb = %d, нужно 1..1000", c.Log.MaxSizeMB)
	case c.Log.Keep < 1 || c.Log.Keep > 100:
		return fmt.Errorf("log.keep = %d, нужно 1..100", c.Log.Keep)
	}
	return nil
}

// loopbackAddr — «адрес:порт» на петлевом интерфейсе. В этом этапе ни API
// агента, ни панель наружу не слушают: наружу — nginx и TLS (этапы 2б и 4).
func loopbackAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.Addr().IsLoopback() && ap.Port() != 0
}

func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, buf.Bytes(), 0o600)
}

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
