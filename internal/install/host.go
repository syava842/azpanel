package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

// NewWizard — мастер на настоящей системе. CreateAdmin и AdminExists
// подставляет вызывающий (им нужна база панели).
func NewWizard(self string, in io.Reader, out io.Writer, interactive bool, flags map[string]string) *Wizard {
	o := Defaults()
	o.Self = self
	nginx := NewNginx()
	return &Wizard{
		In: bufio.NewReader(in), Out: out, Interactive: interactive,
		Getenv: os.Getenv, Flags: flags,
		Host:  RealHost(o),
		Nginx: nginx, TLS: NewTLS(nginx),
		AntiZapretDir: o.AntiZapretDir, ScriptsDir: o.ScriptsDir,
	}
}

// RealHost — действия настоящей системы.
func RealHost(o Options) Host {
	return Host{
		Geteuid:  os.Geteuid,
		ReadFile: os.ReadFile,
		Stat:     os.Stat,
		HasSystemd: func() bool {
			_, err := os.Stat("/run/systemd/system")
			return err == nil
		},
		PortBusy: func(port int) bool {
			l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
			if err != nil {
				return true
			}
			l.Close()
			return false
		},
		Port80Owner: port80Owner,
		Fetch:       httpsGet,
		AdminExists: func(string) bool { return false },
		LoadConfig:  func() (config.Config, error) { return config.Load(paths.ConfigFile()) },

		MkLayout:        makeLayout,
		CopyBinary:      func() error { return copyBinary(o.Self, paths.Binary()) },
		WriteConfig:     func(c config.Config) error { return config.Save(paths.ConfigFile(), c) },
		EnsureNodeToken: func() error { return ensureNodeToken(paths.SecretsFile()) },
		WriteSecrets:    func(kv map[string]string) error { return secrets.SetMany(paths.SecretsFile(), kv) },
		WriteInstallEnv: func(data []byte) error {
			return fsutil.WriteFileAtomic(filepath.Join(paths.Etc(), "install.env"), data, 0o600)
		},
		WriteUnit: func(name, content string) error {
			return fsutil.WriteFileAtomic(filepath.Join(o.UnitDir, name), []byte(content), 0o644)
		},
		InstallHook: func() error {
			_, err := (antizapret.HookFiles{ScriptsDir: o.ScriptsDir, Binary: paths.Binary()}).Ensure()
			return err
		},
		Systemctl: func(args ...string) error { return o.Run("systemctl", args...) },
		WaitAgent: waitAgent,
		WaitPanel: waitHealthz,
		CreateAdmin: func(string, string, bool) error {
			return errors.New("создание администратора не подключено")
		},
		OpenFirewall: func(port int) error {
			rule := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
			if o.Run("iptables", append([]string{"-C"}, rule...)...) == nil {
				return nil // правило уже есть
			}
			return o.Run("iptables", append([]string{"-I"}, rule...)...)
		},
	}
}

// makeLayout создаёт каталоги установки с нужными правами.
func makeLayout() error {
	for _, d := range layout() {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil { // MkdirAll не меняет права существующего
			return err
		}
	}
	return nil
}

func httpsGet(url string) (string, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	return string(b), err
}

// waitHealthz ждёт ответ 200 на адрес (до 30 с).
func waitHealthz(url string) error {
	c := &http.Client{Timeout: 2 * time.Second}
	var last error
	for i := 0; i < 60; i++ {
		resp, err := c.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = errors.New(resp.Status)
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

// port80Owner — кто слушает TCP 80: "" свободен, иначе имя процесса.
func port80Owner() string {
	out, err := exec.Command("ss", "-ltnpH", "sport = :80").Output()
	if err != nil {
		return ""
	}
	return ParsePortOwner(string(out))
}

// ParsePortOwner разбирает вывод `ss -ltnpH`: имя первого процесса из
// users:(("nginx",pid=1,fd=6)). Строка без имени (нет прав) — "?".
func ParsePortOwner(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if i := strings.Index(line, `users:(("`); i >= 0 {
			rest := line[i+len(`users:(("`):]
			if j := strings.Index(rest, `"`); j > 0 {
				return rest[:j]
			}
		}
		return "?"
	}
	return ""
}
