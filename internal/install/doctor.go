package install

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
)

const (
	// doctorMinFreeMB — меньше свободного места на диске установки — проблема.
	doctorMinFreeMB = 500
	// doctorCertDays — сертификат, которому осталось меньше, — проблема.
	doctorCertDays = 14
)

// Doctor — проверка установки (azpanel doctor). Всё, что смотрит в систему,
// — поля-функции.
type Doctor struct {
	Out     io.Writer
	UnitDir string
	Cfg     config.Config

	Stat          func(path string) (fs.FileInfo, error)
	ReadFile      func(path string) ([]byte, error)
	ReadDir       func(path string) ([]os.DirEntry, error)
	IsActive      func(unit string) bool
	HookInstalled func() (bool, error)
	AgentList     func() error
	Healthz       func(url string) error
	CertNotAfter  func(file string) (time.Time, error)
	DiskFreeMB    func(dir string) (uint64, error)
	NginxTest     func() error
	Now           func() time.Time
}

// RealDoctor — проверка на настоящей системе.
func RealDoctor(out io.Writer, o Options, cfg config.Config) *Doctor {
	n := NewNginx()
	return &Doctor{
		Out: out, UnitDir: o.UnitDir, Cfg: cfg,
		Stat: os.Stat, ReadFile: os.ReadFile, ReadDir: os.ReadDir,
		IsActive: func(unit string) bool { return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil },
		HookInstalled: func() (bool, error) {
			return (antizapret.HookFiles{ScriptsDir: cfg.Node.OpenVPNScriptsDir, Binary: paths.Binary()}).Installed()
		},
		AgentList: func() error {
			_, err := agentproto.Call(paths.NodeSocket(), agentproto.Request{Op: agentproto.OpList}, 2*time.Second)
			return err
		},
		Healthz:      func(url string) error { _, err := httpsGet(url); return err },
		CertNotAfter: certNotAfter,
		DiskFreeMB:   diskFreeMB,
		NginxTest: func() error {
			out, err := n.Run("nginx", "-t")
			if err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		Now: time.Now,
	}
}

func certNotAfter(file string) (time.Time, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, errors.New("в файле нет сертификата PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

// Run печатает строки OK/ПРОБЛЕМА и возвращает число проблем.
func (d *Doctor) Run() int {
	problems := 0
	ok := func(format string, a ...any) { fmt.Fprintf(d.Out, "OK        %s\n", fmt.Sprintf(format, a...)) }
	bad := func(format string, a ...any) {
		problems++
		fmt.Fprintf(d.Out, "ПРОБЛЕМА  %s\n", fmt.Sprintf(format, a...))
	}
	note := func(format string, a ...any) { fmt.Fprintf(d.Out, "-         %s\n", fmt.Sprintf(format, a...)) }

	installed := func(unit string) bool {
		_, err := d.Stat(filepath.Join(d.UnitDir, unit))
		return err == nil
	}
	if !installed(nodeUnitName) {
		bad("служба azpanel-node: юнит %s не установлен (azpanel install)", filepath.Join(d.UnitDir, nodeUnitName))
	} else if d.IsActive("azpanel-node") {
		ok("служба azpanel-node работает")
	} else {
		bad("служба azpanel-node не запущена: systemctl status azpanel-node, журнал %s", filepath.Join(paths.Log(), "node.log"))
	}
	hasPanel := installed(panelUnitName)
	if !hasPanel {
		note("панель на этом сервере не установлена")
	} else if d.IsActive("azpanel-panel") {
		ok("служба azpanel-panel работает")
	} else {
		bad("служба azpanel-panel не запущена: systemctl status azpanel-panel, журнал %s", filepath.Join(paths.Log(), "panel.log"))
	}

	if inst, err := d.HookInstalled(); err != nil {
		bad("хук лимита: %v", err)
	} else if !inst {
		bad("хук лимита не установлен или изменён: azpanel hook install")
	} else {
		ok("хук лимита на месте")
	}

	dir := d.Cfg.Node.OpenVPNSocketDir
	socks := 0
	if entries, err := d.ReadDir(dir); err != nil {
		bad("сокеты управления OpenVPN: %v", err)
	} else {
		for _, e := range entries {
			if e.Type()&fs.ModeSocket != 0 {
				socks++
			}
		}
		if socks == 0 {
			bad("в %s нет сокетов управления OpenVPN: OpenVPN не запущен?", dir)
		} else {
			ok("сокетов управления OpenVPN: %d (%s)", socks, dir)
		}
	}

	if err := d.AgentList(); err != nil {
		bad("API агента не отвечает: %v", err)
	} else {
		ok("API агента отвечает")
	}

	if hasPanel {
		base := d.Cfg.Panel.BasePath
		if base == "" {
			base = "/"
		}
		url := "http://" + d.Cfg.Panel.Listen + base + "healthz"
		if err := d.Healthz(url); err != nil {
			bad("панель не отвечает на %s: %v", url, err)
		} else {
			ok("панель отвечает на /healthz")
		}
	}

	d.certCheck(ok, bad, note)

	if free, err := d.DiskFreeMB(paths.Root()); err != nil {
		bad("место на диске: %v", err)
	} else if free < doctorMinFreeMB {
		bad("на диске с %s свободно %d МБ (меньше %d)", paths.Root(), free, doctorMinFreeMB)
	} else {
		ok("на диске свободно %d МБ", free)
	}

	if _, err := d.Stat(SnippetPath); err == nil {
		if err := d.NginxTest(); err != nil {
			bad("nginx -t не проходит: %v", err)
		} else {
			ok("nginx -t проходит")
		}
	}
	return problems
}

func (d *Doctor) certCheck(ok, bad, note func(string, ...any)) {
	data, err := d.ReadFile(filepath.Join(paths.Etc(), "install.env"))
	if err != nil {
		note("сертификат: install.env нет, пропуск")
		return
	}
	kv, err := ParseEnvFile(data)
	if err != nil || kv[KeyCert] == "" {
		note("сертификат HTTPS не записан в install.env, пропуск")
		return
	}
	end, err := d.CertNotAfter(kv[KeyCert])
	if err != nil {
		bad("сертификат %s: %v", kv[KeyCert], err)
		return
	}
	left := end.Sub(d.Now())
	switch {
	case left <= 0:
		bad("сертификат %s истёк %s", kv[KeyCert], end.Format("2006-01-02"))
	case left < doctorCertDays*24*time.Hour:
		bad("сертификат %s истекает %s (осталось %d дн.)", kv[KeyCert], end.Format("2006-01-02"), int(left.Hours()/24))
	default:
		ok("сертификат действует до %s", end.Format("2006-01-02"))
	}
}
