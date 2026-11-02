package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/panel"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/store"
)

// installArgs — разобранные флаги install/uninstall.
type installArgs struct {
	Yes            bool
	Panel          bool
	Purge          bool
	SkipBackup     bool
	NonInteractive bool
	// Answers — ответы из флагов: ключ ответа → значение.
	Answers map[string]string
}

// answerFlags: имя флага → ключ ответа.
var answerFlags = map[string]string{
	"mode": install.KeyMode, "address": install.KeyAddress, "domain": install.KeyDomain,
	"access": install.KeyAccess, "nginx-file": install.KeyNginxFile, "port": install.KeyPort,
	"tls": install.KeyTLS, "cert": install.KeyCert, "key": install.KeyKey, "email": install.KeyEmail,
	"admin": install.KeyAdmin, "admin-password": install.KeyAdminPass, "must-change": install.KeyMustChg,
	"telegram": install.KeyTelegram, "telegram-token": install.KeyTgToken, "telegram-chat": install.KeyTgChat,
	"backup-dir": install.KeyBackupDir, "backup-days": install.KeyBackupDay, "backup-keep": install.KeyBackupKp,
	"firewall": install.KeyFirewall,
}

func parseInstallArgs(args []string) (installArgs, error) {
	a := installArgs{Answers: map[string]string{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--yes", "-y":
			a.Yes = true
			continue
		case "--panel":
			a.Panel = true
			continue
		case "--purge":
			a.Purge = true
			continue
		case "--skip-backup":
			a.SkipBackup = true
			continue
		case "--non-interactive":
			a.NonInteractive = true
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		key, known := answerFlags[name]
		if !strings.HasPrefix(arg, "--") || !known {
			return a, errUsage
		}
		if !hasVal {
			if i+1 >= len(args) {
				return a, fmt.Errorf("у флага --%s нет значения", name)
			}
			i++
			val = args[i]
		}
		a.Answers[key] = val
	}
	return a, nil
}

// legacy — прежний вызов «install [--yes] [--panel]»: узел (и панель на
// 127.0.0.1) без вопросов мастера.
func (a installArgs) legacy() bool {
	return (a.Yes || a.Panel) && !a.NonInteractive && len(a.Answers) == 0
}

func installOptions(a installArgs) install.Options {
	o := install.Defaults()
	if cfg, err := config.Load(paths.ConfigFile()); err == nil {
		o.ScriptsDir = cfg.Node.OpenVPNScriptsDir
	}
	o.Yes, o.Panel, o.Purge, o.SkipBackup = a.Yes, a.Panel, a.Purge, a.SkipBackup
	return o
}

func runInstall(args []string) error {
	a, err := parseInstallArgs(args)
	if err != nil {
		return err
	}
	if a.legacy() {
		return install.InstallNode(installOptions(a))
	}
	self, _ := os.Executable()
	w := install.NewWizard(self, os.Stdin, os.Stdout, !a.NonInteractive, a.Answers)
	w.AssumeYes = a.Yes
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		w.ReadSecret = func() (string, error) {
			b, err := term.ReadPassword(fd)
			return string(b), err
		}
	}
	w.Host.AdminExists = panelAdminExists
	w.Host.CreateAdmin = panelCreateAdmin
	return w.Run()
}

// panelAdminExists: есть ли логин в базе панели (нет базы — нет логина).
// База открывается только на чтение, без миграций: вопрос задаётся до
// подтверждения, и ответ «n» ничего не должен менять (иначе установленная
// старая панель откажется стартовать на базе новой версии).
func panelAdminExists(login string) bool {
	st, err := store.OpenReadOnly(panelDBPath())
	if err != nil {
		return false
	}
	defer st.Close()
	_, err = st.UserByLogin(context.Background(), login)
	return err == nil
}

// panelCreateAdmin создаёт администратора прямо в базе панели.
func panelCreateAdmin(login, password string, mustChange bool) error {
	if err := install.ValidatePassword(login, password); err != nil {
		return err
	}
	hash, err := panel.HashPassword(password)
	if err != nil {
		return err
	}
	st, err := store.Open(panelDBPath())
	if err != nil {
		return fmt.Errorf("база панели: %w", err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now()
	_, err = st.CreateUser(ctx, store.User{Login: login, Hash: hash, Role: store.RoleAdmin, MustChange: mustChange, Created: now.Unix()})
	if errors.Is(err, store.ErrLoginTaken) {
		return install.ErrAdminExists
	}
	if err != nil {
		return err
	}
	return st.Audit(ctx, store.AuditEntry{TS: now.Unix(), User: consoleUser, Action: "user_create", Target: login, After: "администратор создан установщиком"})
}

func runUninstall(args []string) error {
	a, err := parseInstallArgs(args)
	if err != nil {
		return err
	}
	return install.Uninstall(installOptions(a))
}

// cmdDoctor — «azpanel doctor»: код выхода 1, если есть проблемы.
func cmdDoctor(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errUsage
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return err
	}
	if n := install.RealDoctor(out, install.Defaults(), cfg).Run(); n > 0 {
		return fmt.Errorf("проблем: %d", n)
	}
	return nil
}
