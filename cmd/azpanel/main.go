// azpanel — панель и агент для AntiZapret-VPN. Режим задаёт первый аргумент.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/hook"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/node"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/proxy"
)

var version = "dev"

// hookTimeout — сколько хук ждёт агента; дольше держать подключение нельзя.
const hookTimeout = time.Second

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return 0
	case "node":
		return runNode()
	case "proxy":
		return runProxy()
	case "panel":
		return report(cmdPanel(args[1:]))
	case "hook":
		return runHook(args[1:])
	case "user":
		return report(cmdUser(args[1:], os.Stdout))
	case "limit":
		return report(cmdLimit(args[1:], os.Stdout))
	case "update":
		return report(cmdUpdate(args[1:], os.Stdin, os.Stdout))
	case "internal":
		return report(cmdInternal(args[1:], os.Stdout))
	case "sessions":
		return report(runSessions())
	case "install":
		return report(runInstall(args[1:]))
	case "uninstall":
		return report(runUninstall(args[1:]))
	case "doctor":
		return report(cmdDoctor(args[1:], os.Stdout))
	default:
		usage()
		return 2
	}
}

func report(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		usage()
		return 2
	case errors.As(err, new(exitCodeError)):
		var ec exitCodeError
		errors.As(err, &ec)
		return ec.code
	default:
		fmt.Fprintln(os.Stderr, "azpanel:", err)
		return 1
	}
}

func hookFiles(cfg config.Config) antizapret.HookFiles {
	return antizapret.HookFiles{ScriptsDir: cfg.Node.OpenVPNScriptsDir, Binary: paths.Binary()}
}

func runNode() int {
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		fmt.Fprintln(os.Stderr, "azpanel node:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := node.Run(ctx, cfg, version, hookFiles(cfg).Ensure); err != nil {
		fmt.Fprintln(os.Stderr, "azpanel node:", err)
		return 1
	}
	return 0
}

func runHook(args []string) int {
	if len(args) != 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "connect", "disconnect":
		call := func(r agentproto.Request) (agentproto.Response, error) {
			return agentproto.Call(paths.NodeSocket(), r, hookTimeout)
		}
		return hook.Run(args[0], os.Getenv, call, os.Stderr)
	}
	// Остальные подкоманды — для администратора, от root.
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return report(err)
	}
	h := hookFiles(cfg)
	switch args[0] {
	case "install":
		_, err := h.Ensure()
		return report(err)
	case "uninstall":
		return report(h.Remove())
	case "status":
		ok, err := h.Installed()
		if err != nil {
			return report(err)
		}
		if ok {
			fmt.Println("хук установлен")
			return 0
		}
		fmt.Println("хук не установлен")
		return 1
	default:
		usage()
		return 2
	}
}

func runSessions() error {
	resp, err := agentproto.Call(paths.NodeSocket(), agentproto.Request{Op: agentproto.OpList}, 2*time.Second)
	if err != nil {
		return fmt.Errorf("агент не отвечает: %w", err)
	}
	lim, err := limits.Load(paths.LimitsFile())
	if err != nil {
		return err
	}
	formatSessions(resp.Counts, lim.Limits, os.Stdout)
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `Использование:
  azpanel version
  azpanel install                      мастер установки (вопросы 1-12, Enter — умолчание)
  azpanel install --non-interactive    без вопросов: ответы в AZPANEL_MODE, AZPANEL_ACCESS, AZPANEL_DOMAIN,
                                       AZPANEL_TLS, AZPANEL_ADMIN, ... или флагами --mode, --access, ...
                                       пароль — только в AZPANEL_ADMIN_PASSWORD: флаг --admin-password виден в ps и истории shell
  azpanel install --yes [--panel]      по-старому: агент узла (--panel — и веб-панель на 127.0.0.1)
  azpanel uninstall [--yes] [--purge] [--skip-backup]
                                       удалить (бэкап AntiZapret, юниты, хук, nginx; --purge — и /opt/azpanel)
  azpanel doctor                       проверка установки (код выхода 1 при проблемах)
  azpanel node                         агент узла (запускает systemd)
  azpanel panel                        веб-панель (запускает systemd)
  azpanel proxy                        агент прокси для VPS с proxy.sh (запускает systemd)
  azpanel panel passwd [--user ИМЯ]    задать пароль администратора панели
  azpanel user list                    пользователи панели
  azpanel user reset <логин>           новый пароль, 2FA выключить, сессии завершить
  azpanel limit set <клиент> <число>   лимит одновременных подключений OpenVPN
  azpanel limit unset <клиент>         снять лимит
  azpanel limit get <клиент>
  azpanel limit list
  azpanel update [--check] [--yes]     обновить azpanel до последнего релиза (с бэкапом и откатом)
  azpanel sessions                     сессии и лимиты по клиентам
  azpanel hook install|uninstall|status
  azpanel hook connect|disconnect      вызывается OpenVPN
`)
}

func runProxy() int {
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		fmt.Fprintln(os.Stderr, "azpanel proxy:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := proxy.Run(ctx, cfg, version); err != nil {
		fmt.Fprintln(os.Stderr, "azpanel proxy:", err)
		return 1
	}
	return 0
}
