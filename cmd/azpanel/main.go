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
	case "panel":
		return report(cmdPanel(args[1:]))
	case "hook":
		return runHook(args[1:])
	case "limit":
		return report(cmdLimit(args[1:], os.Stdout))
	case "sessions":
		return report(runSessions())
	case "install":
		return report(runInstall(args[1:]))
	case "uninstall":
		return report(runUninstall(args[1:]))
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
  azpanel install [--yes] [--panel]    установить агент узла (--panel — и веб-панель)
  azpanel uninstall [--yes] [--purge]  удалить (--purge — вместе с /opt/azpanel)
  azpanel node                         агент узла (запускает systemd)
  azpanel panel                        веб-панель (запускает systemd)
  azpanel panel passwd [--user ИМЯ]    задать пароль администратора панели
  azpanel limit set <клиент> <число>   лимит одновременных подключений OpenVPN
  azpanel limit unset <клиент>         снять лимит
  azpanel limit get <клиент>
  azpanel limit list
  azpanel sessions                     сессии и лимиты по клиентам
  azpanel hook install|uninstall|status
  azpanel hook connect|disconnect      вызывается OpenVPN
`)
}
