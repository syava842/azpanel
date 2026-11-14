package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/paths"
)

// cmdRelocate — «azpanel relocate [--yes]»: перенос установки версий до
// 0.1.2 из /opt/azpanel в /root/azpanel, к остальным сервисам AntiZapret.
func cmdRelocate(args []string, in io.Reader, out io.Writer) error {
	yes := false
	for _, a := range args {
		if a != "--yes" {
			return errUsage
		}
		yes = true
	}
	if !paths.Legacy() {
		if _, err := os.Stat(paths.ConfigFile()); err != nil {
			return errors.New("azpanel не установлен: переносить нечего")
		}
		fmt.Fprintf(out, "azpanel уже в %s: переносить нечего.\n", paths.Root())
		return nil
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("перенос выполняется от root на сервере")
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return err
	}
	o := install.LegacyRelocation(cfg.Node.OpenVPNScriptsDir)
	o.Out = out
	fmt.Fprintf(out, `Перенос azpanel из %s в %s:
  службы azpanel останавливаются на время переноса (VPN работает; пока идёт
  перенос, лимит подключений не проверяется);
  каталог перемещается целиком: настройки, база, журналы, бэкапы;
  файлы служб, хук OpenVPN и команда azpanel переводятся на новый каталог;
  копия программы для хука — %s (хук работает не от root,
  а /root ему закрыт).
При сбое всё возвращается на место.
`, o.From, o.To, o.HookBinary)
	if !yes {
		fmt.Fprint(out, "Продолжить? [y/N]: ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes", "д", "да":
		default:
			fmt.Fprintln(out, "Отменено.")
			return nil
		}
	}
	return install.Relocate(o)
}
