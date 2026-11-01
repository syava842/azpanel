// Package install — azpanel install / uninstall. Этап 1: только узел.
package install

import (
	"bufio"
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
	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/paths"
)

const nodeUnitName = "azpanel-node.service"

type Options struct {
	Yes           bool
	Purge         bool
	In            io.Reader
	Out           io.Writer
	Run           func(name string, args ...string) error
	Wait          func() error // ждать, пока агент ответит
	UnitDir       string
	AntiZapretDir string
	ScriptsDir    string
	Self          string // путь к запущенному бинарнику
}

func Defaults() Options {
	self, _ := os.Executable()
	return Options{
		In:  os.Stdin,
		Out: os.Stdout,
		Run: func(name string, args ...string) error {
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		Wait:          waitAgent,
		UnitDir:       "/etc/systemd/system",
		AntiZapretDir: "/root/antizapret",
		ScriptsDir:    config.Default().Node.OpenVPNScriptsDir,
		Self:          self,
	}
}

func NodeUnit(bin string) string {
	return `[Unit]
Description=azpanel: агент узла AntiZapret
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + bin + ` node
Restart=on-failure
RestartSec=3
RuntimeDirectory=azpanel
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
`
}

type dirMode struct {
	path string
	mode os.FileMode
}

func layout() []dirMode {
	return []dirMode{
		{paths.Root(), 0o755}, {paths.Bin(), 0o755}, {paths.Etc(), 0o700},
		{paths.Log(), 0o700}, {paths.Data(), 0o700}, {paths.Backup(), 0o700},
	}
}

func InstallNode(o Options) error {
	if _, err := os.Stat(filepath.Join(o.AntiZapretDir, "client.sh")); err != nil {
		return fmt.Errorf("AntiZapret не найден: нет %s", filepath.Join(o.AntiZapretDir, "client.sh"))
	}
	if _, err := os.Stat(o.ScriptsDir); err != nil {
		return fmt.Errorf("нет каталога скриптов OpenVPN %s", o.ScriptsDir)
	}
	unit := filepath.Join(o.UnitDir, nodeUnitName)
	fmt.Fprintf(o.Out, `Будет установлено:
  %s — каталоги bin, etc, log, data, backup
  %s — служба azpanel-node (включится и перезапустится)
  хук лимита в %s: custom-client-connect.sh, custom-client-disconnect.sh
    (перед первой правкой — копии .bak-azpanel)
Лимитов после установки нет: все клиенты подключаются как раньше.
`, paths.Root(), unit, o.ScriptsDir)
	if !o.Yes && !confirm(o.In, o.Out, "Продолжить? [y/N]: ") {
		return errors.New("установка отменена")
	}
	for _, d := range layout() {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil { // MkdirAll не меняет права существующего
			return err
		}
	}
	if err := copyBinary(o.Self, paths.Binary()); err != nil {
		return fmt.Errorf("копирование бинарника: %w", err)
	}
	if _, err := os.Stat(paths.ConfigFile()); errors.Is(err, fs.ErrNotExist) {
		if err := config.Save(paths.ConfigFile(), config.Default()); err != nil {
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(unit, []byte(NodeUnit(paths.Binary())), 0o644); err != nil {
		return err
	}
	if _, err := (antizapret.HookFiles{ScriptsDir: o.ScriptsDir, Binary: paths.Binary()}).Ensure(); err != nil {
		return fmt.Errorf("хук: %w", err)
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "azpanel-node"}, {"restart", "azpanel-node"}} {
		if err := o.Run("systemctl", args...); err != nil {
			return err
		}
	}
	if err := o.Wait(); err != nil {
		return fmt.Errorf("агент не ответил: %w; журнал — %s", err, filepath.Join(paths.Log(), "node.log"))
	}
	fmt.Fprintln(o.Out, "Готово. Лимит: azpanel limit set <клиент> <число>; состояние: azpanel sessions")
	return nil
}

// Uninstall: сначала служба (иначе агент вернёт хук), потом хук и юнит.
func Uninstall(o Options) error {
	unit := filepath.Join(o.UnitDir, nodeUnitName)
	what := "служба azpanel-node, хук лимита, " + unit
	if o.Purge {
		// Корень можно переопределить переменной: не дать ей превратить
		// --purge в удаление чужого каталога.
		if root := filepath.Clean(paths.Root()); filepath.Base(root) != "azpanel" || filepath.Dir(root) == root {
			return fmt.Errorf("--purge: %s не похож на каталог azpanel, удалите его вручную", root)
		}
		what += ", " + paths.Root() + " целиком"
	}
	fmt.Fprintf(o.Out, "Будет удалено: %s\n", what)
	if !o.Yes && !confirm(o.In, o.Out, "Продолжить? [y/N]: ") {
		return errors.New("удаление отменено")
	}
	if err := o.Run("systemctl", "disable", "--now", "azpanel-node"); err != nil {
		fmt.Fprintln(o.Out, "служба не остановлена (возможно, её нет):", err)
	}
	if err := (antizapret.HookFiles{ScriptsDir: o.ScriptsDir, Binary: paths.Binary()}).Remove(); err != nil {
		return fmt.Errorf("хук: %w", err)
	}
	if err := os.Remove(unit); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := o.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if o.Purge {
		return os.RemoveAll(paths.Root())
	}
	fmt.Fprintf(o.Out, "Настройки, лимиты и журналы оставлены в %s\n", paths.Root())
	return nil
}

func copyBinary(src, dst string) error {
	if a, err := filepath.EvalSymlinks(src); err == nil {
		if b, err := filepath.EvalSymlinks(dst); err == nil && a == b {
			return nil // запущен уже установленный бинарник
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(dst, data, 0o755)
}

func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "д", "да":
		return true
	}
	return false
}

func waitAgent() error {
	var err error
	for i := 0; i < 50; i++ {
		if _, err = agentproto.Call(paths.NodeSocket(), agentproto.Request{Op: agentproto.OpList}, time.Second); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}
