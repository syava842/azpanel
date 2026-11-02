//go:build linux

package warp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// RunPTY запускает команду под псевдотерминалом и ведёт её диалог. Нужен
// потому, что install.sh читает ответы с /dev/tty, а не со стандартного ввода.
// Неизвестный вопрос или сбой ответа убивают установщик; код выхода команды
// возвращается ошибкой, если он не нулевой.
func RunPTY(ctx context.Context, d *Dialog, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "TERM=xterm", "LANG=C.UTF-8")
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 250})
	if err != nil {
		return fmt.Errorf("псевдотерминал не создан: %w", err)
	}
	defer ptmx.Close()
	derr := d.Run(ctx, ptmx)
	if derr != nil && cmd.Process != nil {
		cmd.Process.Kill()
	}
	werr := cmd.Wait()
	if derr != nil {
		return derr
	}
	var ee *exec.ExitError
	if errors.As(werr, &ee) {
		return fmt.Errorf("установщик завершился с кодом %d", ee.ExitCode())
	}
	return werr
}
