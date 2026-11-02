//go:build linux

package antizapret

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup запускает команду в своей группе процессов и по отмене
// убивает всю группу: иначе потомки client.sh (easyrsa, socat) переживают
// таймаут и накладываются на следующий вызов.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
