//go:build !linux

package antizapret

import "os/exec"

// ownProcessGroup — заглушка: группы процессов нужны только на Linux.
func ownProcessGroup(cmd *exec.Cmd) {}
