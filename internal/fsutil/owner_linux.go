//go:build linux

package fsutil

import (
	"os"
	"syscall"
)

// copyOwner переносит владельца и группу прежнего файла на временный.
// Если владелец тот же, что у процесса, chown не нужен.
func copyOwner(info os.FileInfo, name string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) == os.Getuid() && int(st.Gid) == os.Getgid() {
		return nil
	}
	return os.Chown(name, int(st.Uid), int(st.Gid))
}
