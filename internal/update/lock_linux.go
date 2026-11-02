//go:build linux

package update

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var errLocked = errors.New("другое обновление azpanel на этом хосте уже идёт")

// acquireLock берёт исключительный flock на файле: второе обновление (из CLI,
// пока идёт задача агента, и наоборот) не начнётся. Замок снимается при
// выходе процесса, залипнуть файл не может.
func acquireLock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errLocked
		}
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
