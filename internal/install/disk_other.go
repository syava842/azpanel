//go:build !linux

package install

import "errors"

func diskFreeMB(string) (uint64, error) {
	return 0, errors.New("проверка места на диске работает только на Linux")
}
