//go:build !linux

package sysinfo

import "errors"

func DiskUsage(string) (Disk, error) {
	return Disk{}, errors.New("место на диске считается только на linux")
}
