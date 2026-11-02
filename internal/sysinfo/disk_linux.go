//go:build linux

package sysinfo

import "syscall"

func DiskUsage(path string) (Disk, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Disk{}, err
	}
	bs := uint64(st.Bsize)
	return Disk{TotalBytes: st.Blocks * bs, FreeBytes: st.Bavail * bs}, nil
}
