package sysinfo

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Disk struct {
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

type Snapshot struct {
	Taken      time.Time   `json:"taken"`
	CPUPercent float64     `json:"cpu_percent"`
	Load       [3]float64  `json:"load"`
	Memory     Memory      `json:"memory"`
	Disk       Disk        `json:"disk"`
	NetIface   string      `json:"net_iface"`
	Net        NetCounters `json:"net"`
	UptimeSec  int64       `json:"uptime_seconds"`
}

// Sampler снимает ресурсы по запросу. CPU — доля занятого времени с
// прошлого вызова (у первого — с загрузки системы), поэтому фонового
// опроса не нужно: панель спрашивает раз в collect_seconds.
type Sampler struct {
	Proc     string // /proc
	DiskPath string // /
	mu       sync.Mutex
	prev     CPUTimes
}

// Sample: без CPU и памяти — ошибка; нагрузка, uptime, сеть и диск
// необязательны, их сбой оставляет нули.
func (s *Sampler) Sample(now time.Time) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{Taken: now.UTC()}
	cpu, err := parseFile(filepath.Join(s.Proc, "stat"), ParseCPU)
	if err != nil {
		return snap, err
	}
	snap.CPUPercent, s.prev = CPUPercent(s.prev, cpu), cpu
	if snap.Memory, err = parseFile(filepath.Join(s.Proc, "meminfo"), ParseMeminfo); err != nil {
		return snap, err
	}
	if l, err := parseFile(filepath.Join(s.Proc, "loadavg"), ParseLoadavg); err == nil {
		snap.Load = l
	}
	if u, err := parseFile(filepath.Join(s.Proc, "uptime"), ParseUptime); err == nil {
		snap.UptimeSec = int64(u / time.Second)
	}
	if iface, err := parseFile(filepath.Join(s.Proc, "net", "route"), DefaultRouteIface); err == nil {
		snap.NetIface = iface
		parse := func(r io.Reader) (NetCounters, error) { return ParseNetDev(r, iface) }
		if n, err := parseFile(filepath.Join(s.Proc, "net", "dev"), parse); err == nil {
			snap.Net = n
		}
	}
	if d, err := DiskUsage(s.DiskPath); err == nil {
		snap.Disk = d
	}
	return snap, nil
}

func parseFile[T any](path string, parse func(io.Reader) (T, error)) (T, error) {
	f, err := os.Open(path)
	if err != nil {
		var zero T
		return zero, err
	}
	defer f.Close()
	return parse(f)
}
