// Package sysinfo — ресурсы сервера из /proc и состояние служб systemd.
package sysinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type CPUTimes struct{ Idle, Total uint64 }

// ParseCPU — строка «cpu» /proc/stat: user nice system idle iowait irq
// softirq steal. Простой — idle + iowait; guest уже входит в user.
func ParseCPU(r io.Reader) (CPUTimes, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 9 || f[0] != "cpu" {
			continue
		}
		var v [8]uint64
		var total uint64
		for i := range v {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return CPUTimes{}, fmt.Errorf("/proc/stat: %w", err)
			}
			v[i] = n
			total += n
		}
		return CPUTimes{Idle: v[3] + v[4], Total: total}, nil
	}
	return CPUTimes{}, errors.New("/proc/stat: нет строки cpu")
}

// CPUPercent — доля занятого времени между двумя замерами.
func CPUPercent(prev, cur CPUTimes) float64 {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return 0
	}
	dt := cur.Total - prev.Total
	di := cur.Idle - prev.Idle
	if di > dt {
		return 0
	}
	return 100 * float64(dt-di) / float64(dt)
}

type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

func ParseMeminfo(r io.Reader) (Memory, error) {
	var m Memory
	var haveTotal, haveAvail bool
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			m.TotalBytes, haveTotal = n*1024, true
		case "MemAvailable:":
			m.AvailableBytes, haveAvail = n*1024, true
		}
	}
	if !haveTotal || !haveAvail {
		return Memory{}, errors.New("/proc/meminfo: нет MemTotal или MemAvailable")
	}
	return m, sc.Err()
}

type NetCounters struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// ParseNetDev — счётчики интерфейса из /proc/net/dev: после «имя:» восемь
// полей приёма, затем передача.
func ParseNetDev(r io.Reader, iface string) (NetCounters, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			return NetCounters{}, fmt.Errorf("/proc/net/dev: мало полей у %s", iface)
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			return NetCounters{}, fmt.Errorf("/proc/net/dev: счётчики %s не разобраны", iface)
		}
		return NetCounters{RxBytes: rx, TxBytes: tx}, nil
	}
	return NetCounters{}, fmt.Errorf("/proc/net/dev: нет интерфейса %s", iface)
}

// DefaultRouteIface — интерфейс маршрута по умолчанию из /proc/net/route.
func DefaultRouteIface(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0], nil
		}
	}
	return "", errors.New("/proc/net/route: нет маршрута по умолчанию")
}

func ParseUptime(r io.Reader) (time.Duration, error) {
	var s float64
	if _, err := fmt.Fscan(r, &s); err != nil {
		return 0, fmt.Errorf("/proc/uptime: %w", err)
	}
	return time.Duration(s * float64(time.Second)).Round(time.Millisecond), nil
}

func ParseLoadavg(r io.Reader) ([3]float64, error) {
	var l [3]float64
	if _, err := fmt.Fscan(r, &l[0], &l[1], &l[2]); err != nil {
		return l, fmt.Errorf("/proc/loadavg: %w", err)
	}
	return l, nil
}
