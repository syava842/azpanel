package sysinfo

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestParseCPU(t *testing.T) {
	c, err := ParseCPU(strings.NewReader("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 100 0 50 800 50 0 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Idle != 850 || c.Total != 1000 {
		t.Fatalf("%+v", c)
	}
	if _, err := ParseCPU(strings.NewReader("intr 1 2 3\n")); err == nil {
		t.Fatal("нет строки cpu — нет ошибки")
	}
}

func TestCPUPercent(t *testing.T) {
	prev := CPUTimes{Idle: 850, Total: 1000}
	cur := CPUTimes{Idle: 925, Total: 1100}
	if p := CPUPercent(prev, cur); math.Abs(p-25) > 0.001 {
		t.Fatalf("p = %v", p)
	}
	if p := CPUPercent(cur, cur); p != 0 {
		t.Fatalf("без прироста p = %v", p)
	}
}

func TestParseMeminfo(t *testing.T) {
	m, err := ParseMeminfo(strings.NewReader("MemTotal:        2014056 kB\nMemFree:  100 kB\nMemAvailable:    1000000 kB\n"))
	if err != nil || m.TotalBytes != 2014056*1024 || m.AvailableBytes != 1000000*1024 {
		t.Fatalf("%+v, %v", m, err)
	}
	if _, err := ParseMeminfo(strings.NewReader("MemTotal: 1 kB\n")); err == nil {
		t.Fatal("без MemAvailable — нет ошибки")
	}
}

const netDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     100       1    0    0    0     0          0         0      100       1    0    0    0     0       0          0
  eth0: 123456     100    0    0    0     0          0         0   654321     200    0    0    0     0       0          0
`

func TestParseNetDev(t *testing.T) {
	n, err := ParseNetDev(strings.NewReader(netDev), "eth0")
	if err != nil || n.RxBytes != 123456 || n.TxBytes != 654321 {
		t.Fatalf("%+v, %v", n, err)
	}
	if _, err := ParseNetDev(strings.NewReader(netDev), "eth9"); err == nil {
		t.Fatal("нет интерфейса — нет ошибки")
	}
}

func TestDefaultRouteIface(t *testing.T) {
	route := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"vpn-udp\t0018A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	i, err := DefaultRouteIface(strings.NewReader(route))
	if err != nil || i != "eth0" {
		t.Fatalf("%q, %v", i, err)
	}
}

func TestParseUptimeLoadavg(t *testing.T) {
	u, err := ParseUptime(strings.NewReader("3600.52 100.00\n"))
	if err != nil || u != 3600*time.Second+520*time.Millisecond {
		t.Fatalf("%v, %v", u, err)
	}
	l, err := ParseLoadavg(strings.NewReader("0.15 0.10 0.05 1/123 4567\n"))
	if err != nil || l != [3]float64{0.15, 0.10, 0.05} {
		t.Fatalf("%v, %v", l, err)
	}
}
