package sysinfo

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeProc(t *testing.T, dir, stat string) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
	os.WriteFile(filepath.Join(dir, "meminfo"), []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "loadavg"), []byte("0.50 0.40 0.30 1/1 1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "uptime"), []byte("120.00 50.00\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "route"), []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "dev"), []byte(netDev), 0o644)
}

func TestSampler(t *testing.T) {
	dir := t.TempDir()
	writeProc(t, dir, "cpu  100 0 50 800 50 0 0 0\n")
	s := &Sampler{Proc: dir, DiskPath: dir}
	first, err := s.Sample(time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(first.CPUPercent-15) > 0.001 { // с загрузки: 150 из 1000
		t.Fatalf("первый замер CPU %v", first.CPUPercent)
	}
	if first.Memory.TotalBytes != 1000*1024 || first.UptimeSec != 120 || first.Load[0] != 0.5 {
		t.Fatalf("%+v", first)
	}
	if first.NetIface != "eth0" || first.Net.RxBytes != 123456 {
		t.Fatalf("сеть: %+v", first)
	}
	writeProc(t, dir, "cpu  175 0 50 825 50 0 0 0\n") // +100 всего, +25 простоя
	second, _ := s.Sample(time.Unix(20, 0))
	if math.Abs(second.CPUPercent-75) > 0.001 {
		t.Fatalf("второй замер CPU %v", second.CPUPercent)
	}
}

func TestSamplerNeedsCPUAndMemory(t *testing.T) {
	s := &Sampler{Proc: t.TempDir(), DiskPath: "/"}
	if _, err := s.Sample(time.Now()); err == nil {
		t.Fatal("без /proc/stat — нет ошибки")
	}
}
