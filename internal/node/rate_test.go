package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

func TestRate(t *testing.T) {
	a := &API{}
	t0 := time.Unix(1000, 0)
	if _, _, ok := a.rate("k", 100, 50, t0); ok {
		t.Fatal("первый замер дал скорость")
	}
	if rx, tx, ok := a.rate("k", 1100, 250, t0.Add(10*time.Second)); !ok || rx != 100 || tx != 20 {
		t.Fatalf("скорость %d %d %v", rx, tx, ok)
	}
	// Запрос через секунду — прежняя скорость, база не сдвигается.
	if rx, _, ok := a.rate("k", 1105, 250, t0.Add(11*time.Second)); !ok || rx != 100 {
		t.Fatalf("частый запрос: %d %v", rx, ok)
	}
	// Сброс счётчика — скорости нет.
	if _, _, ok := a.rate("k", 10, 10, t0.Add(20*time.Second)); ok {
		t.Fatal("скорость после сброса счётчика")
	}
	// Замер старше rateMaxGap не в счёт.
	if _, _, ok := a.rate("k", 5000, 5000, t0.Add(20*time.Second+rateMaxGap+time.Second)); ok {
		t.Fatal("скорость по старому замеру")
	}
}

func TestSessionsListenAndVPNAddr(t *testing.T) {
	e := newAPI(t)
	conf := t.TempDir()
	os.WriteFile(filepath.Join(conf, "antizapret-udp.conf"), []byte("proto udp4\nport 50443\n"), 0o644)
	e.api.OpenVPNConfDir = conf
	now := time.Unix(2_000_000_000, 0)
	e.api.Tracker.ApplySnapshot("antizapret-udp", now, []antizapret.Session{{
		Instance: "antizapret-udp", CommonName: "alice", RealAddr: "5.6.7.8:1000", VirtAddr: "10.29.0.10", ConnectedSince: now.Add(-time.Hour),
	}})
	ss, err := e.client.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ovpn, wg bool
	for _, s := range ss {
		switch s.Kind {
		case "openvpn":
			ovpn = s.VPNAddr == "10.29.0.10" && s.Proto == "udp" && s.Port == 50443
		case "wireguard":
			wg = s.Proto == "udp"
		}
	}
	if !ovpn || !wg {
		t.Fatalf("сеансы: %+v", ss)
	}
	if l := antizapret.InstanceListen(conf, "vpn-tcp"); l.Proto != "tcp" || l.Port != 0 {
		t.Fatalf("без конфига: %+v", l)
	}
}
