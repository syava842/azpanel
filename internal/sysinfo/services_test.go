package sysinfo

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestServiceUnits(t *testing.T) {
	got := strings.Join(ServiceUnits([]string{"kresd@1", "kresd@2"}, false), ",")
	want := "openvpn-server@antizapret-udp,openvpn-server@antizapret-tcp,openvpn-server@vpn-udp,openvpn-server@vpn-tcp,kresd@1,kresd@2,azpanel-node"
	if got != want {
		t.Fatalf("%s", got)
	}
	if got := ServiceUnits(nil, true); !strings.Contains(strings.Join(got, ","), "wg-quick@antizapret,wg-quick@vpn") {
		t.Fatalf("%v", got)
	}
}

func TestParseListUnits(t *testing.T) {
	out := "kresd@2.service loaded active running Knot Resolver daemon\nkresd@1.service loaded active running Knot Resolver daemon\n"
	if got := strings.Join(ParseListUnits(out), ","); got != "kresd@1,kresd@2" {
		t.Fatalf("%s", got)
	}
}

func TestParseIsActive(t *testing.T) {
	got := ParseIsActive([]string{"a", "b", "c"}, "active\nfailed\n")
	if len(got) != 3 || got[0].State != "active" || got[1].State != "failed" || got[2].State != "unknown" {
		t.Fatalf("%+v", got)
	}
}

func TestServicesCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Отменённый контекст — ошибка, а не молчаливое «unknown».
	if _, err := Services(ctx, []string{"a"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
