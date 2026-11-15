package panel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

// Статистика раздела: только клиенты своего вида, по убыванию трафика, с итогом.
func TestVPNStatsByKind(t *testing.T) {
	e, c, _ := storeEnv(t)
	ctx := context.Background()
	e.srv.Store.AddTraffic(ctx, store.LocalNode, histNow.Add(-time.Hour).Unix(), map[string]store.Bytes{
		"bob": {Rx: 5 << 20, Tx: 5 << 20}, "wg-only": {Rx: 7 << 20}, "azpanel-test-1": {Rx: 1 << 20}})
	body := get(e, c, "/openvpn/stats").Body.String()
	pos := func(name string) int { return strings.Index(body, ">"+name+"</a>") }
	if pos("bob") < 0 || pos("azpanel-test-1") < pos("bob") || pos("wg-only") >= 0 {
		t.Fatalf("статистика OpenVPN: %s", body)
	}
	if !strings.Contains(body, "Итого") || !strings.Contains(body, `?range=7d`) {
		t.Fatalf("нет итога или периодов: %s", body)
	}
	if wg := get(e, c, "/wireguard/stats").Body.String(); !strings.Contains(wg, ">wg-only</a>") {
		t.Fatalf("статистика WireGuard: %s", wg)
	}
}

// Без клиентов WireGuard на главной нет его плитки, в меню — пункта.
func TestHomeHidesWireGuardWithoutClients(t *testing.T) {
	e, c, _ := clientsEnv(t)
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "only-ovpn", OpenVPN: true}}, nil
	}
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	body := get(e, c, "/").Body.String()
	if !strings.Contains(body, `href="/openvpn"`) || strings.Contains(body, `href="/wireguard"`) {
		t.Fatalf("главная без WireGuard: %s", body)
	}
}
