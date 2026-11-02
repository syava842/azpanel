package panel

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

func monitorSystem() nodeapi.System {
	return nodeapi.System{
		Resources: sysinfo.Snapshot{
			CPUPercent: 12.34, Load: [3]float64{0.5, 0.25, 0.1},
			Memory:    sysinfo.Memory{TotalBytes: 4 << 30, AvailableBytes: 3 << 30},
			Disk:      sysinfo.Disk{TotalBytes: 50 << 30, FreeBytes: 20 << 30},
			NetIface:  "eth0",
			Net:       sysinfo.NetCounters{RxBytes: 1536, TxBytes: 5 << 30},
			UptimeSec: 76 * 3600,
		},
		Services: []sysinfo.Service{
			{Unit: "openvpn-server@vpn-udp", State: "active"},
			{Unit: "openvpn-server@vpn-tcp", State: "failed"},
		},
	}
}

func monitorSessions() []nodeapi.Session {
	since := time.Now().Add(-time.Hour)
	return []nodeapi.Session{{Kind: "openvpn", Instance: "vpn-udp", Name: "alice", Addr: "1.2.3.4:5", RxBytes: 1536, TxBytes: 5 << 30, Since: &since}}
}

func TestMonitorPage(t *testing.T) {
	e, c, _ := clientsEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return monitorSystem(), nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return monitorSessions(), nil }
	rec := get(e, c, "/monitor")
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, body)
	}
	for _, want := range []string{
		`<meta http-equiv="refresh" content="15">`, "12.3 %", "0.50 0.25 0.10", "1.0 ГБ из 4.0 ГБ", "свободно 20.0 ГБ из 50.0 ГБ",
		"eth0", "принято 1.5 КБ", "отправлено 5.0 ГБ", "3 д 4 ч",
		`<td class="ok">active</td>`, `<td class="bad">failed</td>`,
		`href="/clients/alice"`, "1.2.3.4:5",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	// Автообновление только на этой странице.
	if strings.Contains(get(e, c, "/clients/new").Body.String(), "refresh") {
		t.Error("refresh на чужой странице")
	}
}

func TestMonitorSystemFails(t *testing.T) {
	e, c, _ := clientsEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) {
		return nodeapi.System{}, errors.New("connection refused")
	}
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return monitorSessions(), nil }
	rec := get(e, c, "/monitor")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "alice") || !strings.Contains(body, "агент недоступен: connection refused") {
		t.Fatalf("%d %s", rec.Code, body)
	}
}

func TestMonitorSessionsFail(t *testing.T) {
	e, c, _ := clientsEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return monitorSystem(), nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) {
		return nil, &nodeapi.Error{Status: 500, Message: "сбой сессий"}
	}
	rec := get(e, c, "/monitor")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "сбой сессий") || !strings.Contains(body, "openvpn-server@vpn-udp") {
		t.Fatalf("%d %s", rec.Code, body)
	}
}

func TestMonitorNeedsLogin(t *testing.T) {
	e, _, _ := clientsEnv(t)
	if rec := e.do(httptest.NewRequest("GET", "/monitor", nil)); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
}
