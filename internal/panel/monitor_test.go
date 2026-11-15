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
	// Главная: плитки ресурсов, сводка VPN, службы; /monitor ведёт на неё.
	if rec := get(e, c, "/monitor?range=7d"); rec.Code != 302 || rec.Header().Get("Location") != "/?range=7d" {
		t.Fatalf("/monitor: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec := get(e, c, "/")
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, body)
	}
	for _, want := range []string{
		`<meta http-equiv="refresh" content="15">`, "Главная", "12.3 %", "0.50 0.25 0.10", "1.0 ГБ из 4.0 ГБ", "свободно 20.0 ГБ из 50.0 ГБ",
		"3 д 4 ч", `<td class="ok">active</td>`, `<td class="bad">failed</td>`, "с ошибкой — 1", `href="/openvpn"`, "онлайн из",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("главная: нет %q", want)
		}
	}
	// Сеансы — в разделе OpenVPN.
	ovpn := get(e, c, "/openvpn").Body.String()
	for _, want := range []string{"Сеансы", `class="on"`, `href="/clients/alice"`, "1.2.3.4:5"} {
		if !strings.Contains(ovpn, want) {
			t.Errorf("OpenVPN: нет %q", want)
		}
	}
	// Автообновление только на страницах с живыми данными.
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
	rec := get(e, c, "/")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "агент недоступен: connection refused") || !strings.Contains(body, "OpenVPN") {
		t.Fatalf("%d %s", rec.Code, body)
	}
}

func TestMonitorSessionsFail(t *testing.T) {
	e, c, _ := clientsEnv(t)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return monitorSystem(), nil }
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) {
		return nil, &nodeapi.Error{Status: 500, Message: "сбой сессий"}
	}
	if body := get(e, c, "/openvpn").Body.String(); !strings.Contains(body, "сбой сессий") {
		t.Fatalf("OpenVPN: %s", body)
	}
	if body := get(e, c, "/").Body.String(); !strings.Contains(body, "openvpn-server@vpn-udp") {
		t.Fatalf("главная: %s", body)
	}
}

func TestMonitorNeedsLogin(t *testing.T) {
	e, _, _ := clientsEnv(t)
	if rec := e.do(httptest.NewRequest("GET", "/monitor", nil)); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
}
