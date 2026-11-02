package panel

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

func warpInstalledNode(n *svcNode, domains nodeapi.WarpList) {
	hs := time.Date(2026, 11, 2, 8, 30, 0, 0, time.UTC)
	n.WarpFn = func(context.Context) (nodeapi.Warp, error) {
		w := nodeapi.Warp{Builtin: []nodeapi.WarpIface{{Name: "warp0", Peers: []nodeapi.WarpPeer{{Endpoint: "162.159.1.1:2408", LatestHandshake: &hs, RxBytes: 2048, TxBytes: 1}}}}}
		w.AZ.Installed, w.AZ.Version, w.AZ.RemoteVersion, w.AZ.UpdateAvailable = true, "1.5.7", "1.5.8", true
		w.AZ.DomainsSynced = true
		w.AZ.Subnet.Fake = "10.224.0.0/16"
		w.AZ.Singbox.Running = true
		w.AZ.OutboundMode = "warp"
		return w, nil
	}
	n.WarpDomainsFn = func(context.Context) (nodeapi.WarpList, error) { return domains, nil }
	n.WarpIPsFn = func(context.Context) (nodeapi.WarpList, error) {
		return nodeapi.WarpList{Lines: []string{"1.2.3.0/24"}}, nil
	}
}

func TestWarpPageSummaryDomainsAndIPs(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	warpInstalledNode(n, nodeapi.WarpList{
		Lines:   []string{"claud.ai", "off.example"},
		Domains: []nodeapi.WarpDomain{{Domain: "claud.ai", Source: "user", Enabled: true}, {Domain: "gemini.google.com", Source: "gemini", Enabled: false}},
	})
	rec := get(e, c, "/warp")
	b := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, b)
	}
	for _, want := range []string{"warp0", "162.159.1.1:2408", "2026-11-02 08:30 UTC", "2.0 КБ", "1.5.8", "claud.ai", "gemini.google.com", "1.2.3.0/24", "10.224.0.0/16"} {
		if !strings.Contains(b, want) {
			t.Errorf("нет %q", want)
		}
	}
	// удалять можно только пользовательские домены
	if strings.Contains(b, `name="arg" value="gemini.google.com"`) {
		t.Error("кнопка удаления у домена не из user")
	}
}

func TestWarpDomainsOldAgentShowsRawLines(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	warpInstalledNode(n, nodeapi.WarpList{Lines: []string{"claud.ai|user|1"}})
	rec := get(e, c, "/warp")
	if !strings.Contains(rec.Body.String(), "claud.ai|user|1") {
		t.Fatalf("строка целиком не показана: %s", rec.Body)
	}
}

func TestWarpEditDomainsAndIPs(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	warpInstalledNode(n, nodeapi.WarpList{})
	var gotD, gotI nodeapi.WarpEdit
	n.EditWarpDomainsFn = func(_ context.Context, ed nodeapi.WarpEdit) (nodeapi.Task, error) {
		gotD = ed
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	n.EditWarpIPsFn = func(_ context.Context, ed nodeapi.WarpEdit) (nodeapi.Task, error) {
		gotI = ed
		return nodeapi.Task{ID: "ba9876543210"}, nil
	}
	rec := post(e, c, "/warp/domains", url.Values{"csrf": {csrf}, "action": {"add"}, "arg": {"example.com"}, "sync": {"1"}})
	if rec.Code != 303 || len(gotD.Ops) != 1 || gotD.Ops[0].Op != "add" || gotD.Ops[0].Arg != "example.com" || !gotD.Sync {
		t.Fatalf("add: %d %+v", rec.Code, gotD)
	}
	rec = post(e, c, "/warp/ips", url.Values{"csrf": {csrf}, "action": {"ipadd"}, "arg": {"10.0.0.0/8"}})
	if rec.Code != 303 || gotI.Ops[0].Op != "ipadd" || gotI.Sync {
		t.Fatalf("ipadd: %d %+v", rec.Code, gotI)
	}
	n.Calls = nil
	for name, f := range map[string]url.Values{
		"домен":    {"action": {"add"}, "arg": {"bad domain;rm"}},
		"список":   {"action": {"enable"}, "arg": {"other"}},
		"действие": {"action": {"drop"}, "arg": {"a.com"}},
		"ip":       {"action": {"ipadd"}, "arg": {"a.com"}},
	} {
		f.Set("csrf", csrf)
		if rec := post(e, c, "/warp/domains", f); rec.Code != 400 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if rec := post(e, c, "/warp/ips", url.Values{"csrf": {csrf}, "action": {"ipadd"}, "arg": {"not-a-net"}}); rec.Code != 400 {
		t.Errorf("подсеть: %d", rec.Code)
	}
	if n.called("EditWarpDomains") != 0 {
		t.Error("плохая правка дошла до агента")
	}
}

func TestWarpUpdateNeedsConfirmSyncAndInstall(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	n.WarpFn = func(context.Context) (nodeapi.Warp, error) { return nodeapi.Warp{}, nil } // AZ-WARP не установлен
	n.WarpUpdateFn = func(context.Context) (nodeapi.Task, error) { return nodeapi.Task{ID: "0123456789ab"}, nil }
	n.WarpSyncFn = func(context.Context) (nodeapi.Task, error) { return nodeapi.Task{ID: "0123456789ab"}, nil }
	if rec := post(e, c, "/warp/update", url.Values{"csrf": {csrf}}); rec.Code != 400 || n.called("WarpUpdate") != 0 {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	if rec := post(e, c, "/warp/update", url.Values{"csrf": {csrf}, "confirm": {"1"}}); rec.Code != 303 {
		t.Fatalf("update: %d", rec.Code)
	}
	if rec := post(e, c, "/warp/sync", url.Values{"csrf": {csrf}}); rec.Code != 303 {
		t.Fatalf("sync: %d", rec.Code)
	}
	if b := get(e, c, "/warp").Body.String(); !strings.Contains(b, "AZ-WARP не установлен") || !strings.Contains(b, `name="mode"`) {
		t.Fatalf("форма установки не показана: %s", b)
	}
	var got nodeapi.WarpInstallAnswers
	n.InstallWarpFn = func(_ context.Context, a nodeapi.WarpInstallAnswers) (nodeapi.Task, error) {
		got = a
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	f := url.Values{"csrf": {csrf}, "mode": {"wg"}, "mtu": {"1380"}, "subnet": {"10.224.0.0/16"}, "no_chatgpt": {"1"},
		"wg_endpoint": {"vpn.example.org:51820"}, "wg_address": {"10.9.0.2/32"}, "wg_private_key": {"PRIVATEKEYSECRET="}, "wg_public_key": {"PUB="}}
	rec := post(e, c, "/warp/install", f)
	if rec.Code != 303 || got.Mode != "wg" || got.MTU != 1380 || !got.NoChatGPT || got.WG == nil || got.WG.PrivateKey != "PRIVATEKEYSECRET=" {
		t.Fatalf("install: %d %+v", rec.Code, got)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "warp_install")
	if len(list) != 1 || strings.Contains(list[0].After+list[0].Target, "PRIVATEKEY") {
		t.Fatalf("секрет в журнале: %+v", list)
	}
	// неполные ответы отвергаются до запуска; секреты не возвращаются в форме
	n.Calls = nil
	rec = post(e, c, "/warp/install", url.Values{"csrf": {csrf}, "mode": {"slave"}})
	if rec.Code != 400 || n.called("InstallWarp") != 0 {
		t.Fatalf("slave без ссылки: %d", rec.Code)
	}
	rec = post(e, c, "/warp/install", url.Values{"csrf": {csrf}, "mode": {"nope"}, "ovpn_pass": {"HUNTER2"}})
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "HUNTER2") {
		t.Fatalf("эхо секрета: %d", rec.Code)
	}
}

func TestWarpRoutesAdminOnly(t *testing.T) {
	for _, p := range []string{"GET /warp", "POST /warp/domains", "POST /warp/ips", "POST /warp/sync", "POST /warp/update", "POST /warp/install"} {
		if routes[p] != accAdmin {
			t.Errorf("%s: не администратор", p)
		}
	}
}
