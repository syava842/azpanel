package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type apiEnv struct {
	api    *API
	client *nodeapi.HTTPClient
	srv    *httptest.Server
	calls  *[]string
	kills  *[]string
}

func newAPI(t *testing.T) apiEnv {
	t.Helper()
	root := t.TempDir()
	pki := filepath.Join(root, "pki")
	wg := filepath.Join(root, "wireguard")
	az := filepath.Join(root, "antizapret")
	socks := filepath.Join(root, "run")
	proc := filepath.Join(root, "proc")
	for _, d := range []string{filepath.Join(pki, "issued"), wg, az, socks, proc} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(pki, "issued", "alice.crt"), []byte("не PEM"), 0o644)
	os.WriteFile(filepath.Join(wg, "antizapret.conf"), []byte("# Client = alice\n# PrivateKey = ALICEPRIVATE\n[Peer]\nPublicKey = ALICEPUB\nPresharedKey = ALICEPSK\nAllowedIPs = 10.29.8.2/32\n"), 0o600)
	os.WriteFile(filepath.Join(az, "setup"), []byte("WIREGUARD_ENABLE=y\n"), 0o644)
	prof := filepath.Join(az, "client", "openvpn", "antizapret-udp")
	os.MkdirAll(prof, 0o755)
	os.WriteFile(filepath.Join(prof, "antizapret-alice-(1.2.3.4)-udp.ovpn"), []byte("OVPN-ALICE"), 0o644)
	for _, s := range []string{"antizapret-udp.sock", "vpn-udp.sock"} {
		os.WriteFile(filepath.Join(socks, s), nil, 0o600)
	}
	os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu  100 0 50 800 50 0 0 0\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), 0o644)

	now := time.Unix(2_000_000_000, 0)
	tr := NewTracker()
	tr.ApplySnapshot("antizapret-udp", now, []antizapret.Session{{
		Instance: "antizapret-udp", CommonName: "alice", RealAddr: "5.6.7.8:1000", BytesRx: 1, BytesTx: 2, ConnectedSince: now.Add(-time.Hour),
	}})

	var calls, kills []string
	// Имитация client.sh: опция 2 удаляет сертификат, 5 — пиров WG.
	run := func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "2":
			os.Remove(filepath.Join(pki, "issued", args[1]+".crt"))
		case "5":
			os.WriteFile(filepath.Join(wg, "antizapret.conf"), nil, 0o600)
		}
		return []byte("готово\n"), nil
	}
	api := &API{
		Token: testToken, Version: "v-test", Tracker: tr,
		LimitsPath:    filepath.Join(root, "limits.json"),
		Inventory:     antizapret.Inventory{PKI: pki, WireGuardDir: wg},
		ClientSh:      &antizapret.ClientSh{Dir: az, Timeout: time.Second, Run: run},
		AntiZapretDir: az,
		SocketDir:     socks,
		Sampler:       &sysinfo.Sampler{Proc: proc, DiskPath: root},
		Services: func(context.Context) ([]sysinfo.Service, error) {
			return []sysinfo.Service{{Unit: "openvpn-server@antizapret-udp", State: "active"}}, nil
		},
		WGShow: func(_ context.Context, iface string) ([]antizapret.WGPeer, error) {
			if iface != "antizapret" {
				return nil, nil
			}
			return []antizapret.WGPeer{
				{Interface: iface, PublicKey: "ALICEPUB", Endpoint: "9.9.9.9:51820", LatestHandshake: now.Add(-time.Minute), RxBytes: 5, TxBytes: 6},
				{Interface: iface, PublicKey: "STALEPUB", Endpoint: "8.8.8.8:1", LatestHandshake: now.Add(-time.Minute)},
			}, nil
		},
		Kill: func(sock, name string, _ time.Duration) (int, error) {
			kills = append(kills, filepath.Base(sock)+" "+name)
			return 1, nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now },
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return apiEnv{api: api, client: nodeapi.New(srv.URL, testToken), srv: srv, calls: &calls, kills: &kills}
}

func status(err error) int {
	var e *nodeapi.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func TestAPIRequiresToken(t *testing.T) {
	e := newAPI(t)
	for _, auth := range []string{"", "Bearer wrong", "Bearer " + testToken + "x", testToken} {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/info", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(nodeapi.ProtoHeader) != "1" {
			t.Fatalf("%q: %d, proto %q", auth, resp.StatusCode, resp.Header.Get(nodeapi.ProtoHeader))
		}
	}
	info, err := e.client.Info(context.Background())
	if err != nil || info.Proto != 1 || info.Version != "v-test" || !info.WireGuard {
		t.Fatalf("%+v, %v", info, err)
	}
}

func TestAPIEmptyTokenRejectsAll(t *testing.T) {
	e := newAPI(t)
	e.api.Token = ""
	if _, err := nodeapi.New(e.srv.URL, "").Info(context.Background()); status(err) != http.StatusUnauthorized {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIClients(t *testing.T) {
	e := newAPI(t)
	limits.Save(e.api.LimitsPath, limits.Data{Limits: map[string]int{"alice": 2}, Blocked: map[string]bool{"alice": true}})
	cs, err := e.client.Clients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Name != "alice" || !cs[0].OpenVPN || !cs[0].WireGuard || cs[0].Limit != 2 || !cs[0].Blocked || cs[0].CertExpires != nil {
		t.Fatalf("%+v", cs)
	}
}

func TestAPICreateClient(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindOpenVPN, Days: 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "carol", Kind: nodeapi.KindOpenVPN}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindWireGuard}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		req  nodeapi.CreateClient
		code int
	}{
		{nodeapi.CreateClient{Name: "alice", Kind: nodeapi.KindOpenVPN}, http.StatusConflict},
		{nodeapi.CreateClient{Name: "alice", Kind: nodeapi.KindWireGuard}, http.StatusConflict},
		{nodeapi.CreateClient{Name: "bad name", Kind: nodeapi.KindOpenVPN}, http.StatusBadRequest},
		{nodeapi.CreateClient{Name: "dan", Kind: "ipsec"}, http.StatusBadRequest},
		{nodeapi.CreateClient{Name: "dan", Kind: nodeapi.KindOpenVPN, Days: 5000}, http.StatusBadRequest},
	} {
		if _, err := e.client.CreateClient(ctx, bad.req); status(err) != bad.code {
			t.Fatalf("%+v: err = %v", bad.req, err)
		}
	}
	if got := strings.Join(*e.calls, "|"); got != "1 bob 30|1 carol 3650|4 bob" {
		t.Fatalf("вызовы client.sh: %s", got)
	}
}

func TestAPIRenewAndDelete(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	limits.Save(e.api.LimitsPath, limits.Data{Limits: map[string]int{"alice": 2}, Blocked: map[string]bool{"alice": true}})
	if _, err := e.client.Renew(ctx, "alice", 90); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Renew(ctx, "ghost", 90); status(err) != http.StatusNotFound {
		t.Fatalf("ghost: %v", err)
	}
	if _, err := e.client.Renew(ctx, "alice", 0); status(err) != http.StatusBadRequest {
		t.Fatalf("0 дней: %v", err)
	}
	if _, err := e.client.DeleteClient(ctx, nodeapi.KindOpenVPN, "alice"); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); d.Limits["alice"] != 2 {
		t.Fatal("лимит снят, хотя у клиента остался WireGuard")
	}
	if _, err := e.client.DeleteClient(ctx, nodeapi.KindOpenVPN, "alice"); status(err) != http.StatusNotFound {
		t.Fatalf("повторное удаление: %v", err)
	}
	if _, err := e.client.DeleteClient(ctx, nodeapi.KindWireGuard, "alice"); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); len(d.Limits) != 0 || len(d.Blocked) != 0 {
		t.Fatalf("лимит и блокировка удалённого клиента остались: %+v", d)
	}
	if got := strings.Join(*e.calls, "|"); got != "1 alice 90|2 alice|5 alice" {
		t.Fatalf("вызовы client.sh: %s", got)
	}
}

func TestAPIProfiles(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	ps, err := e.client.Profiles(ctx, "alice")
	if err != nil || len(ps) != 1 || ps[0].File != "antizapret-alice-(1.2.3.4)-udp.ovpn" {
		t.Fatalf("%+v, %v", ps, err)
	}
	data, err := e.client.Profile(ctx, "alice", ps[0])
	if err != nil || string(data) != "OVPN-ALICE" {
		t.Fatalf("%q, %v", data, err)
	}
	if _, err := e.client.Profile(ctx, "alice", nodeapi.Profile{Kind: "openvpn", Variant: "antizapret-udp", File: "../../setup"}); status(err) != http.StatusNotFound {
		t.Fatalf("выход из каталога: %v", err)
	}
}

func TestAPILimitAndBlock(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	if err := e.client.SetLimit(ctx, "alice", 3); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); d.Limits["alice"] != 3 {
		t.Fatalf("%+v", d)
	}
	if err := e.client.SetLimit(ctx, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); len(d.Limits) != 0 {
		t.Fatalf("лимит не снят: %+v", d)
	}
	if err := e.client.SetLimit(ctx, "alice", -1); status(err) != http.StatusBadRequest {
		t.Fatalf("-1: %v", err)
	}
	res, err := e.client.SetBlocked(ctx, "alice", true)
	if err != nil || res.Killed != 2 {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := strings.Join(*e.kills, "|"); got != "antizapret-udp.sock alice|vpn-udp.sock alice" {
		t.Fatalf("kill: %s", got)
	}
	if d, _ := limits.Load(e.api.LimitsPath); !d.Blocked["alice"] {
		t.Fatalf("блокировка не записана: %+v", d)
	}
	if _, err := e.client.SetBlocked(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); d.Blocked["alice"] || len(*e.kills) != 2 {
		t.Fatalf("разблокировка: %+v, kill %v", d, *e.kills)
	}
}

func TestAPIBrokenLimitsNotOverwritten(t *testing.T) {
	e := newAPI(t)
	os.WriteFile(e.api.LimitsPath, []byte("{"), 0o600)
	if err := e.client.SetLimit(context.Background(), "alice", 3); status(err) != http.StatusInternalServerError {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(e.api.LimitsPath); string(b) != "{" {
		t.Fatalf("испорченный файл перезаписан: %q", b)
	}
}

func TestAPISessionsHidesKeys(t *testing.T) {
	e := newAPI(t)
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, secret := range []string{"ALICEPUB", "ALICEPSK", "ALICEPRIVATE", "STALEPUB"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("в ответе %s:\n%s", secret, body)
		}
	}
	ss, err := e.client.Sessions(context.Background())
	if err != nil || len(ss) != 2 {
		t.Fatalf("%+v, %v", ss, err)
	}
	if ss[0].Kind != nodeapi.KindOpenVPN || ss[0].Name != "alice" || ss[0].Addr != "5.6.7.8:1000" || ss[0].Since == nil {
		t.Fatalf("OpenVPN: %+v", ss[0])
	}
	if ss[1].Kind != nodeapi.KindWireGuard || ss[1].Name != "alice" || ss[1].Instance != "antizapret" || ss[1].RxBytes != 5 || ss[1].LastHandshake == nil {
		t.Fatalf("WireGuard: %+v", ss[1])
	}
}

func TestAPISystem(t *testing.T) {
	e := newAPI(t)
	s, err := e.client.System(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Resources.Memory.TotalBytes != 1000*1024 || len(s.Services) != 1 || s.Services[0].State != "active" {
		t.Fatalf("%+v", s)
	}
}

func TestAPIConcurrentCreateRunsOnce(t *testing.T) {
	e := newAPI(t)
	issued := filepath.Join(e.api.Inventory.PKI, "issued")
	release := make(chan struct{})
	var runs atomic.Int32
	e.api.ClientSh.Run = func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		runs.Add(1)
		<-release // держим первый вызов, пока второй запрос не дойдёт до сервера
		os.WriteFile(filepath.Join(issued, args[1]+".crt"), []byte("не PEM"), 0o644)
		return []byte("готово\n"), nil
	}
	codes := make(chan int, 2)
	for range 2 {
		go func() {
			_, err := e.client.CreateClient(context.Background(), nodeapi.CreateClient{Name: "newbie", Kind: nodeapi.KindOpenVPN})
			if err == nil {
				codes <- http.StatusCreated
				return
			}
			codes <- status(err)
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	a, b := <-codes, <-codes
	if !(a == http.StatusCreated && b == http.StatusConflict) && !(a == http.StatusConflict && b == http.StatusCreated) {
		t.Fatalf("коды %d и %d, ждали 201 и 409", a, b)
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("client.sh запущен %d раз, ждали 1", n)
	}
}

func TestAPIDeleteLogsFailedRecheck(t *testing.T) {
	e := newAPI(t)
	var logs bytes.Buffer
	e.api.Log = slog.New(slog.NewTextHandler(&logs, nil))
	limits.Save(e.api.LimitsPath, limits.Data{Limits: map[string]int{"alice": 2}, Blocked: map[string]bool{"alice": true}})
	e.api.ClientSh.Run = func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		// После client.sh состав клиентов перестаёт читаться: путь с NUL
		// даёт ошибку, отличную от «нет файла», на любой ОС.
		e.api.Inventory.PKI = "pki\x00сломан"
		return []byte("готово\n"), nil
	}
	if _, err := e.client.DeleteClient(context.Background(), nodeapi.KindOpenVPN, "alice"); err != nil {
		t.Fatalf("клиент удалён, ответ должен быть 200: %v", err)
	}
	d, _ := limits.Load(e.api.LimitsPath)
	if d.Limits["alice"] != 2 || !d.Blocked["alice"] {
		t.Fatalf("запись снята при неудачной перепроверке: %+v", d)
	}
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "name=alice") {
		t.Fatalf("ошибка не записана в журнал:\n%s", out)
	}
}

func TestAPICreateClientProfileBaseCollision(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	// «alice» есть; «vpn-alice» и «antizapret-alice» пишут те же файлы профилей.
	for _, name := range []string{"antizapret-alice", "vpn-alice"} {
		_, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: name, Kind: nodeapi.KindOpenVPN})
		if status(err) != http.StatusConflict || !strings.Contains(err.Error(), "alice") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "antizapret-alice", Kind: nodeapi.KindWireGuard}); status(err) != http.StatusConflict {
		t.Fatalf("wg: %v", err)
	}
	if len(*e.calls) != 0 {
		t.Fatalf("client.sh не должен запускаться: %v", *e.calls)
	}
}
