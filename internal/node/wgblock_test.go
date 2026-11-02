package node

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
)

// wgWorld — поддельные работающие интерфейсы WireGuard.
type wgWorld struct {
	live map[string]map[string]bool // интерфейс → открытые ключи пиров
	cmds []string
}

func newWGWorld(e apiEnv, t *testing.T) *wgWorld {
	t.Helper()
	wgDir := e.api.Inventory.WireGuardDir
	os.WriteFile(filepath.Join(wgDir, "antizapret.conf"), []byte(
		"[Interface]\nPrivateKey = SRVPRIV\n\n"+
			"# Client = alice\n# PrivateKey = FAKEPRIV1\n[Peer]\nPublicKey = ALICEPUB\nAllowedIPs = 10.29.8.2/32\n\n"+
			"# Client = bob\n# PrivateKey = FAKEPRIV2\n[Peer]\nPublicKey = BOBPUB\nAllowedIPs = 10.29.8.3/32\n"), 0o600)
	os.WriteFile(filepath.Join(wgDir, "vpn.conf"), []byte(
		"# Client = alice\n# PrivateKey = FAKEPRIV3\n[Peer]\nPublicKey = ALICEVPN\nAllowedIPs = 10.28.8.2/32\n\n"+
			"# Client = bob\n# PrivateKey = FAKEPRIV4\n[Peer]\nPublicKey = BOBVPN\nAllowedIPs = 10.28.8.3/32\n"), 0o600)
	w := &wgWorld{live: map[string]map[string]bool{
		"antizapret":      {"ALICEPUB": true, "BOBPUB": true},
		"vpn":             {"ALICEVPN": true, "BOBVPN": true},
		"warp-antizapret": {"ALICEPUB": true}, // чужой интерфейс: трогать нельзя
	}}
	e.api.WGShow = func(_ context.Context, iface string) ([]antizapret.WGPeer, error) {
		var out []antizapret.WGPeer
		for k := range w.live[iface] {
			out = append(out, antizapret.WGPeer{Interface: iface, PublicKey: k})
		}
		return out, nil
	}
	e.api.WGCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		w.cmds = append(w.cmds, name+" "+strings.Join(args, " "))
		switch {
		case name == "wg" && args[0] == "show":
			return []byte("antizapret vpn warp-antizapret\n"), nil
		case name == "wg" && args[0] == "set" && args[4] == "remove":
			delete(w.live[args[1]], args[3])
		case name == "wg-quick" && args[0] == "strip":
			b, _ := os.ReadFile(filepath.Join(wgDir, args[1]+".conf"))
			return b, nil
		case name == "wg" && args[0] == "syncconf":
			b, err := os.ReadFile(args[2])
			if err != nil {
				return nil, err
			}
			w.live[args[1]] = map[string]bool{}
			for _, l := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(l, "PublicKey = "); ok {
					w.live[args[1]][v] = true
				}
			}
		}
		return nil, nil
	}
	return w
}

func (w *wgWorld) count(prefix string) int {
	n := 0
	for _, c := range w.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestWGBlockRemovesPeersOnAllInterfaces(t *testing.T) {
	e := newAPI(t)
	w := newWGWorld(e, t)
	res, err := e.client.SetBlocked(context.Background(), "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	// Два сокета OpenVPN по одной сессии (подставной Kill) и два снятых пира.
	if res.Killed != 4 {
		t.Fatalf("Killed = %d, ожидалось 4", res.Killed)
	}
	if w.live["antizapret"]["ALICEPUB"] || w.live["vpn"]["ALICEVPN"] {
		t.Fatalf("пиры alice не сняты: %v", w.live)
	}
	if !w.live["antizapret"]["BOBPUB"] || !w.live["vpn"]["BOBVPN"] {
		t.Fatalf("снят чужой пир: %v", w.live)
	}
	if !w.live["warp-antizapret"]["ALICEPUB"] {
		t.Fatal("warp-* тронут")
	}
	for _, c := range w.cmds {
		if strings.Contains(c, "warp-") && !strings.HasPrefix(c, "wg show interfaces") {
			t.Fatalf("команда на warp-*: %s", c)
		}
		if strings.Contains(c, "PRIV") {
			t.Fatalf("закрытый ключ в команде: %s", c)
		}
	}
}

func TestWGUnblockSyncsConfigAndKeepsOthersBlocked(t *testing.T) {
	e := newAPI(t)
	w := newWGWorld(e, t)
	ctx := context.Background()
	e.client.SetBlocked(ctx, "alice", true)
	e.client.SetBlocked(ctx, "bob", true)
	if _, err := e.client.SetBlocked(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if w.count("wg syncconf") != 2 {
		t.Fatalf("syncconf должен идти на двух интерфейсах: %v", w.cmds)
	}
	if !w.live["antizapret"]["ALICEPUB"] || !w.live["vpn"]["ALICEVPN"] {
		t.Fatalf("пиры alice не возвращены: %v", w.live)
	}
	if w.live["antizapret"]["BOBPUB"] || w.live["vpn"]["BOBVPN"] {
		t.Fatalf("bob вернулся вместе с alice: %v", w.live)
	}
	// Клиент и так на связи — второй syncconf не нужен.
	before := w.count("wg syncconf")
	e.client.SetBlocked(ctx, "alice", false)
	if w.count("wg syncconf") != before {
		t.Fatal("лишний syncconf")
	}
}

func TestWGGuardRunsAfterClientSh(t *testing.T) {
	e := newAPI(t)
	w := newWGWorld(e, t)
	ctx := context.Background()
	e.client.SetBlocked(ctx, "alice", true)
	// client.sh при создании другого клиента пересобрал пиров из конфига.
	w.live["antizapret"]["ALICEPUB"] = true
	w.live["vpn"]["ALICEVPN"] = true
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "carol", Kind: nodeapi.KindWireGuard}); err != nil {
		t.Fatal(err)
	}
	if w.live["antizapret"]["ALICEPUB"] || w.live["vpn"]["ALICEVPN"] {
		t.Fatalf("сторож не запущен после client.sh: %v", w.live)
	}
}

func TestWGGuardNoBlockedNoCommands(t *testing.T) {
	e := newAPI(t)
	w := newWGWorld(e, t)
	n, err := e.api.guardWG(context.Background())
	if err != nil || n != 0 || len(w.cmds) != 0 {
		t.Fatalf("n=%d, err=%v, cmds=%v", n, err, w.cmds)
	}
}
