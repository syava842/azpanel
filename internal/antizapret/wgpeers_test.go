package antizapret

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWireGuardClientKeys(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "antizapret.conf"), []byte("[Interface]\nPrivateKey = SRVPRIV\n\n# Client = alice\n# PrivateKey = FAKEPRIV1\n[Peer]\nPublicKey = PUBA1\nPresharedKey = PSK\nAllowedIPs = 10.29.8.2/32\n\n# Client = bob\n# PrivateKey = FAKEPRIV2\n[Peer]\nPublicKey = PUBB1\nAllowedIPs = 10.29.8.3/32\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "vpn.conf"), []byte("# Client = alice\n# PrivateKey = FAKEPRIV3\n[Peer]\nPublicKey = PUBA2\nAllowedIPs = 10.28.8.2/32\n"), 0o600)
	got, err := Inventory{WireGuardDir: dir}.WireGuardClientKeys()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string][]string{
		"antizapret": {"alice": {"PUBA1"}, "bob": {"PUBB1"}},
		"vpn":        {"alice": {"PUBA2"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestStripPeers(t *testing.T) {
	conf := "[Interface]\nPrivateKey = SRV\nListenPort = 51820\n\n[Peer]\nPublicKey = PUBA\nAllowedIPs = 10.0.0.2/32\n\n[Peer]\nPublicKey = PUBB\nAllowedIPs = 10.0.0.3/32\n"
	got := string(StripPeers([]byte(conf), map[string]bool{"PUBA": true}))
	if strings.Contains(got, "PUBA") || !strings.Contains(got, "PUBB") || !strings.Contains(got, "ListenPort = 51820") {
		t.Fatalf("%q", got)
	}
	if string(StripPeers([]byte(conf), nil)) != conf {
		t.Fatal("без отбрасываемых ключей текст должен совпасть")
	}
	if all := string(StripPeers([]byte(conf), map[string]bool{"PUBA": true, "PUBB": true})); strings.Contains(all, "[Peer]") || !strings.Contains(all, "[Interface]") {
		t.Fatalf("%q", all)
	}
}
