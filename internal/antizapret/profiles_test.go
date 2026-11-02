package antizapret

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func touch(t *testing.T, path string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte("профиль"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProfiles(t *testing.T) {
	dir := t.TempDir()
	c := filepath.Join(dir, "client")
	touch(t, filepath.Join(c, "openvpn/antizapret-udp/antizapret-client-(1.2.3.4)-udp.ovpn"))
	touch(t, filepath.Join(c, "openvpn/vpn/vpn-client-(1.2.3.4).ovpn"))
	touch(t, filepath.Join(c, "amneziawg/antizapret/antizapret-client-(1.2.3.4)-am.conf"))
	touch(t, filepath.Join(c, "openvpn/antizapret-udp/antizapret-clientx-(1.2.3.4)-udp.ovpn")) // чужой
	touch(t, filepath.Join(c, "openvpn/vpn/vpn-client-(1.2.3.4).ovpn.bak"))                    // не профиль

	got, err := Profiles(dir, "antizapret-client") // база имени — «client»
	if err != nil {
		t.Fatal(err)
	}
	want := []Profile{
		{Kind: "openvpn", Variant: "antizapret-udp", File: "antizapret-client-(1.2.3.4)-udp.ovpn"},
		{Kind: "openvpn", Variant: "vpn", File: "vpn-client-(1.2.3.4).ovpn"},
		{Kind: "amneziawg", Variant: "antizapret", File: "antizapret-client-(1.2.3.4)-am.conf"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	p, err := ProfilePath(dir, "client", "openvpn", "vpn", "vpn-client-(1.2.3.4).ovpn")
	if err != nil || p != filepath.Join(c, "openvpn", "vpn", "vpn-client-(1.2.3.4).ovpn") {
		t.Fatalf("p = %q, err = %v", p, err)
	}
	for _, bad := range [][3]string{
		{"openvpn", "vpn", "../../../setup"},
		{"openvpn", "..", "vpn-client-(1.2.3.4).ovpn"},
		{"openvpn", "antizapret-udp", "antizapret-clientx-(1.2.3.4)-udp.ovpn"},
	} {
		if _, err := ProfilePath(dir, "client", bad[0], bad[1], bad[2]); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%v: err = %v", bad, err)
		}
	}
}
