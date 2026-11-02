package antizapret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSetup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "setup")
	os.WriteFile(p, []byte("# комментарий\nWIREGUARD_ENABLE=n\nOPENVPN_HOST=\nDOMAIN='vpn.example.com'\nX=\"a b\"\r\n\nbroken line\n"), 0o644)
	m, err := ReadSetup(p)
	if err != nil {
		t.Fatal(err)
	}
	if m["WIREGUARD_ENABLE"] != "n" || m["OPENVPN_HOST"] != "" || m["DOMAIN"] != "vpn.example.com" || m["X"] != "a b" {
		t.Fatalf("m = %v", m)
	}
	if _, ok := m["broken line"]; ok {
		t.Fatal("строка без = попала в карту")
	}
}
