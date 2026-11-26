package panel

import (
	"strings"
	"testing"
)

func TestIdentityPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/openvpn/easyrsa3/pki/ca.crt":                        true,
		"/etc/openvpn/easyrsa3/pki/private/ca.key":                true,
		"/etc/openvpn/easyrsa3/pki/dh.pem":                        true,
		"/etc/openvpn/easyrsa3/pki/issued/antizapret-server.crt":  true,
		"/etc/openvpn/easyrsa3/pki/private/antizapret-server.key": true,
		"/etc/openvpn/easyrsa3/pki/reqs/antizapret-server.req":    true,
		"/etc/wireguard/key":                                      true,
		"/etc/amnezia/amneziawg/key":                              true,
		"/etc/openvpn/easyrsa3/pki/index.txt":                     false,
		"/etc/openvpn/easyrsa3/pki/serial":                        false,
		"/etc/openvpn/easyrsa3/pki/crl.pem":                       false,
		"/etc/openvpn/easyrsa3/pki/issued/bob.crt":                false,
		"/etc/openvpn/easyrsa3/pki/private/bob.key":               false,
		"/etc/wireguard/antizapret.conf":                          false, // сверяется по ключу интерфейса
		"/root/antizapret/client/openvpn/vpn/server-key":          false,
		"/root/antizapret/config/include-hosts.txt":               false,
	} {
		if got := identityPath(p); got != want {
			t.Errorf("%s: %v, ждали %v", p, got, want)
		}
	}
	if !wgConfPath("/etc/wireguard/vpn.conf") || wgConfPath("/root/antizapret/client/wireguard/vpn.conf") {
		t.Fatal("wgConfPath")
	}
}

// Ключ интерфейса — только PrivateKey секции [Interface]; пиры не влияют.
func TestInterfaceKey(t *testing.T) {
	key := func(s string) [32]byte {
		t.Helper()
		k, err := interfaceKey(strings.NewReader(s))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	a := key("[Interface]\nPrivateKey = KEYA=\n\n[Peer]\nPublicKey = p1\n")
	if a != key("[Interface]\nAddress = 10.0.0.1/24\nPrivateKey=KEYA=\n\n[Peer]\nPublicKey = p1\n\n[Peer]\nPublicKey = p2\n") {
		t.Fatal("пиры или пробелы изменили ключ интерфейса")
	}
	if a == key("[Interface]\nPrivateKey = KEYB=\n") {
		t.Fatal("разные ключи совпали")
	}
	if a == key("[Peer]\nPrivateKey = KEYA=\n") {
		t.Fatal("PrivateKey вне [Interface] принят за ключ интерфейса")
	}
}
