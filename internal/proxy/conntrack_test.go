package proxy

import (
	"os"
	"strings"
	"testing"
)

func TestParseConntrackProcFile(t *testing.T) {
	f, err := os.Open("testdata/nf_conntrack.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	conns := ParseConntrack(f)
	// Из восьми строк: SSH на сам прокси (22), чужой UDP 5353 и IPv6 отпадают.
	if len(conns) != 5 {
		t.Fatalf("соединений %d: %+v", len(conns), conns)
	}
	byProxy := map[int]string{}
	for _, c := range conns {
		byProxy[c.ProxyPort] = c.ClientIP
	}
	// Порт на прокси со стороны сервера → настоящий адрес клиента.
	for port, ip := range map[int]string{51234: "192.0.2.55", 22345: "192.0.2.77", 60123: "192.0.2.88", 60500: "192.0.2.99", 33333: "192.0.2.44"} {
		if byProxy[port] != ip {
			t.Errorf("порт %d → %q, нужно %s", port, byProxy[port], ip)
		}
	}
	// WireGuard: SNAT поменял порт (40001 → 22345), клиентский порт остаётся своим.
	for _, c := range conns {
		if c.ProxyPort == 22345 {
			if c.Group != "wireguard" || c.Proto != "udp" || c.ListenPort != 540 || c.ClientPort != 40001 || c.Target != "198.51.100.20:51443" {
				t.Errorf("WG: %+v", c)
			}
		}
		if c.ProxyPort == 51234 && (c.Group != "openvpn" || c.ListenPort != 443 || c.Target != "198.51.100.20:50443") {
			t.Errorf("OpenVPN: %+v", c)
		}
	}
	// Порядок: по порту на прокси, затем адрес.
	for i := 1; i < len(conns); i++ {
		if conns[i-1].ListenPort > conns[i].ListenPort {
			t.Errorf("не по возрастанию порта: %+v", conns)
		}
	}
}

func TestParseConntrackCommandOutput(t *testing.T) {
	f, _ := os.Open("testdata/conntrack-list.txt")
	defer f.Close()
	conns := ParseConntrack(f)
	if len(conns) != 3 {
		t.Fatalf("соединений %d", len(conns))
	}
}

func TestParseConntrackSkipsGarbage(t *testing.T) {
	in := "мусор\n\nudp 17 25 src=1.2.3.4\nudp 17 25 src=192.0.2.1 dst=203.0.113.10 sport=1 dport=443 src=203.0.113.10 dst=192.0.2.1 sport=443 dport=1\n"
	if got := ParseConntrack(strings.NewReader(in)); len(got) != 0 {
		t.Fatalf("без DNAT и с мусором соединений быть не должно: %+v", got)
	}
}
