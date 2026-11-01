package antizapret

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const status3 = ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n" +
	"TITLE\tOpenVPN 2.7.8\n" +
	"TIME\t2026-11-01 19:15:12\t1793560512\n" +
	"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n" +
	"CLIENT_LIST\talice\tudp4:203.0.113.5:40001\t10.29.0.2\t\t1000\t2000\t2026-11-01 19:00:00\t1793559600\tUNDEF\t1\t0\tAES-256-GCM\n" +
	"CLIENT_LIST\talice\t::ffff:198.51.100.7:40002\t10.29.0.3\t\t10\t20\t2026-11-01 19:01:00\t1793559660\tUNDEF\t2\t1\tAES-256-GCM\n" +
	"CLIENT_LIST\tUNDEF\t192.0.2.9:40003\t\t\t0\t0\t2026-11-01 19:02:00\t1793559720\tUNDEF\t3\t2\tnone\n" +
	"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\n" +
	"GLOBAL_STATS\tdco_enabled\t1\n" +
	"END\n"

func TestParseStatus3(t *testing.T) {
	s, err := ParseStatus3("antizapret-udp", strings.NewReader(status3))
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 {
		t.Fatalf("сессий %d, ждали 2 (UNDEF пропускается): %+v", len(s), s)
	}
	if s[0].Instance != "antizapret-udp" || s[0].CommonName != "alice" || s[0].RealAddr != "203.0.113.5:40001" {
		t.Fatalf("первая сессия %+v", s[0])
	}
	if s[0].BytesRx != 1000 || s[0].BytesTx != 2000 || s[0].ConnectedSince.Unix() != 1793559600 {
		t.Fatalf("счётчики %+v", s[0])
	}
	if s[1].RealAddr != "198.51.100.7:40002" {
		t.Fatalf("префикс ::ffff: не снят: %q", s[1].RealAddr)
	}
}

func TestParseStatus3Incomplete(t *testing.T) {
	_, err := ParseStatus3("x", strings.NewReader("CLIENT_LIST\talice\t1.2.3.4:1\n"))
	if err != ErrIncomplete {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestNormalizeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4:5":                  "1.2.3.4:5",
		"::ffff:1.2.3.4:5":           "1.2.3.4:5",
		"[AF_INET]1.2.3.4:5":         "1.2.3.4:5",
		"[AF_INET6]::ffff:1.2.3.4:5": "1.2.3.4:5",
		// OpenVPN 2.7 пишет в Real Address протокол (сверено на 94).
		"udp4:1.2.3.4:5":        "1.2.3.4:5",
		"tcp4-server:1.2.3.4:5": "1.2.3.4:5",
		"udp6:::ffff:1.2.3.4:5": "1.2.3.4:5",
		"udp:1.2.3.4:5":         "1.2.3.4:5",
		// IPv6: со скобками и без, IPv4 в IPv6 — к виду IPv4.
		"udp6:2001:db8::1:1194":      "[2001:db8::1]:1194",
		"udp6:[2001:db8::1]:1194":    "[2001:db8::1]:1194",
		"[2001:DB8::1]:1194":         "[2001:db8::1]:1194",
		"udp6:[::ffff:1.2.3.4]:5":    "1.2.3.4:5",
		"[AF_INET6]2001:db8::1:1194": "[2001:db8::1]:1194",
	} {
		if got := NormalizeAddr(in); got != want {
			t.Errorf("NormalizeAddr(%q) = %q, ждали %q", in, got, want)
		}
	}
}

// Хук собирает адрес из trusted_ip и trusted_port; ключ должен совпасть с
// тем, что даёт снимок для той же сессии.
func TestNormalizeAddrHookMatchesSnapshot(t *testing.T) {
	for _, c := range []struct{ snapshot, ip, port string }{
		{"udp4:203.0.113.5:40001", "203.0.113.5", "40001"},
		{"udp6:2001:db8::1:1194", "2001:db8::1", "1194"},
		{"udp6:::ffff:198.51.100.7:5", "::ffff:198.51.100.7", "5"},
	} {
		hook := NormalizeAddr(net.JoinHostPort(c.ip, c.port))
		if snap := NormalizeAddr(c.snapshot); snap != hook {
			t.Errorf("снимок %q → %q, хук %s:%s → %q", c.snapshot, snap, c.ip, c.port, hook)
		}
	}
}

// fakeMgmt поднимает сокет, который отвечает как OpenVPN; silent — молчит.
func fakeMgmt(t *testing.T, name string, silent bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name+".sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if silent {
					time.Sleep(3 * time.Second)
					return
				}
				c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\n"))
				line, _ := bufio.NewReader(c).ReadString('\n')
				if strings.TrimSpace(line) == "status 3" {
					c.Write([]byte(status3[strings.Index(status3, "TITLE"):]))
				}
			}(c)
		}
	}()
	return p
}

func TestQueryStatus(t *testing.T) {
	p := fakeMgmt(t, "vpn-udp", false)
	s, err := QueryStatus(p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 || s[0].Instance != "vpn-udp" {
		t.Fatalf("получено %+v", s)
	}
}

func TestQueryStatusTimeout(t *testing.T) {
	p := fakeMgmt(t, "vpn-tcp", true)
	start := time.Now()
	if _, err := QueryStatus(p, 300*time.Millisecond); err == nil {
		t.Fatal("ждали ошибку тайм-аута")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("ждали %v — тайм-аут не сработал", d)
	}
}
