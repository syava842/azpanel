package proxy

import (
	"bufio"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/syava842/azpanel/internal/proxyapi"
)

// maxConns — предел списка в ответе: nf_conntrack_max у proxy.sh — 131072.
const maxConns = 20000

// tuple — адреса одного направления записи conntrack.
type tuple struct {
	src, dst         string
	sport, dport     int
	hasSrc, hasDport bool
}

// ParseConntrack разбирает /proc/net/nf_conntrack или вывод `conntrack -L` и
// оставляет соединения клиентов через проброшенные порты proxy.sh, у которых
// сработал DNAT. Запись «клиент → прокси:порт» отвечает порту на прокси со
// стороны сервера назначения (ProxyPort): сервер видит клиента как «адрес
// прокси:ProxyPort». Нечитаемые и чужие строки пропускаются.
func ParseConntrack(r io.Reader) []proxyapi.Conn {
	var out []proxyapi.Conn
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if c, ok := parseConnLine(sc.Text()); ok {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ListenPort != b.ListenPort {
			return a.ListenPort < b.ListenPort
		}
		if a.ClientIP != b.ClientIP {
			return a.ClientIP < b.ClientIP
		}
		return a.ClientPort < b.ClientPort
	})
	if len(out) > maxConns {
		out = out[:maxConns]
	}
	return out
}

func parseConnLine(line string) (proxyapi.Conn, bool) {
	fields := strings.Fields(line)
	var proto string
	for i, f := range fields {
		if i > 3 {
			break
		}
		if f == "ipv6" {
			return proxyapi.Conn{}, false
		}
		if f == "tcp" || f == "udp" {
			proto = f
			break
		}
	}
	if proto == "" {
		return proxyapi.Conn{}, false
	}
	var orig, reply tuple
	cur := &orig
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "src":
			if cur.hasSrc {
				cur = &reply
			}
			cur.src, cur.hasSrc = v, true
		case "dst":
			cur.dst = v
		case "sport":
			cur.sport, _ = strconv.Atoi(v)
		case "dport":
			cur.dport, _ = strconv.Atoi(v)
			cur.hasDport = true
		}
	}
	if !orig.hasDport || !reply.hasDport {
		return proxyapi.Conn{}, false
	}
	group, _, ok := classify(proto, orig.dport)
	if !ok {
		return proxyapi.Conn{}, false
	}
	// DNAT сработал: ответ приходит не от адреса, на который шёл клиент.
	if reply.src == orig.dst {
		return proxyapi.Conn{}, false
	}
	for _, a := range []string{orig.src, orig.dst, reply.src, reply.dst} {
		if p, err := netip.ParseAddr(a); err != nil || !p.Is4() {
			return proxyapi.Conn{}, false
		}
	}
	return proxyapi.Conn{
		Proto: proto, Group: group, ListenPort: orig.dport,
		ClientIP: orig.src, ClientPort: orig.sport, ProxyPort: reply.dport,
		Target: reply.src + ":" + strconv.Itoa(reply.sport),
	}, true
}
