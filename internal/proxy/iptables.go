// Package proxy — прокси-агент для VPS с proxy.sh из AntiZapret-VPN: читает
// таблицу nat, меняет адрес назначения проброшенных портов и показывает
// настоящие адреса клиентов за прокси.
package proxy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/syava842/azpanel/internal/proxyapi"
)

// Порты proxy.sh (сверено с GubernievS/AntiZapret-VPN, proxy.sh, ветка main).
// OpenVPN — по UDP и TCP, WireGuard/AmneziaWG — только по UDP. SSH-порты
// (20 и 21) работают после входа по SSH на сам прокси и ведут на :22 того же
// сервера, поэтому переезжают вместе со своей группой.
var (
	openVPNPorts   = []int{80, 443, 504, 508, 50080, 50443}
	wireGuardPorts = []int{540, 580, 51080, 51443, 52080, 52443}
)

const (
	sshOpenVPNPort   = 20
	sshWireGuardPort = 21
)

// classify — группа правила по протоколу и порту на прокси; ok == false —
// правило не из proxy.sh.
func classify(proto string, port int) (group string, ssh, ok bool) {
	switch {
	case (proto == "tcp" || proto == "udp") && slices.Contains(openVPNPorts, port):
		return proxyapi.GroupOpenVPN, false, true
	case proto == "udp" && slices.Contains(wireGuardPorts, port):
		return proxyapi.GroupWireGuard, false, true
	case proto == "tcp" && port == sshOpenVPNPort:
		return proxyapi.GroupOpenVPN, true, true
	case proto == "tcp" && port == sshWireGuardPort:
		return proxyapi.GroupWireGuard, true, true
	}
	return "", false, false
}

// Forward — DNAT-правило proxy.sh и строка, где оно лежит.
type Forward struct {
	proxyapi.Forward
	line int
}

type snat struct {
	line   int
	dest   string // адрес без /32
	source string
}

// Table — разобранный вывод `iptables-save -t nat`. Текст хранится целиком:
// правка меняет только свои строки, остальное (чужие правила, счётчики,
// комментарии) возвращается как было.
type Table struct {
	lines    []string
	trailing bool // исходный текст кончался переводом строки
	Forwards []Forward
	snats    []snat
}

// tokens делит строку правила по пробелам; значение в двойных кавычках
// (например, --comment "a b") остаётся одним токеном.
func tokens(s string) []string {
	var out []string
	var cur strings.Builder
	quoted, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted, has = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

func optValue(tok []string, name string) (string, bool) {
	for i, t := range tok {
		if t == name && i+1 < len(tok) {
			return tok[i+1], true
		}
	}
	return "", false
}

// ParseNAT разбирает вывод `iptables-save -t nat`. Из него берутся DNAT-
// правила proxy.sh в цепочке PREROUTING (без -i, -s, -d и отрицаний) и SNAT-
// правила POSTROUTING вида «-d адрес -j SNAT»; остальные не трогаются.
func ParseNAT(text string) (*Table, error) {
	t := &Table{trailing: strings.HasSuffix(text, "\n")}
	t.lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	inNAT, committed := false, false
	for i, raw := range t.lines {
		line := strings.TrimRight(raw, "\r")
		switch {
		case line == "*nat":
			inNAT = true
		case line == "COMMIT":
			if inNAT {
				committed = true
			}
			inNAT = false
		case inNAT && strings.HasPrefix(line, "-A PREROUTING "):
			if f, ok := parseDNAT(line); ok {
				f.line = i
				t.Forwards = append(t.Forwards, f)
			}
		case inNAT && strings.HasPrefix(line, "-A POSTROUTING "):
			if s, ok := parseSNAT(line); ok {
				s.line = i
				t.snats = append(t.snats, s)
			}
		}
	}
	if !committed {
		return nil, errors.New("в выводе iptables-save нет полной таблицы nat (*nat … COMMIT)")
	}
	return t, nil
}

func parseDNAT(line string) (Forward, bool) {
	tok := tokens(line)
	for _, t := range tok {
		if t == "-i" || t == "-o" || t == "-s" || t == "-d" || t == "!" {
			return Forward{}, false
		}
	}
	if j, _ := optValue(tok, "-j"); j != "DNAT" {
		return Forward{}, false
	}
	proto, _ := optValue(tok, "-p")
	dport, ok := optValue(tok, "--dport")
	if !ok {
		return Forward{}, false
	}
	port, err := strconv.Atoi(dport)
	if err != nil {
		return Forward{}, false
	}
	group, ssh, ok := classify(proto, port)
	if !ok {
		return Forward{}, false
	}
	dest, _ := optValue(tok, "--to-destination")
	ap, err := netip.ParseAddrPort(dest)
	if err != nil || !ap.Addr().Is4() {
		return Forward{}, false
	}
	return Forward{Forward: proxyapi.Forward{
		Group: group, Proto: proto, Port: port, ToIP: ap.Addr().String(), ToPort: int(ap.Port()), SSH: ssh,
	}}, true
}

func parseSNAT(line string) (snat, bool) {
	tok := tokens(line)
	for _, t := range tok {
		if t == "-i" || t == "-o" || t == "-s" || t == "-p" || t == "!" {
			return snat{}, false
		}
	}
	if j, _ := optValue(tok, "-j"); j != "SNAT" {
		return snat{}, false
	}
	d, ok := optValue(tok, "-d")
	if !ok {
		return snat{}, false
	}
	d = strings.TrimSuffix(d, "/32")
	if a, err := netip.ParseAddr(d); err != nil || !a.Is4() {
		return snat{}, false
	}
	src, ok := optValue(tok, "--to-source")
	if !ok {
		return snat{}, false
	}
	return snat{dest: d, source: src}, true
}

// Groups — состояние обеих групп; группа без правил имеет пустой Target.
func (t *Table) Groups() []proxyapi.Group {
	var out []proxyapi.Group
	for _, name := range []string{proxyapi.GroupOpenVPN, proxyapi.GroupWireGuard} {
		g := proxyapi.Group{Name: name, Ports: []int{}}
		targets := map[string]bool{}
		for _, f := range t.Forwards {
			if f.Group != name {
				continue
			}
			if g.Target == "" {
				g.Target = f.ToIP
			}
			targets[f.ToIP] = true
			if !f.SSH && !slices.Contains(g.Ports, f.Port) {
				g.Ports = append(g.Ports, f.Port)
			}
		}
		slices.Sort(g.Ports)
		g.Targets = len(targets)
		g.Mixed = len(targets) > 1
		out = append(out, g)
	}
	return out
}

// ErrNoRules — у группы нет ни одного DNAT-правила proxy.sh.
var ErrNoRules = errors.New("у группы нет DNAT-правил proxy.sh")

// ValidTarget проверяет новый адрес назначения: IPv4, не нулевой, не
// петлевой и не групповой.
func ValidTarget(ip string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("%q: нужен адрес IPv4", ip)
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("%s: адрес назначения не может быть нулевым, петлевым или групповым", a)
	}
	return a, nil
}

// SetTarget возвращает текст таблицы с новым адресом назначения у правил
// группы и число изменённых DNAT-правил. Меняются только DNAT-правила
// портов proxy.sh этой группы (порт назначения сохраняется) и SNAT-правила
// «-d адрес»: без SNAT на новый адрес ответы сервера шли бы клиенту мимо
// прокси.
func (t *Table) SetTarget(group, ip string) (string, int, error) {
	if group != proxyapi.GroupOpenVPN && group != proxyapi.GroupWireGuard {
		return "", 0, &InputError{fmt.Sprintf("неизвестная группа %q: нужна %s или %s", group, proxyapi.GroupOpenVPN, proxyapi.GroupWireGuard)}
	}
	addr, err := ValidTarget(ip)
	if err != nil {
		return "", 0, &InputError{err.Error()}
	}
	newIP := addr.String()
	lines := slices.Clone(t.lines)
	before := map[string]bool{} // адреса назначения всех групп до правки
	after := map[string]bool{}  // и после
	changed, found := 0, false
	for _, f := range t.Forwards {
		before[f.ToIP] = true
		if f.Group != group {
			after[f.ToIP] = true
			continue
		}
		found = true
		after[newIP] = true
		if f.ToIP == newIP {
			continue
		}
		old := "--to-destination " + f.ToIP + ":" + strconv.Itoa(f.ToPort)
		if strings.Count(lines[f.line], old) != 1 {
			return "", 0, fmt.Errorf("строка %d: не нашёл %q для замены", f.line+1, old)
		}
		lines[f.line] = strings.Replace(lines[f.line], old, "--to-destination "+newIP+":"+strconv.Itoa(f.ToPort), 1)
		changed++
	}
	if !found {
		return "", 0, ErrNoRules
	}
	if changed > 0 {
		lines = t.fixSNAT(lines, newIP, before, after)
	}
	out := strings.Join(lines, "\n")
	if t.trailing {
		out += "\n"
	}
	return out, changed, nil
}

// dropMark помечает строку, которую надо убрать.
const dropMark = "\x00drop"

// fixSNAT приводит SNAT-правила в соответствие с адресами назначения: у
// нового адреса правило есть (старое переписывается или добавляется копия), у
// адресов, которых больше нет среди назначений proxy.sh, — убрано.
func (t *Table) fixSNAT(lines []string, newIP string, before, after map[string]bool) []string {
	if len(t.snats) == 0 {
		return lines
	}
	covered := false
	var stale []snat
	for _, s := range t.snats {
		switch {
		case after[s.dest]:
			covered = covered || s.dest == newIP
		case before[s.dest]:
			stale = append(stale, s)
		}
	}
	extra := ""
	if !covered {
		if len(stale) > 0 {
			lines[stale[0].line] = retargetSNAT(t.lines[stale[0].line], stale[0], newIP)
			stale = stale[1:]
		} else {
			last := t.snats[len(t.snats)-1]
			extra = retargetSNAT(t.lines[last.line], last, newIP)
		}
	}
	for _, s := range stale {
		lines[s.line] = dropMark
	}
	last := t.snats[len(t.snats)-1].line
	out := make([]string, 0, len(lines)+1)
	for i, l := range lines {
		if l != dropMark {
			out = append(out, l)
		}
		if i == last && extra != "" {
			out = append(out, extra)
		}
	}
	return out
}

// retargetSNAT переписывает SNAT-правило на другой адрес назначения, оставляя
// остальные опции (например, -m comment) как были. Не нашёлся ровно один «-d»
// с прежним адресом - правило строится заново.
func retargetSNAT(line string, s snat, newDest string) string {
	for _, old := range []string{"-d " + s.dest + "/32", "-d " + s.dest} {
		if strings.Count(line, old+" ") == 1 || strings.HasSuffix(line, old) {
			return strings.Replace(line, old, "-d "+newDest+"/32", 1)
		}
	}
	return snatLine(newDest, s.source)
}

func snatLine(dest, source string) string {
	return "-A POSTROUTING -d " + dest + "/32 -j SNAT --to-source " + source
}
