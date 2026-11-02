package antizapret

import (
	"bytes"
	"strings"
)

// WireGuardClientKeys — открытые ключи пиров каждого клиента по интерфейсам:
// интерфейс → имя клиента → ключи. Берётся из блоков «# Client = …» конфигов
// WireGuard; закрытые ключи из комментариев не читаются дальше разбора и
// сюда не попадают.
func (inv Inventory) WireGuardClientKeys() (map[string]map[string][]string, error) {
	out := map[string]map[string][]string{}
	for _, iface := range WGInterfaces {
		blocks, err := inv.wgBlocks(iface)
		if err != nil {
			return nil, err
		}
		m := map[string][]string{}
		for _, b := range blocks {
			if b.publicKey != "" {
				m[b.name] = append(m[b.name], b.publicKey)
			}
		}
		out[iface] = m
	}
	return out, nil
}

// StripPeers убирает из вывода «wg-quick strip» секции [Peer] с указанными
// открытыми ключами. Остальной текст сохраняется как есть.
func StripPeers(conf []byte, drop map[string]bool) []byte {
	if len(drop) == 0 {
		return conf
	}
	var out bytes.Buffer
	var sect [][]byte
	isPeer, skip := false, false
	flush := func() {
		if !skip {
			for _, l := range sect {
				out.Write(l)
			}
		}
		sect, isPeer, skip = nil, false, false
	}
	for _, line := range bytes.SplitAfter(conf, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		t := strings.TrimSpace(string(line))
		if strings.HasPrefix(t, "[") {
			flush()
			isPeer = strings.EqualFold(t, "[Peer]")
		} else if isPeer {
			if rest, ok := strings.CutPrefix(t, "PublicKey"); ok {
				if v, ok := strings.CutPrefix(strings.TrimSpace(rest), "="); ok && drop[strings.TrimSpace(v)] {
					skip = true
				}
			}
		}
		sect = append(sect, line)
	}
	flush()
	return out.Bytes()
}
