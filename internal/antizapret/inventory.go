package antizapret

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/limits"
)

// WGInterfaces — интерфейсы WireGuard AntiZapret. Прочие (warp-* от AZ-WARP)
// агент не трогает и не показывает.
var WGInterfaces = []string{"antizapret", "vpn"}

// serverCert — сертификат самого сервера в issued/, не клиент.
const serverCert = "antizapret-server"

type ClientInfo struct {
	Name        string
	OpenVPN     bool
	WireGuard   bool
	CertExpires time.Time // нулевое — сертификата нет или он не читается
}

// Inventory читает состав клиентов теми же источниками, что client.sh.
type Inventory struct {
	PKI          string // /etc/openvpn/easyrsa3/pki
	WireGuardDir string // /etc/wireguard
}

// Clients — все клиенты по алфавиту: OpenVPN — файлы issued/*.crt без
// antizapret-server (как listOpenVPN), WireGuard — строки «# Client = имя»
// в antizapret.conf и vpn.conf (как listWireGuard). Нет каталога или
// файла — нет клиентов этого вида.
func (inv Inventory) Clients() ([]ClientInfo, error) {
	byName := map[string]*ClientInfo{}
	get := func(name string) *ClientInfo {
		if c, ok := byName[name]; ok {
			return c
		}
		c := &ClientInfo{Name: name}
		byName[name] = c
		return c
	}
	entries, err := os.ReadDir(filepath.Join(inv.PKI, "issued"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".crt")
		if !ok || name == serverCert || !limits.ValidName(name) || !e.Type().IsRegular() {
			continue
		}
		c := get(name)
		c.OpenVPN = true
		c.CertExpires = certNotAfter(filepath.Join(inv.PKI, "issued", e.Name()))
	}
	for _, iface := range WGInterfaces {
		blocks, err := inv.wgBlocks(iface)
		if err != nil {
			return nil, err
		}
		for _, b := range blocks {
			get(b.name).WireGuard = true
		}
	}
	out := make([]ClientInfo, 0, len(byName))
	for _, c := range byName {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// certNotAfter — срок сертификата; EasyRSA пишет перед PEM текстовую
// расшифровку, pem.Decode её пропускает.
func certNotAfter(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return time.Time{}
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return time.Time{}
		}
		return c.NotAfter.UTC()
	}
}

// WireGuardPeers — имя клиента по открытому ключу пира, для каждого
// интерфейса. Ключи нужны только для сопоставления с выводом wg show и
// наружу не отдаются.
func (inv Inventory) WireGuardPeers() (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, iface := range WGInterfaces {
		blocks, err := inv.wgBlocks(iface)
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		for _, b := range blocks {
			if b.publicKey != "" {
				m[b.publicKey] = b.name
			}
		}
		out[iface] = m
	}
	return out, nil
}

type wgBlock struct{ name, publicKey string }

// wgBlocks разбирает блоки клиентов, которые пишет addWireGuard:
// «# Client = имя», «# PrivateKey = …», «[Peer]», «PublicKey = …», ….
// Закрытые ключи не сохраняются.
func (inv Inventory) wgBlocks(iface string) ([]wgBlock, error) {
	f, err := os.Open(filepath.Join(inv.WireGuardDir, iface+".conf"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []wgBlock
	cur := -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "# Client ="); ok {
			name := strings.ReplaceAll(rest, " ", "")
			if limits.ValidName(name) {
				out = append(out, wgBlock{name: name})
				cur = len(out) - 1
			} else {
				cur = -1
			}
			continue
		}
		if rest, ok := strings.CutPrefix(line, "PublicKey"); ok && cur >= 0 {
			if v, ok := strings.CutPrefix(strings.TrimSpace(rest), "="); ok {
				out[cur].publicKey = strings.TrimSpace(v)
				cur = -1
			}
		}
	}
	return out, sc.Err()
}
