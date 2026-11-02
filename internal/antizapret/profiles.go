package antizapret

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrNotFound = errors.New("не найдено")

type Profile struct {
	Kind    string // openvpn, wireguard, amneziawg
	Variant string // antizapret, antizapret-udp, vpn-tcp, …
	File    string
}

// profileDirs — каталоги /root/antizapret/client в порядке показа.
var profileDirs = []struct{ kind, variant string }{
	{"openvpn", "antizapret"}, {"openvpn", "antizapret-udp"}, {"openvpn", "antizapret-tcp"},
	{"openvpn", "vpn"}, {"openvpn", "vpn-udp"}, {"openvpn", "vpn-tcp"},
	{"wireguard", "antizapret"}, {"wireguard", "vpn"},
	{"amneziawg", "antizapret"}, {"amneziawg", "vpn"},
}

// profileBase — часть имени файла, которую client.sh берёт из имени
// клиента (setServerHost_FileName): без приставок antizapret- и vpn-.
func profileBase(name string) string {
	return strings.TrimPrefix(strings.TrimPrefix(name, "antizapret-"), "vpn-")
}

// Profiles — файлы профилей клиента. Имя файла client.sh строит как
// <antizapret|vpn>-<база>-(<адрес>)[-udp|-tcp|-wg|-am].<ovpn|conf>.
// У клиентов «antizapret-x» и «x» база одна, и AntiZapret кладёт их файлы
// под одним именем — различить их нельзя.
func Profiles(antizapretDir, name string) ([]Profile, error) {
	re := regexp.MustCompile(`^(antizapret|vpn)-` + regexp.QuoteMeta(profileBase(name)) +
		`-\([^()/]*\)(-udp|-tcp|-wg|-am)?\.(ovpn|conf)$`)
	var out []Profile
	for _, d := range profileDirs {
		entries, err := os.ReadDir(filepath.Join(antizapretDir, "client", d.kind, d.variant))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type().IsRegular() && re.MatchString(e.Name()) {
				out = append(out, Profile{Kind: d.kind, Variant: d.variant, File: e.Name()})
			}
		}
	}
	return out, nil
}

// ProfilePath — путь к файлу, только если он есть среди Profiles клиента:
// путь из запроса на диск не попадает.
func ProfilePath(antizapretDir, name, kind, variant, file string) (string, error) {
	ps, err := Profiles(antizapretDir, name)
	if err != nil {
		return "", err
	}
	for _, p := range ps {
		if p.Kind == kind && p.Variant == variant && p.File == file {
			return filepath.Join(antizapretDir, "client", p.Kind, p.Variant, p.File), nil
		}
	}
	return "", ErrNotFound
}
