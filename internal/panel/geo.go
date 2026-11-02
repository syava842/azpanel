package panel

import (
	"net"
	"os"
	"path/filepath"

	"github.com/oschwald/maxminddb-golang"
)

const (
	geoCityFile = "GeoLite2-City.mmdb"
	geoASNFile  = "GeoLite2-ASN.mmdb"
)

// Geo — город и провайдер по IP из баз GeoLite2. nil допустим: тогда
// Lookup возвращает пустые строки.
type Geo struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// OpenGeo ищет GeoLite2-City.mmdb и GeoLite2-ASN.mmdb в dir. Нет обоих —
// nil, nil; нет одного — работает с тем, что есть.
func OpenGeo(dir string) (*Geo, error) {
	g := &Geo{}
	var err error
	if g.city, err = openIfExists(filepath.Join(dir, geoCityFile)); err != nil {
		return nil, err
	}
	if g.asn, err = openIfExists(filepath.Join(dir, geoASNFile)); err != nil {
		g.Close()
		return nil, err
	}
	if g.city == nil && g.asn == nil {
		return nil, nil
	}
	return g, nil
}

func openIfExists(path string) (*maxminddb.Reader, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return maxminddb.Open(path)
}

// Close закрывает базы; nil допустим.
func (g *Geo) Close() {
	if g == nil {
		return
	}
	if g.city != nil {
		g.city.Close()
	}
	if g.asn != nil {
		g.asn.Close()
	}
}

// Lookup — город и провайдер по адресу вида «1.2.3.4», «1.2.3.4:5» или
// «[::1]:5». Не найдено — пустые строки.
func (g *Geo) Lookup(addr string) (city, isp string) {
	if g == nil {
		return "", ""
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", ""
	}
	if g.city != nil {
		var rec struct {
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
		}
		if err := g.city.Lookup(ip, &rec); err == nil {
			if n := rec.City.Names["ru"]; n != "" {
				city = n
			} else {
				city = rec.City.Names["en"]
			}
		}
	}
	if g.asn != nil {
		var rec struct {
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if err := g.asn.Lookup(ip, &rec); err == nil {
			isp = rec.Org
		}
	}
	return city, isp
}
