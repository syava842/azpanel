package config

import "fmt"

// Proxy — раздел [proxy]: прокси-агент (azpanel proxy) на VPS с proxy.sh.
type Proxy struct {
	// Listen — адрес API агента прокси. Наружу, по TLS, агент выйдет вместе с
	// агентом узла (этап 4); пока — только петлевой интерфейс.
	Listen string `toml:"listen"`
}

func defaultProxy() Proxy { return Proxy{Listen: "127.0.0.1:9101"} }

func (p Proxy) validate() error {
	if !loopbackAddr(p.Listen) {
		return fmt.Errorf("proxy.listen = %q: нужен 127.0.0.1:порт или [::1]:порт", p.Listen)
	}
	return nil
}
