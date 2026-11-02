package config

import (
	"errors"
	"fmt"
)

// Proxy — раздел [proxy]: прокси-агент (azpanel proxy) на VPS с proxy.sh.
type Proxy struct {
	// Listen — адрес API агента прокси на петлевом интерфейсе; пусто — только
	// ListenTLS.
	Listen string `toml:"listen"`
	// ListenTLS — внешний порт по TLS (как node.listen_tls): сертификат
	// etc/tls/node.{crt,key}, белый список AllowIPs обязателен.
	ListenTLS string   `toml:"listen_tls"`
	AllowIPs  []string `toml:"allow_ips"`
}

func defaultProxy() Proxy { return Proxy{Listen: "127.0.0.1:9101"} }

func (p Proxy) validate() error {
	switch {
	case p.Listen == "" && p.ListenTLS == "":
		return errors.New("proxy.listen и proxy.listen_tls пусты: агенту прокси негде слушать")
	case p.Listen != "" && !loopbackAddr(p.Listen):
		return fmt.Errorf("proxy.listen = %q: нужен 127.0.0.1:порт, [::1]:порт или пусто", p.Listen)
	case p.ListenTLS != "" && !tlsAddr(p.ListenTLS):
		return fmt.Errorf("proxy.listen_tls = %q: нужен адрес:порт (например 0.0.0.0:9101)", p.ListenTLS)
	case p.ListenTLS != "" && p.ListenTLS == p.Listen:
		return errors.New("proxy.listen_tls и proxy.listen не могут совпадать")
	case p.ListenTLS != "" && len(p.AllowIPs) == 0:
		return errors.New("proxy.allow_ips пуст: при proxy.listen_tls нужен белый список адресов панели")
	}
	if err := allowErr(p.AllowIPs); err != nil {
		return fmt.Errorf("proxy.allow_ips: %w", err)
	}
	return nil
}
