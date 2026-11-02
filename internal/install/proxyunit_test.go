package install

import (
	"strings"
	"testing"
)

func TestProxyUnit(t *testing.T) {
	u := ProxyUnit("/x")
	for _, s := range []string{
		"ExecStart=/x proxy\n", "Description=azpanel: прокси-агент", "ProtectSystem=strict", "ProtectHome=true",
		"ReadWritePaths=/opt/azpanel -/etc/iptables /run/xtables.lock\n", "ExecStartPre=+/usr/bin/touch /run/xtables.lock\n",
		"NoNewPrivileges=true", "PrivateTmp=true",
		"AF_NETLINK", "Restart=always", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, s) {
			t.Errorf("в юните прокси-агента нет %q:\n%s", s, u)
		}
	}
	if strings.Contains(u, "azpanel-node") {
		t.Errorf("прокси-агент не зависит от агента узла:\n%s", u)
	}
	if proxyUnitName != "azpanel-proxy.service" {
		t.Errorf("имя юнита %q", proxyUnitName)
	}
}
