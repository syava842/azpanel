package install

const proxyUnitName = "azpanel-proxy.service"

// ProxyUnit — юнит прокси-агента (azpanel proxy) для VPS с proxy.sh. Агент
// работает от root: iptables-save, iptables-restore и netfilter-persistent
// без прав root не запустить, поэтому набор возможностей не сужен. Пишет он
// только в /opt/azpanel (журнал) и /etc/iptables (rules.v4 после
// `netfilter-persistent save`); остальная файловая система закрыта.
func ProxyUnit(bin string) string {
	return `[Unit]
Description=azpanel: прокси-агент
After=network-online.target netfilter-persistent.service
Wants=network-online.target

[Service]
ExecStart=` + bin + ` proxy
Restart=on-failure
RestartSec=3
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/azpanel -/etc/iptables
PrivateTmp=true
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`
}
