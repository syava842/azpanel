package sysinfo

import (
	"context"
	"errors"
	"os/exec"
	"sort"
	"strings"
)

type Service struct {
	Unit  string `json:"unit"`
	State string `json:"state"` // active, inactive, failed, …; unknown — systemd не ответил
}

var openvpnUnits = []string{
	"openvpn-server@antizapret-udp", "openvpn-server@antizapret-tcp",
	"openvpn-server@vpn-udp", "openvpn-server@vpn-tcp",
}

// ServiceUnits — что показывать: четыре экземпляра OpenVPN, найденные
// kresd@*, wg-quick@antizapret и @vpn — если WireGuard включён, агент.
func ServiceUnits(kresd []string, wireguard bool) []string {
	out := append([]string{}, openvpnUnits...)
	out = append(out, kresd...)
	if wireguard {
		out = append(out, "wg-quick@antizapret", "wg-quick@vpn")
	}
	return append(out, "azpanel-node")
}

// ParseListUnits — первый столбец «systemctl list-units --plain --no-legend»
// без «.service», по алфавиту.
func ParseListUnits(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			units = append(units, strings.TrimSuffix(f[0], ".service"))
		}
	}
	sort.Strings(units)
	return units
}

// ParseIsActive — вывод «systemctl is-active u1 u2 …»: строка на юнит в
// том же порядке.
func ParseIsActive(units []string, out string) []Service {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	svcs := make([]Service, len(units))
	for i, u := range units {
		svcs[i] = Service{Unit: u, State: "unknown"}
		if i < len(lines) && strings.TrimSpace(lines[i]) != "" {
			svcs[i].State = strings.TrimSpace(lines[i])
		}
	}
	return svcs
}

// Services опрашивает systemd. is-active выходит с ненулевым кодом, если
// хоть один юнит не active, — это не ошибка: состояние в выводе.
func Services(ctx context.Context, units []string) ([]Service, error) {
	out, err := exec.CommandContext(ctx, "systemctl", append([]string{"is-active"}, units...)...).Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return nil, err
	}
	return ParseIsActive(units, string(out)), nil
}

// KresdUnits — экземпляры kresd@*, сколько их запустил AntiZapret.
func KresdUnits(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--plain", "--no-legend", "--all", "kresd@*").Output()
	if err != nil {
		return nil, err
	}
	return ParseListUnits(string(out)), nil
}
