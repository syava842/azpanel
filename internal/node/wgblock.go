package node

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/limits"
)

// wgCmdTimeout — предел одной команды wg / wg-quick.
const wgCmdTimeout = 10 * time.Second

// ExecWGCmd запускает wg и wg-quick; в API.WGCmd подменяется в тестах.
func ExecWGCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, wgCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args[:min(len(args), 2)], " "), err)
	}
	return out, nil
}

// wgInterfaces — работающие интерфейсы WireGuard, кроме warp-* (исходящие
// туннели к Cloudflare, клиентов в них нет).
func (a *API) wgInterfaces(ctx context.Context) ([]string, error) {
	out, err := a.WGCmd(ctx, "wg", "show", "interfaces")
	if err != nil {
		return nil, err
	}
	var res []string
	for _, f := range strings.Fields(string(out)) {
		if !strings.HasPrefix(f, "warp-") {
			res = append(res, f)
		}
	}
	return res, nil
}

// blockedKeys — открытые ключи пиров заблокированных клиентов на интерфейсе.
func blockedKeys(keys map[string]map[string][]string, iface string, blocked map[string]bool) map[string]bool {
	out := map[string]bool{}
	for name, ks := range keys[iface] {
		if blocked[name] {
			for _, k := range ks {
				out[k] = true
			}
		}
	}
	return out
}

// guardWG снимает с работающих интерфейсов пиров заблокированных клиентов
// и возвращает число снятых. Вызывается при удерживаемом a.ops.
func (a *API) guardWG(ctx context.Context) (int, error) {
	if a.WGCmd == nil {
		return 0, nil
	}
	lim, err := limits.Load(a.LimitsPath)
	if err != nil {
		return 0, err
	}
	if len(lim.Blocked) == 0 {
		return 0, nil
	}
	ifaces, err := a.wgInterfaces(ctx)
	if err != nil {
		return 0, err
	}
	keys, err := a.Inventory.WireGuardClientKeys()
	if err != nil {
		return 0, err
	}
	removed := 0
	var firstErr error
	for _, iface := range ifaces {
		bk := blockedKeys(keys, iface, lim.Blocked)
		if len(bk) == 0 {
			continue
		}
		live, err := a.WGShow(ctx, iface)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, p := range live {
			if !bk[p.PublicKey] {
				continue
			}
			if _, err := a.WGCmd(ctx, "wg", "set", iface, "peer", p.PublicKey, "remove"); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			removed++
		}
	}
	return removed, firstErr
}

// restoreWG возвращает пиры клиента в работающие интерфейсы из конфига:
// «wg-quick strip» во временный файл и «wg syncconf». Пиры других
// заблокированных клиентов из файла вычищаются, чтобы они не вернулись.
// Вызывается при удерживаемом a.ops, когда блокировка уже снята в limits.json.
func (a *API) restoreWG(ctx context.Context, name string) (int, error) {
	if a.WGCmd == nil {
		return 0, nil
	}
	lim, err := limits.Load(a.LimitsPath)
	if err != nil {
		return 0, err
	}
	ifaces, err := a.wgInterfaces(ctx)
	if err != nil {
		return 0, err
	}
	keys, err := a.Inventory.WireGuardClientKeys()
	if err != nil {
		return 0, err
	}
	restored := 0
	var firstErr error
	for _, iface := range ifaces {
		mine := keys[iface][name]
		if len(mine) == 0 {
			continue
		}
		live, err := a.WGShow(ctx, iface)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		have := map[string]bool{}
		for _, p := range live {
			have[p.PublicKey] = true
		}
		missing := 0
		for _, k := range mine {
			if !have[k] {
				missing++
			}
		}
		if missing == 0 {
			continue
		}
		if err := a.syncIface(ctx, iface, blockedKeys(keys, iface, lim.Blocked)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		restored += missing
	}
	return restored, firstErr
}

func (a *API) syncIface(ctx context.Context, iface string, drop map[string]bool) error {
	conf, err := a.WGCmd(ctx, "wg-quick", "strip", iface)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "azpanel-wg-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(antizapret.StripPeers(conf, drop))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	_, err = a.WGCmd(ctx, "wg", "syncconf", iface, f.Name())
	return err
}

// guardAfterClientSh — проход сторожа сразу после client.sh: он пересобирает
// пиров из конфига и возвращает заблокированных.
func (a *API) guardAfterClientSh(ctx context.Context) {
	if n, err := a.guardWG(ctx); err != nil {
		a.Log.Warn("сторож WireGuard: проход не удался", "err", err)
	} else if n > 0 {
		a.Log.Info("сторож WireGuard: сняты пиры заблокированных клиентов", "peers", n)
	}
}

// RunWGGuard — сторож: раз в every снимает пиров заблокированных клиентов.
func (a *API) RunWGGuard(ctx context.Context, every time.Duration) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			a.ops.Lock()
			a.guardAfterClientSh(ctx)
			a.ops.Unlock()
		}
	}
}
