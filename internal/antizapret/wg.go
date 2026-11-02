package antizapret

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// WGPeer — пир из «wg show <iface> dump». PublicKey нужен только для
// сопоставления с именем клиента и наружу не отдаётся.
type WGPeer struct {
	Interface       string
	PublicKey       string
	Endpoint        string // пусто — пир ни разу не подключался
	LatestHandshake time.Time
	RxBytes         int64 // принято сервером от пира
	TxBytes         int64
}

// ParseWGDump разбирает «wg show <iface> dump»: первая строка — сам
// интерфейс (4 поля, среди них закрытый ключ), дальше пиры по 8 полей.
// Ключи в ошибки не попадают.
func ParseWGDump(iface string, r io.Reader) ([]WGPeer, error) {
	sc := bufio.NewScanner(r)
	var out []WGPeer
	for n := 1; sc.Scan(); n++ {
		f := strings.Split(strings.TrimRight(sc.Text(), "\r"), "\t")
		if n == 1 {
			if len(f) != 4 {
				return nil, fmt.Errorf("wg show %s dump: в строке интерфейса %d полей, ожидалось 4", iface, len(f))
			}
			continue
		}
		if len(f) != 8 {
			return nil, fmt.Errorf("wg show %s dump: в строке %d — %d полей, ожидалось 8", iface, n, len(f))
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		p := WGPeer{Interface: iface, PublicKey: f[0], RxBytes: rx, TxBytes: tx}
		if f[2] != "(none)" {
			p.Endpoint = NormalizeAddr(f[2])
		}
		if hs > 0 {
			p.LatestHandshake = time.Unix(hs, 0)
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// WGShow — пиры интерфейса. Интерфейса нет (WireGuard выключен в setup) —
// пусто без ошибки.
func WGShow(ctx context.Context, iface string) ([]WGPeer, error) {
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return nil, nil
	}
	out, err := exec.CommandContext(ctx, "wg", "show", iface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show %s dump: %w", iface, err)
	}
	return ParseWGDump(iface, bytes.NewReader(out))
}
