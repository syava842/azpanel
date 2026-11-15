package panel

import (
	"fmt"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const monitorTimeout = 10 * time.Second

type serviceRow struct {
	Unit, State string
	Bad         bool
}

type liveSession struct {
	sessionRow
	Name, Href string
	City, ISP  string
	Flapping   bool // у WG-клиента адрес меняется часто
}

const (
	denialsWindow = 24 * time.Hour
	maxDenials    = 50
)

type denialRow struct {
	Time, Name, Href, Instance, Addr, Reason string
}

func denialReason(d nodeapi.Denial) string {
	switch d.Reason {
	case "limit":
		return fmt.Sprintf("превышен лимит подключений: %d из %d", d.Count, d.Limit)
	case "blocked":
		return "клиент заблокирован"
	}
	return d.Reason
}

// resourceView — ресурсы уже в человеческих единицах.
type resourceView struct {
	CPU, Load, Memory, Disk, Net, Uptime string
}

func newResourceView(x sysinfo.Snapshot) resourceView {
	used := uint64(0)
	if x.Memory.TotalBytes > x.Memory.AvailableBytes {
		used = x.Memory.TotalBytes - x.Memory.AvailableBytes
	}
	iface := x.NetIface
	if iface == "" {
		iface = "—"
	}
	return resourceView{
		CPU:    fmt.Sprintf("%.1f %%", x.CPUPercent),
		Load:   fmt.Sprintf("%.2f %.2f %.2f", x.Load[0], x.Load[1], x.Load[2]),
		Memory: fmt.Sprintf("%s из %s", humanBytes(used), humanBytes(x.Memory.TotalBytes)),
		Disk:   fmt.Sprintf("свободно %s из %s", humanBytes(x.Disk.FreeBytes), humanBytes(x.Disk.TotalBytes)),
		Net:    fmt.Sprintf("%s: принято %s, отправлено %s", iface, humanBytes(x.Net.RxBytes), humanBytes(x.Net.TxBytes)),
		Uptime: humanDuration(time.Duration(x.UptimeSec) * time.Second),
	}
}
