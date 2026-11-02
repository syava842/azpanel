package panel

import (
	"context"
	"fmt"
	"net/http"
	"sync"
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

// monitor: ресурсы и сессии спрашиваются параллельно под общим тайм-аутом;
// сбой одной части не мешает показать другую.
func (s *Server) monitor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), monitorTimeout)
	defer cancel()
	var (
		wg      sync.WaitGroup
		sys     nodeapi.System
		sysErr  error
		sess    []nodeapi.Session
		sessErr error
	)
	wg.Add(2)
	go func() { defer wg.Done(); sys, sysErr = s.Node.System(ctx) }()
	go func() { defer wg.Done(); sess, sessErr = s.Node.Sessions(ctx) }()
	wg.Wait()

	data := map[string]any{}
	if sysErr != nil {
		_, tx := s.nodeErr(sysErr)
		data["SystemErr"] = "ресурсы недоступны: " + tx
	} else {
		data["Res"] = newResourceView(sys.Resources)
		services := make([]serviceRow, 0, len(sys.Services))
		for _, sv := range sys.Services {
			services = append(services, serviceRow{Unit: sv.Unit, State: sv.State, Bad: sv.State != "active"})
		}
		data["Services"] = services
	}
	if sessErr != nil {
		_, tx := s.nodeErr(sessErr)
		data["SessionsErr"] = "сессии недоступны: " + tx
	} else {
		rows := make([]liveSession, 0, len(sess))
		for _, x := range sess {
			rows = append(rows, liveSession{sessionRow: newSessionRow(x), Name: x.Name, Href: clientHref(x.Name)})
		}
		data["Sessions"] = rows
	}
	s.render(w, r, http.StatusOK, "monitor", data)
}
