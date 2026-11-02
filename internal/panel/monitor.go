package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
		dens    []nodeapi.Denial
		denErr  error
	)
	now := s.now()
	wg.Add(3)
	go func() { defer wg.Done(); sys, sysErr = s.nodeFor(r).System(ctx) }()
	go func() { defer wg.Done(); sess, sessErr = s.nodeFor(r).Sessions(ctx) }()
	go func() { defer wg.Done(); dens, denErr = s.nodeFor(r).Denials(ctx, now.Add(-denialsWindow)) }()
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
		var flap map[string]bool
		if col := s.collectorFor(r); col != nil {
			flap = col.Flapping()
		}
		rows := make([]liveSession, 0, len(sess))
		for _, x := range sess {
			city, isp := s.Geo.Lookup(x.Addr)
			rows = append(rows, liveSession{sessionRow: newSessionRow(x), Name: x.Name, Href: clientHref(x.Name),
				City: city, ISP: isp, Flapping: x.Kind == nodeapi.KindWireGuard && flap[x.Name]})
		}
		data["Sessions"] = rows
	}
	data["HasGeo"] = s.Geo != nil
	var ne *nodeapi.Error
	switch {
	case denErr == nil:
		sort.SliceStable(dens, func(i, j int) bool { return dens[i].Time.After(dens[j].Time) })
		if len(dens) > maxDenials {
			dens = dens[:maxDenials]
		}
		rows := make([]denialRow, 0, len(dens))
		for _, d := range dens {
			rows = append(rows, denialRow{Time: d.Time.UTC().Format("2006-01-02 15:04:05") + " UTC", Name: d.Name,
				Href: clientHref(d.Name), Instance: d.Instance, Addr: d.Addr, Reason: denialReason(d)})
		}
		data["Denials"] = rows
	case errors.As(denErr, &ne) && ne.Status == http.StatusNotFound:
		data["DenialsNote"] = "агент не поддерживает журнал отказов"
	default:
		_, tx := s.nodeErr(denErr)
		data["DenialsErr"] = "отказы недоступны: " + tx
	}
	if s.Store != nil {
		h := parseRange(r)
		data["Ranges"] = rangeLinks("/monitor", h)
		if ch, err := s.resourceCharts(r.Context(), h, now); err != nil {
			s.Log.Warn("история ресурсов не прочитана", "err", err)
			data["HistoryErr"] = "история ресурсов недоступна"
		} else {
			data["Charts"] = ch
		}
	}
	s.render(w, r, http.StatusOK, "monitor", data)
}
