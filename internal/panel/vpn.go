package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

// Главная и разделы OpenVPN и WireGuard — как в StatusOpenVPN: у раздела
// вкладки «Сеансы», «Клиенты», «Статистика».

// vpnSection — раздел OpenVPN или WireGuard и открытая вкладка.
type vpnSection struct {
	Kind  string // nodeapi.KindOpenVPN | nodeapi.KindWireGuard
	Title string
	Base  string // /openvpn | /wireguard
	Tab   string // sessions | clients | stats
}

var (
	sectionOpenVPN   = vpnSection{Kind: nodeapi.KindOpenVPN, Title: "OpenVPN", Base: "/openvpn"}
	sectionWireGuard = vpnSection{Kind: nodeapi.KindWireGuard, Title: "WireGuard", Base: "/wireguard"}
)

func (v vpnSection) tab(t string) vpnSection { v.Tab = t; return v }

func hasKind(c nodeapi.Client, kind string) bool {
	if kind == nodeapi.KindWireGuard {
		return c.WireGuard
	}
	return c.OpenVPN
}

// wgFlags — есть ли на узле клиенты WireGuard: от этого зависит, виден ли
// раздел в меню. Узнаётся при каждом чтении списка клиентов.
type wgFlags struct {
	mu   sync.Mutex
	used map[int64]bool
}

func (s *Server) noteWG(r *http.Request, list []nodeapi.Client) {
	if s.wg == nil {
		return
	}
	used := false
	for _, c := range list {
		if c.WireGuard {
			used = true
			break
		}
	}
	s.wg.mu.Lock()
	s.wg.used[s.nodeIDFor(r)] = used
	s.wg.mu.Unlock()
}

// wgShown — показывать ли WireGuard в меню: есть его клиенты или открыт сам
// раздел.
func (s *Server) wgShown(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, sectionWireGuard.Base) {
		return true
	}
	if s.wg == nil {
		return false
	}
	s.wg.mu.Lock()
	defer s.wg.mu.Unlock()
	return s.wg.used[s.nodeIDFor(r)]
}

// vpnSummary — плитка раздела на главной.
type vpnSummary struct {
	Title, Href, ClientsHref         string
	Total, Online, Blocked, Expiring int
}

// resourceTile — плитка ресурса на главной.
type resourceTile struct {
	Name, Value, Note string
	Bad               bool
}

func resourceTiles(sys nodeapi.System) []resourceTile {
	x := sys.Resources
	pct := func(a, b uint64) float64 {
		if b == 0 {
			return 0
		}
		return float64(a) * 100 / float64(b)
	}
	memUsed, diskUsed := uint64(0), uint64(0)
	if x.Memory.TotalBytes > x.Memory.AvailableBytes {
		memUsed = x.Memory.TotalBytes - x.Memory.AvailableBytes
	}
	if x.Disk.TotalBytes > x.Disk.FreeBytes {
		diskUsed = x.Disk.TotalBytes - x.Disk.FreeBytes
	}
	memPct, diskPct := pct(memUsed, x.Memory.TotalBytes), pct(diskUsed, x.Disk.TotalBytes)
	v := newResourceView(x)
	return []resourceTile{
		{Name: "Работает", Value: v.Uptime},
		{Name: "Процессор", Value: v.CPU, Note: "нагрузка " + v.Load, Bad: x.CPUPercent >= 90},
		{Name: "Память", Value: fmt.Sprintf("%.0f %%", memPct), Note: humanBytes(memUsed) + " из " + humanBytes(x.Memory.TotalBytes), Bad: memPct >= 90},
		{Name: "Диск", Value: fmt.Sprintf("%.0f %%", diskPct), Note: "свободно " + humanBytes(x.Disk.FreeBytes) + " из " + humanBytes(x.Disk.TotalBytes), Bad: diskPct >= 90},
	}
}

// home — главная: администратору сводка, пользователю — его клиенты.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if sess, _ := session(r); !sess.IsAdmin() {
		s.clientsPage(w, r, nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), monitorTimeout)
	defer cancel()
	var (
		wg      sync.WaitGroup
		sys     nodeapi.System
		sysErr  error
		sess    []nodeapi.Session
		sessErr error
		list    []nodeapi.Client
		listErr error
	)
	node := s.nodeFor(r)
	wg.Add(3)
	go func() { defer wg.Done(); sys, sysErr = node.System(ctx) }()
	go func() { defer wg.Done(); sess, sessErr = node.Sessions(ctx) }()
	go func() { defer wg.Done(); list, listErr = node.Clients(ctx) }()
	wg.Wait()

	data := map[string]any{}
	if sysErr != nil {
		_, tx := s.nodeErr(sysErr)
		data["SystemErr"] = "ресурсы недоступны: " + tx
	} else {
		data["Tiles"] = resourceTiles(sys)
		services := make([]serviceRow, 0, len(sys.Services))
		bad := 0
		for _, sv := range sys.Services {
			row := serviceRow{Unit: sv.Unit, State: sv.State, Bad: sv.State != "active"}
			if row.Bad {
				bad++
			}
			services = append(services, row)
		}
		data["Services"], data["ServicesBad"] = services, bad
	}
	if listErr != nil {
		_, tx := s.nodeErr(listErr)
		data["VPNErr"] = "клиенты недоступны: " + tx
	} else {
		s.noteWG(r, list)
		online := map[string]map[string]bool{nodeapi.KindOpenVPN: {}, nodeapi.KindWireGuard: {}}
		for _, x := range sess {
			if m, ok := online[x.Kind]; ok {
				m[x.Name] = true
			}
		}
		var sums []vpnSummary
		for _, sec := range []vpnSection{sectionOpenVPN, sectionWireGuard} {
			sum := vpnSummary{Title: sec.Title, Href: sec.Base, ClientsHref: sec.Base + "/clients"}
			for _, c := range list {
				if !hasKind(c, sec.Kind) {
					continue
				}
				sum.Total++
				if online[sec.Kind][c.Name] {
					sum.Online++
				}
				if c.Blocked {
					sum.Blocked++
				}
				if sec.Kind == nodeapi.KindOpenVPN {
					if _, soon := certText(c.CertExpires); soon {
						sum.Expiring++
					}
				}
			}
			if sec.Kind == nodeapi.KindWireGuard && sum.Total == 0 {
				continue // WireGuard не используется — плитки нет
			}
			sums = append(sums, sum)
		}
		data["VPN"] = sums
		if sessErr != nil {
			data["OnlineUnknown"] = true
		}
	}
	if s.Store != nil {
		h := parseRange(r)
		data["Ranges"] = rangeLinks("/", h)
		if ch, err := s.resourceCharts(r.Context(), h, s.now()); err != nil {
			s.Log.Warn("история ресурсов не прочитана", "err", err)
			data["HistoryErr"] = "история ресурсов недоступна"
		} else {
			data["Charts"] = ch
		}
	}
	s.render(w, r, http.StatusOK, "dashboard", data)
}

// monitorRedirect — прежний адрес «Сейчас» ведёт на главную.
func (s *Server) monitorRedirect(w http.ResponseWriter, r *http.Request) {
	to := "/"
	if q := r.URL.RawQuery; q != "" {
		to += "?" + q
	}
	s.redirect(w, r, to, http.StatusFound)
}

// vpnSessions — вкладка «Сеансы»: кто подключён сейчас; у OpenVPN ещё
// отказы за сутки (лимит подключений и блокировка — это его хук).
func (s *Server) vpnSessions(sec vpnSection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), monitorTimeout)
		defer cancel()
		var (
			wg      sync.WaitGroup
			sess    []nodeapi.Session
			sessErr error
			dens    []nodeapi.Denial
			denErr  error
		)
		now := s.now()
		node := s.nodeFor(r)
		wg.Add(1)
		go func() { defer wg.Done(); sess, sessErr = node.Sessions(ctx) }()
		if sec.Kind == nodeapi.KindOpenVPN {
			wg.Add(1)
			go func() { defer wg.Done(); dens, denErr = node.Denials(ctx, now.Add(-denialsWindow)) }()
		}
		wg.Wait()

		data := map[string]any{"VPN": sec.tab("sessions"), "HasGeo": s.Geo != nil}
		if sessErr != nil {
			_, tx := s.nodeErr(sessErr)
			data["SessionsErr"] = "сеансы недоступны: " + tx
		} else {
			var flap map[string]bool
			if col := s.collectorFor(r); col != nil {
				flap = col.Flapping()
			}
			rows := []liveSession{}
			var down, up int64
			for _, x := range sess {
				if x.Kind != sec.Kind {
					continue
				}
				city, isp := s.Geo.Lookup(x.Addr)
				rows = append(rows, liveSession{sessionRow: newSessionRow(x), Name: x.Name, Href: clientHref(x.Name),
					City: city, ISP: isp, Flapping: x.Kind == nodeapi.KindWireGuard && flap[x.Name]})
				down += x.TxBytes
				up += x.RxBytes
			}
			sort.SliceStable(rows, func(i, j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
			data["Sessions"] = rows
			data["SumDown"], data["SumUp"] = humanBytes(uint64(max(down, 0))), humanBytes(uint64(max(up, 0)))
		}
		if sec.Kind == nodeapi.KindOpenVPN {
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
		}
		s.render(w, r, http.StatusOK, "vpn", data)
	}
}

// vpnClients — вкладка «Клиенты»: общий список, только клиенты раздела.
func (s *Server) vpnClients(sec vpnSection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := sec.tab("clients")
		s.clientsPage(w, r, &v)
	}
}

// statRow — строка вкладки «Статистика».
type statRow struct {
	Name, Href      string
	Down, Up, Total string
	total           int64
}

// vpnStats — вкладка «Статистика»: трафик клиентов раздела за период.
// Трафик пишется по имени клиента, поэтому у клиента с обоими профилями он
// общий для OpenVPN и WireGuard.
func (s *Server) vpnStats(sec vpnSection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := parseRange(r)
		data := map[string]any{"VPN": sec.tab("stats"), "Ranges": rangeLinks(sec.Base+"/stats", h)}
		if s.Store == nil {
			data["StatsErr"] = "история трафика не ведётся: у панели нет базы"
			s.render(w, r, http.StatusOK, "vpn", data)
			return
		}
		list, err := s.nodeFor(r).Clients(r.Context())
		if err != nil {
			st, tx := s.nodeErr(err)
			s.errorPage(w, r, st, tx)
			return
		}
		s.noteWG(r, list)
		from, to := h.window(s.now())
		totals, err := s.Store.TrafficTotals(r.Context(), s.nodeIDFor(r), from.Unix(), to.Unix()+1)
		if err != nil {
			s.internalError(w, r, "трафик не прочитан", err)
			return
		}
		rows := []statRow{}
		var sum store.Bytes
		both := false
		for _, c := range list {
			if !hasKind(c, sec.Kind) {
				continue
			}
			b := totals[c.Name]
			if b.Rx+b.Tx <= 0 {
				continue
			}
			both = both || (c.OpenVPN && c.WireGuard)
			rows = append(rows, statRow{Name: c.Name, Href: clientHref(c.Name),
				Down: humanBytes(uint64(max(b.Tx, 0))), Up: humanBytes(uint64(max(b.Rx, 0))),
				Total: humanBytes(uint64(max(b.Rx+b.Tx, 0))), total: b.Rx + b.Tx})
			sum.Rx += b.Rx
			sum.Tx += b.Tx
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].total > rows[j].total })
		data["Rows"] = rows
		data["SumDown"], data["SumUp"] = humanBytes(uint64(max(sum.Tx, 0))), humanBytes(uint64(max(sum.Rx, 0)))
		data["SumTotal"] = humanBytes(uint64(max(sum.Rx+sum.Tx, 0)))
		data["Both"] = both
		data["Period"] = from.UTC().Format("2006-01-02 15:04") + " — " + to.UTC().Format("2006-01-02 15:04") + " UTC"
		s.render(w, r, http.StatusOK, "vpn", data)
	}
}
