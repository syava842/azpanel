package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

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
			// У WireGuard «подключён с» нет: берётся начало из истории подключений.
			var starts map[string]int64
			if s.Store != nil && sec.Kind == nodeapi.KindWireGuard {
				starts, _ = s.Store.OpenConnStarts(ctx, s.nodeIDFor(r)) // нет — длительность «—»
			}
			rows := []vpnSessRow{}
			var down, up, downRate, upRate int64
			for _, x := range sess {
				if x.Kind != sec.Kind {
					continue
				}
				var start time.Time
				if ts, ok := starts[x.Kind+"|"+x.Instance+"|"+x.Name]; ok {
					start = time.Unix(ts, 0)
				}
				row := newVPNSessRow(x, now, start)
				row.City, row.ISP = s.Geo.Lookup(x.Addr)
				row.Flapping = x.Kind == nodeapi.KindWireGuard && flap[x.Name]
				rows = append(rows, row)
				down += x.TxBytes
				up += x.RxBytes
				if x.RateOK {
					downRate += x.TxRate
					upRate += x.RxRate
				}
			}
			key, desc := sortParams(r.URL.Query(), sessSortKeys, "name", false)
			sortSessRows(rows, key, desc)
			data["Heads"] = sortHeads(sec.Base, sessSortKeys, key, desc, "")
			data["Sessions"] = rows
			data["SumDown"], data["SumUp"] = humanBytes(uint64(max(down, 0))), humanBytes(uint64(max(up, 0)))
			data["SumDownRate"], data["SumUpRate"] = rateText(downRate, true), rateText(upRate, true)
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
	Share           string // доля в общем трафике раздела
	down, up, total int64
}

// statPeriods — готовые периоды статистики: последние N суток.
var statPeriods = []struct {
	Key, Title string
	Days       int
}{{"day", "Сутки", 1}, {"week", "Неделя", 7}, {"month", "Месяц", 30}, {"year", "Год", 365}}

var statSortKeys = []struct{ Key, Title string }{
	{"name", "Клиент"}, {"down", "Получено"}, {"up", "Отправлено"}, {"total", "Всего"},
}

// statWindow — период из запроса: period=day|week|month|year или свой
// диапазон from..to (даты UTC включительно). Неверное — месяц.
func statWindow(q url.Values, now time.Time) (from, to time.Time, key, label string) {
	if f, err1 := time.Parse("2006-01-02", q.Get("from")); err1 == nil {
		if t, err2 := time.Parse("2006-01-02", q.Get("to")); err2 == nil && !t.Before(f) {
			to = t.AddDate(0, 0, 1)
			if to.After(now) {
				to = now
			}
			return f, to, "custom", f.Format("02.01.2006") + " — " + t.Format("02.01.2006")
		}
	}
	key = q.Get("period")
	for _, p := range statPeriods {
		if p.Key == key {
			return now.AddDate(0, 0, -p.Days), now, p.Key, p.Title
		}
	}
	return now.AddDate(0, 0, -30), now, "month", "Месяц"
}

// vpnStats — вкладка «Статистика»: трафик всех клиентов раздела за период —
// сутки, неделя, месяц, год или свои даты; график по дням, доля, итог.
// Трафик пишется по имени клиента, поэтому у клиента с обоими профилями он
// общий для OpenVPN и WireGuard.
func (s *Server) vpnStats(sec vpnSection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		now := s.now().UTC()
		from, to, period, label := statWindow(q, now)
		base := sec.Base + "/stats"
		periods := make([]rangeLink, 0, len(statPeriods))
		for _, p := range statPeriods {
			periods = append(periods, rangeLink{Name: p.Title, Href: base + "?period=" + p.Key, Current: p.Key == period})
		}
		data := map[string]any{"VPN": sec.tab("stats"), "Periods": periods, "Base": base,
			"From": from.Format("2006-01-02"), "To": to.Add(-time.Second).Format("2006-01-02")}
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
		node := s.nodeIDFor(r)
		totals, err := s.Store.TrafficTotalsLong(r.Context(), node, from.Unix(), to.Unix()+1, now.Unix())
		if err != nil {
			s.internalError(w, r, "трафик не прочитан", err)
			return
		}
		rows := []statRow{}
		names := map[string]bool{}
		var sum store.Bytes
		both := false
		for _, c := range list {
			if !hasKind(c, sec.Kind) {
				continue
			}
			names[c.Name] = true
			b := totals[c.Name]
			both = both || (c.OpenVPN && c.WireGuard)
			rows = append(rows, statRow{Name: c.Name, Href: clientHref(c.Name), down: max(b.Tx, 0), up: max(b.Rx, 0), total: max(b.Rx+b.Tx, 0)})
			sum.Rx += max(b.Rx, 0)
			sum.Tx += max(b.Tx, 0)
		}
		all := sum.Rx + sum.Tx
		for i := range rows {
			x := &rows[i]
			x.Down, x.Up, x.Total = humanBytes(uint64(x.down)), humanBytes(uint64(x.up)), humanBytes(uint64(x.total))
			if all > 0 && x.total > 0 {
				x.Share = fmt.Sprintf("%.1f%%", float64(x.total)*100/float64(all))
			}
		}
		key, desc := sortParams(q, statSortKeys, "total", true)
		sortStatRows(rows, key, desc)
		extra := "&period=" + period
		if period == "custom" {
			extra = "&from=" + url.QueryEscape(q.Get("from")) + "&to=" + url.QueryEscape(q.Get("to"))
		}
		data["Heads"] = sortHeads(base, statSortKeys, key, desc, extra)
		data["Rows"] = rows
		data["SumDown"], data["SumUp"] = humanBytes(uint64(sum.Tx)), humanBytes(uint64(sum.Rx))
		data["SumTotal"] = humanBytes(uint64(all))
		data["Both"] = both
		data["Period"] = label
		// График по суткам — от двух суток: у одних суток точка одна.
		if to.Sub(from) > 36*time.Hour && all > 0 {
			days, err := s.Store.TrafficByDay(r.Context(), node, from.Unix(), to.Unix()+1, now.Unix())
			if err != nil {
				s.internalError(w, r, "трафик по дням не прочитан", err)
				return
			}
			dn, up := Series{Name: "↓ получено", Step: 24 * time.Hour}, Series{Name: "↑ отправлено", Step: 24 * time.Hour}
			for d := from.Truncate(24 * time.Hour); d.Before(to); d = d.Add(24 * time.Hour) {
				var b store.Bytes
				for name, v := range days[d.Unix()] {
					if names[name] {
						b.Rx += v.Rx
						b.Tx += v.Tx
					}
				}
				dn.Points = append(dn.Points, ChartPoint{d, float64(b.Tx)})
				up.Points = append(up.Points, ChartPoint{d, float64(b.Rx)})
			}
			data["Chart"] = LineChart([]Series{dn, up}, from.Truncate(24*time.Hour), to, "Б")
		}
		s.render(w, r, http.StatusOK, "vpn", data)
	}
}

func sortStatRows(rows []statRow, key string, desc bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		var c int
		switch key {
		case "down":
			c = cmpInt(a.down, b.down)
		case "up":
			c = cmpInt(a.up, b.up)
		case "total":
			c = cmpInt(a.total, b.total)
		default:
			c = strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		}
		if desc {
			c = -c
		}
		if c == 0 {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		return c < 0
	})
}
