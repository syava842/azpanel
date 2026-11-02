package panel

import (
	"context"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

// histRange — период графиков: ?range=1d|7d|30d.
type histRange struct {
	Name string
	Dur  time.Duration
	Step store.Step
}

type rangeLink struct {
	Name, Href string
	Current    bool
}

var histRanges = []histRange{
	{"1d", 24 * time.Hour, store.Minute},
	{"7d", 7 * 24 * time.Hour, store.Hour},
	{"30d", 30 * 24 * time.Hour, store.Hour},
}

// parseRange разбирает ?range=; неизвестное значение — сутки.
func parseRange(r *http.Request) histRange {
	v := r.URL.Query().Get("range")
	for _, h := range histRanges {
		if h.Name == v {
			return h
		}
	}
	return histRanges[0]
}

func (h histRange) stepDur() time.Duration {
	if h.Step == store.Hour {
		return time.Hour
	}
	return time.Minute
}

// rangeLinks — переключатель периода для шаблона; base — путь страницы.
func rangeLinks(base string, cur histRange) []rangeLink {
	out := make([]rangeLink, 0, len(histRanges))
	for _, h := range histRanges {
		out = append(out, rangeLink{Name: h.Name, Href: base + "?range=" + h.Name, Current: h.Name == cur.Name})
	}
	return out
}

func (h histRange) window(now time.Time) (from, to time.Time) {
	return now.Add(-h.Dur), now
}

// clientTraffic строит график скорости клиента (Б/с) и итоги за период.
// ↓ — сколько клиент получил (Tx сервера), ↑ — сколько отдал (Rx).
func (s *Server) clientTraffic(ctx context.Context, name string, h histRange, now time.Time) (chart template.HTML, down, up string, err error) {
	from, to := h.window(now)
	pts, err := s.Store.TrafficSeries(ctx, s.nodeIDCtx(ctx), name, from.Unix(), to.Unix()+1, h.Step)
	if err != nil {
		return "", "", "", err
	}
	step := h.stepDur()
	sec := step.Seconds()
	var dn, upS Series
	dn = Series{Name: "↓", Step: step}
	upS = Series{Name: "↑", Step: step}
	var sumRx, sumTx int64
	for _, p := range pts {
		t := time.Unix(p.TS, 0)
		dn.Points = append(dn.Points, ChartPoint{t, float64(p.Tx) / sec})
		upS.Points = append(upS.Points, ChartPoint{t, float64(p.Rx) / sec})
		sumRx += p.Rx
		sumTx += p.Tx
	}
	return LineChart([]Series{dn, upS}, from, to, "Б/с"), humanBytes(uint64(max(sumTx, 0))), humanBytes(uint64(max(sumRx, 0))), nil
}

// resourceCharts — четыре графика «Сейчас»: процессор, память, сеть, онлайн.
type resourceCharts struct {
	CPU, Memory, Net, Online template.HTML
}

func (s *Server) resourceCharts(ctx context.Context, h histRange, now time.Time) (resourceCharts, error) {
	from, to := h.window(now)
	pts, err := s.Store.ResourceSeries(ctx, s.nodeIDCtx(ctx), from.Unix(), to.Unix()+1, h.Step)
	if err != nil {
		return resourceCharts{}, err
	}
	step := h.stepDur()
	cpu := Series{Name: "процессор", Step: step}
	mem := Series{Name: "память", Step: step}
	rx := Series{Name: "↓", Step: step}
	tx := Series{Name: "↑", Step: step}
	onl := Series{Name: "онлайн", Step: step}
	for i, p := range pts {
		t := time.Unix(p.TS, 0)
		cpu.Points = append(cpu.Points, ChartPoint{t, p.CPU})
		memPct := math.NaN()
		if p.MemTotal > 0 {
			memPct = float64(p.MemUsed) / float64(p.MemTotal) * 100
		}
		mem.Points = append(mem.Points, ChartPoint{t, memPct})
		onl.Points = append(onl.Points, ChartPoint{t, float64(p.Online)})
		// скорость сети — из разности соседних накопительных счётчиков
		rv, tv := math.NaN(), math.NaN()
		if i > 0 {
			prev := pts[i-1]
			dt := float64(p.TS - prev.TS)
			if dt > 0 && p.NetRx >= prev.NetRx && p.NetTx >= prev.NetTx {
				rv = float64(p.NetRx-prev.NetRx) / dt
				tv = float64(p.NetTx-prev.NetTx) / dt
			}
		}
		rx.Points = append(rx.Points, ChartPoint{t, rv})
		tx.Points = append(tx.Points, ChartPoint{t, tv})
	}
	return resourceCharts{
		CPU:    LineChart([]Series{cpu}, from, to, "%"),
		Memory: LineChart([]Series{mem}, from, to, "%"),
		Net:    LineChart([]Series{rx, tx}, from, to, "Б/с"),
		Online: LineChart([]Series{onl}, from, to, "шт"),
	}, nil
}

// traffic30 — сводка трафика всех клиентов за 30 суток (для списка).
func (s *Server) traffic30(ctx context.Context, now time.Time) (map[string]store.Bytes, error) {
	return s.Store.TrafficTotals(ctx, s.nodeIDCtx(ctx), now.Add(-30*24*time.Hour).Unix(), now.Unix()+1)
}

// untilText — «доступ до» для списка и формы: дата UTC или прочерк.
func untilText(until *int64) string {
	if until == nil {
		return "—"
	}
	return time.Unix(*until, 0).UTC().Format("2006-01-02")
}

func gbText(limit int64) string {
	if limit <= 0 {
		return "0"
	}
	return fmt.Sprintf("%g", float64(limit)/(1<<30))
}
