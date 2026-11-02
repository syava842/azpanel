package panel

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	chartW, chartH = 720, 200
	chartLeft      = 64
	chartRight     = 12
	chartTop       = 22
	chartBottom    = 24
	maxChartLines  = 3
)

// ChartPoint — точка графика; NaN в V — пропуск, линия рвётся.
type ChartPoint struct {
	T time.Time
	V float64
}

// Series — одна линия графика. Step — обычный шаг между точками: разрыв
// больше двух с половиной шагов тоже рвёт линию (0 — не проверять).
type Series struct {
	Name   string
	Points []ChartPoint
	Step   time.Duration
}

// LineChart рисует линии за [from, to] как SVG 720×200 с viewBox. unit
// выбирает подписи оси: "%" — проценты, "Б" и "Б/с" — размер, остальное —
// число с припиской. Линий не больше трёх (лишние отбрасываются), цвета
// задаются классами s1..s3 в style.css.
func LineChart(series []Series, from, to time.Time, unit string) template.HTML {
	if len(series) > maxChartLines {
		series = series[:maxChartLines]
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" class="chart" viewBox="0 0 %d %d" role="img" preserveAspectRatio="xMidYMid meet">`, chartW, chartH)
	span := to.Sub(from)
	maxV, have := 0.0, false
	for _, s := range series {
		for _, p := range s.Points {
			if math.IsNaN(p.V) || p.T.Before(from) || p.T.After(to) {
				continue
			}
			have = true
			maxV = math.Max(maxV, p.V)
		}
	}
	if !have || span <= 0 {
		fmt.Fprintf(&b, `<text class="empty" x="%d" y="%d" text-anchor="middle">нет данных</text></svg>`, chartW/2, chartH/2)
		return template.HTML(b.String())
	}
	top := niceCeil(maxV)
	px := func(t time.Time) float64 {
		return chartLeft + float64(t.Sub(from))/float64(span)*float64(chartW-chartLeft-chartRight)
	}
	py := func(v float64) float64 {
		return float64(chartH-chartBottom) - v/top*float64(chartH-chartBottom-chartTop)
	}
	// сетка и подписи оси Y
	for i := 0; i <= 2; i++ {
		v := top * float64(i) / 2
		y := py(v)
		fmt.Fprintf(&b, `<line class="grid" x1="%d" y1="%.1f" x2="%d" y2="%.1f"/>`, chartLeft, y, chartW-chartRight, y)
		fmt.Fprintf(&b, `<text class="axis" x="%d" y="%.1f" text-anchor="end">%s</text>`, chartLeft-6, y+4, html.EscapeString(formatUnit(v, unit)))
	}
	// подписи оси X
	layout := "02.01"
	if span <= 36*time.Hour {
		layout = "15:04"
	}
	for i := 0; i <= 4; i++ {
		t := from.Add(span * time.Duration(i) / 4)
		anchor := "middle"
		switch i {
		case 0:
			anchor = "start"
		case 4:
			anchor = "end"
		}
		fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%d" text-anchor="%s">%s</text>`, px(t), chartH-6, anchor, t.Local().Format(layout))
	}
	// линии
	for i, s := range series {
		var path strings.Builder
		pen := false
		var last time.Time
		for _, p := range s.Points {
			if math.IsNaN(p.V) || p.T.Before(from) || p.T.After(to) {
				pen = false
				continue
			}
			if pen && s.Step > 0 && p.T.Sub(last) > s.Step*5/2 {
				pen = false
			}
			cmd := "L"
			if !pen {
				cmd = "M"
			}
			fmt.Fprintf(&path, "%s%.1f %.1f ", cmd, px(p.T), py(p.V))
			pen, last = true, p.T
		}
		fmt.Fprintf(&b, `<path class="line s%d" d="%s"/>`, i+1, strings.TrimSpace(path.String()))
	}
	// легенда
	if len(series) > 1 {
		x := chartLeft
		for i, s := range series {
			fmt.Fprintf(&b, `<rect class="key s%d" x="%d" y="6" width="10" height="10"/>`, i+1, x)
			fmt.Fprintf(&b, `<text class="axis" x="%d" y="15">%s</text>`, x+14, html.EscapeString(s.Name))
			x += 14 + 9*len([]rune(s.Name)) + 16
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// niceCeil округляет вверх до 1, 2 или 5 × 10^n; для нуля — 1.
func niceCeil(v float64) float64 {
	if v <= 0 {
		return 1
	}
	e := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if v <= m*e {
			return m * e
		}
	}
	return 10 * e
}

func formatUnit(v float64, unit string) string {
	switch unit {
	case "%":
		return strconv.FormatFloat(v, 'f', -1, 64) + " %"
	case "Б":
		return humanBytes(uint64(v))
	case "Б/с":
		return humanBytes(uint64(v)) + "/с"
	}
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if unit != "" {
		s += " " + unit
	}
	return s
}
