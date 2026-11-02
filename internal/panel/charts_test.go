package panel

import (
	"encoding/xml"
	"io"
	"math"
	"strings"
	"testing"
	"time"
)

func validXML(t *testing.T, s string) {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(s))
	for {
		if _, err := d.Token(); err == io.EOF {
			return
		} else if err != nil {
			t.Fatalf("невалидный XML: %v\n%s", err, s)
		}
	}
}

func TestLineChartEmpty(t *testing.T) {
	now := time.Now()
	out := string(LineChart(nil, now.Add(-time.Hour), now, "%"))
	validXML(t, out)
	if !strings.Contains(out, "нет данных") || !strings.Contains(out, `viewBox="0 0 720 200"`) {
		t.Fatal(out)
	}
	out = string(LineChart([]Series{{Name: "x", Points: []ChartPoint{{now, math.NaN()}}}}, now.Add(-time.Hour), now, "%"))
	if !strings.Contains(out, "нет данных") {
		t.Fatal("только пропуски: " + out)
	}
}

func TestLineChartTwoPointsAndEscaping(t *testing.T) {
	to := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	from := to.Add(-time.Hour)
	s := []Series{
		{Name: `A<&>"b`, Points: []ChartPoint{{from.Add(10 * time.Minute), 10}, {from.Add(20 * time.Minute), 40}}},
		{Name: "B", Points: []ChartPoint{{from.Add(10 * time.Minute), 1}}},
	}
	out := string(LineChart(s, from, to, "Б/с"))
	validXML(t, out)
	if strings.Contains(out, `A<&>`) || !strings.Contains(out, `class="line s1"`) || !strings.Contains(out, `class="line s2"`) {
		t.Fatal(out)
	}
}

func TestLineChartGapBreaksLine(t *testing.T) {
	to := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	from := to.Add(-time.Hour)
	m := func(n int) time.Time { return from.Add(time.Duration(n) * time.Minute) }
	s := []Series{{Step: time.Minute, Points: []ChartPoint{
		{m(1), 1}, {m(2), 2}, {m(3), math.NaN()}, {m(4), 2}, {m(5), 3}, {m(20), 3}, {m(21), 4}}}}
	out := string(LineChart(s, from, to, "шт"))
	validXML(t, out)
	d := out[strings.Index(out, ` d="`):]
	if n := strings.Count(d, "M"); n != 3 {
		t.Fatalf("сегментов %d, нужно 3 (NaN и большой шаг рвут линию): %s", n, out)
	}
}

func TestLineChartMaxThreeLines(t *testing.T) {
	to := time.Now()
	p := []ChartPoint{{to.Add(-time.Minute), 1}}
	out := string(LineChart([]Series{{Name: "a", Points: p}, {Name: "b", Points: p}, {Name: "c", Points: p}, {Name: "d", Points: p}}, to.Add(-time.Hour), to, ""))
	if strings.Contains(out, "s4") {
		t.Fatal(out)
	}
}
