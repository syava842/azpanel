package store

import (
	"os"
	"reflect"
	"testing"
)

func osStat(p string) (os.FileInfo, error) { return os.Stat(p) }

const h0 = int64(1_800_000_000) / 3600 * 3600 // начало часа

func TestAddTrafficSumsWithinMinute(t *testing.T) {
	s := open(t)
	if err := s.AddTraffic(ctx, 1, h0+10, map[string]Bytes{"alice": {Rx: 5, Tx: 7}, "bob": {Rx: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTraffic(ctx, 1, h0+50, map[string]Bytes{"alice": {Rx: 3, Tx: 1}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.TrafficSeries(ctx, 1, "alice", h0, h0+3600, Minute)
	want := []Point{{TS: h0, Rx: 8, Tx: 8}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestTrafficSeriesHourFillsUnrolledFromMinutes(t *testing.T) {
	s := open(t)
	s.AddTraffic(ctx, 1, h0, map[string]Bytes{"a": {Rx: 1, Tx: 1}})
	s.AddTraffic(ctx, 1, h0+60, map[string]Bytes{"a": {Rx: 2, Tx: 2}})
	s.AddTraffic(ctx, 1, h0+3600+5, map[string]Bytes{"a": {Rx: 10, Tx: 20}})
	// Свёрнут только первый час; второй досчитывается из минут.
	if err := s.Rollup(ctx, h0+3600+30, 30); err != nil {
		t.Fatal(err)
	}
	got, err := s.TrafficSeries(ctx, 1, "a", h0, h0+7200, Hour)
	want := []Point{{TS: h0, Rx: 3, Tx: 3}, {TS: h0 + 3600, Rx: 10, Tx: 20}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestRollupTrafficIdempotentAndCleans(t *testing.T) {
	s := open(t)
	day := int64(86400)
	now := h0 + 40*day
	old := now - 2*day
	s.AddTraffic(ctx, 1, old, map[string]Bytes{"a": {Rx: 1, Tx: 1}})                // минута старше суток
	s.AddTraffic(ctx, 1, now-5*3600, map[string]Bytes{"a": {Rx: 4, Tx: 5}})         // свежая законченная
	s.AddTraffic(ctx, 1, now-5*3600+120, map[string]Bytes{"a": {Rx: 6, Tx: 7}})     // тот же час
	s.AddTraffic(ctx, 1, now-35*day, map[string]Bytes{"a": {Rx: 9, Tx: 9}})         // уйдёт при чистке часовых
	s.AddTraffic(ctx, 1, hourOf(now)+10, map[string]Bytes{"a": {Rx: 100, Tx: 100}}) // текущий час не сворачивается
	for i := 0; i < 3; i++ {
		if err := s.Rollup(ctx, now, 30); err != nil {
			t.Fatal(err)
		}
	}
	var hours []Point
	rows, _ := s.db.Query(`SELECT ts, rx, tx FROM traffic_hour ORDER BY ts`)
	for rows.Next() {
		var p Point
		rows.Scan(&p.TS, &p.Rx, &p.Tx)
		hours = append(hours, p)
	}
	rows.Close()
	want := []Point{{TS: hourOf(old), Rx: 1, Tx: 1}, {TS: hourOf(now - 5*3600), Rx: 10, Tx: 12}}
	if !reflect.DeepEqual(hours, want) {
		t.Fatalf("часовые: %+v, ждали %+v", hours, want)
	}
	var minutes int
	s.db.QueryRow(`SELECT count(*) FROM traffic_minute WHERE ts < ?`, hourOf(now-day)).Scan(&minutes)
	if minutes != 0 {
		t.Fatalf("минут старше суток осталось %d", minutes)
	}
	s.db.QueryRow(`SELECT count(*) FROM traffic_minute`).Scan(&minutes)
	if minutes != 3 {
		t.Fatalf("минут осталось %d, ждали 3", minutes)
	}
}

func TestRollupKeepsHourWhenMinutesPartiallyDeleted(t *testing.T) {
	s := open(t)
	now := h0 + 10*86400 + 1800 // 30-я минута часа
	// Час, в который попадает граница «сутки назад»: минуты до границы и после.
	hr := hourOf(now - 86400)
	s.AddTraffic(ctx, 1, hr+60, map[string]Bytes{"a": {Rx: 1}})
	s.AddTraffic(ctx, 1, hr+3000, map[string]Bytes{"a": {Rx: 2}})
	for i := 0; i < 2; i++ {
		s.Rollup(ctx, now, 30)
	}
	var rx int64
	s.db.QueryRow(`SELECT rx FROM traffic_hour WHERE ts = ?`, hr).Scan(&rx)
	if rx != 3 {
		t.Fatalf("час на границе суток пересчитан по неполным данным: %d", rx)
	}
}

func TestTrafficTotalsNoDoubleCount(t *testing.T) {
	s := open(t)
	s.AddTraffic(ctx, 1, h0+10, map[string]Bytes{"a": {Rx: 1, Tx: 2}, "b": {Rx: 10}})
	s.AddTraffic(ctx, 1, h0+3600+10, map[string]Bytes{"a": {Rx: 4, Tx: 8}})
	s.Rollup(ctx, h0+3600+100, 30) // первый час свёрнут, минуты его ещё лежат
	s.AddTraffic(ctx, 1, h0+3600+70, map[string]Bytes{"a": {Rx: 1, Tx: 1}})
	got, err := s.TrafficTotals(ctx, 1, h0, h0+7200)
	want := map[string]Bytes{"a": {Rx: 6, Tx: 11}, "b": {Rx: 10}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v, %v", got, err)
	}
	// Другой узел не подмешивается.
	if other, _ := s.TrafficTotals(ctx, 2, h0, h0+7200); len(other) != 0 {
		t.Fatalf("чужой узел: %+v", other)
	}
}
