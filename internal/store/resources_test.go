package store

import (
	"reflect"
	"testing"
)

func TestResourceRollupAveragesAndMaxes(t *testing.T) {
	s := open(t)
	s.AddResource(ctx, 1, ResourcePoint{TS: h0, CPU: 10, Load1: 1, MemUsed: 100, MemTotal: 1000, DiskFree: 50, DiskTotal: 500, NetRx: 1000, NetTx: 2000, Online: 3})
	s.AddResource(ctx, 1, ResourcePoint{TS: h0 + 60, CPU: 30, Load1: 3, MemUsed: 300, MemTotal: 1000, DiskFree: 70, DiskTotal: 500, NetRx: 1500, NetTx: 2500, Online: 5})
	for i := 0; i < 2; i++ {
		if err := s.Rollup(ctx, h0+3600+1, 30); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ResourceSeries(ctx, 1, h0, h0+3600, Hour)
	want := []ResourcePoint{{TS: h0, CPU: 20, Load1: 2, MemUsed: 200, MemTotal: 1000, DiskFree: 60, DiskTotal: 500, NetRx: 1500, NetTx: 2500, Online: 5}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestResourceSeriesMinuteReplacesSameMinute(t *testing.T) {
	s := open(t)
	s.AddResource(ctx, 1, ResourcePoint{TS: h0 + 5, CPU: 1})
	s.AddResource(ctx, 1, ResourcePoint{TS: h0 + 50, CPU: 2})
	got, err := s.ResourceSeries(ctx, 1, h0, h0+3600, Minute)
	if err != nil || len(got) != 1 || got[0].CPU != 2 || got[0].TS != h0 {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestResourceSeriesHourFillsUnrolled(t *testing.T) {
	s := open(t)
	s.AddResource(ctx, 1, ResourcePoint{TS: h0 + 3600, CPU: 40, Online: 2})
	got, err := s.ResourceSeries(ctx, 1, h0, h0+7200, Hour)
	if err != nil || len(got) != 1 || got[0].TS != h0+3600 || got[0].CPU != 40 || got[0].Online != 2 {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestResourceRollupCleans(t *testing.T) {
	s := open(t)
	now := h0 + 40*86400
	s.AddResource(ctx, 1, ResourcePoint{TS: now - 2*86400})
	s.AddResource(ctx, 1, ResourcePoint{TS: now - 35*86400})
	s.AddResource(ctx, 1, ResourcePoint{TS: now - 3600})
	s.Rollup(ctx, now, 30)
	var m, h int
	s.db.QueryRow(`SELECT count(*) FROM resource_minute`).Scan(&m)
	s.db.QueryRow(`SELECT count(*) FROM resource_hour`).Scan(&h)
	if m != 1 || h != 2 {
		t.Fatalf("минут %d (ждали 1), часов %d (ждали 2)", m, h)
	}
}
