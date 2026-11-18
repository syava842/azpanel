package store

import (
	"context"
	"testing"
)

func TestConnLogSync(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	ovpn := ConnSeen{Kind: "openvpn", Instance: "vpn-udp", Name: "alice", Since: 900, RealAddr: "1.2.3.4:5", VPNAddr: "10.28.0.2", Proto: "udp", Port: 50080}
	wg := ConnSeen{Kind: "wireguard", Instance: "vpn", Name: "bob", RealAddr: "5.6.7.8:9", Proto: "udp", Port: 51443}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SyncConnLog(ctx, 1, 1000, []ConnSeen{ovpn, wg, wg}))
	// Через минуту alice отключилась, у bob сменился адрес.
	wg.RealAddr = "5.6.7.8:10"
	must(s.SyncConnLog(ctx, 1, 1060, []ConnSeen{wg}))
	// alice вернулась новым сеансом.
	ovpn.Since = 1100
	must(s.SyncConnLog(ctx, 1, 1120, []ConnSeen{ovpn, wg}))

	all, total, err := s.ConnLog(ctx, 1, ConnLogQuery{Kind: "openvpn"})
	must(err)
	if total != 2 || all[0].Start != 1100 || all[0].Ended != 0 || all[1].Start != 900 || all[1].Ended != 1000 {
		t.Fatalf("openvpn: %d %+v", total, all)
	}
	w, total, err := s.ConnLog(ctx, 1, ConnLogQuery{Kind: "wireguard"})
	must(err)
	if total != 1 || w[0].Start != 1000 || w[0].LastSeen != 1120 || w[0].RealAddr != "5.6.7.8:10" {
		t.Fatalf("wireguard: %d %+v", total, w)
	}
	starts, err := s.OpenConnStarts(ctx, 1)
	must(err)
	if starts["wireguard|vpn|bob"] != 1000 {
		t.Fatalf("начала: %v", starts)
	}
	if got, n, _ := s.ConnLog(ctx, 1, ConnLogQuery{Kind: "openvpn", Q: "10.28"}); n != 2 || len(got) != 2 {
		t.Fatalf("фильтр по адресу: %d", n)
	}
	if _, n, _ := s.ConnLog(ctx, 1, ConnLogQuery{Kind: "openvpn", Q: "bob"}); n != 0 {
		t.Fatalf("фильтр по имени: %d", n)
	}
	// Закрытые старше срока истории уходят при свёртке.
	must(s.Rollup(ctx, 1000+40*86400, 30))
	if _, n, _ := s.ConnLog(ctx, 1, ConnLogQuery{Kind: "openvpn"}); n != 1 {
		t.Fatalf("после свёртки: %d", n)
	}
}

func TestTrafficLongRange(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := int64(100 * 86400)
	// старые сутки — только в traffic_day
	if _, err := s.db.Exec(`INSERT INTO traffic_day (node_id, name, ts, rx, tx) VALUES (1, 'a', ?, 10, 20)`, now-60*86400); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTraffic(ctx, 1, now-3600, map[string]Bytes{"a": {1, 2}}); err != nil {
		t.Fatal(err)
	}
	tot, err := s.TrafficTotalsLong(ctx, 1, now-365*86400, now, now)
	if err != nil || tot["a"] != (Bytes{11, 22}) {
		t.Fatalf("за год: %v %v", tot, err)
	}
	days, err := s.TrafficByDay(ctx, 1, now-365*86400, now, now)
	if err != nil || days[now-60*86400]["a"] != (Bytes{10, 20}) || days[now-86400]["a"] != (Bytes{1, 2}) {
		t.Fatalf("по дням: %v %v", days, err)
	}
}
