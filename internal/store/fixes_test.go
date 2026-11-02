package store

import "testing"

func TestRollupKeepsTrafficLongerThanHistoryDays(t *testing.T) {
	s := open(t)
	now := h0 + 40*86400
	s.AddTraffic(ctx, 1, now-31*86400, map[string]Bytes{"a": {Rx: 7}})
	s.AddTraffic(ctx, 1, now-36*86400, map[string]Bytes{"a": {Rx: 9}})
	s.AddResource(ctx, 1, ResourcePoint{TS: now - 31*86400})
	if err := s.Rollup(ctx, now+1, 30); err != nil {
		t.Fatal(err)
	}
	var th, rh int
	s.db.QueryRow(`SELECT count(*) FROM traffic_hour`).Scan(&th)
	s.db.QueryRow(`SELECT count(*) FROM resource_hour`).Scan(&rh)
	// трафик 31-дневной давности жив (до 35 суток), ресурсы — по history_days
	if th != 1 || rh != 0 {
		t.Fatalf("часов трафика %d (ждали 1), ресурсов %d (ждали 0)", th, rh)
	}
}

func TestRollupCleansOldAudit(t *testing.T) {
	s := open(t)
	now := h0 + 400*86400
	s.Audit(ctx, AuditEntry{TS: now - 366*86400, User: "u", Action: "old"})
	s.Audit(ctx, AuditEntry{TS: now - 10*86400, User: "u", Action: "new"})
	if err := s.Rollup(ctx, now, 30); err != nil {
		t.Fatal(err)
	}
	list, n, _ := s.AuditList(ctx, 10, 0, "")
	if n != 1 || len(list) != 1 || list[0].Action != "new" {
		t.Fatalf("журнал: %+v", list)
	}
}

func TestAuditSearchIgnoresCyrillicCase(t *testing.T) {
	s := open(t)
	s.Audit(ctx, AuditEntry{TS: 1, User: "Админ", Action: "Вход", Target: "ПЕТР"})
	s.Audit(ctx, AuditEntry{TS: 2, User: "u", Action: "create", Target: "x"})
	for _, q := range []string{"вход", "ВХОД", "Вход", "петр", "АДМИН"} {
		list, n, err := s.AuditList(ctx, 10, 0, q)
		if err != nil || n != 1 || len(list) != 1 || list[0].TS != 1 {
			t.Fatalf("q=%q: %+v %d %v", q, list, n, err)
		}
	}
}

func TestDeleteTraffic(t *testing.T) {
	s := open(t)
	s.AddTraffic(ctx, 1, h0+10, map[string]Bytes{"a": {Rx: 1}, "b": {Rx: 2}})
	s.Rollup(ctx, h0+7200, 30)
	s.AddTraffic(ctx, 1, h0+7300, map[string]Bytes{"a": {Rx: 5}})
	if err := s.DeleteTraffic(ctx, 1, "a"); err != nil {
		t.Fatal(err)
	}
	tot, _ := s.TrafficTotals(ctx, 1, 0, h0+10000)
	if _, ok := tot["a"]; ok || tot["b"].Rx != 2 {
		t.Fatalf("итоги: %v", tot)
	}
}
