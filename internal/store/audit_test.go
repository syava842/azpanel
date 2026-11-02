package store

import "testing"

func TestAuditListSearchAndCount(t *testing.T) {
	s := open(t)
	for i, e := range []AuditEntry{
		{TS: 100, User: "admin", IP: "1.1.1.1", Action: "клиент создан", Target: "alice", After: "openvpn"},
		{TS: 200, User: "admin", IP: "1.1.1.1", Action: "лимит изменён", Target: "alice", Before: "0", After: "2"},
		{TS: 300, User: "Boss", IP: "2.2.2.2", Action: "клиент удалён", Target: "bob_100%"},
	} {
		if err := s.Audit(ctx, e); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	all, n, err := s.AuditList(ctx, 2, 0, "")
	if err != nil || n != 3 || len(all) != 2 || all[0].TS != 300 || all[1].TS != 200 {
		t.Fatalf("%+v, %d, %v", all, n, err)
	}
	if all[1].Before != "0" || all[1].After != "2" || all[1].IP != "1.1.1.1" || all[1].ID == 0 {
		t.Fatalf("поля: %+v", all[1])
	}
	page2, _, _ := s.AuditList(ctx, 2, 2, "")
	if len(page2) != 1 || page2[0].TS != 100 {
		t.Fatalf("вторая страница: %+v", page2)
	}
	for q, want := range map[string]int{"ALICE": 2, "boss": 1, "изменён": 1, "клиент": 2, "100%": 1, "%": 1, "_": 1, "нет такого": 0} {
		got, n, err := s.AuditList(ctx, 50, 0, q)
		if err != nil || n != want || len(got) != want {
			t.Errorf("q=%q: %d/%d записей, %v (ждали %d)", q, len(got), n, err, want)
		}
	}
}
