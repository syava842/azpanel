package store

import (
	"errors"
	"testing"
)

const dayS = int64(86400)

func codeState(t *testing.T, s *Store, now int64) map[string]int {
	t.Helper()
	all, err := s.Codes(ctx, CodeFilter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int{}
	for _, c := range all {
		m[c.State(now)]++
	}
	return m
}

// Гашение и продление — одна транзакция: успех делает оба шага.
func TestRedeemAndExtendOK(t *testing.T) {
	s := open(t)
	_, codes := issue(t, s, IssueParams{Days: 30, ValidUntil: 5000 * dayS, Now: 1})
	s.SaveCard(ctx, Card{Node: 1, Name: "a", AccessUntil: i64(100 * dayS)})
	rc, before, after, err := s.RedeemAndExtend(ctx, codes[0], nil, 1, "a", 10*dayS)
	if err != nil || rc.Days != 30 || before != 100*dayS || after != 130*dayS {
		t.Fatalf("%+v %d %d %v", rc, before, after, err)
	}
	if _, _, _, err := s.RedeemAndExtend(ctx, codes[0], nil, 1, "a", 10*dayS); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("повтор: %v", err)
	}
	if _, _, _, err := s.RedeemAndExtend(ctx, "мусор", nil, 1, "a", 10*dayS); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("мусор: %v", err)
	}
	if c, _ := s.Card(ctx, 1, "a"); *c.AccessUntil != 130*dayS {
		t.Fatalf("карточка: %d", *c.AccessUntil)
	}
}

// Нет карточки или срока: ErrNoLimit, код остаётся активным.
func TestRedeemAndExtendNoLimitKeepsCode(t *testing.T) {
	s := open(t)
	_, codes := issue(t, s, IssueParams{Count: 2, ValidUntil: 5000 * dayS, Now: 1})
	if _, _, _, err := s.RedeemAndExtend(ctx, codes[0], nil, 1, "нет", 10*dayS); !errors.Is(err, ErrNoLimit) {
		t.Fatalf("без карточки: %v", err)
	}
	s.SaveCard(ctx, Card{Node: 1, Name: "a"})
	if _, _, _, err := s.RedeemAndExtend(ctx, codes[1], nil, 1, "a", 10*dayS); !errors.Is(err, ErrNoLimit) {
		t.Fatalf("без срока: %v", err)
	}
	if m := codeState(t, s, 10*dayS); m[CodeActive] != 2 || m[CodeUsed] != 0 {
		t.Fatalf("коды: %v", m)
	}
}

// Сбой на шаге продления откатывает и гашение: код цел.
func TestRedeemAndExtendFailureRollsBack(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	_, codes := issue(t, s, IssueParams{ValidUntil: 5000 * dayS, Now: 1})
	s.SaveCard(ctx, Card{Node: 1, Name: "a"})
	s.SetOwner(ctx, 1, "a", &u.ID)
	s.SetUserAccessUntil(ctx, u.ID, i64(50*dayS))
	// последний шаг — сдвиг срока владельца — падает
	if _, err := s.db.Exec(`CREATE TRIGGER no_shift BEFORE UPDATE OF access_until ON users
		BEGIN SELECT RAISE(ABORT, 'сбой записи'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.RedeemAndExtend(ctx, codes[0], nil, 1, "a", 10*dayS); err == nil || errors.Is(err, ErrNoLimit) || errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("ожидался сбой записи: %v", err)
	}
	if m := codeState(t, s, 10*dayS); m[CodeActive] != 1 || m[CodeUsed] != 0 {
		t.Fatalf("код сгорел: %v", m)
	}
	s.db.Exec(`DROP TRIGGER no_shift`)
	if _, _, _, err := s.RedeemAndExtend(ctx, codes[0], nil, 1, "a", 10*dayS); err != nil {
		t.Fatalf("после сбоя код должен сработать: %v", err)
	}
}

// Код на пользователя гасится только для его клиентов.
func TestRedeemAndExtendUserBound(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	_, codes := issue(t, s, IssueParams{UserID: &u.ID, ValidUntil: 5000 * dayS, Now: 1})
	s.SaveCard(ctx, Card{Node: 1, Name: "a", AccessUntil: i64(100 * dayS)})
	if _, _, _, err := s.RedeemAndExtend(ctx, codes[0], nil, 1, "a", 10*dayS); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("без владельца: %v", err)
	}
	if _, _, _, err := s.RedeemAndExtend(ctx, codes[0], &u.ID, 1, "a", 10*dayS); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteDownloadLinksAndLinkedClients(t *testing.T) {
	s := open(t)
	tok := mkDownload(t, s, "", 1<<40)
	if _, err := s.CreateClientLink(ctx, 1, "bob", 1); err != nil {
		t.Fatal(err)
	}
	names, err := s.LinkedClients(ctx, 1)
	if err != nil || len(names) != 2 || names[0] != "alice" || names[1] != "bob" {
		t.Fatalf("%v %v", names, err)
	}
	if err := s.DeleteDownloadLinks(ctx, 1, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DownloadLinkByToken(ctx, tok, 5); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("ссылка жива: %v", err)
	}
}

// Срок удалённого владельца переходит на карточки клиентов: просрочка не пропадает.
func TestDeleteUserKeepsExpiredLimitOnClients(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	s.SaveCard(ctx, Card{Node: 1, Name: "a"})
	s.SaveCard(ctx, Card{Node: 1, Name: "b", AccessUntil: i64(30 * dayS)})
	s.SaveCard(ctx, Card{Node: 1, Name: "c", AccessUntil: i64(500 * dayS)})
	for _, n := range []string{"a", "b", "c"} {
		s.SetOwner(ctx, 1, n, &u.ID)
	}
	s.SetUserAccessUntil(ctx, u.ID, i64(100*dayS))
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]int64{"a": 100, "b": 30, "c": 100} {
		v, err := s.EffectiveUntil(ctx, 1, n)
		if err != nil || v == nil || *v != want*dayS {
			t.Fatalf("%s: %v %v", n, v, err)
		}
	}
	if _, has, _ := s.OwnerOf(ctx, 1, "a"); has {
		t.Fatal("владелец остался")
	}
}

// У пользователя без срока карточки не меняются.
func TestDeleteUserWithoutLimitLeavesCards(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	s.SaveCard(ctx, Card{Node: 1, Name: "a"})
	s.SetOwner(ctx, 1, "a", &u.ID)
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.EffectiveUntil(ctx, 1, "a"); v != nil {
		t.Fatalf("появился срок %d", *v)
	}
}

// Снятие владельца тоже оставляет его срок на клиенте.
func TestSetOwnerNilKeepsLimit(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	s.SaveCard(ctx, Card{Node: 1, Name: "a"})
	s.SetOwner(ctx, 1, "a", &u.ID)
	s.SetUserAccessUntil(ctx, u.ID, i64(100*dayS))
	if err := s.SetOwner(ctx, 1, "a", nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.EffectiveUntil(ctx, 1, "a"); v == nil || *v != 100*dayS {
		t.Fatalf("срок: %v", v)
	}
	if err := s.SetOwner(ctx, 1, "нет", nil); err != nil {
		t.Fatal(err)
	}
}

func TestRollupPurgesDeadLinksAndSentOutbox(t *testing.T) {
	s := open(t)
	now := 1000 * dayS
	mkDownload(t, s, "", now-10)           // истекла
	live := mkDownload(t, s, "", now+3600) // жива
	s.db.Exec(`INSERT INTO outbox (kind, payload, created, sent) VALUES ('k','{}',1,?)`, now-31*dayS)
	s.db.Exec(`INSERT INTO outbox (kind, payload, created, sent) VALUES ('k','{}',1,?)`, now-5*dayS)
	s.db.Exec(`INSERT INTO outbox (kind, payload, created) VALUES ('k','{}',1)`)
	if err := s.Rollup(ctx, now, 30); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM download_links`).Scan(&n)
	if n != 1 {
		t.Fatalf("ссылок %d", n)
	}
	if _, err := s.DownloadLinkByToken(ctx, live, now); err != nil {
		t.Fatalf("живая ссылка пропала: %v", err)
	}
	s.db.QueryRow(`SELECT count(*) FROM outbox`).Scan(&n)
	if n != 2 {
		t.Fatalf("outbox %d, нужно 2 (свежий отправленный и неотправленный)", n)
	}
}

func TestCodesPageAndBatches(t *testing.T) {
	s := open(t)
	b1, _ := issue(t, s, IssueParams{Count: 5, CreatedBy: "root", Now: 10, ValidUntil: 5000})
	b2, c2 := issue(t, s, IssueParams{Count: 3, CreatedBy: "boss", Now: 11, ValidUntil: 5000, Days: 7})
	p1, _ := s.CodesPage(ctx, CodeFilter{}, 20, 3, 0)
	p2, _ := s.CodesPage(ctx, CodeFilter{}, 20, 3, 3)
	p3, _ := s.CodesPage(ctx, CodeFilter{}, 20, 3, 6)
	if len(p1) != 3 || len(p2) != 3 || len(p3) != 2 || p1[0].ID < p1[2].ID || p1[2].ID < p2[0].ID {
		t.Fatalf("страницы: %d %d %d", len(p1), len(p2), len(p3))
	}
	s.SaveCard(ctx, Card{Node: 1, Name: "a", AccessUntil: i64(100)})
	if _, _, _, err := s.RedeemAndExtend(ctx, c2[0], nil, 1, "a", 20); err != nil {
		t.Fatal(err)
	}
	bs, err := s.Batches(ctx, 20, 0)
	if err != nil || len(bs) != 2 || bs[0].Batch != b2 || bs[1].Batch != b1 {
		t.Fatalf("%+v %v", bs, err)
	}
	if x := bs[0]; x.Total != 3 || x.Used != 1 || x.Active != 2 || x.Days != 7 || x.CreatedBy != "boss" || x.Created != 11 {
		t.Fatalf("%+v", x)
	}
	if x := bs[1]; x.Total != 5 || x.Active != 5 {
		t.Fatalf("%+v", x)
	}
	if one, _ := s.Batches(ctx, 20, 1); len(one) != 1 {
		t.Fatal("предел пачек")
	}
	// просрочка считается на момент запроса
	if late, _ := s.Batches(ctx, 6000, 0); late[1].Expired != 5 || late[1].Active != 0 {
		t.Fatalf("%+v", late[1])
	}
}

func TestAttemptHelpers(t *testing.T) {
	s := open(t)
	if _, ok, _ := s.LastAttempt(ctx, "k", 0); ok {
		t.Fatal("пусто")
	}
	s.Attempt(ctx, "k", 100)
	s.Attempt(ctx, "k", 200)
	if ts, ok, _ := s.LastAttempt(ctx, "k", 0); !ok || ts != 200 {
		t.Fatalf("%d %v", ts, ok)
	}
	if _, ok, _ := s.LastAttempt(ctx, "k", 201); ok {
		t.Fatal("за окном")
	}
	if err := s.RefundAttempt(ctx, "k", 200); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Attempts(ctx, "k", 0); n != 1 {
		t.Fatalf("после возврата %d", n)
	}
}
