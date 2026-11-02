package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestCodeGenerationAndNormalize(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := GenerateCode()
		if err != nil || len(c) != 16 {
			t.Fatalf("код %q, ошибка %v", c, err)
		}
		if strings.ContainsAny(c, "01OI") || seen[c] {
			t.Fatalf("плохой или повторный код %q", c)
		}
		seen[c] = true
		f := FormatCode(c)
		if len(f) != 19 || f[4] != '-' || f[9] != '-' || f[14] != '-' {
			t.Fatalf("формат %q", f)
		}
		if n, ok := NormalizeCode(strings.ToLower(f)); !ok || n != c {
			t.Fatalf("нормализация %q -> %q %v", f, n, ok)
		}
	}
	if n, ok := NormalizeCode(" abcd efgh-jkmn pqrs "); !ok || n != "ABCDEFGHJKMNPQRS" {
		t.Fatalf("пробелы и дефисы: %q %v", n, ok)
	}
	for _, bad := range []string{"", "ABCD", "ABCDEFGHJKMNPQR0", "ABCDEFGHJKMNPQRI", "ABCDEFGHJKMNPQRSA", "ПРИВЕТПРИВЕТПРИВЕ"} {
		if _, ok := NormalizeCode(bad); ok {
			t.Fatalf("%q принят", bad)
		}
	}
}

func issue(t *testing.T, s *Store, p IssueParams) (string, []string) {
	t.Helper()
	if p.Count == 0 {
		p.Count = 1
	}
	if p.Days == 0 {
		p.Days = 30
	}
	if p.ValidUntil == 0 {
		p.ValidUntil = 1000
	}
	b, codes, err := s.IssueCodes(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	return b, codes
}

func TestIssueAndListCodes(t *testing.T) {
	s := open(t)
	b1, c1 := issue(t, s, IssueParams{Count: 3, CreatedBy: "root", Now: 10})
	b2, _ := issue(t, s, IssueParams{Count: 2, CreatedBy: "root", Now: 11})
	if b1 == b2 || len(c1) != 3 {
		t.Fatal("пачки")
	}
	// В базе открытых кодов нет.
	var n int
	for _, c := range c1 {
		norm, _ := NormalizeCode(c)
		s.db.QueryRow(`SELECT count(*) FROM unlock_codes WHERE hash = ?`, norm).Scan(&n)
		if n != 0 {
			t.Fatal("в базе открытый код")
		}
	}
	all, _ := s.Codes(ctx, CodeFilter{}, 20)
	if len(all) != 5 {
		t.Fatalf("всего %d", len(all))
	}
	one, _ := s.Codes(ctx, CodeFilter{Batch: b1}, 20)
	if len(one) != 3 {
		t.Fatalf("пачка %d", len(one))
	}
	if err := s.RevokeCode(ctx, one[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemCode(ctx, c1[0], nil, 20); err != nil {
		t.Fatal(err)
	}
	for st, want := range map[string]int{CodeActive: 3, CodeUsed: 1, CodeRevoked: 1, CodeExpired: 0} {
		got, err := s.Codes(ctx, CodeFilter{State: st}, 20)
		if err != nil || len(got) != want {
			t.Fatalf("состояние %s: %d, ждали %d (%v)", st, len(got), want, err)
		}
	}
	if got, _ := s.Codes(ctx, CodeFilter{State: CodeExpired}, 2000); len(got) != 3 {
		t.Fatalf("просрочено %d", len(got))
	}
	if _, _, err := s.IssueCodes(ctx, IssueParams{Count: 0, Days: 1}); err == nil {
		t.Fatal("пустая пачка выпущена")
	}
}

func TestRedeemCodeOnce(t *testing.T) {
	s := open(t)
	_, codes := issue(t, s, IssueParams{Days: 45})
	c, err := s.RedeemCode(ctx, strings.ToLower(strings.ReplaceAll(codes[0], "-", " ")), nil, 500)
	if err != nil || c.Days != 45 || c.UsedAt == nil || *c.UsedAt != 500 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := s.RedeemCode(ctx, codes[0], nil, 501); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("второй раз: %v", err)
	}
	if err := s.SetCodeTarget(ctx, c.ID, 1, "alice"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Codes(ctx, CodeFilter{State: CodeUsed}, 600)
	if len(got) != 1 || got[0].UsedClient != "alice" || *got[0].UsedNode != 1 {
		t.Fatalf("%+v", got)
	}
	if err := s.RevokeCode(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("отзыв погашенного: %v", err)
	}
}

func TestRedeemCodeParallel(t *testing.T) {
	s := open(t)
	_, codes := issue(t, s, IssueParams{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RedeemCode(ctx, codes[0], nil, 5); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			} else if !errors.Is(err, ErrCodeInvalid) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("успехов %d, ждали 1", ok)
	}
}

func TestRedeemCodeUserBound(t *testing.T) {
	s := open(t)
	alice, bob := mkUser(t, s, "alice", RoleUser), mkUser(t, s, "bob", RoleUser)
	_, codes := issue(t, s, IssueParams{UserID: &alice.ID})
	if _, err := s.RedeemCode(ctx, codes[0], &bob.ID, 5); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("чужой клиент: %v", err)
	}
	if _, err := s.RedeemCode(ctx, codes[0], nil, 5); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("клиент без владельца: %v", err)
	}
	if _, err := s.RedeemCode(ctx, codes[0], &alice.ID, 5); err != nil {
		t.Fatalf("свой клиент: %v", err)
	}
	// Код на любого гасится и для клиента с владельцем.
	_, any := issue(t, s, IssueParams{})
	if _, err := s.RedeemCode(ctx, any[0], &bob.ID, 5); err != nil {
		t.Fatal(err)
	}
}

func TestRedeemCodeExpiredRevokedGarbage(t *testing.T) {
	s := open(t)
	_, exp := issue(t, s, IssueParams{ValidUntil: 100})
	if _, err := s.RedeemCode(ctx, exp[0], nil, 101); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("просрочен: %v", err)
	}
	if _, err := s.RedeemCode(ctx, exp[0], nil, 100); err != nil {
		t.Fatalf("в последнюю секунду: %v", err)
	}
	b, rev := issue(t, s, IssueParams{Count: 2})
	if n, err := s.RevokeBatch(ctx, b); err != nil || n != 2 {
		t.Fatalf("отзыв пачки %d %v", n, err)
	}
	if _, err := s.RedeemCode(ctx, rev[0], nil, 5); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("отозван: %v", err)
	}
	for _, g := range []string{"", "AAAA-BBBB", "AAAAAAAAAAAAAAAA"} {
		if _, err := s.RedeemCode(ctx, g, nil, 5); !errors.Is(err, ErrCodeInvalid) {
			t.Fatalf("мусор %q: %v", g, err)
		}
	}
}

func TestPortalLinks(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	t1, err := s.CreateClientLink(ctx, 1, "alice-vpn", 10)
	if err != nil || len(t1) != 43 {
		t.Fatalf("токен %q %v", t1, err)
	}
	l, err := s.PortalLinkByToken(ctx, t1)
	if err != nil || l.Kind != LinkClient || l.Node != 1 || l.Client != "alice-vpn" || l.Hash == t1 {
		t.Fatalf("%+v %v", l, err)
	}
	t2, _ := s.CreateClientLink(ctx, 1, "alice-vpn", 11)
	if _, err := s.PortalLinkByToken(ctx, t1); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("старая ссылка жива: %v", err)
	}
	if _, err := s.PortalLinkByToken(ctx, t2); err != nil {
		t.Fatal(err)
	}
	// Другой клиент не затронут.
	t3, _ := s.CreateClientLink(ctx, 1, "bob-vpn", 12)
	if _, err := s.PortalLinkByToken(ctx, t2); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteClientLink(ctx, 1, "bob-vpn"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PortalLinkByToken(ctx, t3); !errors.Is(err, ErrLinkGone) {
		t.Fatal("не удалена")
	}

	u1, err := s.CreateUserLink(ctx, u.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	ul, err := s.PortalLinkByToken(ctx, u1)
	if err != nil || ul.Kind != LinkUser || ul.UserID != u.ID {
		t.Fatalf("%+v %v", ul, err)
	}
	u2, _ := s.CreateUserLink(ctx, u.ID, 21)
	if _, err := s.PortalLinkByToken(ctx, u1); !errors.Is(err, ErrLinkGone) {
		t.Fatal("прежняя ссылка пользователя жива")
	}
	// Удаление пользователя убирает его ссылку каскадом.
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PortalLinkByToken(ctx, u2); !errors.Is(err, ErrLinkGone) {
		t.Fatal("ссылка пережила пользователя")
	}
	if _, err := s.PortalLinkByToken(ctx, "мусор"); !errors.Is(err, ErrLinkGone) {
		t.Fatal(err)
	}
}

func mkDownload(t *testing.T, s *Store, pin string, expires int64) string {
	t.Helper()
	tok, err := s.CreateDownloadLink(ctx, DownloadParams{Node: 1, Client: "alice", PKind: "openvpn", Variant: "antizapret", File: "a.ovpn", PIN: pin, Expires: expires, Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestDownloadLinkOneShot(t *testing.T) {
	s := open(t)
	tok := mkDownload(t, s, "", 100)
	l, err := s.DownloadLinkByToken(ctx, tok, 50)
	if err != nil || l.Client != "alice" || l.File != "a.ovpn" || l.HasPIN {
		t.Fatalf("%+v %v", l, err)
	}
	if err := s.CheckDownloadPIN(ctx, tok, "", 50); err != nil {
		t.Fatalf("без PIN: %v", err)
	}
	if err := s.MarkDownloadUsed(ctx, tok, 50); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDownloadUsed(ctx, tok, 51); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("второе скачивание: %v", err)
	}
	if _, err := s.DownloadLinkByToken(ctx, tok, 51); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("использованная видна: %v", err)
	}
}

func TestDownloadLinkExpiry(t *testing.T) {
	s := open(t)
	tok := mkDownload(t, s, "", 100)
	if _, err := s.DownloadLinkByToken(ctx, tok, 101); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("просрочена: %v", err)
	}
	if err := s.MarkDownloadUsed(ctx, tok, 101); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("просроченную отметили: %v", err)
	}
}

func TestDownloadLinkParallelUse(t *testing.T) {
	s := open(t)
	tok := mkDownload(t, s, "", 100)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.MarkDownloadUsed(ctx, tok, 5) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("успехов %d", ok)
	}
}

func TestDownloadLinkPIN(t *testing.T) {
	s := open(t)
	tok := mkDownload(t, s, "4821", 100)
	if l, _ := s.DownloadLinkByToken(ctx, tok, 5); !l.HasPIN {
		t.Fatal("PIN не виден")
	}
	if err := s.CheckDownloadPIN(ctx, tok, "4821", 5); err != nil {
		t.Fatalf("верный PIN: %v", err)
	}
	for i := 1; i <= MaxPINFails; i++ {
		if err := s.CheckDownloadPIN(ctx, tok, "0000", 5); !errors.Is(err, ErrPINWrong) {
			t.Fatalf("ошибка %d: %v", i, err)
		}
	}
	// Пять ошибок закрыли ссылку навсегда, даже верный PIN не помогает.
	if err := s.CheckDownloadPIN(ctx, tok, "4821", 5); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("после закрытия: %v", err)
	}
	if err := s.MarkDownloadUsed(ctx, tok, 5); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("закрытую отметили: %v", err)
	}
	if _, err := s.DownloadLinkByToken(ctx, tok, 5); !errors.Is(err, ErrLinkGone) {
		t.Fatalf("закрытая видна: %v", err)
	}
}

func TestAttempts(t *testing.T) {
	s := open(t)
	for _, ts := range []int64{10, 20, 30} {
		if err := s.Attempt(ctx, "code:x", ts); err != nil {
			t.Fatal(err)
		}
	}
	s.Attempt(ctx, "code:y", 25)
	if n, _ := s.Attempts(ctx, "code:x", 20); n != 2 {
		t.Fatalf("с 20: %d", n)
	}
	if n, _ := s.Attempts(ctx, "code:x", 0); n != 3 {
		t.Fatalf("все: %d", n)
	}
	if err := s.PurgeAttempts(ctx, 25); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Attempts(ctx, "code:x", 0); n != 1 {
		t.Fatalf("после чистки: %d", n)
	}
	if n, _ := s.Attempts(ctx, "code:y", 0); n != 1 {
		t.Fatalf("чужой ключ: %d", n)
	}
}

func TestOutbox(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	a, err := s.Enqueue(ctx, "expiring", &u.ID, `{"d":1}`, 10)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.Enqueue(ctx, "activation", nil, `{}`, 11)
	s.Enqueue(ctx, "x", nil, `{}`, 12)
	p, err := s.Pending(ctx, 2)
	if err != nil || len(p) != 2 || p[0].ID != a || p[0].UserID == nil || *p[0].UserID != u.ID || p[1].ID != b || p[1].UserID != nil {
		t.Fatalf("%+v %v", p, err)
	}
	if err := s.MarkSent(ctx, a, 50); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSent(ctx, a, 51); !errors.Is(err, ErrNotFound) {
		t.Fatalf("повторная отметка: %v", err)
	}
	if p, _ := s.Pending(ctx, 0); len(p) != 2 || p[0].ID != b {
		t.Fatalf("после отметки: %+v", p)
	}
}

func TestEffectiveUntil(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	got := func(name string) *int64 {
		v, err := s.EffectiveUntil(ctx, 1, name)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if got("нет-карточки") != nil {
		t.Fatal("без карточки срок есть")
	}
	i := func(v int64) *int64 { return &v }
	// Карточка без срока и без владельца.
	s.SaveCard(ctx, Card{Node: 1, Name: "a"})
	if got("a") != nil {
		t.Fatal("ждали nil")
	}
	// Только срок карточки.
	s.SaveCard(ctx, Card{Node: 1, Name: "b", AccessUntil: i(200)})
	if v := got("b"); v == nil || *v != 200 {
		t.Fatalf("%v", v)
	}
	// Только срок владельца.
	s.SetOwner(ctx, 1, "a", &u.ID)
	if err := s.SetUserAccessUntil(ctx, u.ID, i(300)); err != nil {
		t.Fatal(err)
	}
	if v := got("a"); v == nil || *v != 300 {
		t.Fatalf("%v", v)
	}
	// Оба срока — меньший.
	s.SetOwner(ctx, 1, "b", &u.ID)
	if v := got("b"); v == nil || *v != 200 {
		t.Fatalf("карточка меньше: %v", v)
	}
	s.SaveCard(ctx, Card{Node: 1, Name: "b", AccessUntil: i(900)})
	if v := got("b"); v == nil || *v != 300 {
		t.Fatalf("владелец меньше: %v", v)
	}
	// Сняли срок владельца — остаётся срок карточки.
	if err := s.SetUserAccessUntil(ctx, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if v := got("b"); v == nil || *v != 900 {
		t.Fatalf("%v", v)
	}
	if err := s.SetUserAccessUntil(ctx, 9999, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("несуществующий: %v", err)
	}
}

func TestSetUserAccessUntilKeepsOtherFields(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	s.SetPassword(ctx, u.ID, "новый", true)
	v := int64(77)
	if err := s.SetUserAccessUntil(ctx, u.ID, &v); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(ctx, u.ID)
	if got.AccessUntil == nil || *got.AccessUntil != 77 || got.Hash != "новый" || !got.MustChange {
		t.Fatalf("%+v", got)
	}
	// Общее обновление пользователя срок не затирает.
	got.Role = RoleAdmin
	s.UpdateUser(ctx, got)
	got, _ = s.UserByID(ctx, u.ID)
	if got.AccessUntil == nil || *got.AccessUntil != 77 {
		t.Fatalf("срок затёрт: %+v", got)
	}
}
