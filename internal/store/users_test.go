package store

import (
	"errors"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func mkUser(t *testing.T, s *Store, login, role string) User {
	t.Helper()
	u, err := s.CreateUser(ctx, User{Login: login, Hash: "h", Role: role, Created: 1})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUserLoginUnique(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleAdmin)
	if u.ID == 0 {
		t.Fatal("нет id")
	}
	_, err := s.CreateUser(ctx, User{Login: "alice", Hash: "h", Role: RoleUser})
	if !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("ждали ErrLoginTaken, получили %v", err)
	}
	got, err := s.UserByLogin(ctx, "alice")
	if err != nil || got.ID != u.ID || got.Role != RoleAdmin {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := s.UserByLogin(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ждали ErrNotFound, получили %v", err)
	}
	if _, err := s.UserByID(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UserByID: %v", err)
	}
}

func TestAdminCountAndUpdate(t *testing.T) {
	s := open(t)
	a := mkUser(t, s, "a1", RoleAdmin)
	b := mkUser(t, s, "a2", RoleAdmin)
	mkUser(t, s, "u1", RoleUser)
	if n, _ := s.AdminCount(ctx); n != 2 {
		t.Fatalf("админов %d", n)
	}
	b.Disabled = true
	b.TOTPSecret = []byte{1, 2, 3}
	b.TOTPLastStep = 77
	b.MustChange = true
	if err := s.UpdateUser(ctx, b); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.AdminCount(ctx); n != 1 {
		t.Fatalf("после отключения админов %d", n)
	}
	got, _ := s.UserByID(ctx, b.ID)
	if !got.Disabled || !got.MustChange || got.TOTPLastStep != 77 || string(got.TOTPSecret) != "\x01\x02\x03" {
		t.Fatalf("%+v", got)
	}
	a.Role = RoleUser
	s.UpdateUser(ctx, a)
	if n, _ := s.AdminCount(ctx); n != 0 {
		t.Fatalf("админов %d", n)
	}
	us, err := s.Users(ctx)
	if err != nil || len(us) != 3 {
		t.Fatalf("%v %v", us, err)
	}
}

func TestDeleteUserCascades(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	if err := s.SetBackupCodes(ctx, u.ID, []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, Session{IDHash: "s1", UserID: u.ID, CSRF: "c", Expires: 99}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByIDHash(ctx, "s1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("сессия осталась: %v", err)
	}
	var n int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM backup_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("кодов осталось %d", n)
	}
}

func TestBackupCodeOnce(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	h1, _ := bcrypt.GenerateFromPassword([]byte("abcde23456"), bcrypt.MinCost)
	h2, _ := bcrypt.GenerateFromPassword([]byte("zzzzz99999"), bcrypt.MinCost)
	if err := s.SetBackupCodes(ctx, u.ID, []string{string(h1), string(h2)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	okN := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.UseBackupCode(ctx, u.ID, "abcde23456")
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				okN++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if okN != 1 {
		t.Fatalf("сработало %d раз", okN)
	}
	if ok, _ := s.UseBackupCode(ctx, u.ID, "wrongwrong"); ok {
		t.Fatal("чужой код принят")
	}
	if ok, _ := s.UseBackupCode(ctx, u.ID, "zzzzz99999"); !ok {
		t.Fatal("второй код не принят")
	}
	// замена стирает всё, включая использованные
	s.SetBackupCodes(ctx, u.ID, []string{string(h1)})
	if ok, _ := s.UseBackupCode(ctx, u.ID, "abcde23456"); !ok {
		t.Fatal("после замены код не работает")
	}
}

func TestOwners(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	if err := s.SetOwner(ctx, LocalNode, "c1", &u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOwner(ctx, LocalNode, "c2", &u.ID); err != nil {
		t.Fatal(err)
	}
	refs, err := s.ClientsOf(ctx, u.ID)
	if err != nil || len(refs) != 2 || refs[0].Name != "c1" || refs[1].Name != "c2" || refs[0].Node != LocalNode {
		t.Fatalf("%+v %v", refs, err)
	}
	c, _ := s.Card(ctx, LocalNode, "c1")
	if c.Name != "c1" {
		t.Fatalf("карточка: %+v", c)
	}
	if err := s.SetOwner(ctx, LocalNode, "c2", nil); err != nil {
		t.Fatal(err)
	}
	if refs, _ := s.ClientsOf(ctx, u.ID); len(refs) != 1 {
		t.Fatalf("после снятия %+v", refs)
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	var owner *int64
	var n int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM client_cards WHERE owner_id IS NOT NULL`).Scan(&n)
	_ = owner
	if n != 0 {
		t.Fatalf("владелец остался у %d карточек", n)
	}
	if refs, _ := s.ClientsOf(ctx, u.ID); len(refs) != 0 {
		t.Fatalf("%+v", refs)
	}
}

func TestSaveCardKeepsOwner(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	s.SetOwner(ctx, LocalNode, "c1", &u.ID)
	if err := s.SaveCard(ctx, Card{Node: LocalNode, Name: "c1", Note: "n"}); err != nil {
		t.Fatal(err)
	}
	if refs, _ := s.ClientsOf(ctx, u.ID); len(refs) != 1 {
		t.Fatalf("SaveCard стёрла владельца: %+v", refs)
	}
}

func TestOwnerOf(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	if _, ok, err := s.OwnerOf(ctx, LocalNode, "c1"); err != nil || ok {
		t.Fatalf("без карточки: ok=%v err=%v", ok, err)
	}
	s.SetOwner(ctx, LocalNode, "c1", &u.ID)
	if id, ok, err := s.OwnerOf(ctx, LocalNode, "c1"); err != nil || !ok || id != u.ID {
		t.Fatalf("id=%d ok=%v err=%v", id, ok, err)
	}
	s.SetOwner(ctx, LocalNode, "c1", nil)
	if _, ok, _ := s.OwnerOf(ctx, LocalNode, "c1"); ok {
		t.Fatal("владелец не снят")
	}
}

func TestTargetedUpdatesDoNotClobber(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "carol", RoleAdmin)
	if err := s.SetRole(ctx, u.ID, RoleUser); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, u.ID, "reset", true); err != nil {
		t.Fatal(err)
	}
	// смена пароля по старому хешу «h» уже невозможна: сброс не теряется
	if err := s.ChangePassword(ctx, u.ID, "h", "mine"); !errors.Is(err, ErrPasswordChanged) {
		t.Fatalf("ждали ErrPasswordChanged, получили %v", err)
	}
	got, _ := s.UserByID(ctx, u.ID)
	if got.Role != RoleUser || !got.Disabled || got.Hash != "reset" || !got.MustChange {
		t.Fatalf("%+v", got)
	}
	if err := s.ChangePassword(ctx, u.ID, "reset", "mine"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(ctx, u.ID)
	if got.Hash != "mine" || got.MustChange {
		t.Fatalf("%+v", got)
	}
	if err := s.SetRole(ctx, 9999, RoleUser); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestTOTPStepAndEnable(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "dave", RoleUser)
	if ok, _ := s.AdvanceTOTPStep(ctx, u.ID, 5); ok {
		t.Fatal("шаг принят без 2FA")
	}
	if err := s.EnableTOTP(ctx, u.ID, []byte{1}, 3); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableTOTP(ctx, u.ID, []byte{2}, 3); !errors.Is(err, ErrTOTPAlreadyOn) {
		t.Fatalf("%v", err)
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, u.ID, 5); !ok {
		t.Fatal("шаг не принят")
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, u.ID, 5); ok {
		t.Fatal("повтор шага принят")
	}
	if err := s.SetTOTP(ctx, u.ID, nil, 0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(ctx, u.ID)
	if len(got.TOTPSecret) != 0 || got.TOTPLastStep != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestReencryptTOTPAllOrNothing(t *testing.T) {
	s := open(t)
	var ids []int64
	for i, login := range []string{"a", "b", "c"} {
		u, err := s.CreateUser(ctx, User{Login: login, Hash: "h", Role: RoleUser, Created: 1,
			TOTPSecret: []byte{byte('0' + i)}, TOTPLastStep: 7})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
	}
	read := func() []string {
		var out []string
		for _, id := range ids {
			u, err := s.UserByID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(u.TOTPSecret))
		}
		return out
	}
	// Сбой посередине: ничего не должно измениться.
	calls := 0
	_, err := s.ReencryptTOTP(ctx, func(raw []byte) ([]byte, bool, error) {
		calls++
		if calls == 2 {
			return nil, false, errors.New("сбой посередине")
		}
		return append([]byte("new-"), raw...), true, nil
	}, nil)
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if got := read(); got[0] != "0" || got[1] != "1" || got[2] != "2" {
		t.Fatalf("транзакция не откатилась: %v", got)
	}
	// Сбой перед фиксацией (замена файла ключа не удалась) — тоже откат.
	_, err = s.ReencryptTOTP(ctx, func(raw []byte) ([]byte, bool, error) {
		return append([]byte("new-"), raw...), true, nil
	}, func() error { return errors.New("файл не заменён") })
	if err == nil || read()[0] != "0" {
		t.Fatalf("откат при сбое beforeCommit: %v %v", err, read())
	}
	// Успех; секрет, помеченный ok=false, остаётся прежним; последний шаг цел.
	n, err := s.ReencryptTOTP(ctx, func(raw []byte) ([]byte, bool, error) {
		if string(raw) == "1" {
			return nil, false, nil
		}
		return append([]byte("new-"), raw...), true, nil
	}, nil)
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if got := read(); got[0] != "new-0" || got[1] != "1" || got[2] != "new-2" {
		t.Fatalf("итог: %v", got)
	}
	if u, _ := s.UserByID(ctx, ids[0]); u.TOTPLastStep != 7 {
		t.Fatal("последний шаг затёрт")
	}
}
