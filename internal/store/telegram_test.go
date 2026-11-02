package store

import (
	"context"
	"errors"
	"testing"
)

func tgUser(t *testing.T, s *Store, login string) User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), User{Login: login, Hash: "x", Role: "user", Created: 1})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTelegramMigrationApplied(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	u := tgUser(t, s, "a")
	if u.TelegramID != nil {
		t.Fatal("новый пользователь уже привязан")
	}
	for _, tbl := range []string{"tg_link_codes", "tg_requests", "tg_banned", "client_kinds"} {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
	}
}

func TestTelegramIDSetClearLookup(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	a, b := tgUser(t, s, "a"), tgUser(t, s, "b")
	if err := s.SetTelegramID(ctx, a.ID, 111); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserByTelegramID(ctx, 111)
	if err != nil || got.ID != a.ID || got.TelegramID == nil || *got.TelegramID != 111 {
		t.Fatalf("получено %+v, %v", got, err)
	}
	if err := s.SetTelegramID(ctx, b.ID, 111); !errors.Is(err, ErrTelegramTaken) {
		t.Fatalf("занятый ID: %v", err)
	}
	if err := s.SetTelegramID(ctx, 999, 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет пользователя: %v", err)
	}
	if err := s.ClearTelegramID(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByTelegramID(ctx, 111); !errors.Is(err, ErrNotFound) {
		t.Fatalf("после отвязки: %v", err)
	}
	if err := s.SetTelegramID(ctx, b.ID, 111); err != nil {
		t.Fatalf("освободившийся ID: %v", err)
	}
	// Точечная запись не трогает остальные поля.
	if u, _ := s.UserByID(ctx, b.ID); u.Role != "user" || u.Hash != "x" {
		t.Fatalf("затронуты чужие поля: %+v", u)
	}
}

func TestLinkCodeOnceAndExpiry(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	u := tgUser(t, s, "a")
	code, err := s.CreateLinkCode(ctx, u.ID, 1000)
	if err != nil || len(code) != 22 { // 16 байт в base64url без дополнения
		t.Fatalf("код %q, %v", code, err)
	}
	if id, err := s.RedeemLinkCode(ctx, code, 1000+LinkCodeTTL-1); err != nil || id != u.ID {
		t.Fatalf("погашение: %d, %v", id, err)
	}
	if _, err := s.RedeemLinkCode(ctx, code, 1001); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("повтор: %v", err)
	}
	old, _ := s.CreateLinkCode(ctx, u.ID, 1000)
	if _, err := s.RedeemLinkCode(ctx, old, 1000+LinkCodeTTL); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("просроченный: %v", err)
	}
	if _, err := s.RedeemLinkCode(ctx, "нет-такого", 1); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("неизвестный: %v", err)
	}
	// Новый код заменяет прежний того же пользователя.
	c1, _ := s.CreateLinkCode(ctx, u.ID, 2000)
	c2, _ := s.CreateLinkCode(ctx, u.ID, 2000)
	if _, err := s.RedeemLinkCode(ctx, c1, 2001); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("прежний код жив: %v", err)
	}
	if _, err := s.RedeemLinkCode(ctx, c2, 2001); err != nil {
		t.Fatal(err)
	}
	// В базе лежит хеш, а не код.
	c3, _ := s.CreateLinkCode(ctx, u.ID, 3000)
	var n int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM tg_link_codes WHERE hash = ?`, c3).Scan(&n)
	if n != 0 {
		t.Fatal("код лежит открытым")
	}
}

func TestLinkCodeDeletedWithUser(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	u := tgUser(t, s, "a")
	code, _ := s.CreateLinkCode(ctx, u.ID, 10)
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemLinkCode(ctx, code, 11); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("код удалённого пользователя: %v", err)
	}
}

func TestTelegramRequestsAndBans(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.AddTelegramRequest(ctx, TelegramRequest{ID: 7, Username: "u", Name: "Имя", Created: 10}); err != nil {
		t.Fatal(err)
	}
	// Повторная заявка обновляет, а не дублирует и не сдвигает время.
	if err := s.AddTelegramRequest(ctx, TelegramRequest{ID: 7, Username: "u2", Name: "Имя2", Created: 20}); err != nil {
		t.Fatal(err)
	}
	list, err := s.TelegramRequests(ctx)
	if err != nil || len(list) != 1 || list[0].Username != "u2" || list[0].Created != 10 {
		t.Fatalf("заявки %+v, %v", list, err)
	}
	if err := s.DeleteTelegramRequest(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if list, _ = s.TelegramRequests(ctx); len(list) != 0 {
		t.Fatalf("осталось %+v", list)
	}
	if b, _ := s.TelegramBanned(ctx, 7); b {
		t.Fatal("не блокирован, а блокирован")
	}
	// Блокировка убирает заявку.
	s.AddTelegramRequest(ctx, TelegramRequest{ID: 7, Created: 1})
	if err := s.BanTelegram(ctx, 7, 30); err != nil {
		t.Fatal(err)
	}
	if err := s.BanTelegram(ctx, 7, 31); err != nil {
		t.Fatalf("повторная блокировка: %v", err)
	}
	if b, _ := s.TelegramBanned(ctx, 7); !b {
		t.Fatal("блокировка не видна")
	}
	if list, _ = s.TelegramRequests(ctx); len(list) != 0 {
		t.Fatal("заявка пережила блокировку")
	}
	if err := s.UnbanTelegram(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.TelegramBanned(ctx, 7); b {
		t.Fatal("блокировка не снята")
	}
}

func TestClientKinds(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if k, ok, err := s.ClientKinds(ctx, 1, "c"); err != nil || ok || k != nil {
		t.Fatalf("без записи: %v %v %v", k, ok, err)
	}
	if err := s.SetClientKinds(ctx, 1, "c", []string{"wireguard", "openvpn", "wireguard"}); err != nil {
		t.Fatal(err)
	}
	k, ok, err := s.ClientKinds(ctx, 1, "c")
	if err != nil || !ok || len(k) != 2 || k[0] != "openvpn" || k[1] != "wireguard" {
		t.Fatalf("получено %v %v %v", k, ok, err)
	}
	if err := s.SetClientKinds(ctx, 1, "c", []string{"icq"}); err == nil {
		t.Fatal("неизвестный тип принят")
	}
	// Пусто — «всё»: запись снимается.
	if err := s.SetClientKinds(ctx, 1, "c", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ClientKinds(ctx, 1, "c"); ok {
		t.Fatal("запись осталась")
	}
	s.SetClientKinds(ctx, 1, "c", []string{"vpn"})
	if err := s.DeleteClientKinds(ctx, 1, "c"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ClientKinds(ctx, 1, "c"); ok {
		t.Fatal("DeleteClientKinds не удалил")
	}
}

func TestBindTelegramIDOnlyFreeActiveUser(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	free := tgUser(t, s, "free")
	adm, _ := s.CreateUser(ctx, User{Login: "adm", Hash: "x", Role: RoleAdmin, Created: 1})
	off, _ := s.CreateUser(ctx, User{Login: "off", Hash: "x", Role: RoleUser, Disabled: true, Created: 1})
	taken := tgUser(t, s, "taken")
	if err := s.SetTelegramID(ctx, taken.ID, 50); err != nil {
		t.Fatal(err)
	}
	if err := s.BindTelegramID(ctx, adm.ID, 1); !errors.Is(err, ErrBindRefused) {
		t.Fatalf("администратор: %v", err)
	}
	if err := s.BindTelegramID(ctx, off.ID, 1); !errors.Is(err, ErrBindRefused) {
		t.Fatalf("отключённый: %v", err)
	}
	if err := s.BindTelegramID(ctx, taken.ID, 1); !errors.Is(err, ErrTelegramBound) {
		t.Fatalf("уже привязанный: %v", err)
	}
	if u, _ := s.UserByID(ctx, taken.ID); u.TelegramID == nil || *u.TelegramID != 50 {
		t.Fatal("чужая привязка затёрта")
	}
	if err := s.BindTelegramID(ctx, 9999, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет пользователя: %v", err)
	}
	if err := s.BindTelegramID(ctx, free.ID, 50); !errors.Is(err, ErrTelegramTaken) {
		t.Fatalf("занятый ID: %v", err)
	}
	if err := s.BindTelegramID(ctx, free.ID, 7); err != nil {
		t.Fatal(err)
	}
}

func TestTelegramBansList(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	_ = s.BanTelegram(ctx, 5, 100)
	_ = s.BanTelegram(ctx, 6, 200)
	got, err := s.TelegramBans(ctx)
	if err != nil || len(got) != 2 || got[0].ID != 6 {
		t.Fatalf("получено %+v, %v", got, err)
	}
}

func TestOutboxFailCountAndStale(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	old, _ := s.Enqueue(ctx, "k", nil, "a", 100)
	fresh, _ := s.Enqueue(ctx, "k", nil, "b", 1000)
	if n, err := s.FailOutbox(ctx, fresh); err != nil || n != 1 {
		t.Fatalf("первый сбой: %d, %v", n, err)
	}
	if n, _ := s.FailOutbox(ctx, fresh); n != 2 {
		t.Fatalf("второй сбой: %d", n)
	}
	items, _ := s.Pending(ctx, 0)
	if len(items) != 2 || items[1].Attempts != 2 {
		t.Fatalf("счётчик не в очереди: %+v", items)
	}
	n, err := s.MarkSentBefore(ctx, 500, 2000)
	if err != nil || n != 1 {
		t.Fatalf("устаревших: %d, %v", n, err)
	}
	items, _ = s.Pending(ctx, 0)
	if len(items) != 1 || items[0].ID != fresh {
		t.Fatalf("осталось %+v (старая %d)", items, old)
	}
	if _, err := s.FailOutbox(ctx, old); !errors.Is(err, ErrNotFound) {
		t.Fatalf("отправленная запись: %v", err)
	}
}

func TestLinkTelegramIDAllowsAdminButNotBound(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	adm, _ := s.CreateUser(ctx, User{Login: "adm", Hash: "x", Role: RoleAdmin, Created: 1})
	if err := s.LinkTelegramID(ctx, adm.ID, 11); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkTelegramID(ctx, adm.ID, 12); !errors.Is(err, ErrTelegramBound) {
		t.Fatalf("повторная привязка: %v", err)
	}
	if u, _ := s.UserByID(ctx, adm.ID); *u.TelegramID != 11 {
		t.Fatal("привязка затёрта")
	}
}
