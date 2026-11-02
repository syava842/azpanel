package store

import (
	"errors"
	"testing"
)

func TestSessions(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	for _, h := range []string{"a", "b", "c"} {
		if err := s.CreateSession(ctx, Session{IDHash: h, UserID: u.ID, CSRF: "csrf" + h, IP: "1.1.1.1", Agent: "ua", Created: 100, Seen: 100, Expires: 1000, MFAPending: h == "c"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.SessionByIDHash(ctx, "c")
	if err != nil || !got.MFAPending || got.CSRF != "csrfc" || got.UserID != u.ID || got.Expires != 1000 {
		t.Fatalf("%+v %v", got, err)
	}
	list, err := s.UserSessions(ctx, u.ID)
	if err != nil || len(list) != 3 {
		t.Fatalf("%v %v", list, err)
	}
	if err := s.DeleteUserSessions(ctx, u.ID, "b"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.UserSessions(ctx, u.ID)
	if len(list) != 1 || list[0].IDHash != "b" {
		t.Fatalf("осталось %+v", list)
	}
	if err := s.DeleteUserSessions(ctx, u.ID, ""); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.UserSessions(ctx, u.ID); len(list) != 0 {
		t.Fatalf("осталось %+v", list)
	}
}

func TestTouchSessionOncePerMinute(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	s.CreateSession(ctx, Session{IDHash: "a", UserID: u.ID, Seen: 1000, Expires: 9999})
	s.TouchSession(ctx, "a", 1030)
	if g, _ := s.SessionByIDHash(ctx, "a"); g.Seen != 1000 {
		t.Fatalf("seen обновлён раньше минуты: %d", g.Seen)
	}
	s.TouchSession(ctx, "a", 1060)
	if g, _ := s.SessionByIDHash(ctx, "a"); g.Seen != 1060 {
		t.Fatalf("seen не обновлён: %d", g.Seen)
	}
}

func TestPurgeAndDelete(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "bob", RoleUser)
	s.CreateSession(ctx, Session{IDHash: "old", UserID: u.ID, Expires: 50})
	s.CreateSession(ctx, Session{IDHash: "new", UserID: u.ID, Expires: 500})
	if err := s.PurgeExpiredSessions(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByIDHash(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old: %v", err)
	}
	if err := s.DeleteSession(ctx, "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByIDHash(ctx, "new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new: %v", err)
	}
}
