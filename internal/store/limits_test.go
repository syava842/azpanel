package store

import (
	"errors"
	"testing"
)

func i64(v int64) *int64 { return &v }

func TestExtendAccessFromFutureAndPast(t *testing.T) {
	s := open(t)
	day := int64(86400)
	// срок карточки в будущем: прибавляется к нему
	s.SaveCard(ctx, Card{Node: 1, Name: "a", AccessUntil: i64(1000 * day)})
	before, after, err := s.ExtendAccess(ctx, 1, "a", 30, 10*day)
	if err != nil || *before != 1000*day || after != 1030*day {
		t.Fatalf("%v %v %v", before, after, err)
	}
	if c, _ := s.Card(ctx, 1, "a"); *c.AccessUntil != 1030*day {
		t.Fatalf("карточка: %v", *c.AccessUntil)
	}
	// срок в прошлом: считается от now
	s.SaveCard(ctx, Card{Node: 1, Name: "b", AccessUntil: i64(5 * day)})
	_, after, err = s.ExtendAccess(ctx, 1, "b", 30, 100*day)
	if err != nil || after != 130*day {
		t.Fatalf("%v %v", after, err)
	}
}

func TestExtendAccessMovesBothLimits(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	day := int64(86400)
	s.SaveCard(ctx, Card{Node: 1, Name: "a", AccessUntil: i64(200 * day)})
	s.SetOwner(ctx, 1, "a", &u.ID)
	s.SetUserAccessUntil(ctx, u.ID, i64(50*day)) // владелец ограничивает сильнее
	before, after, err := s.ExtendAccess(ctx, 1, "a", 30, 100*day)
	if err != nil || *before != 50*day || after != 130*day {
		t.Fatalf("%v %v %v", before, after, err)
	}
	if v, _ := s.EffectiveUntil(ctx, 1, "a"); *v != 130*day {
		t.Fatalf("действующий срок %d", *v/day)
	}
	// срок карточки (200) позже нового и не тронут
	if c, _ := s.Card(ctx, 1, "a"); *c.AccessUntil != 200*day {
		t.Fatalf("карточка сдвинута: %d", *c.AccessUntil/day)
	}
	if got, _ := s.UserByID(ctx, u.ID); *got.AccessUntil != 130*day {
		t.Fatalf("владелец: %v", got.AccessUntil)
	}
}

func TestExtendAccessNoLimit(t *testing.T) {
	s := open(t)
	if _, _, err := s.ExtendAccess(ctx, 1, "нет", 30, 1); !errors.Is(err, ErrNoLimit) {
		t.Fatalf("без карточки: %v", err)
	}
	s.SaveCard(ctx, Card{Node: 1, Name: "a"})
	if _, _, err := s.ExtendAccess(ctx, 1, "a", 30, 1); !errors.Is(err, ErrNoLimit) {
		t.Fatalf("без срока: %v", err)
	}
	if _, _, err := s.ExtendAccess(ctx, 1, "a", 0, 1); err == nil {
		t.Fatal("ноль дней принят")
	}
}

func TestClientLimits(t *testing.T) {
	s := open(t)
	u := mkUser(t, s, "alice", RoleUser)
	s.SaveCard(ctx, Card{Node: 1, Name: "a", AccessUntil: i64(300)})
	s.SaveCard(ctx, Card{Node: 1, Name: "b"})
	s.SetOwner(ctx, 1, "a", &u.ID)
	s.SetOwner(ctx, 1, "b", &u.ID)
	s.SetUserAccessUntil(ctx, u.ID, i64(200))
	got, err := s.ClientLimits(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if *got["a"].Effective() != 200 || *got["b"].Effective() != 200 || got["a"].OwnerID == nil || *got["a"].OwnerID != u.ID {
		t.Fatalf("%+v", got)
	}
	s.SetUserAccessUntil(ctx, u.ID, nil)
	got, _ = s.ClientLimits(ctx, 1)
	if *got["a"].Effective() != 300 || got["b"].Effective() != nil {
		t.Fatalf("%+v", got)
	}
}
