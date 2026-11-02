package store

import (
	"reflect"
	"testing"
)

func TestCardDefaultIsNotError(t *testing.T) {
	s := open(t)
	c, err := s.Card(ctx, 1, "alice")
	want := Card{Node: 1, Name: "alice", TrafficPeriod: "month"}
	if err != nil || !reflect.DeepEqual(c, want) {
		t.Fatalf("%+v, %v", c, err)
	}
}

func TestCardSaveReadDelete(t *testing.T) {
	s := open(t)
	until := int64(1_900_000_000)
	in := Card{Node: 1, Name: "alice", Note: "ноутбук", AccessUntil: &until, TrafficLimit: 5 << 30, TrafficPeriod: PeriodWeek, AutoBlock: AutoBlockTraffic}
	if err := s.SaveCard(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := s.Card(ctx, 1, "alice")
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Fatalf("%+v, %v", got, err)
	}
	in.AccessUntil = nil // сброс срока
	in.Note = "новая"
	s.SaveCard(ctx, in)
	s.SaveCard(ctx, Card{Node: 1, Name: "bob"})
	all, err := s.Cards(ctx, 1)
	if err != nil || len(all) != 2 || all["alice"].AccessUntil != nil || all["alice"].Note != "новая" || all["bob"].TrafficPeriod != "month" {
		t.Fatalf("%+v, %v", all, err)
	}
	if err := s.DeleteCard(ctx, 1, "alice"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Card(ctx, 1, "alice"); c.Note != "" {
		t.Fatalf("карточка не удалена: %+v", c)
	}
}

func TestCardUnknownNodeRejected(t *testing.T) {
	s := open(t)
	if err := s.SaveCard(ctx, Card{Node: 7, Name: "x"}); err == nil {
		t.Fatal("карточка несуществующего узла записана: foreign_keys не включены")
	}
}
