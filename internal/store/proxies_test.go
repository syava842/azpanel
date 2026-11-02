package store

import (
	"errors"
	"testing"
)

func TestProxiesCRUD(t *testing.T) {
	s := open(t)
	if list, err := s.Proxies(ctx); err != nil || len(list) != 0 {
		t.Fatalf("пустая база: %v %v", list, err)
	}
	p, err := s.CreateProxy(ctx, Proxy{Name: "ru-1", IP: "203.0.113.5", Note: "основной", Created: 10, AddedByPanel: true})
	if err != nil || p.ID == 0 {
		t.Fatalf("создание: %+v %v", p, err)
	}
	if _, err := s.CreateProxy(ctx, Proxy{Name: "ещё", IP: "203.0.113.5"}); !errors.Is(err, ErrProxyExists) {
		t.Fatalf("повторный адрес: %v", err)
	}
	if _, err := s.CreateProxy(ctx, Proxy{Name: "ru-2", IP: "203.0.113.6"}); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Proxies(ctx)
	if len(list) != 2 || list[0].Name != "ru-1" || !list[0].AddedByPanel || list[1].AddedByPanel {
		t.Fatalf("список: %+v", list)
	}
	got, err := s.ProxyByID(ctx, p.ID)
	if err != nil || got != p {
		t.Fatalf("по номеру: %+v %v", got, err)
	}
	if _, err := s.ProxyByIP(ctx, "198.51.100.1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой адрес: %v", err)
	}
	if err := s.DeleteProxy(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProxy(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("повторное удаление: %v", err)
	}
	if _, err := s.ProxyByID(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("после удаления: %v", err)
	}
}
