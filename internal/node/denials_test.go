package node

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/nodeapi"
)

func TestHandleRecordsDenials(t *testing.T) {
	s, _ := newServer(t, map[string]int{"alice": 1})
	s.Denials = NewDenials(10)
	s.Handle(connect("alice", "1.1.1.1:1"))
	s.Handle(connect("alice", "1.1.1.1:2")) // сверх лимита

	p := writeFile(t, "limits.json", "")
	if err := limits.Save(p, limits.Data{Blocked: map[string]bool{"bob": true}}); err != nil {
		t.Fatal(err)
	}
	s.Limits = limits.NewStore(p)
	s.Handle(connect("bob", "2.2.2.2:1"))

	got := s.Denials.Since(time.Time{})
	if len(got) != 2 {
		t.Fatalf("отказов %d: %+v", len(got), got)
	}
	want0 := nodeapi.Denial{Time: t0, Name: "alice", Instance: "antizapret-udp", Addr: "1.1.1.1:2", Reason: "limit", Count: 1, Limit: 1}
	want1 := nodeapi.Denial{Time: t0, Name: "bob", Instance: "antizapret-udp", Addr: "2.2.2.2:1", Reason: "blocked"}
	if got[0] != want0 || got[1] != want1 {
		t.Fatalf("%+v\nждали %+v и %+v", got, want0, want1)
	}
}

func TestHandleAllowedNotRecorded(t *testing.T) {
	s, _ := newServer(t, nil)
	s.Denials = NewDenials(10)
	s.Handle(connect("alice", "1.1.1.1:1"))
	if got := s.Denials.Since(time.Time{}); len(got) != 0 {
		t.Fatalf("успешное подключение записано: %+v", got)
	}
}

func TestHandleWithoutDenialsBuffer(t *testing.T) {
	s, _ := newServer(t, map[string]int{"alice": 1})
	s.Handle(connect("alice", "1.1.1.1:1"))
	if r := s.Handle(connect("alice", "1.1.1.1:2")); r.Allow { // Denials == nil — не падает
		t.Fatalf("%+v", r)
	}
}

func TestDenialsRingEvictsOldest(t *testing.T) {
	d := NewDenials(1000)
	for i := 0; i < 1001; i++ {
		d.Add(nodeapi.Denial{Time: time.Unix(int64(1000+i), 0), Name: "c" + strconv.Itoa(i), Reason: "limit"})
	}
	got := d.Since(time.Time{})
	if len(got) != 1000 || got[0].Name != "c1" || got[999].Name != "c1000" {
		t.Fatalf("%d записей, первая %q, последняя %q", len(got), got[0].Name, got[len(got)-1].Name)
	}
}

func TestDenialsSinceFiltersStrictlyNewer(t *testing.T) {
	d := NewDenials(10)
	for i := 0; i < 5; i++ {
		d.Add(nodeapi.Denial{Time: time.Unix(int64(100+i), 0), Name: strconv.Itoa(i)})
	}
	got := d.Since(time.Unix(102, 0))
	if len(got) != 2 || got[0].Name != "3" || got[1].Name != "4" {
		t.Fatalf("%+v", got)
	}
}

func TestAPIDenials(t *testing.T) {
	e := newAPI(t)
	for i := 0; i < 3; i++ {
		e.api.Denials.Add(nodeapi.Denial{Time: time.Unix(int64(2000+i), 0), Name: "alice", Instance: "antizapret-udp", Addr: "1.1.1.1:1", Reason: "limit", Count: 2, Limit: 2})
	}
	all, err := e.client.Denials(context.Background(), time.Time{})
	if err != nil || len(all) != 3 || all[0].Time.Unix() != 2000 || all[2].Time.Unix() != 2002 {
		t.Fatalf("%+v, %v", all, err)
	}
	if all[0].Name != "alice" || all[0].Reason != "limit" || all[0].Count != 2 || all[0].Limit != 2 {
		t.Fatalf("поля: %+v", all[0])
	}
	newer, err := e.client.Denials(context.Background(), time.Unix(2000, 0))
	if err != nil || len(newer) != 2 || newer[0].Time.Unix() != 2001 {
		t.Fatalf("since: %+v, %v", newer, err)
	}
	empty, err := e.client.Denials(context.Background(), time.Unix(9999, 0))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("пусто: %#v, %v", empty, err)
	}
}

func TestAPIDenialsRequiresToken(t *testing.T) {
	e := newAPI(t)
	resp, err := http.Get(e.srv.URL + "/v1/denials")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без токена: %d", resp.StatusCode)
	}
}

func TestAPIDenialsBadSince(t *testing.T) {
	e := newAPI(t)
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/denials?since=вчера", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("%d", resp.StatusCode)
	}
}
