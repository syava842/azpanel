package node

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func sess(cn, addr string) antizapret.Session {
	return antizapret.Session{CommonName: cn, RealAddr: addr}
}

func TestCountAcrossInstances(t *testing.T) {
	tr := NewTracker()
	tr.ApplySnapshot("antizapret-udp", at(0), []antizapret.Session{sess("alice", "1.1.1.1:1"), sess("alice", "1.1.1.1:2"), sess("bob", "2.2.2.2:1")})
	tr.ApplySnapshot("vpn-tcp", at(0), []antizapret.Session{sess("alice", "3.3.3.3:1")})
	if n := tr.Count("alice"); n != 3 {
		t.Fatalf("alice = %d", n)
	}
	if got := tr.Counts(); got["alice"] != 3 || got["bob"] != 1 || len(got) != 2 {
		t.Fatalf("Counts = %v", got)
	}
}

func TestAdmitLimit(t *testing.T) {
	tr := NewTracker()
	tr.ApplySnapshot("antizapret-udp", at(0), []antizapret.Session{sess("alice", "1.1.1.1:1")})
	ok, n := tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:2"}, at(1), 2)
	if !ok || n != 2 {
		t.Fatalf("второе подключение: ok=%v n=%d", ok, n)
	}
	ok, n = tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:3"}, at(2), 2)
	if ok || n != 2 {
		t.Fatalf("третье при лимите 2: ok=%v n=%d", ok, n)
	}
}

func TestAdmitUnlimited(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 10; i++ {
		if ok, _ := tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:" + strconv.Itoa(i)}, at(i), 0); !ok {
			t.Fatalf("подключение %d без лимита отклонено", i)
		}
	}
	if n := tr.Count("alice"); n != 10 {
		t.Fatalf("alice = %d", n)
	}
}

func TestRepeatOfSameKeyIsNotSecond(t *testing.T) {
	tr := NewTracker()
	k := Key{"vpn-udp", "alice", "1.1.1.1:1"}
	tr.Admit(k, at(1), 1)
	if ok, n := tr.Admit(k, at(2), 1); !ok || n != 1 {
		t.Fatalf("повтор: ok=%v n=%d", ok, n)
	}
}

func TestFailedConnectDisappearsWithNextSnapshot(t *testing.T) {
	tr := NewTracker()
	tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:1"}, at(1), 0)
	tr.ApplySnapshot("vpn-udp", at(5), nil) // подключение так и не состоялось
	if n := tr.Count("alice"); n != 0 {
		t.Fatalf("alice = %d", n)
	}
}

func TestOlderSnapshotKeepsNewerConnect(t *testing.T) {
	tr := NewTracker()
	tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:1"}, at(3), 0)
	tr.ApplySnapshot("vpn-udp", at(2), nil) // снимок начат до подключения
	if n := tr.Count("alice"); n != 1 {
		t.Fatalf("alice = %d", n)
	}
}

func TestDisconnectBeatsOlderSnapshot(t *testing.T) {
	tr := NewTracker()
	tr.ApplySnapshot("vpn-udp", at(0), []antizapret.Session{sess("alice", "1.1.1.1:1")})
	tr.Disconnect(Key{"vpn-udp", "alice", "1.1.1.1:1"}, at(1))
	if n := tr.Count("alice"); n != 0 {
		t.Fatalf("после отключения alice = %d", n)
	}
	ok, _ := tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:2"}, at(2), 1)
	if !ok {
		t.Fatal("после отключения место освободилось, но подключение отклонено")
	}
}

func TestForgetDropsInstance(t *testing.T) {
	tr := NewTracker()
	tr.ApplySnapshot("vpn-tcp", at(0), []antizapret.Session{sess("alice", "1.1.1.1:1"), sess("alice", "1.1.1.1:2")})
	tr.ApplySnapshot("vpn-udp", at(0), nil)
	tr.Admit(Key{"vpn-tcp", "alice", "1.1.1.1:3"}, at(1), 0)
	tr.Forget("vpn-tcp")
	if n := tr.Count("alice"); n != 0 {
		t.Fatalf("после Forget alice = %d", n)
	}
	if tr.Known("vpn-tcp") || !tr.Known("vpn-udp") {
		t.Fatalf("Known: vpn-tcp=%v vpn-udp=%v", tr.Known("vpn-tcp"), tr.Known("vpn-udp"))
	}
	if got := tr.Instances(); len(got) != 1 || got[0] != "vpn-udp" {
		t.Fatalf("Instances = %v", got)
	}
}

func TestConnectAfterDisconnectOfSameKey(t *testing.T) {
	tr := NewTracker()
	k := Key{"vpn-udp", "alice", "1.1.1.1:1"}
	tr.Admit(k, at(1), 0)
	tr.Disconnect(k, at(2))
	tr.Admit(k, at(3), 0)
	if n := tr.Count("alice"); n != 1 {
		t.Fatalf("alice = %d", n)
	}
}

func TestTrackerSessions(t *testing.T) {
	tr := NewTracker()
	at := time.Unix(1000, 0)
	tr.ApplySnapshot("vpn-udp", at, []antizapret.Session{
		{Instance: "vpn-udp", CommonName: "bob", RealAddr: "5.6.7.8:1", BytesRx: 10},
	})
	tr.ApplySnapshot("antizapret-udp", at, []antizapret.Session{
		{Instance: "antizapret-udp", CommonName: "bob", RealAddr: "1.1.1.1:2"},
		{Instance: "antizapret-udp", CommonName: "alice", RealAddr: "1.1.1.1:1"},
	})
	got := tr.Sessions()
	var keys []string
	for _, s := range got {
		keys = append(keys, s.Instance+"/"+s.CommonName)
	}
	if strings.Join(keys, ",") != "antizapret-udp/alice,antizapret-udp/bob,vpn-udp/bob" {
		t.Fatalf("порядок %v", keys)
	}
	if got[2].BytesRx != 10 {
		t.Fatalf("подробности потеряны: %+v", got[2])
	}
	tr.Forget("vpn-udp")
	if n := len(tr.Sessions()); n != 2 {
		t.Fatalf("после Forget осталось %d", n)
	}
}
