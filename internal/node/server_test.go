package node

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/logx"
)

func newServer(t *testing.T, lim map[string]int) (*Server, *bytes.Buffer) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "limits.json")
	if lim != nil {
		if err := limits.Save(p, lim); err != nil {
			t.Fatal(err)
		}
	}
	var hookLog bytes.Buffer
	tr := NewTracker()
	// Агент принимает события только от экземпляров, которые видел в снимках.
	tr.ApplySnapshot("antizapret-udp", t0.Add(-time.Second), nil)
	return &Server{
		Tracker: tr,
		Limits:  limits.NewStore(p),
		HookLog: logx.New(&hookLog),
		Log:     logx.New(io.Discard),
		Now:     func() time.Time { return t0 },
	}, &hookLog
}

func connect(cn, addr string) agentproto.Request {
	return agentproto.Request{Op: agentproto.OpConnect, Instance: "antizapret-udp", CN: cn, Addr: addr}
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHandleUnknownInstanceNotCounted(t *testing.T) {
	s, hookLog := newServer(t, map[string]int{"alice": 1})
	for i := 0; i < 3; i++ {
		r := s.Handle(agentproto.Request{Op: agentproto.OpConnect, Instance: "fake", CN: "alice", Addr: "1.1.1.1:" + strconv.Itoa(i)})
		if !r.Allow {
			t.Fatalf("неизвестный экземпляр, подключение %d: %+v", i, r)
		}
	}
	if n := s.Tracker.Count("alice"); n != 0 {
		t.Fatalf("события неизвестного экземпляра засчитаны: %d", n)
	}
	if !strings.Contains(hookLog.String(), "неизвестный экземпляр") {
		t.Fatalf("hook.log:\n%s", hookLog.String())
	}
	if r := s.Handle(connect("alice", "1.1.1.1:9")); !r.Allow {
		t.Fatalf("настоящее подключение после подделок: %+v", r)
	}
}

func TestHandleConnectWithinAndOverLimit(t *testing.T) {
	s, hookLog := newServer(t, map[string]int{"alice": 1})
	if r := s.Handle(connect("alice", "1.1.1.1:1")); !r.Allow || r.Count != 1 || r.Limit != 1 {
		t.Fatalf("первое: %+v", r)
	}
	r := s.Handle(connect("alice", "1.1.1.1:2"))
	if r.Allow || r.Count != 1 || r.Limit != 1 || r.Error != "" {
		t.Fatalf("второе: %+v", r)
	}
	if !strings.Contains(hookLog.String(), "отказ") {
		t.Fatalf("в hook.log нет отказа:\n%s", hookLog.String())
	}
}

func TestHandleNoLimitAllows(t *testing.T) {
	s, _ := newServer(t, nil)
	for i := 0; i < 5; i++ {
		if r := s.Handle(connect("bob", "2.2.2.2:"+strconv.Itoa(i))); !r.Allow {
			t.Fatalf("подключение %d: %+v", i, r)
		}
	}
}

func TestHandleBrokenLimitsFailsOpen(t *testing.T) {
	s, hookLog := newServer(t, nil)
	s.Limits = limits.NewStore(writeFile(t, "limits.json", "{"))
	r := s.Handle(connect("alice", "1.1.1.1:1"))
	if !r.Allow {
		t.Fatalf("ответ %+v", r)
	}
	if !strings.Contains(hookLog.String(), "не прочитан") {
		t.Fatalf("hook.log:\n%s", hookLog.String())
	}
}

// Файл испортили после того, как лимиты были прочитаны: лимиты продолжают
// действовать, а не снимаются у всех разом.
func TestHandleBrokenLimitsKeepsLastGood(t *testing.T) {
	s, _ := newServer(t, nil)
	p := writeFile(t, "limits.json", `{"version":1,"limits":{"alice":1}}`)
	s.Limits = limits.NewStore(p)
	if r := s.Handle(connect("alice", "1.1.1.1:1")); !r.Allow {
		t.Fatalf("первое: %+v", r)
	}
	os.WriteFile(p, []byte("{"), 0o600)
	if r := s.Handle(connect("alice", "1.1.1.1:2")); r.Allow || r.Error != "" {
		t.Fatalf("второе при испорченном файле: %+v", r)
	}
}

func TestServeLimitsRequestSize(t *testing.T) {
	s, _ := newServer(t, nil)
	sock := filepath.Join(t.TempDir(), "node.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.Serve(ln)
	big := agentproto.Request{Op: agentproto.OpConnect, Instance: "antizapret-udp", CN: strings.Repeat("a", 10000), Addr: "1.1.1.1:1"}
	if _, err := agentproto.Call(sock, big, time.Second); err == nil {
		t.Fatal("запрос больше предела получил ответ")
	}
}

func TestHandleDisconnectFreesSlot(t *testing.T) {
	s, _ := newServer(t, map[string]int{"alice": 1})
	s.Handle(connect("alice", "1.1.1.1:1"))
	s.Now = func() time.Time { return t0.Add(time.Second) }
	s.Handle(agentproto.Request{Op: agentproto.OpDisconnect, Instance: "antizapret-udp", CN: "alice", Addr: "1.1.1.1:1"})
	s.Now = func() time.Time { return t0.Add(2 * time.Second) }
	if r := s.Handle(connect("alice", "1.1.1.1:2")); !r.Allow {
		t.Fatalf("после отключения: %+v", r)
	}
}

func TestHandleUnknownOpAllows(t *testing.T) {
	s, _ := newServer(t, nil)
	if r := s.Handle(agentproto.Request{Op: "что-то"}); !r.Allow || r.Error == "" {
		t.Fatalf("ответ %+v", r)
	}
}

func TestServeOverSocket(t *testing.T) {
	s, _ := newServer(t, map[string]int{"alice": 1})
	sock := filepath.Join(t.TempDir(), "node.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.Serve(ln)
	r, err := agentproto.Call(sock, connect("alice", "1.1.1.1:1"), time.Second)
	if err != nil || !r.Allow {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	r, err = agentproto.Call(sock, agentproto.Request{Op: agentproto.OpList}, time.Second)
	if err != nil || r.Counts["alice"] != 1 {
		t.Fatalf("list: r=%+v err=%v", r, err)
	}
}

func TestServeRejectsForeignPeer(t *testing.T) {
	s, _ := newServer(t, nil)
	s.Peer = func(net.Conn) error { return io.ErrUnexpectedEOF }
	sock := filepath.Join(t.TempDir(), "node.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.Serve(ln)
	if _, err := agentproto.Call(sock, connect("alice", "1.1.1.1:1"), time.Second); err == nil {
		t.Fatal("чужой собеседник получил ответ")
	}
	if n := s.Tracker.Count("alice"); n != 0 {
		t.Fatalf("событие от чужого засчитано: %d", n)
	}
}
