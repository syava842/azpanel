package antizapret

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeRun struct {
	calls [][]string
	out   string
	err   error
	sleep time.Duration
}

func (f *fakeRun) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{dir}, args...))
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return []byte(f.out), ctx.Err()
		}
	}
	return []byte(f.out), f.err
}

func TestClientShArgs(t *testing.T) {
	f := &fakeRun{out: "ok\n"}
	c := &ClientSh{Dir: "/root/antizapret", Timeout: time.Second, Run: f.run}
	ctx := context.Background()
	c.AddOpenVPN(ctx, "azpanel-test-a1", 30)
	c.DeleteOpenVPN(ctx, "azpanel-test-a1")
	c.AddWireGuard(ctx, "azpanel-test-a1")
	c.DeleteWireGuard(ctx, "azpanel-test-a1")
	want := []string{
		"/root/antizapret 1 azpanel-test-a1 30",
		"/root/antizapret 2 azpanel-test-a1",
		"/root/antizapret 4 azpanel-test-a1",
		"/root/antizapret 5 azpanel-test-a1",
	}
	for i, w := range want {
		if got := strings.Join(f.calls[i], " "); got != w {
			t.Fatalf("[%d] %q, want %q", i, got, w)
		}
	}
}

func TestClientShRejectsBeforeRun(t *testing.T) {
	f := &fakeRun{}
	c := &ClientSh{Dir: "/x", Timeout: time.Second, Run: f.run}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		days int
	}{{"bad name", 30}, {"", 30}, {"a\nkill all", 30}, {"ok", 0}, {"ok", 3651}} {
		if _, err := c.AddOpenVPN(ctx, tc.name, tc.days); err == nil {
			t.Fatalf("%q/%d принято", tc.name, tc.days)
		}
	}
	if _, err := c.DeleteWireGuard(ctx, "x y"); err == nil {
		t.Fatal("имя с пробелом принято")
	}
	if len(f.calls) != 0 {
		t.Fatalf("client.sh запускался: %v", f.calls)
	}
}

func TestClientShErrorCarriesOutputTail(t *testing.T) {
	f := &fakeRun{out: "строка 1\nError at line 140: easyrsa revoke\n", err: errors.New("exit status 1")}
	c := &ClientSh{Dir: "/x", Timeout: time.Second, Run: f.run}
	_, err := c.DeleteOpenVPN(context.Background(), "nobody-here")
	if err == nil || !strings.Contains(err.Error(), "easyrsa revoke") || !strings.Contains(err.Error(), "client.sh 2 nobody-here") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientShTimeout(t *testing.T) {
	f := &fakeRun{sleep: time.Second}
	c := &ClientSh{Dir: "/x", Timeout: 20 * time.Millisecond, Run: f.run}
	_, err := c.AddWireGuard(context.Background(), "slow")
	if err == nil || !strings.Contains(err.Error(), "не уложился") {
		t.Fatalf("err = %v", err)
	}
}
