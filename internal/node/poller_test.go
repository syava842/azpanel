package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/logx"
)

func TestPollOnceKeepsSnapshotOfSilentInstance(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"antizapret-udp.sock", "vpn-udp.sock"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	silent := false
	var logBuf bytes.Buffer
	tr := NewTracker()
	p := &Poller{
		Dir: dir, Timeout: time.Second, Tracker: tr, Log: logx.New(&logBuf),
		Now: func() time.Time { return t0 },
		Query: func(sock string, _ time.Duration) ([]antizapret.Session, error) {
			if antizapret.InstanceFromSocket(sock) == "vpn-udp" && silent {
				return nil, errors.New("i/o timeout")
			}
			return []antizapret.Session{{CommonName: "alice", RealAddr: antizapret.InstanceFromSocket(sock)}}, nil
		},
	}
	p.PollOnce()
	if n := tr.Count("alice"); n != 2 {
		t.Fatalf("после первого опроса alice = %d", n)
	}
	silent = true
	for i := 0; i < 3; i++ {
		p.PollOnce()
	}
	if n := tr.Count("alice"); n != 2 {
		t.Fatalf("молчащий экземпляр потерял снимок: alice = %d", n)
	}
	if c := strings.Count(logBuf.String(), "не отвечает"); c != 1 {
		t.Fatalf("предупреждений %d, ждали одно:\n%s", c, logBuf.String())
	}
}
