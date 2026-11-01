package node

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/paths"
)

func TestRunAnswersHook(t *testing.T) {
	// Короткий путь: у unix-сокета на Windows предел 108 символов.
	root, err := os.MkdirTemp("", "az")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	t.Setenv("AZPANEL_ROOT", root)
	for _, d := range []string{paths.Log(), paths.Data(), filepath.Dir(paths.NodeSocket())} {
		os.MkdirAll(d, 0o755)
	}
	limits.Save(paths.LimitsFile(), map[string]int{"alice": 1})

	mgmtDir := filepath.Join(root, "ovpn")
	os.MkdirAll(mgmtDir, 0o755)
	ln, err := net.Listen("unix", filepath.Join(mgmtDir, "antizapret-udp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadString('\n')
			c.Write([]byte("CLIENT_LIST\talice\tudp4:1.1.1.1:1\t10.0.0.2\t\t1\t1\tx\t1\tUNDEF\t1\t0\tnone\nEND\n"))
			c.Close()
		}
	}()

	cfg := config.Default()
	cfg.Node.OpenVPNSocketDir = mgmtDir
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hooked atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, func() (bool, error) { hooked.Store(true); return true, nil })
	}()

	var r agentproto.Response
	for i := 0; i < 50; i++ {
		r, err = agentproto.Call(paths.NodeSocket(), agentproto.Request{Op: agentproto.OpConnect, Instance: "vpn-udp", CN: "alice", Addr: "2.2.2.2:1"}, time.Second)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if r.Allow {
		t.Fatalf("alice уже подключена (снимок), лимит 1 — ждали отказ: %+v", r)
	}
	if !hooked.Load() {
		t.Fatal("Run не вызвал установку хука")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(paths.Log(), "hook.log"))
	if !strings.Contains(string(b), "отказ") {
		t.Fatalf("hook.log:\n%s", b)
	}
}
