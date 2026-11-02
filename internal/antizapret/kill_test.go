package antizapret

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeKillMgmt отвечает на одну команду так, как управляющий интерфейс OpenVPN.
func fakeKillMgmt(t *testing.T, reply string) (sock string, got chan string) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "x.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n"))
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- strings.TrimSpace(line)
		c.Write([]byte(reply))
	}()
	return sock, got
}

func TestKillClientSuccess(t *testing.T) {
	sock, got := fakeKillMgmt(t, "SUCCESS: common name 'alice' found, 2 client(s) killed\r\n")
	n, err := KillClient(sock, "alice", time.Second)
	if err != nil || n != 2 {
		t.Fatalf("n = %d, err = %v", n, err)
	}
	if cmd := <-got; cmd != "kill alice" {
		t.Fatalf("команда %q", cmd)
	}
}

func TestKillClientNotFoundIsZero(t *testing.T) {
	sock, _ := fakeKillMgmt(t, "ERROR: common name 'alice' not found\r\n")
	n, err := KillClient(sock, "alice", time.Second)
	if err != nil || n != 0 {
		t.Fatalf("n = %d, err = %v", n, err)
	}
}

func TestKillClientOtherError(t *testing.T) {
	sock, _ := fakeKillMgmt(t, "ERROR: unknown command\r\n")
	if _, err := KillClient(sock, "alice", time.Second); err == nil {
		t.Fatal("ошибка интерфейса не передана")
	}
}

func TestKillClientRejectsBadName(t *testing.T) {
	if _, err := KillClient(filepath.Join(t.TempDir(), "нет.sock"), "a\nsignal SIGTERM", time.Second); err == nil || !strings.Contains(err.Error(), "имя") {
		t.Fatalf("err = %v", err)
	}
}
