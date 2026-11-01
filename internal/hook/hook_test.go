package hook

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/agentproto"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// aliceEnv — окружение client-connect, как его видит скрипт на 94.
var aliceEnv = env(map[string]string{
	"common_name": "alice", "config": "antizapret-udp.conf",
	"trusted_ip": "203.0.113.5", "trusted_port": "40001",
})

func TestConnectSendsSessionAndAllows(t *testing.T) {
	var got agentproto.Request
	call := func(r agentproto.Request) (agentproto.Response, error) {
		got = r
		return agentproto.Response{Allow: true}, nil
	}
	if code := Run("connect", aliceEnv, call, &bytes.Buffer{}); code != 0 {
		t.Fatalf("код %d", code)
	}
	want := agentproto.Request{Op: agentproto.OpConnect, Instance: "antizapret-udp", CN: "alice", Addr: "203.0.113.5:40001"}
	if got != want {
		t.Fatalf("запрос %+v, ждали %+v", got, want)
	}
}

func TestConnectDenied(t *testing.T) {
	var stderr bytes.Buffer
	call := func(agentproto.Request) (agentproto.Response, error) {
		return agentproto.Response{Allow: false, Count: 3, Limit: 3}, nil
	}
	if code := Run("connect", aliceEnv, call, &stderr); code != ExitDeny {
		t.Fatalf("код %d", code)
	}
	if !strings.Contains(stderr.String(), "3 из 3") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestAgentDownFailsOpen(t *testing.T) {
	var stderr bytes.Buffer
	call := func(agentproto.Request) (agentproto.Response, error) {
		return agentproto.Response{}, errors.New("connect: no such file or directory")
	}
	if code := Run("connect", aliceEnv, call, &stderr); code != 0 {
		t.Fatalf("код %d", code)
	}
	if !strings.Contains(stderr.String(), "агент недоступен") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestDenyWithErrorIsNotDeny(t *testing.T) {
	call := func(agentproto.Request) (agentproto.Response, error) {
		return agentproto.Response{Allow: false, Error: "сбой"}, nil
	}
	if code := Run("connect", aliceEnv, call, &bytes.Buffer{}); code != 0 {
		t.Fatalf("код %d", code)
	}
}

func TestDisconnectNeverDenies(t *testing.T) {
	call := func(r agentproto.Request) (agentproto.Response, error) {
		if r.Op != agentproto.OpDisconnect {
			t.Fatalf("op %q", r.Op)
		}
		return agentproto.Response{Allow: false}, nil
	}
	if code := Run("disconnect", aliceEnv, call, &bytes.Buffer{}); code != 0 {
		t.Fatalf("код %d", code)
	}
}

func TestEmptyCommonNameSkipsAgent(t *testing.T) {
	call := func(agentproto.Request) (agentproto.Response, error) {
		t.Fatal("агент не должен вызываться")
		return agentproto.Response{}, nil
	}
	if code := Run("connect", env(nil), call, &bytes.Buffer{}); code != 0 {
		t.Fatalf("код %d", code)
	}
}
