package node

import (
	"context"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/limits"
)

// Клиент подключается по OpenVPN, а сертификата в pki/issued нет (index.txt
// неполный): он в списке с пометкой NoCert. Заблокированный такой клиент
// отключён, но тоже в списке — иначе его негде разблокировать.
func TestAPIClientsWithoutCert(t *testing.T) {
	e := newAPI(t)
	now := time.Unix(2_000_000_000, 0)
	e.api.Tracker.ApplySnapshot("antizapret-udp", now, []antizapret.Session{
		{Instance: "antizapret-udp", CommonName: "alice", RealAddr: "5.6.7.8:1000", ConnectedSince: now},
		{Instance: "antizapret-udp", CommonName: "hudik", RealAddr: "1.1.1.1:1", ConnectedSince: now},
		{Instance: "antizapret-udp", CommonName: "bad name", RealAddr: "1.1.1.2:1", ConnectedSince: now},
	})
	limits.Save(e.api.LimitsPath, limits.Data{Limits: map[string]int{}, Blocked: map[string]bool{"ghost": true}})
	cs, err := e.client.Clients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range cs {
		got[c.Name] = map[bool]string{true: "ovpn", false: "-"}[c.OpenVPN] + map[bool]string{true: " nocert", false: ""}[c.NoCert] +
			map[bool]string{true: " blocked", false: ""}[c.Blocked]
	}
	want := map[string]string{"alice": "ovpn", "hudik": "ovpn nocert", "ghost": "ovpn nocert blocked"}
	if len(got) != len(want) {
		t.Fatalf("клиенты: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %q, ждали %q (все: %v)", k, got[k], v, got)
		}
	}
	for i := 1; i < len(cs); i++ {
		if cs[i-1].Name > cs[i].Name {
			t.Fatalf("не по алфавиту: %v", got)
		}
	}
}
