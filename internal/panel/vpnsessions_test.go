package panel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

func TestVPNSessionsTable(t *testing.T) {
	e, c, _ := storeEnv(t)
	since := histNow.Add(-(26*time.Hour + 5*time.Minute))
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) {
		return []nodeapi.Session{
			{Kind: "openvpn", Instance: "vpn-udp", Name: "bob", Addr: "195.211.167.252:4000", VPNAddr: "10.28.0.4", TxBytes: 2 << 20, RxBytes: 1 << 20,
				Since: &since, Proto: "udp", Port: 50080, TxRate: 2048, RxRate: 1024, RateOK: true},
			{Kind: "openvpn", Instance: "antizapret-udp", Name: "azpanel-test-1", Addr: "9.9.9.9:1", VPNAddr: "10.29.0.2", Since: &since, Proto: "udp", Port: 50443},
		}, nil
	}
	body := get(e, c, "/openvpn?sort=name&order=desc").Body.String()
	for _, want := range []string{"10.28.0.4", "UDP :50080", "VPN", "AntiZapret", "1 д 2 ч 5 мин", "2.0 КБ/с", "Итого: 2", "data-toggle-ip", "data-autorefresh", `datetime="`} {
		if !strings.Contains(body, want) {
			t.Fatalf("нет %q:\n%s", want, body)
		}
	}
	if strings.Index(body, ">bob</a>") > strings.Index(body, ">azpanel-test-1</a>") {
		t.Fatal("сортировка по имени по убыванию не применилась")
	}
}

func TestVPNHistoryTab(t *testing.T) {
	e, c, _ := storeEnv(t)
	ctx := context.Background()
	st := e.srv.Store
	seen := store.ConnSeen{Kind: "openvpn", Instance: "vpn-udp", Name: "bob", Since: histNow.Add(-2 * time.Hour).Unix(), RealAddr: "1.2.3.4:5", VPNAddr: "10.28.0.9", Proto: "udp", Port: 50080}
	st.SyncConnLog(ctx, store.LocalNode, histNow.Add(-time.Hour).Unix(), []store.ConnSeen{seen})
	st.SyncConnLog(ctx, store.LocalNode, histNow.Add(-30*time.Minute).Unix(), nil)
	body := get(e, c, "/openvpn/history").Body.String()
	for _, want := range []string{"История", ">bob</a>", "10.28.0.9", "UDP :50080", "1 ч 0 мин", "Подключений: 1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("нет %q:\n%s", want, body)
		}
	}
	if b := get(e, c, "/openvpn/history?q=nobody").Body.String(); !strings.Contains(b, "Ничего не найдено") {
		t.Fatalf("фильтр: %s", b)
	}
}

func TestStatWindow(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	q := map[string][]string{"from": {"2026-11-01"}, "to": {"2026-11-10"}}
	f, to, key, _ := statWindow(q, now)
	if key != "custom" || !f.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) || !to.Equal(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("свой период: %v %v %s", f, to, key)
	}
	if _, _, key, _ := statWindow(map[string][]string{"period": {"year"}}, now); key != "year" {
		t.Fatal("год")
	}
	if _, _, key, _ := statWindow(map[string][]string{"from": {"2026-11-10"}, "to": {"2026-11-01"}}, now); key != "month" {
		t.Fatal("перевёрнутый диапазон должен дать умолчание")
	}
}
