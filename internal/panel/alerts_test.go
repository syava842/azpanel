package panel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

func alertEnv(t *testing.T) *collEnv {
	t.Helper()
	e := newCollEnv(t)
	cfg := config.Default().Telegram
	cfg.Enabled = true
	e.c.Alerts = &cfg
	e.node.DenialsFn = func(context.Context, time.Time) ([]nodeapi.Denial, error) { return nil, nil }
	return e
}

// outbox возвращает тексты неотправленных уведомлений по видам.
func (e *collEnv) outbox(t *testing.T) map[string][]string {
	t.Helper()
	items, err := e.st.Pending(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, it := range items {
		var n struct{ Text string }
		if err := json.Unmarshal([]byte(it.Payload), &n); err != nil {
			t.Fatalf("payload %q: %v", it.Payload, err)
		}
		out[it.Kind] = append(out[it.Kind], n.Text)
	}
	return out
}

func (e *collEnv) tickAny() { _ = e.c.Tick(context.Background()) }

func TestAlertNodeDownAfterThreeAndBack(t *testing.T) {
	e := alertEnv(t)
	var down bool
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) {
		if down {
			return nodeapi.System{}, errors.New("connection refused")
		}
		return nodeapi.System{}, nil
	}
	e.tick(t)
	down = true
	for i := 0; i < 2; i++ {
		e.advance(time.Minute)
		e.tickAny()
	}
	if got := e.outbox(t)[kindNodeDown]; len(got) != 0 {
		t.Fatalf("уведомление после двух проходов: %v", got)
	}
	e.advance(time.Minute)
	e.tickAny()
	e.advance(time.Minute)
	e.tickAny() // четвёртый проход: повтора нет
	if got := e.outbox(t)[kindNodeDown]; len(got) != 1 || !strings.Contains(got[0], "недоступен") {
		t.Fatalf("после трёх проходов: %v", got)
	}
	down = false
	e.advance(time.Minute)
	e.tick(t)
	got := e.outbox(t)[kindNodeDown]
	if len(got) != 2 || !strings.Contains(got[1], "снова доступен") {
		t.Fatalf("возврат узла: %v", got)
	}
}

const kindNodeDown = "node_down"

func TestAlertLoadHighOnceUntilBelow(t *testing.T) {
	e := alertEnv(t)
	cpu := 95.0
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) {
		return nodeapi.System{Resources: sysinfo.Snapshot{CPUPercent: cpu, UptimeSec: 1000}}, nil
	}
	for i := 0; i < 5; i++ { // 0..4 минуты: ещё не пять
		e.tick(t)
		e.advance(time.Minute)
	}
	if got := e.outbox(t)["load_high"]; len(got) != 0 {
		t.Fatalf("раньше пяти минут: %v", got)
	}
	e.tick(t) // ровно пять минут
	if got := e.outbox(t)["load_high"]; len(got) != 1 || !strings.Contains(got[0], "ЦП") {
		t.Fatalf("на пятой минуте: %v", got)
	}
	for i := 0; i < 10; i++ {
		e.advance(time.Minute)
		e.tick(t)
	}
	if got := e.outbox(t)["load_high"]; len(got) != 1 {
		t.Fatalf("повтор до возврата ниже порога: %v", got)
	}
	// ниже порога — снова можно
	cpu = 10
	e.advance(time.Minute)
	e.tick(t)
	cpu = 95
	for i := 0; i < 7; i++ {
		e.advance(time.Minute)
		e.tick(t)
	}
	if got := e.outbox(t)["load_high"]; len(got) != 2 {
		t.Fatalf("после возврата ниже порога: %v", got)
	}
}

func TestAlertRebootOnUptimeDrop(t *testing.T) {
	e := alertEnv(t)
	up := int64(5000)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) {
		return nodeapi.System{Resources: sysinfo.Snapshot{UptimeSec: up}}, nil
	}
	e.tick(t)
	up += 60
	e.advance(time.Minute)
	e.tick(t)
	if got := e.outbox(t)["reboot"]; len(got) != 0 {
		t.Fatalf("рост аптайма принят за перезагрузку: %v", got)
	}
	up = 30
	e.advance(time.Minute)
	e.tick(t)
	if got := e.outbox(t)["reboot"]; len(got) != 1 {
		t.Fatalf("перезагрузка: %v", got)
	}
}

func TestAlertDenialsHourlySummary(t *testing.T) {
	e := alertEnv(t)
	var asked []time.Time
	e.node.DenialsFn = func(_ context.Context, since time.Time) ([]nodeapi.Denial, error) {
		asked = append(asked, since)
		return []nodeapi.Denial{{Name: "alice", Reason: "limit"}, {Name: "alice", Reason: "limit"}, {Name: "bob", Reason: "blocked"}}, nil
	}
	e.tick(t)
	e.advance(59 * time.Minute)
	e.tick(t)
	if len(asked) != 0 {
		t.Fatalf("опрос раньше часа: %v", asked)
	}
	e.advance(2 * time.Minute)
	e.tick(t)
	got := e.outbox(t)["limit_denials"]
	if len(got) != 1 || !strings.Contains(got[0], "alice — 2") || !strings.Contains(got[0], "bob — 1") {
		t.Fatalf("сводка отказов: %v", got)
	}
	e.advance(time.Minute)
	e.tick(t)
	if len(e.outbox(t)["limit_denials"]) != 1 {
		t.Fatal("сводка повторилась в тот же час")
	}
}

func TestAlertCertExpiringOncePerDay(t *testing.T) {
	e := alertEnv(t)
	soon := e.now.Add(5 * 24 * time.Hour)
	far := e.now.Add(60 * 24 * time.Hour)
	gone := e.now.Add(-time.Hour)
	e.clients = []nodeapi.Client{
		{Name: "soon", OpenVPN: true, CertExpires: &soon},
		{Name: "far", OpenVPN: true, CertExpires: &far},
		{Name: "gone", OpenVPN: true, CertExpires: &gone},
	}
	e.tick(t)
	e.advance(2 * time.Hour)
	e.tick(t) // тот же день
	got := e.outbox(t)["cert_expiring"]
	if len(got) != 1 || !strings.Contains(got[0], "soon") {
		t.Fatalf("первый день: %v", got)
	}
	e.advance(24 * time.Hour)
	e.tick(t)
	if got := e.outbox(t)["cert_expiring"]; len(got) != 2 {
		t.Fatalf("на следующие сутки: %v", got)
	}
}

func TestAlertsRespectDisabledKindAndOff(t *testing.T) {
	e := alertEnv(t)
	e.c.Alerts.Notify = []string{"load_high"} // reboot выключен
	up := int64(5000)
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) {
		return nodeapi.System{Resources: sysinfo.Snapshot{UptimeSec: up}}, nil
	}
	e.tick(t)
	up = 10
	e.advance(time.Minute)
	e.tick(t)
	if len(e.outbox(t)) != 0 {
		t.Fatalf("выключенный вид положен: %v", e.outbox(t))
	}
	e.c.Alerts = nil
	up = 5000
	e.advance(time.Minute)
	e.tick(t)
	up = 1
	e.advance(time.Minute)
	e.tick(t)
	if len(e.outbox(t)) != 0 {
		t.Fatalf("без настроек что-то положено: %v", e.outbox(t))
	}
}
