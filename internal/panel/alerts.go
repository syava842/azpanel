package panel

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/panel/bot"
)

const (
	nodeDownAfter  = 3         // проходов без ответа агента до node_down
	denialsEvery   = time.Hour // сводка отказов хука
	certWarnWithin = 7 * 24 * time.Hour
	certCheckEvery = time.Hour
	certWarnKey    = "cert_warn:" // + имя клиента: сутки последнего предупреждения
	denialsTop     = 10
)

// alertState — состояние источников уведомлений сборщика (под tickMu).
type alertState struct {
	fails      int  // проходов подряд без ответа агента
	down       bool // node_down отправлен, «снова доступен» ещё нет
	lastUptime int64

	highSince map[string]time.Time // с какого момента метрика выше порога
	highSent  map[string]bool      // уведомление уже ушло, метрика ещё выше порога

	denialsAt     time.Time // последняя сводка отказов
	certCheckedAt time.Time
}

func (c *Collector) alertOn(kind string) bool {
	return c.Alerts != nil && c.Alerts.Enabled && slices.Contains(c.Alerts.Notify, kind)
}

// notify кладёт уведомление в outbox; выключенный вид не кладётся вовсе.
func (c *Collector) notify(ctx context.Context, now time.Time, kind, text string) error {
	if !c.alertOn(kind) {
		return nil
	}
	_, err := c.Store.Enqueue(ctx, kind, nil, bot.NoticeJSON(text), now.Unix())
	return err
}

// alerts — источники уведомлений администраторам: недоступность и возврат
// узла, высокая нагрузка, перезагрузка, отказы хука, сертификаты.
func (c *Collector) alerts(ctx context.Context, now time.Time) error {
	if c.Alerts == nil || !c.Alerts.Enabled {
		return nil
	}
	if err := c.alertNode(ctx, now); err != nil {
		return err
	}
	if !c.sysOK {
		return nil
	}
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	keep(c.alertLoad(ctx, now))
	keep(c.alertReboot(ctx, now))
	keep(c.alertDenials(ctx, now))
	keep(c.alertCerts(ctx, now))
	return firstErr
}

// alertNode: агент не отвечает nodeDownAfter прохода подряд — node_down, ответил снова — «снова доступен».
func (c *Collector) alertNode(ctx context.Context, now time.Time) error {
	st := &c.alert
	if c.sysOK {
		st.fails = 0
		if st.down {
			st.down = false
			return c.notify(ctx, now, bot.KindNodeDown, "Узел снова доступен: агент отвечает.")
		}
		return nil
	}
	st.fails++
	if st.fails >= nodeDownAfter && !st.down {
		st.down = true
		return c.notify(ctx, now, bot.KindNodeDown, fmt.Sprintf("Узел недоступен: агент не отвечает %d прохода подряд.", nodeDownAfter))
	}
	return nil
}

// alertLoad: ЦП, память или диск не ниже порога дольше LoadMinutes — одно
// уведомление, следующее только после возврата ниже порога.
func (c *Collector) alertLoad(ctx context.Context, now time.Time) error {
	st := &c.alert
	if st.highSince == nil {
		st.highSince, st.highSent = map[string]time.Time{}, map[string]bool{}
	}
	r := c.sys.Resources
	mem, disk := 0.0, 0.0
	if r.Memory.TotalBytes > 0 {
		mem = float64(r.Memory.TotalBytes-min(r.Memory.AvailableBytes, r.Memory.TotalBytes)) / float64(r.Memory.TotalBytes) * 100
	}
	if r.Disk.TotalBytes > 0 {
		disk = float64(r.Disk.TotalBytes-min(r.Disk.FreeBytes, r.Disk.TotalBytes)) / float64(r.Disk.TotalBytes) * 100
	}
	metrics := []struct {
		key, title string
		val        float64
		limit      int
	}{
		{"cpu", "ЦП", r.CPUPercent, c.Alerts.CPUPercent},
		{"mem", "Память", mem, c.Alerts.MemPercent},
		{"disk", "Диск", disk, c.Alerts.DiskPercent},
	}
	hold := time.Duration(c.Alerts.LoadMinutes) * time.Minute
	var firstErr error
	for _, m := range metrics {
		if m.limit <= 0 || m.val < float64(m.limit) {
			delete(st.highSince, m.key)
			delete(st.highSent, m.key)
			continue
		}
		since, ok := st.highSince[m.key]
		if !ok {
			since = now
			st.highSince[m.key] = now
		}
		if st.highSent[m.key] || now.Sub(since) < hold {
			continue
		}
		st.highSent[m.key] = true
		text := fmt.Sprintf("%s: %.0f%% (порог %d%%) уже %d мин.", m.title, m.val, m.limit, int(now.Sub(since)/time.Minute))
		if err := c.notify(ctx, now, bot.KindLoadHigh, text); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// alertReboot: аптайм стал меньше прежнего — сервер перезагружался.
func (c *Collector) alertReboot(ctx context.Context, now time.Time) error {
	up := c.sys.Resources.UptimeSec
	prev := c.alert.lastUptime
	c.alert.lastUptime = up
	if prev > 0 && up < prev {
		return c.notify(ctx, now, bot.KindReboot, fmt.Sprintf("Сервер перезагружался: аптайм сейчас %s.", humanDuration(time.Duration(up)*time.Second)))
	}
	return nil
}

// alertDenials: раз в час — сводка отказов хука «имя — число».
func (c *Collector) alertDenials(ctx context.Context, now time.Time) error {
	st := &c.alert
	if st.denialsAt.IsZero() {
		st.denialsAt = now // история до запуска не пересказывается
		return nil
	}
	if now.Sub(st.denialsAt) < denialsEvery {
		return nil
	}
	list, err := c.Node.Denials(ctx, st.denialsAt)
	if err != nil {
		return err // окно не сдвигается: следующий проход повторит
	}
	st.denialsAt = now
	if len(list) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, d := range list {
		counts[d.Name]++
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	var parts []string
	for i, n := range names {
		if i >= denialsTop {
			parts = append(parts, fmt.Sprintf("и ещё %d", len(names)-denialsTop))
			break
		}
		parts = append(parts, fmt.Sprintf("%s — %d", n, counts[n]))
	}
	return c.notify(ctx, now, bot.KindLimitDenials, fmt.Sprintf("Отказы в подключении за час (%d): %s.", len(list), strings.Join(parts, ", ")))
}

// alertCerts: сертификат OpenVPN кончается через 7 дней — раз в сутки на клиента.
func (c *Collector) alertCerts(ctx context.Context, now time.Time) error {
	st := &c.alert
	if !c.alertOn(bot.KindCertExpiring) || now.Sub(st.certCheckedAt) < certCheckEvery {
		return nil
	}
	clients, err := c.Node.Clients(ctx)
	if err != nil {
		return err
	}
	st.certCheckedAt = now
	today := now.UTC().Format("2006-01-02")
	var firstErr error
	for _, cl := range clients {
		if cl.CertExpires == nil || !cl.CertExpires.After(now) || cl.CertExpires.After(now.Add(certWarnWithin)) {
			continue
		}
		key := certWarnKey + cl.Name
		if v, found, err := c.Store.Meta(ctx, key); err != nil {
			firstErr = err
			continue
		} else if found && v == today {
			continue
		}
		text := fmt.Sprintf("Сертификат клиента %s кончается %s UTC (через %s).", cl.Name,
			cl.CertExpires.UTC().Format("2006-01-02"), humanDuration(cl.CertExpires.Sub(now)))
		if err := c.notify(ctx, now, bot.KindCertExpiring, text); err != nil {
			firstErr = err
			continue
		}
		if err := c.Store.SetMeta(ctx, key, today); err != nil {
			firstErr = err
		}
	}
	return firstErr
}
