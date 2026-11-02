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
	nodeUpAfter    = 3         // проходов с ответом подряд до «снова доступен» (гистерезис: мигающий узел не засыпает сообщениями)
	denialsEvery   = time.Hour // сводка отказов хука
	certWarnWithin = 7 * 24 * time.Hour
	certCheckEvery = time.Hour
	certWarnKey    = "cert_warn:" // + имя клиента: сутки последнего предупреждения
	denialsTop     = 10
	certListTop    = 10

	metaNodeDown = "alert_node_down" // «узел недоступен» уже отправлено ("1")
	metaLoadSent = "alert_load:"     // + cpu|mem|disk: уведомление о нагрузке уже отправлено ("1")
)

// alertState — состояние источников уведомлений сборщика (под tickMu).
type alertState struct {
	fails      int  // проходов подряд без ответа агента
	oks        int  // проходов подряд с ответом, пока узел считается недоступным
	down       bool // node_down отправлен, «снова доступен» ещё нет (хранится в meta)
	downLoaded bool
	loadLoaded bool // highSent прочитан из meta
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
	_, err := c.Store.Enqueue(ctx, kind, nil, bot.NoticeJSON(c.titled(text)), now.Unix())
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

// loadDown читает из meta, отправлено ли «узел недоступен»: после перезапуска
// панели то же сообщение повторно не уходит.
func (c *Collector) loadDown(ctx context.Context) error {
	st := &c.alert
	if st.downLoaded {
		return nil
	}
	v, found, err := c.Store.Meta(ctx, c.mk(metaNodeDown))
	if err != nil {
		return err
	}
	st.down, st.downLoaded = found && v == "1", true
	return nil
}

func (c *Collector) setDown(ctx context.Context, down bool) error {
	c.alert.down = down
	if down {
		return c.Store.SetMeta(ctx, c.mk(metaNodeDown), "1")
	}
	return c.Store.ClearMeta(ctx, c.mk(metaNodeDown))
}

// alertNode: агент не отвечает nodeDownAfter прохода подряд — node_down; «снова
// доступен» — только после nodeUpAfter проходов подряд с ответом.
func (c *Collector) alertNode(ctx context.Context, now time.Time) error {
	st := &c.alert
	if err := c.loadDown(ctx); err != nil {
		return err
	}
	if c.sysOK {
		st.fails = 0
		if !st.down {
			st.oks = 0
			return nil
		}
		if st.oks++; st.oks < nodeUpAfter {
			return nil
		}
		st.oks = 0
		if err := c.setDown(ctx, false); err != nil {
			return err
		}
		return c.notify(ctx, now, bot.KindNodeDown, "Узел снова доступен: агент отвечает.")
	}
	st.oks = 0
	st.fails++
	if st.fails >= nodeDownAfter && !st.down {
		if err := c.setDown(ctx, true); err != nil {
			return err
		}
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
	if !st.loadLoaded {
		// «уже отправлено» переживает перезапуск; время начала превышения — нет
		saved, err := c.Store.MetaPrefix(ctx, c.mkp(metaLoadSent))
		if err != nil {
			return err
		}
		for k, v := range saved {
			if v == "1" {
				st.highSent[strings.TrimPrefix(k, c.mkp(metaLoadSent))] = true
			}
		}
		st.loadLoaded = true
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
			if st.highSent[m.key] {
				delete(st.highSent, m.key)
				if err := c.Store.ClearMeta(ctx, c.mkp(metaLoadSent)+m.key); err != nil && firstErr == nil {
					firstErr = err
				}
			}
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
		if err := c.Store.SetMeta(ctx, c.mkp(metaLoadSent)+m.key, "1"); err != nil && firstErr == nil {
			firstErr = err
		}
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

// alertCerts: сертификат OpenVPN кончается через 7 дней — раз в сутки одной
// сводкой по всем клиентам, которым ещё не напоминали сегодня.
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
	warned, err := c.Store.MetaPrefix(ctx, c.mkp(certWarnKey))
	if err != nil {
		return err
	}
	type due struct {
		name string
		at   time.Time
	}
	var list []due
	soon := map[string]bool{}
	for _, cl := range clients {
		if cl.CertExpires == nil || !cl.CertExpires.After(now) || cl.CertExpires.After(now.Add(certWarnWithin)) {
			continue
		}
		soon[c.mkp(certWarnKey)+cl.Name] = true
		if warned[c.mkp(certWarnKey)+cl.Name] == today {
			continue
		}
		list = append(list, due{cl.Name, *cl.CertExpires})
	}
	// записи о клиентах, которым уже не грозит срок (продлены или удалены), не копятся
	for k := range warned {
		if !soon[k] {
			if err := c.Store.ClearMeta(ctx, k); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if len(list) == 0 {
		return firstErr
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].at.Equal(list[j].at) {
			return list[i].at.Before(list[j].at)
		}
		return list[i].name < list[j].name
	})
	var text string
	if len(list) == 1 {
		text = fmt.Sprintf("Сертификат клиента %s кончается %s UTC (через %s).", list[0].name,
			list[0].at.UTC().Format("2006-01-02"), humanDuration(list[0].at.Sub(now)))
	} else {
		parts := make([]string, 0, certListTop+1)
		for i, d := range list {
			if i >= certListTop {
				parts = append(parts, fmt.Sprintf("и ещё %d", len(list)-certListTop))
				break
			}
			parts = append(parts, fmt.Sprintf("%s — %s UTC", d.name, d.at.UTC().Format("2006-01-02")))
		}
		text = fmt.Sprintf("Сертификаты кончаются в ближайшие 7 дней (%d): %s.", len(list), strings.Join(parts, ", "))
	}
	if err := c.notify(ctx, now, bot.KindCertExpiring, text); err != nil {
		return err
	}
	for _, d := range list {
		if err := c.Store.SetMeta(ctx, c.mkp(certWarnKey)+d.name, today); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
