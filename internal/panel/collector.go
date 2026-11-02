package panel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	collectorUser  = "система" // пользователь в журнале автоблокировок
	flapWindow     = 5 * time.Minute
	flapMinAddrs   = 3 // разных адресов в окне — уже «частая смена»
	flapMinChanges = 3 // или столько смен подряд (больше двух)
	defaultEvery   = time.Minute
	stepTimeout    = 30 * time.Second
	reasonExpired  = "срок действия истёк"
	reasonTraffic  = "лимит трафика исчерпан"
	reasonGone     = "причина блокировки ушла"
)

// Collector раз в Every снимает с агента счётчики сессий и ресурсы, кладёт их
// в базу, сворачивает историю и ставит и снимает автоблокировки по сроку и
// трафику. Ручную блокировку (auto_block пуст) не трогает никогда.
type Collector struct {
	Node        Node
	Store       *store.Store
	NodeID      int64
	Every       time.Duration // panel.collect_seconds
	HistoryDays int
	Log         *slog.Logger
	Now         func() time.Time

	tickMu   sync.Mutex // один проход за раз
	prev     map[string]sessionCounters
	lastTick time.Time
	lastHour int64 // час (Unix/3600) последнего успешного Rollup
	online   int

	mu    sync.Mutex // защищает историю адресов и результат Flapping
	addrs map[string]*peerAddrs
	flap  map[string]bool
}

type sessionCounters struct{ rx, tx int64 }

type peerAddrs struct {
	last    string
	changes []time.Time // моменты смены адреса
	seen    []addrAt    // адреса, замеченные в окне
}

type addrAt struct {
	at   time.Time
	addr string
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Collector) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Run делает проход сразу, затем раз в Every, пока ctx не отменён.
func (c *Collector) Run(ctx context.Context) {
	every := c.Every
	if every <= 0 {
		every = defaultEvery
	}
	for {
		_ = c.Tick(ctx) // ошибки шагов уже в журнале
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// Flapping — имена WG-клиентов, чей адрес часто меняется.
func (c *Collector) Flapping() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]bool, len(c.flap))
	for k, v := range c.flap {
		out[k] = v
	}
	return out
}

// Tick — один проход. Ошибка одного шага пишется в журнал и не мешает
// остальным; возвращается объединение ошибок шагов.
func (c *Collector) Tick(ctx context.Context) error {
	c.tickMu.Lock()
	defer c.tickMu.Unlock()
	now := c.now().UTC()
	var errs []error
	step := func(name string, f func(context.Context) error) {
		sctx, cancel := context.WithTimeout(ctx, stepTimeout)
		defer cancel()
		if err := f(sctx); err != nil {
			c.log().Warn("сборщик: шаг не выполнен", "шаг", name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	step("сессии", func(ctx context.Context) error {
		s, err := c.Node.Sessions(ctx)
		if err != nil {
			return err
		}
		c.trackAddrs(now, s)
		return c.collectTraffic(ctx, now, s)
	})
	step("ресурсы", func(ctx context.Context) error { return c.collectResources(ctx, now) })
	step("свёртка", func(ctx context.Context) error { return c.rollup(ctx, now) })
	step("автоблокировка", func(ctx context.Context) error { return c.autoBlock(ctx, now) })
	return errors.Join(errs...)
}

func sessionKey(s nodeapi.Session) string {
	if s.Kind == nodeapi.KindWireGuard {
		return s.Kind + "|" + s.Instance + "|" + s.Name
	}
	since := int64(0)
	if s.Since != nil {
		since = s.Since.Unix()
	}
	return fmt.Sprintf("%s|%s|%s|%d", s.Kind, s.Instance, s.Name, since)
}

// collectTraffic считает дельты счётчиков сессий и пишет их в минуту now.
func (c *Collector) collectTraffic(ctx context.Context, now time.Time, sessions []nodeapi.Session) error {
	prev := c.prev
	first := prev == nil
	cur := make(map[string]sessionCounters, len(sessions))
	rows := map[string]store.Bytes{}
	for _, s := range sessions {
		key := sessionKey(s)
		cnt := sessionCounters{max(s.RxBytes, 0), max(s.TxBytes, 0)}
		cur[key] = cnt
		var d sessionCounters
		if old, ok := prev[key]; ok {
			d = sessionCounters{cnt.rx - old.rx, cnt.tx - old.tx}
			if cnt.rx < old.rx || cnt.tx < old.tx { // сброс счётчика
				d = cnt
			}
		} else if !first && s.Kind != nodeapi.KindWireGuard && s.Since != nil && s.Since.After(c.lastTick) {
			d = cnt // сессия началась после прошлого прохода — счётчики целиком наши
		}
		if d.rx == 0 && d.tx == 0 {
			continue
		}
		b := rows[s.Name]
		b.Rx += d.rx
		b.Tx += d.tx
		rows[s.Name] = b
	}
	c.online = len(sessions)
	if len(rows) > 0 {
		if err := c.Store.AddTraffic(ctx, c.NodeID, now.Truncate(time.Minute).Unix(), rows); err != nil {
			// прежние счётчики не обновляем: дельта попадёт в следующий проход
			return err
		}
	}
	c.prev, c.lastTick = cur, now
	return nil
}

func (c *Collector) collectResources(ctx context.Context, now time.Time) error {
	sys, err := c.Node.System(ctx)
	if err != nil {
		return err
	}
	r := sys.Resources
	used := int64(0)
	if r.Memory.TotalBytes > r.Memory.AvailableBytes {
		used = int64(r.Memory.TotalBytes - r.Memory.AvailableBytes)
	}
	return c.Store.AddResource(ctx, c.NodeID, store.ResourcePoint{
		TS:        now.Truncate(time.Minute).Unix(),
		CPU:       r.CPUPercent,
		Load1:     r.Load[0],
		MemUsed:   used,
		MemTotal:  int64(r.Memory.TotalBytes),
		DiskFree:  int64(r.Disk.FreeBytes),
		DiskTotal: int64(r.Disk.TotalBytes),
		NetRx:     int64(r.Net.RxBytes),
		NetTx:     int64(r.Net.TxBytes),
		Online:    c.online,
	})
}

// trackAddrs ведёт историю адресов WG-пиров. «Частая смена»: три и более
// разных адреса за 5 минут или больше двух смен.
func (c *Collector) trackAddrs(now time.Time, sessions []nodeapi.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.addrs == nil {
		c.addrs = map[string]*peerAddrs{}
	}
	cutoff := now.Add(-flapWindow)
	for _, s := range sessions {
		if s.Kind != nodeapi.KindWireGuard || s.Addr == "" {
			continue
		}
		p := c.addrs[s.Name]
		if p == nil {
			p = &peerAddrs{}
			c.addrs[s.Name] = p
		}
		if p.last != "" && p.last != s.Addr {
			p.changes = append(p.changes, now)
		}
		p.last = s.Addr
		p.seen = append(p.seen, addrAt{now, s.Addr})
	}
	flap := map[string]bool{}
	for name, p := range c.addrs {
		p.changes = dropOld(p.changes, func(t time.Time) time.Time { return t }, cutoff)
		p.seen = dropOld(p.seen, func(a addrAt) time.Time { return a.at }, cutoff)
		if len(p.seen) == 0 {
			delete(c.addrs, name)
			continue
		}
		distinct := map[string]bool{}
		for _, a := range p.seen {
			distinct[a.addr] = true
		}
		if len(distinct) >= flapMinAddrs || len(p.changes) >= flapMinChanges {
			flap[name] = true
		}
	}
	c.flap = flap
}

func dropOld[T any](xs []T, at func(T) time.Time, cutoff time.Time) []T {
	i := 0
	for i < len(xs) && !at(xs[i]).After(cutoff) {
		i++
	}
	return xs[i:]
}

func (c *Collector) rollup(ctx context.Context, now time.Time) error {
	hour := now.Unix() / 3600
	if hour == c.lastHour {
		return nil
	}
	if err := c.Store.Rollup(ctx, now.Unix(), c.HistoryDays); err != nil {
		return err
	}
	c.lastHour = hour
	return nil
}

// periodStart — начало текущего периода лимита трафика (UTC).
func periodStart(period string, now time.Time) time.Time {
	now = now.UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	switch period {
	case store.PeriodDay:
		return day
	case store.PeriodWeek:
		return day.AddDate(0, 0, -((int(now.Weekday()) + 6) % 7)) // понедельник
	default:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
}

func (c *Collector) autoBlock(ctx context.Context, now time.Time) error {
	clients, err := c.Node.Clients(ctx)
	if err != nil {
		return err
	}
	cards, err := c.Store.Cards(ctx, c.NodeID)
	if err != nil {
		return err
	}
	totals := map[string]map[string]store.Bytes{} // период -> имя -> трафик
	totalsFor := func(period string) (map[string]store.Bytes, error) {
		if t, ok := totals[period]; ok {
			return t, nil
		}
		t, err := c.Store.TrafficTotals(ctx, c.NodeID, periodStart(period, now).Unix(), now.Unix()+1)
		if err != nil {
			return nil, err
		}
		totals[period] = t
		return t, nil
	}
	var errs []error
	for _, cl := range clients {
		card, ok := cards[cl.Name]
		if !ok {
			continue
		}
		reason := ""
		if card.AccessUntil != nil && *card.AccessUntil <= now.Unix() {
			reason = store.AutoBlockExpired
		} else if card.TrafficLimit > 0 {
			t, err := totalsFor(card.TrafficPeriod)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if b := t[cl.Name]; b.Rx+b.Tx >= card.TrafficLimit {
				reason = store.AutoBlockTraffic
			}
		}
		if reason != "" && card.AutoSkip == blockFingerprint(reason, card, now) {
			reason = "" // админ уже снял блокировку по этой самой причине
		}
		if err := c.applyAutoBlock(ctx, now, cl, card, reason); err != nil {
			c.log().Warn("сборщик: автоблокировка клиента не удалась", "client", cl.Name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", cl.Name, err))
		}
	}
	return errors.Join(errs...)
}

// blockFingerprint — отпечаток причины блокировки: меняется вместе со сроком,
// лимитом или началом периода, поэтому ручная разблокировка действует только
// на ту причину, которую админ видел.
func blockFingerprint(reason string, card store.Card, now time.Time) string {
	if reason == store.AutoBlockExpired {
		until := int64(0)
		if card.AccessUntil != nil {
			until = *card.AccessUntil
		}
		return fmt.Sprintf("%s:%d", reason, until)
	}
	return fmt.Sprintf("%s:%d:%d", reason, periodStart(card.TrafficPeriod, now).Unix(), card.TrafficLimit)
}

func reasonText(reason string) string {
	if reason == store.AutoBlockExpired {
		return reasonExpired
	}
	return reasonTraffic
}

// applyAutoBlock решает судьбу одного клиента. reason — текущая причина
// блокировки или пусто.
func (c *Collector) applyAutoBlock(ctx context.Context, now time.Time, cl nodeapi.Client, card store.Card, reason string) error {
	was := card.AutoBlock
	switch {
	case was != "" && !cl.Blocked:
		// администратор снял блок вручную — панель только забывает о нём
		return c.Store.SetAutoBlock(ctx, c.NodeID, cl.Name, "", card.AutoSkip)
	case was == "" && !cl.Blocked && reason != "":
		if _, err := c.Node.SetBlocked(ctx, cl.Name, true); err != nil {
			return err
		}
		if err := c.Store.SetAutoBlock(ctx, c.NodeID, cl.Name, reason, card.AutoSkip); err != nil {
			return err
		}
		c.audit(ctx, now, "автоблокировка", cl.Name, "не заблокирован", "заблокирован: "+reasonText(reason))
	case was != "" && cl.Blocked && reason == "":
		if _, err := c.Node.SetBlocked(ctx, cl.Name, false); err != nil {
			return err
		}
		if err := c.Store.SetAutoBlock(ctx, c.NodeID, cl.Name, "", card.AutoSkip); err != nil {
			return err
		}
		c.audit(ctx, now, "авторазблокировка", cl.Name, "заблокирован: "+reasonText(was), "не заблокирован: "+reasonGone)
	case was != "" && cl.Blocked && reason != was:
		// причина сменилась, блок остаётся
		return c.Store.SetAutoBlock(ctx, c.NodeID, cl.Name, reason, card.AutoSkip)
	}
	return nil
}

func (c *Collector) audit(ctx context.Context, now time.Time, action, target, before, after string) {
	c.log().Info("сборщик: "+action, "client", target, "было", before, "стало", after)
	err := c.Store.Audit(ctx, store.AuditEntry{TS: now.Unix(), User: collectorUser, Action: action,
		Target: target, Before: before, After: after})
	if err != nil {
		c.log().Warn("сборщик: запись в журнал не удалась", "err", err)
	}
}
