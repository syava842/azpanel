package bot

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/telegram"
)

const (
	summaryDayKey    = "tg_summary_day" // сутки последней сводки (UTC, ГГГГ-ММ-ДД)
	backupLastKey    = "tg_backup_last" // Unix-время последнего удачного бэкапа по расписанию
	backupTryKey     = "tg_backup_try"  // Unix-время последней попытки
	summaryWindow    = 10 * time.Minute // сводка уходит, если бот проснулся не позже чем через столько после времени
	backupRetryAfter = time.Hour        // не чаще раза в час при сбоях
	summaryTop       = 10               // клиентов в топе трафика
	scheduleEvery    = 30 * time.Second // период проверки расписания
)

func (b *Bot) scheduleLoop(ctx context.Context) {
	t := time.NewTicker(scheduleEvery)
	defer t.Stop()
	for {
		b.scheduleTick(ctx, b.now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// scheduleTick выполняет то, что подошло по расписанию: сводку и бэкап.
func (b *Bot) scheduleTick(ctx context.Context, now time.Time) {
	b.maybeSummary(ctx, now)
	b.maybeBackup(ctx, now)
}

// parseClock разбирает «ЧЧ:ММ».
func parseClock(v string) (h, m int, ok bool) {
	hs, ms, found := strings.Cut(v, ":")
	if !found {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(hs)
	m, err2 := strconv.Atoi(ms)
	return h, m, err1 == nil && err2 == nil && h >= 0 && h < 24 && m >= 0 && m < 60
}

func (b *Bot) maybeSummary(ctx context.Context, now time.Time) {
	h, m, ok := parseClock(b.Cfg.SummaryAt)
	if !ok {
		return
	}
	utc := now.UTC()
	at := time.Date(utc.Year(), utc.Month(), utc.Day(), h, m, 0, 0, time.UTC)
	if utc.Before(at) || !utc.Before(at.Add(summaryWindow)) {
		return
	}
	today := utc.Format("2006-01-02")
	if v, found, err := b.Store.Meta(ctx, summaryDayKey); err != nil {
		b.log().Warn("бот: сутки сводки не прочитаны", "err", err)
		return
	} else if found && v == today {
		return
	}
	// Сутки отмечаются до отправки: сбой отправки не должен слать сводку каждые полминуты.
	if err := b.Store.SetMeta(ctx, summaryDayKey, today); err != nil {
		b.log().Warn("бот: сутки сводки не записаны", "err", err)
		return
	}
	text := b.summaryText(ctx, utc)
	for _, chat := range b.recipients(ctx, "summary", nil) {
		if _, err := b.TG.SendMessage(ctx, telegram.SendMessageParams{ChatID: chat, Text: clip(text)}); err != nil {
			b.log().Warn("бот: сводка не отправлена", "chat", chat, "err", err)
		}
	}
}

// summaryText — онлайн сейчас, трафик за сутки (топ-10), узел.
func (b *Bot) summaryText(ctx context.Context, now time.Time) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Сводка на %s UTC\n", now.Format("2006-01-02 15:04"))
	if ss, err := b.Node.Sessions(ctx); err == nil {
		names := map[string]bool{}
		for _, s := range ss {
			names[s.Name] = true
		}
		fmt.Fprintf(&sb, "Онлайн сейчас: клиентов %d, сессий %d\n", len(names), len(ss))
	} else {
		fmt.Fprintf(&sb, "Онлайн: агент недоступен (%s)\n", agentErr(err))
	}
	if tr, err := b.Store.TrafficTotals(ctx, b.NodeID, now.Add(-24*time.Hour).Unix(), now.Unix()+1); err == nil {
		type row struct {
			name  string
			total int64
		}
		var rows []row
		var all int64
		for _, n := range sortedKeys(tr) {
			t := max(tr[n].Rx+tr[n].Tx, 0)
			all += t
			rows = append(rows, row{n, t})
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].total > rows[j].total })
		fmt.Fprintf(&sb, "Трафик за сутки: %s\n", humanBytes(uint64(all)))
		for i, r := range rows {
			if i >= summaryTop || r.total == 0 {
				break
			}
			fmt.Fprintf(&sb, "  %d. %s: %s\n", i+1, r.name, humanBytes(uint64(r.total)))
		}
	}
	if sys, err := b.Node.System(ctx); err == nil {
		r := sys.Resources
		mem, disk := 0.0, 0.0
		if r.Memory.TotalBytes > 0 {
			mem = float64(r.Memory.TotalBytes-min(r.Memory.AvailableBytes, r.Memory.TotalBytes)) / float64(r.Memory.TotalBytes) * 100
		}
		if r.Disk.TotalBytes > 0 {
			disk = float64(r.Disk.TotalBytes-min(r.Disk.FreeBytes, r.Disk.TotalBytes)) / float64(r.Disk.TotalBytes) * 100
		}
		fmt.Fprintf(&sb, "Узел: ЦП %.0f%%, память %.0f%%, диск %.0f%%, аптайм %s\n", r.CPUPercent, mem, disk,
			humanDuration(time.Duration(r.UptimeSec)*time.Second))
		var bad []string
		for _, s := range sys.Services {
			if s.State != "active" {
				bad = append(bad, s.Unit+": "+s.State)
			}
		}
		if len(bad) > 0 {
			fmt.Fprintf(&sb, "Службы не в порядке: %s\n", strings.Join(bad, ", "))
		}
	}
	return sb.String()
}

// maybeBackup делает бэкап раз в backup_every_days и отправляет его в backup_chats.
func (b *Bot) maybeBackup(ctx context.Context, now time.Time) {
	if b.Cfg.BackupEveryDays <= 0 || len(b.Cfg.BackupChats) == 0 {
		return
	}
	last, hasLast := b.metaUnix(ctx, backupLastKey)
	if hasLast && now.Unix()-last < int64(b.Cfg.BackupEveryDays)*86400 {
		return
	}
	if try, has := b.metaUnix(ctx, backupTryKey); has && now.Unix()-try < int64(backupRetryAfter/time.Second) {
		return
	}
	if !b.backupMu.TryLock() {
		return // бэкап из бота уже идёт
	}
	defer b.backupMu.Unlock()
	if err := b.Store.SetMeta(ctx, backupTryKey, strconv.FormatInt(now.Unix(), 10)); err != nil {
		b.log().Warn("бот: попытка бэкапа не записана", "err", err)
		return
	}
	bf, err := b.makeBackup(ctx)
	if err != nil {
		b.log().Warn("бот: бэкап по расписанию не создан", "err", err)
		for _, chat := range b.Cfg.BackupChats {
			b.send(ctx, chat, "Бэкап по расписанию не создан: "+err.Error(), nil)
		}
		return
	}
	defer bf.cleanup()
	for _, chat := range b.Cfg.BackupChats {
		b.sendBackup(ctx, chat, bf)
	}
	if err := b.Store.SetMeta(ctx, backupLastKey, strconv.FormatInt(now.Unix(), 10)); err != nil {
		b.log().Warn("бот: время бэкапа не записано", "err", err)
	}
}

func (b *Bot) metaUnix(ctx context.Context, key string) (int64, bool) {
	v, found, err := b.Store.Meta(ctx, key)
	if err != nil || !found {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil
}
