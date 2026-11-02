package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/telegram"
)

// Виды уведомлений (совпадают с config.TelegramNotifyKinds).
const (
	KindNodeDown         = "node_down"
	KindLoadHigh         = "load_high"
	KindReboot           = "reboot"
	KindSyncMismatch     = "sync_mismatch"
	KindHookError        = "hook_error"
	KindLimitDenials     = "limit_denials"
	KindAntizapretUpdate = "antizapret_update"
	KindUpdateResult     = "update_result"
	KindCertExpiring     = "cert_expiring"
	KindAccessExpiring   = "access_expiring"
	KindAzpanelUpdate    = "azpanel_update"
)

const (
	maxDeliveryFails = 10 // проходов с ошибкой, после которых запись помечается отправленной
	deliverBatch     = 100
	staleAfter       = 48 * time.Hour // записи старше при первом запуске бота не пересказываются
	outboxStartedKey = "tg_outbox_started"
)

// Notice — содержимое уведомления в outbox: готовый текст. Так кладёт сборщик
// и так же должны класть этапы 4, 5 и 2в; запись с другим содержимым
// доставляется как есть.
type Notice struct {
	Text string `json:"text"`
}

// NoticeJSON — payload outbox для готового текста.
func NoticeJSON(text string) string {
	b, _ := json.Marshal(Notice{Text: text})
	return string(b)
}

// accessPayload — содержимое access_expiring (его кладёт сборщик напоминаний).
type accessPayload struct {
	Until   int64    `json:"until"`
	Days    int      `json:"days"`
	Clients []string `json:"clients"`
}

func (b *Bot) enabled(kind string) bool { return slices.Contains(b.Cfg.Notify, kind) }

func (b *Bot) notifyEvery() time.Duration {
	if b.NotifyEvery > 0 {
		return b.NotifyEvery
	}
	return 30 * time.Second
}

func (b *Bot) notifyLoop(ctx context.Context) {
	t := time.NewTicker(b.notifyEvery())
	defer t.Stop()
	for {
		b.DeliverOutbox(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// itemText собирает текст уведомления из записи outbox.
func itemText(it store.OutboxItem) string {
	if it.Kind == KindAccessExpiring {
		var p accessPayload
		if json.Unmarshal([]byte(it.Payload), &p) == nil && len(p.Clients) > 0 {
			when := "сегодня"
			if p.Days > 0 {
				when = fmt.Sprintf("через %d дн.", p.Days)
			}
			until := time.Unix(p.Until, 0).UTC().Format("2006-01-02")
			return fmt.Sprintf("Доступ истекает %s (%s UTC): %s.", when, until, strings.Join(p.Clients, ", "))
		}
	}
	var n Notice
	if json.Unmarshal([]byte(it.Payload), &n) == nil && n.Text != "" {
		return n.Text
	}
	return it.Payload
}

// recipients — чаты получателей записи: access_expiring идёт владельцу, если
// он привязан; остальное — привязанным администраторам и чатам из настроек.
func (b *Bot) recipients(ctx context.Context, kind string, userID *int64) ([]int64, error) {
	if kind == KindAccessExpiring {
		if userID == nil {
			return nil, nil
		}
		u, err := b.Store.UserByID(ctx, *userID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if u.Disabled || u.TelegramID == nil {
			return nil, nil
		}
		return []int64{*u.TelegramID}, nil
	}
	admins, err := b.adminsErr(ctx)
	if err != nil {
		return nil, err
	}
	var out []int64
	for _, a := range admins {
		out = append(out, *a.TelegramID)
	}
	for _, c := range b.Cfg.NotifyChats {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// permanent: повтор не поможет (бот заблокирован, чата нет).
func permanent(err error) bool {
	var api *telegram.APIError
	if !errors.As(err, &api) {
		return false
	}
	return api.Code == http.StatusForbidden || (api.Code == http.StatusBadRequest && strings.Contains(strings.ToLower(api.Description), "chat not found"))
}

// DeliverOutbox доставляет неотправленные уведомления. Выключенный вид
// помечается отправленным без отправки; ошибка оставляет запись до
// следующего прохода, после maxDeliveryFails проходов — запись в журнал и отметка.
func (b *Bot) DeliverOutbox(ctx context.Context) {
	b.skipStale(ctx)
	items, err := b.Store.Pending(ctx, deliverBatch)
	if err != nil {
		b.log().Warn("бот: очередь уведомлений не прочитана", "err", err)
		return
	}
	for _, it := range items {
		if ctx.Err() != nil {
			return
		}
		b.deliver(ctx, it)
	}
}

// skipStale при первом включении бота помечает отправленными записи старше
// двух суток: очередь копится с развёртывания, и недельное «истекает
// сегодня» пересказывать незачем. Отметка в meta — раз и навсегда.
func (b *Bot) skipStale(ctx context.Context) {
	b.mu.Lock()
	done := b.outboxOK
	b.mu.Unlock()
	if done {
		return
	}
	if _, found, err := b.Store.Meta(ctx, outboxStartedKey); err != nil {
		b.log().Warn("бот: отметка первого запуска не прочитана", "err", err)
		return
	} else if !found {
		now := b.now()
		n, err := b.Store.MarkSentBefore(ctx, now.Add(-staleAfter).Unix(), now.Unix())
		if err != nil {
			b.log().Warn("бот: устаревшие уведомления не отмечены", "err", err)
			return
		}
		if n > 0 {
			b.log().Info("бот: устаревшие уведомления пропущены при первом запуске", "записей", n)
		}
		if err := b.Store.SetMeta(ctx, outboxStartedKey, strconv.FormatInt(now.Unix(), 10)); err != nil {
			b.log().Warn("бот: отметка первого запуска не записана", "err", err)
			return
		}
	}
	b.mu.Lock()
	b.outboxOK = true
	b.mu.Unlock()
}

func (b *Bot) deliver(ctx context.Context, it store.OutboxItem) {
	mark := func() {
		if err := b.Store.MarkSent(ctx, it.ID, b.now().Unix()); err != nil && !errors.Is(err, store.ErrNotFound) {
			b.log().Warn("бот: уведомление не помечено отправленным", "id", it.ID, "err", err)
		}
		b.mu.Lock()
		delete(b.sentTo, it.ID)
		b.mu.Unlock()
	}
	if !b.enabled(it.Kind) {
		mark()
		return
	}
	chats, err := b.recipients(ctx, it.Kind, it.UserID)
	if err != nil {
		// Список получателей не прочитан — запись не помечается, проход повторится.
		b.log().Warn("бот: получатели уведомления не прочитаны", "id", it.ID, "err", err)
		return
	}
	text := itemText(it)
	failed := false
	for _, chat := range chats {
		b.mu.Lock()
		done := b.sentTo[it.ID][chat]
		b.mu.Unlock()
		if done {
			continue
		}
		_, err := b.TG.SendMessage(ctx, telegram.SendMessageParams{ChatID: chat, Text: clip(text)})
		if err != nil && !permanent(err) {
			b.log().Warn("бот: уведомление не доставлено", "id", it.ID, "kind", it.Kind, "chat", chat, "err", err)
			failed = true
			continue
		}
		b.mu.Lock()
		if b.sentTo == nil {
			b.sentTo = map[int64]map[int64]bool{}
		}
		if b.sentTo[it.ID] == nil {
			b.sentTo[it.ID] = map[int64]bool{}
		}
		b.sentTo[it.ID][chat] = true
		b.mu.Unlock()
	}
	if !failed {
		mark()
		return
	}
	n, err := b.Store.FailOutbox(ctx, it.ID)
	if err != nil {
		b.log().Warn("бот: неудачный проход не записан", "id", it.ID, "err", err)
		return
	}
	if n >= maxDeliveryFails {
		b.log().Error("бот: уведомление не доставлено за 10 проходов, отброшено", "id", it.ID, "kind", it.Kind)
		mark()
	}
}

// sortedKeys — для устойчивого порядка в тексте.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
