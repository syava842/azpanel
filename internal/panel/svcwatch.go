package panel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/panel/bot"
	"github.com/syava842/azpanel/internal/store"
)

const (
	watchEvery     = 5 * time.Minute  // как часто смотрим состояние обновлений
	azVersionEvery = 24 * time.Hour   // новые коммиты AntiZapret — раз в сутки
	resultFresh    = 48 * time.Hour   // итог старше не пересказывается (как у бота)
	azNewTop       = 5                // коммитов в тексте уведомления
	metaAZChecked  = "az_ver_checked" // когда последний раз спрашивали версию
	metaAZSeen     = "az_ver_seen"    // последний коммит, о котором сообщили
	metaAZResult   = "az_result_sent" // итог обновления, о котором сообщили
	metaSelfResult = "self_result_sent"
)

// enqueueNotice кладёт готовый текст в outbox, если бот включён и вид
// уведомления разрешён. Выключенный вид не кладётся вовсе (как у сборщика).
func enqueueNotice(ctx context.Context, st *store.Store, tg *config.Telegram, now time.Time, kind, text string) error {
	if st == nil || tg == nil || !tg.Enabled || !slices.Contains(tg.Notify, kind) {
		return nil
	}
	_, err := st.Enqueue(ctx, kind, nil, bot.NoticeJSON(text), now.Unix())
	return err
}

// Watcher следит за обновлениями и кладёт уведомления в outbox: новые коммиты
// AntiZapret (раз в сутки), итог обновления AntiZapret и итог самообновления
// azpanel. Состояние «уже сообщили» лежит в meta и переживает перезапуск.
type Watcher struct {
	Node  ServiceNode
	Store *store.Store
	// Alerts — настройки бота; nil — уведомления выключены.
	Alerts *config.Telegram
	Every  time.Duration
	Now    func() time.Time
	Log    *slog.Logger
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Run проверяет сразу и затем каждые Every, пока ctx не отменён.
func (w *Watcher) Run(ctx context.Context) {
	every := w.Every
	if every <= 0 {
		every = watchEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick — один проход. Недоступный агент (перезагрузка) проход не ломает: в
// следующий раз итог всё равно будет.
func (w *Watcher) Tick(ctx context.Context) {
	if w.Node == nil || w.Store == nil || w.Alerts == nil || !w.Alerts.Enabled {
		return
	}
	for _, step := range []func(context.Context) error{w.azResult, w.azVersion, w.selfResult} {
		if err := step(ctx); err != nil && ctx.Err() == nil && w.Log != nil {
			w.Log.Warn("проверка обновлений для уведомлений не удалась", "err", err)
		}
	}
}

// azResult: итог обновления или восстановления AntiZapret — одно уведомление
// на запуск.
func (w *Watcher) azResult(ctx context.Context) error {
	st, err := w.Node.AZUpdateState(ctx)
	if err != nil || st.Finished == nil || (st.Status != nodeapi.AZStatusOK && st.Status != nodeapi.AZStatusFailed) {
		return nil
	}
	now := w.now()
	if now.Sub(*st.Finished) > resultFresh {
		return nil
	}
	key := fmt.Sprintf("%d:%s", st.Started.Unix(), st.Status)
	if v, found, err := w.Store.Meta(ctx, metaAZResult); err != nil {
		return err
	} else if found && v == key {
		return nil
	}
	what := "Обновление AntiZapret"
	if st.Action == nodeapi.AZActionRestore {
		what = "Восстановление AntiZapret из бэкапа"
	}
	var text string
	if st.Status == nodeapi.AZStatusOK {
		text = what + " завершено успешно."
		if st.Commit != "" {
			text += " Коммит " + shortSHA(st.Commit) + "."
		}
		if len(st.Warnings) > 0 {
			text += " Замечания: " + strings.Join(st.Warnings, "; ") + "."
		}
	} else {
		text = what + " не удалось: " + strings.Join(st.Reasons, "; ") + "."
		if st.CanRestore {
			text += " В панели можно восстановить из бэкапа."
		}
	}
	if err := enqueueNotice(ctx, w.Store, w.Alerts, now, bot.KindUpdateResult, text); err != nil {
		return err
	}
	return w.Store.SetMeta(ctx, metaAZResult, key)
}

// azVersion: раз в сутки спрашивает версию; новый последний коммит при
// известной установленной версии — уведомление antizapret_update, один раз на
// коммит. Неизвестная версия не повод для уведомления.
func (w *Watcher) azVersion(ctx context.Context) error {
	now := w.now()
	if v, found, err := w.Store.Meta(ctx, metaAZChecked); err != nil {
		return err
	} else if found {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil && now.Sub(time.Unix(ts, 0)) < azVersionEvery {
			return nil
		}
	}
	ver, err := w.Node.AZVersion(ctx)
	if err != nil || ver.Error != "" {
		return nil // GitHub или агент недоступны: попробуем в следующий проход
	}
	if err := w.Store.SetMeta(ctx, metaAZChecked, strconv.FormatInt(now.Unix(), 10)); err != nil {
		return err
	}
	if ver.Current == "" || ver.UpToDate || ver.Latest == nil || len(ver.Behind) == 0 {
		return nil
	}
	if seen, found, err := w.Store.Meta(ctx, metaAZSeen); err != nil {
		return err
	} else if found && seen == ver.Latest.SHA {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "В AntiZapret-VPN новых коммитов: %d (установлен %s).", len(ver.Behind), shortSHA(ver.Current))
	for i, c := range ver.Behind {
		if i == azNewTop {
			fmt.Fprintf(&b, "\n… и ещё %d", len(ver.Behind)-azNewTop)
			break
		}
		fmt.Fprintf(&b, "\n%s %s", shortSHA(c.SHA), c.Message)
	}
	b.WriteString("\nОбновление — в панели, раздел «Обновление AZ».")
	if err := enqueueNotice(ctx, w.Store, w.Alerts, now, bot.KindAntizapretUpdate, b.String()); err != nil {
		return err
	}
	return w.Store.SetMeta(ctx, metaAZSeen, ver.Latest.SHA)
}

// selfResult: итог последнего самообновления azpanel (result.json на узле) —
// одно уведомление на запись.
func (w *Watcher) selfResult(ctx context.Context) error {
	res, err := w.Node.UpdateResult(ctx)
	if err != nil || res == nil || res.Time.IsZero() {
		return nil
	}
	now := w.now()
	if now.Sub(res.Time) > resultFresh {
		return nil
	}
	key := strconv.FormatInt(res.Time.Unix(), 10)
	if v, found, err := w.Store.Meta(ctx, metaSelfResult); err != nil {
		return err
	} else if found && v == key {
		return nil
	}
	var text string
	if res.OK {
		text = fmt.Sprintf("azpanel обновлён: %s → %s.", res.From, res.To)
	} else {
		text = fmt.Sprintf("Обновление azpanel %s → %s откачено: %s.", res.From, res.To, res.Reason)
	}
	if err := enqueueNotice(ctx, w.Store, w.Alerts, now, bot.KindUpdateResult, text); err != nil {
		return err
	}
	return w.Store.SetMeta(ctx, metaSelfResult, key)
}
