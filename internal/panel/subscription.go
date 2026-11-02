package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	remindHourUTC   = 9 // с этого часа (UTC) сборщик раз в сутки кладёт напоминания
	remindDayKey    = "remind_access_day"
	remindGroupKey  = "remind_access:" // + пользователь:срок:дней
	kindAccessSoon  = "access_expiring"
	certMinRemain   = 30 * 24 * time.Hour // сертификат перевыпускается, если после продления остаётся меньше
	certRenewExtra  = 365                 // дней сверх нового срока доступа при перевыпуске
	maxRenewDays    = 3650
	secondsInDay    = 86400
	remindTodayDays = 0
	remindSoonDays  = 3
)

// utcDay — начало суток по UTC.
func utcDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// parseUntil разбирает «доступ до»: дата ГГГГ-ММ-ДД — конец этих суток по
// UTC; пусто — без срока (nil).
func parseUntil(v string) (*int64, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return nil, errors.New("доступ до: нужна дата в виде ГГГГ-ММ-ДД")
	}
	end := t.UTC().Add(24*time.Hour - time.Second).Unix()
	return &end, nil
}

// untilStamp — срок с подписью часового пояса.
func untilStamp(until *int64) string {
	if until == nil {
		return "без срока"
	}
	return time.Unix(*until, 0).UTC().Format("2006-01-02 15:04") + " UTC"
}

// extendResult — итог продления кодом.
type extendResult struct {
	Before, After int64 // прежний действующий срок (0 — не было) и новый
	Days          int64
	CertRenewed   bool
	CertErr       error // сертификат не перевыпущен: срок доступа при этом продлён
}

// errManualBlock — клиент заблокирован администратором вручную: продление
// сдвинуло бы срок, но доступа не вернуло, и код не тратится.
var errManualBlock = errors.New("клиент заблокирован администратором: код не потрачен, обратитесь к администратору")

// redeemForClient гасит код для клиента и продлевает доступ: новый срок =
// max(сейчас, действующий срок) + дни кода; гашение и продление — одна
// транзакция в хранилище. Сертификат OpenVPN перевыпускается, только если
// после продления до его конца остаётся меньше 30 дней. owner — владелец
// клиента (nil — нет): код на конкретного пользователя подходит только его
// клиентам. Неверный код — store.ErrCodeInvalid; клиент без срока —
// store.ErrNoLimit; клиент под ручной блокировкой — errManualBlock; в обоих
// последних код не гасится.
func (s *Server) redeemForClient(ctx context.Context, c nodeapi.Client, owner *int64, code string) (extendResult, error) {
	now := s.now()
	if c.Blocked {
		card, err := s.Store.Card(ctx, s.NodeID, c.Name)
		if err != nil {
			return extendResult{}, err
		}
		if card.AutoBlock == "" {
			// без срока продлевать нечего — это важнее блокировки
			if eff, err := s.Store.EffectiveUntil(ctx, s.NodeID, c.Name); err != nil {
				return extendResult{}, err
			} else if eff == nil {
				return extendResult{}, store.ErrNoLimit
			}
			return extendResult{}, errManualBlock
		}
	}
	rc, bef, after, err := s.Store.RedeemAndExtend(ctx, code, owner, s.NodeID, c.Name, now.Unix())
	if err != nil {
		return extendResult{}, err
	}
	res := extendResult{Before: bef, After: after, Days: rc.Days}
	if c.OpenVPN && c.CertExpires != nil && c.CertExpires.Sub(time.Unix(after, 0)) < certMinRemain {
		days := int((after-now.Unix())/secondsInDay) + certRenewExtra
		if _, err := s.Node.Renew(ctx, c.Name, min(days, maxRenewDays)); err != nil {
			res.CertErr = err
		} else {
			res.CertRenewed = true
		}
	}
	return res, nil
}

// remindPayload — содержимое уведомления access_expiring.
type remindPayload struct {
	Until   int64    `json:"until"`
	Days    int      `json:"days"` // 0 — истекает сегодня, 3 — через три дня
	Clients []string `json:"clients"`
}

// remindExpiring раз в сутки (первый проход после 09:00 UTC) кладёт в outbox
// access_expiring владельцам, у кого действующий срок клиента кончается
// сегодня или через три дня. Одно уведомление на владельца и срок. Повтор в
// тот же день исключён: ключ суток и ключ каждой группы лежат в meta.
func (c *Collector) remindExpiring(ctx context.Context, now time.Time) error {
	if now.Hour() < remindHourUTC {
		return nil
	}
	today := now.Format("2006-01-02")
	if v, ok, err := c.Store.Meta(ctx, remindDayKey); err != nil {
		return err
	} else if ok && v == today {
		return nil
	}
	limits, err := c.Store.ClientLimits(ctx, c.NodeID)
	if err != nil {
		return err
	}
	type group struct {
		user  int64
		until int64
		days  int
	}
	groups := map[group][]string{}
	for name, l := range limits {
		eff := l.Effective()
		if l.OwnerID == nil || l.OwnerDisabled || eff == nil || *eff <= now.Unix() {
			continue
		}
		d := int(utcDay(time.Unix(*eff, 0)).Sub(utcDay(now)) / (24 * time.Hour))
		if d != remindTodayDays && d != remindSoonDays {
			continue
		}
		g := group{*l.OwnerID, *eff, d}
		groups[g] = append(groups[g], name)
	}
	keys := make([]group, 0, len(groups))
	for g := range groups {
		keys = append(keys, g)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.user != b.user {
			return a.user < b.user
		}
		return a.until < b.until
	})
	for _, g := range keys {
		mk := fmt.Sprintf("%s%d:%d:%d", remindGroupKey, g.user, g.until, g.days)
		if _, done, err := c.Store.Meta(ctx, mk); err != nil {
			return err
		} else if done {
			continue
		}
		names := groups[g]
		sort.Strings(names)
		body, err := json.Marshal(remindPayload{Until: g.until, Days: g.days, Clients: names})
		if err != nil {
			return err
		}
		uid := g.user
		if _, err := c.Store.Enqueue(ctx, kindAccessSoon, &uid, string(body), now.Unix()); err != nil {
			return err
		}
		if err := c.Store.SetMeta(ctx, mk, today); err != nil {
			return err
		}
	}
	return c.Store.SetMeta(ctx, remindDayKey, today)
}

// redeemCode — «Продлить кодом» в карточке клиента: администратор и владелец
// клиента (lookup пропускает чужого как несуществующего).
func (s *Server) redeemCode(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.Store == nil {
		s.card(w, r, c, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	var owner *int64
	if id, has, err := s.Store.OwnerOf(r.Context(), s.NodeID, c.Name); err != nil {
		s.internalError(w, r, "владелец клиента не прочитан", err)
		return
	} else if has {
		owner = &id
	}
	// те же 5 неверных кодов в час, что и в портале, — по пользователю панели
	sess, _ := session(r)
	now := s.now()
	key := fmt.Sprintf("code:user:%d", sess.UserID)
	ticket, retry, err := s.openAttempt(r.Context(), key, now)
	if err != nil {
		s.internalError(w, r, "попытки не прочитаны", err)
		return
	}
	if retry > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(math.Ceil(retry.Seconds()))))
		s.card(w, r, c, http.StatusTooManyRequests, closedText(retry))
		return
	}
	counted := false
	defer func() {
		if !counted {
			s.refundAttempt(context.WithoutCancel(r.Context()), ticket)
		}
	}()
	res, err := s.redeemForClient(r.Context(), c, owner, r.PostForm.Get("code"))
	switch {
	case errors.Is(err, store.ErrCodeInvalid):
		counted = true
		left := s.failAttempt(context.WithoutCancel(r.Context()), ticket, now)
		msg := fmt.Sprintf("%s. Осталось попыток: %d", store.ErrCodeInvalid.Error(), left)
		if left == 0 {
			msg = store.ErrCodeInvalid.Error() + ". Ввод закрыт на час"
		}
		s.card(w, r, c, http.StatusBadRequest, msg)
		return
	case errors.Is(err, store.ErrNoLimit):
		s.card(w, r, c, http.StatusBadRequest, "у клиента нет срока доступа: продлевать нечего")
		return
	case errors.Is(err, errManualBlock):
		s.card(w, r, c, http.StatusBadRequest, errManualBlock.Error())
		return
	case err != nil:
		s.Log.Error("код не применён", "client", c.Name, "err", err)
		s.card(w, r, c, http.StatusInternalServerError, "код не применён: "+err.Error())
		return
	}
	detail := fmt.Sprintf("+%d дн., до %s", res.Days, untilStamp(&res.After))
	if res.CertRenewed {
		detail += "; сертификат перевыпущен"
	}
	s.Log.Info("действие", "user", s.user(r), "op", "redeem", "client", c.Name, "detail", detail)
	s.audit(r, "redeem", c.Name, "до "+untilStamp(&res.Before), detail)
	if res.CertErr != nil {
		s.Log.Warn("сертификат не перевыпущен после продления", "client", c.Name, "err", res.CertErr)
		_, tx := s.nodeErr(res.CertErr)
		s.card(w, r, c, http.StatusBadGateway, "доступ продлён до "+untilStamp(&res.After)+", но сертификат не перевыпущен: "+tx)
		return
	}
	redirectMsg(w, r, clientHref(c.Name), "access_extended", int(res.Days))
}
