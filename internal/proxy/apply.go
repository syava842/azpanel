package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/syava842/azpanel/internal/proxyapi"
)

// Applier меняет правила nat. Команды iptables — поля-функции: в тестах их
// подменяют, настоящие лежат в exec.go.
type Applier struct {
	Save    func(ctx context.Context) (string, error)     // iptables-save -t nat
	Restore func(ctx context.Context, rules string) error // iptables-restore для таблицы nat
	Persist func(ctx context.Context) error               // netfilter-persistent save
	Log     *slog.Logger

	mu sync.Mutex // одна смена адреса за раз
}

// Table читает текущие правила nat.
func (a *Applier) Table(ctx context.Context) (*Table, error) {
	text, err := a.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("iptables-save: %w", err)
	}
	return ParseNAT(text)
}

// SetTarget направляет трафик группы на новый адрес: снимок iptables-save,
// правка только DNAT-правил proxy.sh этой группы (и SNAT на их адреса),
// iptables-restore, проверка по повторному снимку и сохранение как у
// proxy.sh. Любая ошибка после начала правки — восстановление снимка.
func (a *Applier) SetTarget(ctx context.Context, group, ip string) (proxyapi.TargetResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	snapshot, err := a.Save(ctx)
	if err != nil {
		return proxyapi.TargetResult{}, fmt.Errorf("iptables-save: %w", err)
	}
	tb, err := ParseNAT(snapshot)
	if err != nil {
		return proxyapi.TargetResult{}, err
	}
	next, changed, err := tb.SetTarget(group, ip)
	if err != nil {
		return proxyapi.TargetResult{}, err
	}
	res := proxyapi.TargetResult{Group: group, To: mustAddr(ip), Changed: changed}
	for _, g := range tb.Groups() {
		if g.Name == group {
			res.From = g.Target
		}
	}
	if changed == 0 {
		return res, nil // уже так, ничего не трогаем
	}
	if err := a.Restore(ctx, next); err != nil {
		return proxyapi.TargetResult{}, a.rollback(ctx, snapshot, fmt.Errorf("iptables-restore: %w", err))
	}
	if err := a.verify(ctx, group, res.To); err != nil {
		return proxyapi.TargetResult{}, a.rollback(ctx, snapshot, err)
	}
	if err := a.Persist(ctx); err != nil {
		return proxyapi.TargetResult{}, a.rollback(ctx, snapshot, fmt.Errorf("правила не сохранены (netfilter-persistent save): %w", err))
	}
	res.Saved = true
	a.Log.Info("адрес назначения прокси изменён", "group", group, "from", res.From, "to", res.To, "rules", changed)
	return res, nil
}

// verify сверяет правила в ядре с тем, что просили.
func (a *Applier) verify(ctx context.Context, group, ip string) error {
	tb, err := a.Table(ctx)
	if err != nil {
		return fmt.Errorf("проверка после iptables-restore: %w", err)
	}
	for _, g := range tb.Groups() {
		if g.Name == group && (g.Target != ip || g.Mixed) {
			return fmt.Errorf("после iptables-restore у группы %s адрес %s, нужен %s", group, g.Target, ip)
		}
	}
	return nil
}

// rollback возвращает снимок; cause — причина отката, она остаётся в ошибке.
func (a *Applier) rollback(ctx context.Context, snapshot string, cause error) error {
	// Откат не должен оборваться вместе с запросом.
	rctx := context.WithoutCancel(ctx)
	if err := a.Restore(rctx, snapshot); err != nil {
		a.Log.Error("откат правил не удался — проверьте iptables вручную", "cause", cause, "err", err)
		return fmt.Errorf("%w; откат прежних правил не удался: %v", cause, err)
	}
	a.Log.Warn("правила возвращены к снимку", "cause", cause)
	return fmt.Errorf("%w; прежние правила возвращены", cause)
}

func mustAddr(ip string) string {
	a, err := ValidTarget(ip)
	if err != nil {
		return ip
	}
	return a.String()
}

// IsInput — ошибка в запросе (а не сбой системы).
func IsInput(err error) bool {
	var ve *InputError
	return errors.As(err, &ve)
}

// InputError — неверная группа или адрес в запросе.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }
