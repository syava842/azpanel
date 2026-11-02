package panel

import (
	"context"
	"sync"
	"time"
)

// keyedMutex — мьютекс на ключ: запросы с разными ключами друг друга не ждут,
// записи без держателей из карты убираются.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyLock
}

type keyLock struct {
	mu sync.Mutex
	n  int // держатели и ожидающие
}

// Lock берёт замок ключа и возвращает функцию, которая его отпускает.
func (k *keyedMutex) Lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*keyLock{}
	}
	l := k.m[key]
	if l == nil {
		l = &keyLock{}
		k.m[key] = l
	}
	l.n++
	k.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		if l.n--; l.n == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

const lockPrefix = "lock:" // ключ метки закрытия ввода

// attemptTicket — резерв одной попытки ввода кода.
type attemptTicket struct {
	key string
	ts  int64
}

// openAttempt резервирует попытку ввода кода под ключом key (замок ключа
// держится только на время подсчёта и записи, а не на вызовах агента).
// Закрытый ввод — retry > 0 (сколько ждать), резерв не создаётся. Резерв
// учитывается как ошибка, пока его не вернёт refundAttempt (код не был
// неверным) или не подтвердит failAttempt: параллельные запросы так не
// обходят предел.
func (s *Server) openAttempt(ctx context.Context, key string, now time.Time) (t attemptTicket, retry time.Duration, err error) {
	unlock := s.attemptMu.Lock(key)
	defer unlock()
	ts := now.Unix()
	// ввод закрыт на час с момента пятой ошибки, а не скользящим окном
	if lt, ok, err := s.Store.LastAttempt(ctx, lockPrefix+key, ts-int64(unlockWindow.Seconds())+1); err != nil {
		return t, 0, err
	} else if ok {
		return t, retryLeft(lt, ts), nil
	}
	n, err := s.Store.Attempts(ctx, key, ts-int64(unlockWindow.Seconds()))
	if err != nil {
		return t, 0, err
	}
	if n >= unlockMax { // пять попыток ещё в пути: ждём, пока окно их не отпустит
		last, _, err := s.Store.LastAttempt(ctx, key, 0)
		if err != nil {
			return t, 0, err
		}
		return t, retryLeft(last, ts), nil
	}
	if err := s.Store.Attempt(ctx, key, ts); err != nil {
		return t, 0, err
	}
	return attemptTicket{key: key, ts: ts}, 0, nil
}

// retryLeft — сколько осталось до конца часа от момента from (не меньше секунды).
func retryLeft(from, now int64) time.Duration {
	d := time.Duration(from+int64(unlockWindow.Seconds())-now) * time.Second
	return max(d, time.Second)
}

// refundAttempt снимает резерв: код не оказался неверным (принят или отказ
// по другой причине).
func (s *Server) refundAttempt(ctx context.Context, t attemptTicket) {
	if err := s.Store.RefundAttempt(ctx, t.key, t.ts); err != nil {
		s.Log.Warn("попытка не возвращена", "err", err)
	}
}

// failAttempt подтверждает неверный код: резерв остаётся ошибкой. Пятая ошибка
// ставит метку закрытия на час. Возвращает, сколько попыток осталось.
func (s *Server) failAttempt(ctx context.Context, t attemptTicket, now time.Time) (left int) {
	unlock := s.attemptMu.Lock(t.key)
	defer unlock()
	n, err := s.Store.Attempts(ctx, t.key, now.Unix()-int64(unlockWindow.Seconds()))
	if err != nil {
		s.Log.Warn("попытки не прочитаны", "err", err)
		return 0
	}
	if n >= unlockMax {
		if err := s.Store.Attempt(ctx, lockPrefix+t.key, now.Unix()); err != nil {
			s.Log.Warn("закрытие ввода не записано", "err", err)
		}
	}
	if err := s.Store.PurgeAttempts(ctx, now.Unix()-int64(attemptsKeep.Seconds())); err != nil {
		s.Log.Warn("старые попытки не стёрты", "err", err)
	}
	return max(unlockMax-n, 0)
}
