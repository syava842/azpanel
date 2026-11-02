package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

const pendingMetaPrefix = "pending:"

// Pending — опасная настройка, применённая с таймером: новое значение уже
// действует, но если его не подтвердили до Deadline (секунды Unix), на его
// место возвращается Old. Хранится в meta, поэтому переживает перезапуск
// панели. Механизм общий: этап 2б заведёт на нём адрес, порт и HTTPS.
type Pending struct {
	Key      string `json:"key"`
	Old      string `json:"old"`
	New      string `json:"new"`
	Deadline int64  `json:"deadline"`
}

// PendingStore ведёт ожидающие подтверждения изменения. Apply — по ключу
// настройки функция, которая ставит значение в работу и в файл; ею же
// возвращается прежнее значение. Ключи без функции игнорируются.
type PendingStore struct {
	Store *store.Store
	Now   func() time.Time
	Apply map[string]func(value string) error
}

func (p *PendingStore) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Begin запоминает изменение и его срок. Новое значение вызывающий применяет
// сам. Незавершённое изменение того же ключа — ошибка.
func (p *PendingStore) Begin(ctx context.Context, key, old, new string, ttl time.Duration) (Pending, error) {
	if _, ok, err := p.Get(ctx, key); err != nil {
		return Pending{}, err
	} else if ok {
		return Pending{}, errors.New("предыдущее изменение ещё не подтверждено")
	}
	x := Pending{Key: key, Old: old, New: new, Deadline: p.now().Add(ttl).Unix()}
	b, err := json.Marshal(x)
	if err != nil {
		return Pending{}, err
	}
	if err := p.Store.SetMeta(ctx, pendingMetaPrefix+key, string(b)); err != nil {
		return Pending{}, err
	}
	return x, nil
}

// Get возвращает ожидающее изменение ключа.
func (p *PendingStore) Get(ctx context.Context, key string) (Pending, bool, error) {
	v, ok, err := p.Store.Meta(ctx, pendingMetaPrefix+key)
	if err != nil || !ok {
		return Pending{}, false, err
	}
	var x Pending
	if err := json.Unmarshal([]byte(v), &x); err != nil {
		return Pending{}, false, fmt.Errorf("запись ожидания %s испорчена: %w", key, err)
	}
	return x, true, nil
}

// Confirm оставляет новое значение. После срока подтвердить нельзя: возврат
// уже положен, он выполнится при ближайшей проверке.
func (p *PendingStore) Confirm(ctx context.Context, key string) error {
	x, ok, err := p.Get(ctx, key)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("нечего подтверждать")
	}
	if p.now().Unix() >= x.Deadline {
		return errors.New("время подтверждения вышло")
	}
	return p.Store.ClearMeta(ctx, pendingMetaPrefix+key)
}

// Expire возвращает прежние значения всех изменений, чей срок вышел, и
// снимает их с учёта. Не вернулось (ошибка применения) — запись остаётся,
// следующая проверка повторит.
func (p *PendingStore) Expire(ctx context.Context) ([]Pending, error) {
	var done []Pending
	var errs []error
	for key, apply := range p.Apply {
		x, ok, err := p.Get(ctx, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok || p.now().Unix() < x.Deadline {
			continue
		}
		if err := apply(x.Old); err != nil {
			errs = append(errs, fmt.Errorf("возврат %s: %w", key, err))
			continue
		}
		if err := p.Store.ClearMeta(ctx, pendingMetaPrefix+key); err != nil {
			errs = append(errs, err)
			continue
		}
		done = append(done, x)
	}
	return done, errors.Join(errs...)
}
