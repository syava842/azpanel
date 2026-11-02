package store

import (
	"context"
	"database/sql"
	"errors"
)

// ErrNoLimit — у клиента нет срока доступа ни на карточке, ни у владельца:
// продлевать нечего.
var ErrNoLimit = errors.New("у клиента нет срока доступа")

// MinUntil — меньший из двух сроков; nil не ограничивает.
func MinUntil(a, b *int64) *int64 {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *b < *a:
		return b
	}
	return a
}

// ClientLimit — сроки одного клиента: свой (карточка) и владельца.
type ClientLimit struct {
	Name          string
	Card          *int64 // client_cards.access_until
	Owner         *int64 // users.access_until владельца
	OwnerID       *int64
	OwnerDisabled bool
}

// Effective — действующий срок: меньший из двух; nil — без ограничения.
func (l ClientLimit) Effective() *int64 { return MinUntil(l.Card, l.Owner) }

func nullPtr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	x := v.Int64
	return &x
}

// ClientLimits — сроки всех клиентов узла по имени (одним запросом).
func (s *Store) ClientLimits(ctx context.Context, node int64) (map[string]ClientLimit, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.name, c.access_until, c.owner_id, u.access_until, COALESCE(u.disabled, 0)
		FROM client_cards c LEFT JOIN users u ON u.id = c.owner_id WHERE c.node_id = ?`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ClientLimit{}
	for rows.Next() {
		var l ClientLimit
		var card, owner, oid sql.NullInt64
		if err := rows.Scan(&l.Name, &card, &oid, &owner, &l.OwnerDisabled); err != nil {
			return nil, err
		}
		l.Card, l.Owner, l.OwnerID = nullPtr(card), nullPtr(owner), nullPtr(oid)
		out[l.Name] = l
	}
	return out, rows.Err()
}

// ExtendAccess продлевает доступ клиента на days дней: новый срок =
// max(now, действующий срок) + days. Сдвигаются те из сроков (карточки,
// владельца), что раньше нового, — иначе второй из них продолжал бы
// ограничивать. Возвращает прежний действующий срок и новый; у клиента без
// срока — ErrNoLimit, и ничего не пишется.
func (s *Store) ExtendAccess(ctx context.Context, node int64, client string, days, now int64) (before *int64, after int64, err error) {
	if days < 1 {
		return nil, 0, errors.New("срок продления — минимум один день")
	}
	err = s.tx(ctx, func(t *sql.Tx) error {
		// Запись первой: транзакция берёт блокировку записи сразу, а не
		// повышает чтение до записи (иначе параллельная запись даёт BUSY).
		res, err := t.ExecContext(ctx, `UPDATE client_cards SET name = name WHERE node_id = ? AND name = ?`, node, client)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoLimit
		}
		var card, owner, oid sql.NullInt64
		if err := t.QueryRowContext(ctx, `SELECT c.access_until, c.owner_id, u.access_until FROM client_cards c
			LEFT JOIN users u ON u.id = c.owner_id WHERE c.node_id = ? AND c.name = ?`, node, client).Scan(&card, &oid, &owner); err != nil {
			return err
		}
		before = MinUntil(nullPtr(card), nullPtr(owner))
		if before == nil {
			return ErrNoLimit
		}
		after = max(now, *before) + days*86400
		if card.Valid && card.Int64 < after {
			if _, err := t.ExecContext(ctx, `UPDATE client_cards SET access_until = ? WHERE node_id = ? AND name = ?`, after, node, client); err != nil {
				return err
			}
		}
		if owner.Valid && owner.Int64 < after {
			if _, err := t.ExecContext(ctx, `UPDATE users SET access_until = ? WHERE id = ?`, after, oid.Int64); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return before, after, nil
}
