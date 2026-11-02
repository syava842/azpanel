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
		var err error
		before, err = lockLimit(ctx, t, node, client)
		if err != nil {
			return err
		}
		after, err = shiftLimits(ctx, t, node, client, days, now)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return before, after, nil
}

// RedeemAndExtend гасит код и продлевает доступ клиента в одной транзакции:
// любой сбой откатывает обе половины, поэтому код не сгорает без продления.
// Порядок внутри: блокировка записи, чтение сроков (нет срока — ErrNoLimit до
// гашения), гашение (неверный код — ErrCodeInvalid), сдвиг сроков.
func (s *Store) RedeemAndExtend(ctx context.Context, code string, owner *int64, node int64, client string, now int64) (rc Code, before int64, after int64, err error) {
	norm, ok := NormalizeCode(code)
	if !ok {
		return Code{}, 0, 0, ErrCodeInvalid
	}
	var uid any
	if owner != nil {
		uid = *owner
	}
	err = s.tx(ctx, func(t *sql.Tx) error {
		b, err := lockLimit(ctx, t, node, client)
		if err != nil {
			return err
		}
		rc, err = scanCode(t.QueryRowContext(ctx, `UPDATE unlock_codes SET used_at = ?, used_node = ?, used_client = ?
			WHERE hash = ? AND used_at IS NULL AND revoked = 0 AND valid_until >= ?
			  AND (user_id IS NULL OR user_id = ?)
			RETURNING `+codeCols, now, node, client, hashCode(norm), now, uid))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCodeInvalid
		}
		if err != nil {
			return err
		}
		before = *b
		after, err = shiftLimits(ctx, t, node, client, rc.Days, now)
		return err
	})
	if err != nil {
		return Code{}, 0, 0, err
	}
	return rc, before, after, nil
}

// lockLimit берёт блокировку записи первой командой (а не повышает чтение до
// записи — иначе параллельная запись даёт BUSY) и читает действующий срок
// клиента; нет карточки или срока — ErrNoLimit.
func lockLimit(ctx context.Context, t *sql.Tx, node int64, client string) (*int64, error) {
	res, err := t.ExecContext(ctx, `UPDATE client_cards SET name = name WHERE node_id = ? AND name = ?`, node, client)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNoLimit
	}
	var card, owner sql.NullInt64
	if err := t.QueryRowContext(ctx, `SELECT c.access_until, u.access_until FROM client_cards c
		LEFT JOIN users u ON u.id = c.owner_id WHERE c.node_id = ? AND c.name = ?`, node, client).Scan(&card, &owner); err != nil {
		return nil, err
	}
	before := MinUntil(nullPtr(card), nullPtr(owner))
	if before == nil {
		return nil, ErrNoLimit
	}
	return before, nil
}

// shiftLimits сдвигает сроки карточки и владельца на days дней от
// max(now, действующий срок) и возвращает новый срок.
func shiftLimits(ctx context.Context, t *sql.Tx, node int64, client string, days, now int64) (int64, error) {
	var card, owner, oid sql.NullInt64
	if err := t.QueryRowContext(ctx, `SELECT c.access_until, c.owner_id, u.access_until FROM client_cards c
		LEFT JOIN users u ON u.id = c.owner_id WHERE c.node_id = ? AND c.name = ?`, node, client).Scan(&card, &oid, &owner); err != nil {
		return 0, err
	}
	cur := MinUntil(nullPtr(card), nullPtr(owner))
	if cur == nil {
		return 0, ErrNoLimit
	}
	after := max(now, *cur) + days*86400
	if card.Valid && card.Int64 < after {
		if _, err := t.ExecContext(ctx, `UPDATE client_cards SET access_until = ? WHERE node_id = ? AND name = ?`, after, node, client); err != nil {
			return 0, err
		}
	}
	if owner.Valid && owner.Int64 < after {
		if _, err := t.ExecContext(ctx, `UPDATE users SET access_until = ? WHERE id = ?`, after, oid.Int64); err != nil {
			return 0, err
		}
	}
	return after, nil
}
