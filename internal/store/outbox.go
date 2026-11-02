package store

import (
	"context"
	"database/sql"
	"errors"
)

// OutboxItem — запись очереди уведомлений.
type OutboxItem struct {
	ID      int64
	Kind    string
	UserID  *int64
	Payload string
	Created int64
	// Attempts — проходов доставки, закончившихся ошибкой.
	Attempts int
}

// Enqueue ставит уведомление в очередь; userID nil — адресата-пользователя нет.
func (s *Store) Enqueue(ctx context.Context, kind string, userID *int64, payload string, now int64) (int64, error) {
	var uid any
	if userID != nil {
		uid = *userID
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO outbox (kind, user_id, payload, created) VALUES (?, ?, ?, ?)`, kind, uid, payload, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Pending — неотправленные уведомления, старые первыми; limit <= 0 — без предела.
func (s *Store) Pending(ctx context.Context, limit int) ([]OutboxItem, error) {
	if limit <= 0 {
		limit = -1
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, user_id, payload, created, attempts FROM outbox
		WHERE sent IS NULL ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxItem{}
	for rows.Next() {
		var it OutboxItem
		var uid sql.NullInt64
		if err := rows.Scan(&it.ID, &it.Kind, &uid, &it.Payload, &it.Created, &it.Attempts); err != nil {
			return nil, err
		}
		if uid.Valid {
			it.UserID = &uid.Int64
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkSent отмечает уведомление отправленным; ErrNotFound, если его нет или оно уже отправлено.
func (s *Store) MarkSent(ctx context.Context, id, now int64) error {
	return s.setFields(ctx, `UPDATE outbox SET sent = ? WHERE id = ? AND sent IS NULL`, now, id)
}

// FailOutbox прибавляет неудачный проход доставки и возвращает новое число.
func (s *Store) FailOutbox(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `UPDATE outbox SET attempts = attempts + 1 WHERE id = ? AND sent IS NULL RETURNING attempts`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

// MarkSentBefore отмечает отправленными все неотправленные записи, созданные
// раньше before; возвращает их число.
func (s *Store) MarkSentBefore(ctx context.Context, before, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE outbox SET sent = ? WHERE sent IS NULL AND created < ?`, now, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
