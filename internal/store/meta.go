package store

import (
	"context"
	"database/sql"
	"errors"
)

// Meta читает значение из служебной таблицы meta; второе значение — было ли оно.
func (s *Store) Meta(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetMeta записывает значение в meta (заменяя прежнее).
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ClearMeta убирает ключ; нет такого — не ошибка.
func (s *Store) ClearMeta(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, key)
	return err
}

// MetaPrefix — все пары meta, ключ которых начинается с prefix (без учёта
// подстановочных знаков LIKE в самом префиксе).
func (s *Store) MetaPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM meta WHERE substr(key, 1, ?) = ?`, len([]rune(prefix)), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
