// Package store — SQLite-хранилище панели: история трафика и ресурсов,
// карточки клиентов, журнал действий. Драйвер modernc.org/sqlite — без cgo.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// LocalNode — идентификатор единственного узла до этапа 4.
const LocalNode int64 = 1

// Store — обёртка над одним *sql.DB на процесс.
type Store struct{ db *sql.DB }

// Open создаёт файл базы с правами 600 (если его нет), включает WAL и
// применяет миграции.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("каталог базы: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("файл базы: %w", err)
	}
	f.Close()
	// Права ставим и на уже существующий файл: создан мог быть кем угодно.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("права файла базы: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly открывает существующую базу только на чтение: без создания
// файла, без прав, без WAL-прагмы и без миграций. Годится для проверок до
// подтверждения (мастер установки): база более старой версии остаётся как была.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("файл базы: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// tx выполняет f в транзакции; ошибка f откатывает её.
func (s *Store) tx(ctx context.Context, f func(*sql.Tx) error) error {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := f(t); err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}
