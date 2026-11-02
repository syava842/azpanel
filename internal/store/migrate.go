package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// migrations — схема по версиям; версия N лежит в migrations[N-1].
// Последующие планы добавляют миграции только в конец среза.
var migrations = []string{
	`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL);
INSERT INTO nodes (id, name, url) VALUES (1, 'local', '');
CREATE TABLE client_cards (
  node_id INTEGER NOT NULL REFERENCES nodes(id),
  name TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  access_until INTEGER,
  traffic_limit INTEGER NOT NULL DEFAULT 0,
  traffic_period TEXT NOT NULL DEFAULT 'month',
  auto_block TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (node_id, name));
CREATE TABLE traffic_minute (node_id INTEGER, name TEXT, ts INTEGER, rx INTEGER, tx INTEGER, PRIMARY KEY (node_id, name, ts));
CREATE TABLE traffic_hour   (node_id INTEGER, name TEXT, ts INTEGER, rx INTEGER, tx INTEGER, PRIMARY KEY (node_id, name, ts));
CREATE TABLE resource_minute (node_id INTEGER, ts INTEGER, cpu REAL, load1 REAL,
  mem_used INTEGER, mem_total INTEGER, disk_free INTEGER, disk_total INTEGER,
  net_rx INTEGER, net_tx INTEGER, online INTEGER, PRIMARY KEY (node_id, ts));
CREATE TABLE resource_hour (node_id INTEGER, ts INTEGER, cpu REAL, load1 REAL,
  mem_used INTEGER, mem_total INTEGER, disk_free INTEGER, disk_total INTEGER,
  net_rx INTEGER, net_tx INTEGER, online INTEGER, PRIMARY KEY (node_id, ts));
CREATE TABLE audit (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user TEXT NOT NULL, ip TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL, before TEXT NOT NULL DEFAULT '', after TEXT NOT NULL DEFAULT '');
CREATE INDEX audit_ts ON audit(ts);`,
	// 2: отпечаток причины, по которой админ вручную снял автоблокировку.
	`ALTER TABLE client_cards ADD COLUMN auto_skip TEXT NOT NULL DEFAULT '';`,
}

// SchemaVersion — версия схемы в базе; 0 у пустой.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'`).Scan(&n)
	if err != nil || n == 0 {
		return 0, err
	}
	var v string
	err = s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(v)
}

func (s *Store) migrate(ctx context.Context) error {
	cur, err := s.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("версия схемы: %w", err)
	}
	if cur > len(migrations) {
		return fmt.Errorf("база версии %d новее, чем знает эта версия azpanel (%d)", cur, len(migrations))
	}
	for v := cur + 1; v <= len(migrations); v++ {
		err := s.tx(ctx, func(t *sql.Tx) error {
			if _, err := t.ExecContext(ctx, migrations[v-1]); err != nil {
				return err
			}
			_, err := t.ExecContext(ctx,
				`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
				 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.Itoa(v))
			return err
		})
		if err != nil {
			return fmt.Errorf("миграция %d: %w", v, err)
		}
	}
	return nil
}
