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
	// 3: пользователи, резервные коды 2FA, сессии и владелец клиента.
	`CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  login TEXT NOT NULL UNIQUE,
  hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  disabled INTEGER NOT NULL DEFAULT 0,
  must_change INTEGER NOT NULL DEFAULT 0,
  totp_secret BLOB,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL);
CREATE TABLE backup_codes (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, ip TEXT NOT NULL, agent TEXT NOT NULL,
  created INTEGER NOT NULL, seen INTEGER NOT NULL, expires INTEGER NOT NULL,
  mfa_pending INTEGER NOT NULL DEFAULT 0);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX backup_codes_user ON backup_codes(user_id);
ALTER TABLE client_cards ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL;`,
	// 4: портал клиента — срок пользователя, unlock-коды, ссылки портала,
	// одноразовые ссылки, счётчик попыток и очередь уведомлений.
	`ALTER TABLE users ADD COLUMN access_until INTEGER;
CREATE TABLE unlock_codes (id INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE,
  days INTEGER NOT NULL, valid_until INTEGER NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  batch TEXT NOT NULL, created INTEGER NOT NULL, created_by TEXT NOT NULL,
  used_at INTEGER, used_node INTEGER, used_client TEXT, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX unlock_codes_batch ON unlock_codes(batch);
CREATE TABLE portal_links (hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('c','u')),
  node_id INTEGER, client TEXT, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL);
CREATE TABLE download_links (hash TEXT PRIMARY KEY, node_id INTEGER NOT NULL, client TEXT NOT NULL,
  pkind TEXT NOT NULL, variant TEXT NOT NULL, file TEXT NOT NULL,
  pin_hash TEXT, pin_fails INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL);
CREATE TABLE attempts (key TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX attempts_key ON attempts(key, ts);
CREATE TABLE outbox (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, user_id INTEGER, payload TEXT NOT NULL,
  created INTEGER NOT NULL, sent INTEGER);`,
	// Telegram-бот: привязка, коды, заявки, блокировки, разрешённые типы профилей.
	`ALTER TABLE users ADD COLUMN telegram_id INTEGER;
CREATE UNIQUE INDEX users_tg ON users(telegram_id) WHERE telegram_id IS NOT NULL;
CREATE TABLE tg_link_codes (hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE tg_requests (telegram_id INTEGER PRIMARY KEY, username TEXT, name TEXT, created INTEGER NOT NULL);
CREATE TABLE tg_banned (telegram_id INTEGER PRIMARY KEY, created INTEGER NOT NULL);
CREATE TABLE client_kinds (node_id INTEGER NOT NULL, name TEXT NOT NULL, allowed TEXT NOT NULL,
  PRIMARY KEY (node_id, name));`,
	// Очередь уведомлений: счётчик неудачных проходов доставки переживает перезапуск.
	`ALTER TABLE outbox ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;`,
	// 7: несколько узлов и группы синхронизации (этап 4). Узел: тип (узел или
	// прокси-агент), закреплённый отпечаток TLS, токен (зашифрован ключом
	// панели), роль в группе. У локального узла (id 1) адрес и токен не нужны.
	`ALTER TABLE nodes ADD COLUMN kind TEXT NOT NULL DEFAULT 'node';
ALTER TABLE nodes ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN token TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN role TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN group_id INTEGER;
ALTER TABLE nodes ADD COLUMN created INTEGER NOT NULL DEFAULT 0;
CREATE TABLE groups (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  domain TEXT NOT NULL DEFAULT '',
  remotes TEXT NOT NULL DEFAULT '[]',
  failover INTEGER NOT NULL DEFAULT 0,
  failover_after INTEGER NOT NULL DEFAULT 120,
  created INTEGER NOT NULL DEFAULT 0);`,
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
