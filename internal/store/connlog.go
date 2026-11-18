package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// История подключений: сборщик панели на каждом проходе сверяет живые
// сеансы узла с открытыми записями — новые открывает, ушедшие закрывает
// временем последнего прохода, где они ещё были. Точность — период
// сборщика (по умолчанию минута); перезапуск панели или агента записи не
// рвёт: сеанс OpenVPN узнаётся по «подключён с», WireGuard — по имени и
// интерфейсу.

// ConnSeen — живой сеанс в проходе сборщика.
type ConnSeen struct {
	Kind, Instance, Name string
	Since                int64 // «подключён с» OpenVPN; 0 — WireGuard
	RealAddr, VPNAddr    string
	Proto                string
	Port                 int
	Rx, Tx               int64
}

func (c ConnSeen) key() string {
	return fmt.Sprintf("%s|%s|%s|%d", c.Kind, c.Instance, c.Name, c.Since)
}

// ConnEntry — запись истории.
type ConnEntry struct {
	Kind, Instance, Name string
	Start, LastSeen      int64
	Ended                int64 // 0 — сеанс идёт
	RealAddr, VPNAddr    string
	Proto                string
	Port                 int
	Rx, Tx               int64
}

// SyncConnLog сверяет живые сеансы узла с открытыми записями на момент now.
func (s *Store) SyncConnLog(ctx context.Context, node, now int64, seen []ConnSeen) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		rows, err := t.QueryContext(ctx, `SELECT id, kind, instance, name, since FROM conn_log
			WHERE node_id = ? AND ended IS NULL`, node)
		if err != nil {
			return err
		}
		open := map[string]int64{}
		for rows.Next() {
			var id int64
			var c ConnSeen
			if err := rows.Scan(&id, &c.Kind, &c.Instance, &c.Name, &c.Since); err != nil {
				rows.Close()
				return err
			}
			open[c.key()] = id
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		done := map[string]bool{} // дубль в одном проходе не открывает вторую запись
		for _, c := range seen {
			k := c.key()
			if done[k] {
				continue
			}
			done[k] = true
			if id, ok := open[k]; ok {
				delete(open, k)
				if _, err := t.ExecContext(ctx, `UPDATE conn_log SET last_seen = ?, real_addr = ?, vpn_addr = ?, proto = ?, port = ?, rx = ?, tx = ?
					WHERE id = ?`, now, c.RealAddr, c.VPNAddr, c.Proto, c.Port, c.Rx, c.Tx, id); err != nil {
					return err
				}
				continue
			}
			start := c.Since
			if start <= 0 || start > now {
				start = now
			}
			if _, err := t.ExecContext(ctx, `INSERT INTO conn_log (node_id, kind, instance, name, since, start, last_seen, real_addr, vpn_addr, proto, port, rx, tx)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, node, c.Kind, c.Instance, c.Name, c.Since, start, now,
				c.RealAddr, c.VPNAddr, c.Proto, c.Port, c.Rx, c.Tx); err != nil {
				return err
			}
		}
		for _, id := range open {
			if _, err := t.ExecContext(ctx, `UPDATE conn_log SET ended = last_seen WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// OpenConnStarts — начало идущих сеансов узла по ключу «вид|экземпляр|имя»:
// у WireGuard своего «подключён с» нет, его берут отсюда.
func (s *Store) OpenConnStarts(ctx context.Context, node int64) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, instance, name, min(start) FROM conn_log
		WHERE node_id = ? AND ended IS NULL GROUP BY kind, instance, name`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var kind, inst, name string
		var start int64
		if err := rows.Scan(&kind, &inst, &name, &start); err != nil {
			return nil, err
		}
		out[kind+"|"+inst+"|"+name] = start
	}
	return out, rows.Err()
}

// ConnLogQuery — выборка истории: вид, подстрока имени, адреса или
// протокола, страница.
type ConnLogQuery struct {
	Kind          string
	Q             string
	Limit, Offset int
}

// ConnLog — записи по убыванию начала и их общее число по фильтру.
func (s *Store) ConnLog(ctx context.Context, node int64, q ConnLogQuery) ([]ConnEntry, int, error) {
	where := `node_id = ? AND kind = ?`
	args := []any{node, q.Kind}
	if v := strings.TrimSpace(q.Q); v != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(v)) + "%"
		where += ` AND (lower(name) LIKE ? ESCAPE '\' OR real_addr LIKE ? ESCAPE '\' OR vpn_addr LIKE ? ESCAPE '\' OR lower(proto) LIKE ? ESCAPE '\')`
		args = append(args, like, like, like, like)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM conn_log WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT kind, instance, name, start, last_seen, coalesce(ended, 0), real_addr, vpn_addr, proto, port, rx, tx
		FROM conn_log WHERE `+where+` ORDER BY start DESC, id DESC LIMIT ? OFFSET ?`, append(args, limit, max(q.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ConnEntry
	for rows.Next() {
		var e ConnEntry
		if err := rows.Scan(&e.Kind, &e.Instance, &e.Name, &e.Start, &e.LastSeen, &e.Ended, &e.RealAddr, &e.VPNAddr, &e.Proto, &e.Port, &e.Rx, &e.Tx); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
