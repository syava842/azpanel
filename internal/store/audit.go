package store

import (
	"context"
	"strings"
)

// AuditEntry — запись журнала действий. Секретов в ней быть не должно.
type AuditEntry struct {
	ID     int64
	TS     int64
	User   string
	IP     string
	Action string
	Target string
	Before string
	After  string
}

// Audit дописывает запись в журнал.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (ts, user, ip, action, target, before, after)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, e.TS, e.User, e.IP, e.Action, e.Target, e.Before, e.After)
	return err
}

// likeEscaper экранирует спецсимволы LIKE (ESCAPE '\').
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// AuditList — страница журнала, новые сверху. q — подстрока по user, action
// и target без учёта регистра (пусто — все записи). Второе значение — число
// всех подходящих строк.
func (s *Store) AuditList(ctx context.Context, limit, offset int, q string) ([]AuditEntry, int, error) {
	where, args := "", []any{}
	if q != "" {
		where = ` WHERE lower(user) LIKE ? ESCAPE '\' OR lower(action) LIKE ? ESCAPE '\' OR lower(target) LIKE ? ESCAPE '\'`
		pat := "%" + likeEscaper.Replace(strings.ToLower(q)) + "%"
		args = append(args, pat, pat, pat)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, user, ip, action, target, before, after FROM audit`+where+
		` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.User, &e.IP, &e.Action, &e.Target, &e.Before, &e.After); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
