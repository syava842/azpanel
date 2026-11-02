package store

import (
	"context"
	"database/sql"
	"errors"
)

// touchEvery — не чаще этого числа секунд обновляется Session.Seen.
const touchEvery = 60

// Session — сессия панели. IDHash — SHA-256 от идентификатора из cookie
// (сам идентификатор в базе не хранится). MFAPending — пароль верен, ждём
// код 2FA. Времена — секунды Unix.
type Session struct {
	IDHash     string
	UserID     int64
	CSRF       string
	IP         string
	Agent      string
	Created    int64
	Seen       int64
	Expires    int64
	MFAPending bool
}

const sessionCols = `id_hash, user_id, csrf, ip, agent, created, seen, expires, mfa_pending`

func scanSession(sc interface{ Scan(...any) error }) (Session, error) {
	var x Session
	err := sc.Scan(&x.IDHash, &x.UserID, &x.CSRF, &x.IP, &x.Agent, &x.Created, &x.Seen, &x.Expires, &x.MFAPending)
	return x, err
}

// CreateSession сохраняет сессию.
func (s *Store) CreateSession(ctx context.Context, x Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (`+sessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		x.IDHash, x.UserID, x.CSRF, x.IP, x.Agent, x.Created, x.Seen, x.Expires, x.MFAPending)
	return err
}

// SessionByIDHash — сессия по хешу идентификатора; ErrNotFound, если нет.
func (s *Store) SessionByIDHash(ctx context.Context, idHash string) (Session, error) {
	x, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id_hash = ?`, idHash))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return x, err
}

// TouchSession отмечает активность: seen = now, но не чаще раза в минуту.
func (s *Store) TouchSession(ctx context.Context, idHash string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET seen = ? WHERE id_hash = ? AND seen <= ?`,
		now, idHash, now-touchEvery)
	return err
}

// DeleteSession удаляет одну сессию.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions удаляет все сессии пользователя, кроме exceptIDHash
// (пусто — удаляются все).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, exceptIDHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id_hash != ?`, userID, exceptIDHash)
	return err
}

// UserSessions — сессии пользователя, свежие по активности сверху.
func (s *Store) UserSessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE user_id = ? ORDER BY seen DESC, id_hash`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// PurgeExpiredSessions удаляет сессии, истёкшие к моменту now.
func (s *Store) PurgeExpiredSessions(ctx context.Context, now int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires <= ?`, now)
	return err
}
