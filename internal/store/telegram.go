package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrTelegramTaken — этот Telegram ID уже привязан к другому пользователю.
var ErrTelegramTaken = errors.New("этот Telegram уже привязан к другому пользователю")

// LinkCodeTTL — срок жизни кода привязки, секунды (10 минут).
const LinkCodeTTL = 600

// ClientKindsAll — допустимые значения client_kinds.allowed.
var ClientKindsAll = []string{"openvpn", "wireguard", "amneziawg", "antizapret", "vpn"}

// SetTelegramID привязывает Telegram к пользователю точечным UPDATE.
func (s *Store) SetTelegramID(ctx context.Context, userID, tgID int64) error {
	err := s.setFields(ctx, `UPDATE users SET telegram_id = ? WHERE id = ?`, tgID, userID)
	if isUnique(err) {
		return ErrTelegramTaken
	}
	return err
}

// ErrBindRefused — пользователь не подходит для привязки из бота: администратор
// или отключённая учётная запись.
var ErrBindRefused = errors.New("к этому пользователю Telegram из бота привязать нельзя")

// ErrTelegramBound — у пользователя уже есть привязка.
var ErrTelegramBound = errors.New("у пользователя уже привязан другой Telegram")

// BindTelegramID привязывает Telegram по заявке: одним UPDATE и только обычному
// активному пользователю без привязки. Администратору привязка из бота по
// заявке не выдаётся никогда (только через вход в веб), чужая привязка не
// затирается.
func (s *Store) BindTelegramID(ctx context.Context, userID, tgID int64) error {
	return s.bindTelegram(ctx, userID, tgID, true)
}

// LinkTelegramID привязывает Telegram по одноразовому коду из веб-сессии
// самого пользователя (с подтверждением паролем): подходит и администратору,
// но тоже только активному и без прежней привязки.
func (s *Store) LinkTelegramID(ctx context.Context, userID, tgID int64) error {
	return s.bindTelegram(ctx, userID, tgID, false)
}

func (s *Store) bindTelegram(ctx context.Context, userID, tgID int64, userOnly bool) error {
	q := `UPDATE users SET telegram_id = ? WHERE id = ? AND telegram_id IS NULL AND disabled = 0`
	if userOnly {
		q += ` AND role = 'user'`
	}
	res, err := s.db.ExecContext(ctx, q, tgID, userID)
	if isUnique(err) {
		return ErrTelegramTaken
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.TelegramID != nil {
		return ErrTelegramBound
	}
	return ErrBindRefused
}

// ClearTelegramID снимает привязку.
func (s *Store) ClearTelegramID(ctx context.Context, userID int64) error {
	return s.setFields(ctx, `UPDATE users SET telegram_id = NULL WHERE id = ?`, userID)
}

// UserByTelegramID — пользователь по привязанному Telegram ID; ErrNotFound, если нет.
func (s *Store) UserByTelegramID(ctx context.Context, tgID int64) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE telegram_id = ?`, tgID))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// CreateLinkCode выпускает одноразовый код привязки (16 байт, base64url),
// заменяя прежние коды пользователя; в базе лежит только SHA-256.
func (s *Store) CreateLinkCode(ctx context.Context, userID, now int64) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(b[:])
	err := s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `DELETE FROM tg_link_codes WHERE user_id = ? OR expires <= ?`, userID, now); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx, `INSERT INTO tg_link_codes (hash, user_id, expires) VALUES (?, ?, ?)`,
			HashToken(code), userID, now+LinkCodeTTL)
		return err
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// RedeemLinkCode гасит код и возвращает ID пользователя. Неверный, уже
// погашенный и просроченный код — одна ошибка ErrCodeInvalid.
func (s *Store) RedeemLinkCode(ctx context.Context, code string, now int64) (int64, error) {
	var uid int64
	err := s.tx(ctx, func(t *sql.Tx) error {
		h := HashToken(code)
		var expires int64
		err := t.QueryRowContext(ctx, `SELECT user_id, expires FROM tg_link_codes WHERE hash = ?`, h).Scan(&uid, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM tg_link_codes WHERE hash = ?`, h); err != nil {
			return err
		}
		if expires <= now {
			// Просроченный код стирается, но не засчитывается.
			uid = 0
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if uid == 0 {
		return 0, ErrCodeInvalid
	}
	return uid, nil
}

// TelegramRequest — заявка незнакомца на доступ.
type TelegramRequest struct {
	ID       int64
	Username string
	Name     string
	Created  int64
}

// AddTelegramRequest записывает заявку; повтор обновляет имя, но не время подачи.
func (s *Store) AddTelegramRequest(ctx context.Context, r TelegramRequest) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO tg_requests (telegram_id, username, name, created) VALUES (?, ?, ?, ?)
		ON CONFLICT(telegram_id) DO UPDATE SET username = excluded.username, name = excluded.name`,
		r.ID, r.Username, r.Name, r.Created)
	return err
}

// TelegramRequests — заявки, старые первыми.
func (s *Store) TelegramRequests(ctx context.Context) ([]TelegramRequest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT telegram_id, coalesce(username, ''), coalesce(name, ''), created
		FROM tg_requests ORDER BY created, telegram_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TelegramRequest{}
	for rows.Next() {
		var r TelegramRequest
		if err := rows.Scan(&r.ID, &r.Username, &r.Name, &r.Created); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteTelegramRequest снимает заявку; нет такой — не ошибка.
func (s *Store) DeleteTelegramRequest(ctx context.Context, tgID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tg_requests WHERE telegram_id = ?`, tgID)
	return err
}

// BanTelegram блокирует ID (повтор не ошибка) и снимает его заявку.
func (s *Store) BanTelegram(ctx context.Context, tgID, now int64) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `INSERT OR IGNORE INTO tg_banned (telegram_id, created) VALUES (?, ?)`, tgID, now); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx, `DELETE FROM tg_requests WHERE telegram_id = ?`, tgID)
		return err
	})
}

// UnbanTelegram снимает блокировку.
func (s *Store) UnbanTelegram(ctx context.Context, tgID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tg_banned WHERE telegram_id = ?`, tgID)
	return err
}

// TelegramBanned — заблокирован ли ID.
func (s *Store) TelegramBanned(ctx context.Context, tgID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM tg_banned WHERE telegram_id = ?`, tgID).Scan(&n)
	return n > 0, err
}

// SetClientKinds задаёт типы профилей клиента, доступные в боте. Пустой список
// снимает ограничение («всё»). Значения — из ClientKindsAll; дубли убираются.
func (s *Store) SetClientKinds(ctx context.Context, node int64, name string, kinds []string) error {
	if len(kinds) == 0 {
		return s.DeleteClientKinds(ctx, node, name)
	}
	norm := make([]string, 0, len(kinds))
	for _, k := range kinds {
		k = strings.TrimSpace(k)
		if !slices.Contains(ClientKindsAll, k) {
			return fmt.Errorf("неизвестный тип профиля %q", k)
		}
		norm = append(norm, k)
	}
	slices.Sort(norm)
	norm = slices.Compact(norm)
	_, err := s.db.ExecContext(ctx, `INSERT INTO client_kinds (node_id, name, allowed) VALUES (?, ?, ?)
		ON CONFLICT(node_id, name) DO UPDATE SET allowed = excluded.allowed`,
		node, name, strings.Join(norm, ","))
	return err
}

// ClientKinds — разрешённые типы профилей; false — записи нет, разрешено всё.
func (s *Store) ClientKinds(ctx context.Context, node int64, name string) ([]string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT allowed FROM client_kinds WHERE node_id = ? AND name = ?`, node, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if v == "" {
		return nil, false, nil
	}
	return strings.Split(v, ","), true, nil
}

// DeleteClientKinds снимает ограничение; нет записи — не ошибка.
func (s *Store) DeleteClientKinds(ctx context.Context, node int64, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM client_kinds WHERE node_id = ? AND name = ?`, node, name)
	return err
}

// TelegramBan — заблокированный Telegram ID.
type TelegramBan struct {
	ID      int64
	Created int64
}

// TelegramBans — заблокированные ID, новые первыми.
func (s *Store) TelegramBans(ctx context.Context) ([]TelegramBan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT telegram_id, created FROM tg_banned ORDER BY created DESC, telegram_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TelegramBan{}
	for rows.Next() {
		var b TelegramBan
		if err := rows.Scan(&b.ID, &b.Created); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
