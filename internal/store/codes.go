package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrCodeInvalid — код неверен или уже использован: одна ошибка на неверный,
// погашенный, отозванный, просроченный и чужой код, чтобы ответ ничего не выдавал.
var ErrCodeInvalid = errors.New("код неверен или уже использован")

// Алфавит unlock-кодов: A-Z и 2-9 без похожих 0, O, 1, I — ровно 32 символа,
// то есть 5 бит на символ без перекоса при выборе по байту.
const (
	codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codeLen      = 16
)

// GenerateCode — новый случайный код в нормализованном виде (16 символов).
func GenerateCode() (string, error) {
	var b [codeLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	out := make([]byte, codeLen)
	for i, v := range b {
		out[i] = codeAlphabet[v&31]
	}
	return string(out), nil
}

// FormatCode показывает нормализованный код группами по 4 через дефис.
func FormatCode(code string) string {
	var sb strings.Builder
	for i := 0; i < len(code); i += 4 {
		if i > 0 {
			sb.WriteByte('-')
		}
		end := min(i+4, len(code))
		sb.WriteString(code[i:end])
	}
	return sb.String()
}

// NormalizeCode приводит ввод к виду хранения: без учёта регистра, дефисов и
// пробелов. false — это не код (длина или символы вне алфавита).
func NormalizeCode(in string) (string, bool) {
	var sb strings.Builder
	for _, r := range strings.ToUpper(in) {
		switch {
		case r == '-', r == ' ', r == '\t', r == '\n', r == '\r':
			continue
		case r < 128 && strings.IndexByte(codeAlphabet, byte(r)) >= 0:
			sb.WriteRune(r)
		default:
			return "", false
		}
	}
	if sb.Len() != codeLen {
		return "", false
	}
	return sb.String(), true
}

// hashCode — SHA-256 нормализованного кода (у кода 80 бит, bcrypt не нужен).
func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// Code — код в базе; открытого значения здесь нет, в базе лежит только хеш.
type Code struct {
	ID         int64
	Days       int64
	ValidUntil int64
	UserID     *int64 // nil — код на любого пользователя
	Batch      string
	Created    int64
	CreatedBy  string
	UsedAt     *int64
	UsedNode   *int64
	UsedClient string
	Revoked    bool
}

// Состояния кода для фильтра и показа.
const (
	CodeActive  = "active"
	CodeUsed    = "used"
	CodeRevoked = "revoked"
	CodeExpired = "expired"
)

// State — состояние кода на момент now.
func (c Code) State(now int64) string {
	switch {
	case c.UsedAt != nil:
		return CodeUsed
	case c.Revoked:
		return CodeRevoked
	case c.ValidUntil < now:
		return CodeExpired
	}
	return CodeActive
}

// IssueParams — параметры выпуска пачки.
type IssueParams struct {
	Count      int
	Days       int64
	ValidUntil int64  // код можно ввести до этого момента включительно
	UserID     *int64 // nil — на любого
	CreatedBy  string
	Now        int64
}

// IssueCodes выпускает пачку и возвращает её идентификатор и открытые коды
// (в показанном виде, с дефисами). Больше открытые значения нигде не лежат.
func (s *Store) IssueCodes(ctx context.Context, p IssueParams) (batch string, codes []string, err error) {
	if p.Count < 1 || p.Count > 1000 {
		return "", nil, errors.New("число кодов в пачке — от 1 до 1000")
	}
	if p.Days < 1 {
		return "", nil, errors.New("срок продления — минимум один день")
	}
	batch, err = randHex(6)
	if err != nil {
		return "", nil, err
	}
	var uid any
	if p.UserID != nil {
		uid = *p.UserID
	}
	plain := make([]string, 0, p.Count)
	err = s.tx(ctx, func(t *sql.Tx) error {
		for i := 0; i < p.Count; i++ {
			code, err := GenerateCode()
			if err != nil {
				return err
			}
			if _, err := t.ExecContext(ctx, `INSERT INTO unlock_codes (hash, days, valid_until, user_id, batch, created, created_by)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, hashCode(code), p.Days, p.ValidUntil, uid, batch, p.Now, p.CreatedBy); err != nil {
				return err
			}
			plain = append(plain, FormatCode(code))
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return batch, plain, nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const codeCols = `id, days, valid_until, user_id, batch, created, created_by, used_at, used_node, used_client, revoked`

func scanCode(sc interface{ Scan(...any) error }) (Code, error) {
	var c Code
	var uid, usedAt, usedNode sql.NullInt64
	var usedClient sql.NullString
	if err := sc.Scan(&c.ID, &c.Days, &c.ValidUntil, &uid, &c.Batch, &c.Created, &c.CreatedBy,
		&usedAt, &usedNode, &usedClient, &c.Revoked); err != nil {
		return Code{}, err
	}
	if uid.Valid {
		c.UserID = &uid.Int64
	}
	if usedAt.Valid {
		c.UsedAt = &usedAt.Int64
	}
	if usedNode.Valid {
		c.UsedNode = &usedNode.Int64
	}
	c.UsedClient = usedClient.String
	return c, nil
}

// CodeFilter — отбор списка кодов; пустое поле не отбирает.
type CodeFilter struct {
	Batch string
	State string // CodeActive, CodeUsed, CodeRevoked, CodeExpired
}

// Codes — коды по фильтру, новые сверху; состояние считается на момент now.
func (s *Store) Codes(ctx context.Context, f CodeFilter, now int64) ([]Code, error) {
	q := `SELECT ` + codeCols + ` FROM unlock_codes WHERE 1=1`
	var args []any
	if f.Batch != "" {
		q += ` AND batch = ?`
		args = append(args, f.Batch)
	}
	switch f.State {
	case "":
	case CodeUsed:
		q += ` AND used_at IS NOT NULL`
	case CodeRevoked:
		q += ` AND used_at IS NULL AND revoked = 1`
	case CodeExpired:
		q += ` AND used_at IS NULL AND revoked = 0 AND valid_until < ?`
		args = append(args, now)
	case CodeActive:
		q += ` AND used_at IS NULL AND revoked = 0 AND valid_until >= ?`
		args = append(args, now)
	default:
		return nil, fmt.Errorf("неизвестное состояние кода %q", f.State)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Code{}
	for rows.Next() {
		c, err := scanCode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeCode отзывает непогашенный код; ErrNotFound, если такого нет или он уже погашен.
func (s *Store) RevokeCode(ctx context.Context, id int64) error {
	return s.setFields(ctx, `UPDATE unlock_codes SET revoked = 1 WHERE id = ? AND used_at IS NULL`, id)
}

// RevokeBatch отзывает все непогашенные коды пачки и возвращает их число.
func (s *Store) RevokeBatch(ctx context.Context, batch string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE unlock_codes SET revoked = 1 WHERE batch = ? AND used_at IS NULL AND revoked = 0`, batch)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RedeemCode гасит код одним UPDATE: два одновременных ввода дают ровно один
// успех. userID — владелец клиента, для которого вводят код (nil — владельца
// нет); код на конкретного пользователя гасится только для его клиентов.
// Неверный, погашенный, отозванный, просроченный и чужой код — ErrCodeInvalid.
// На каком клиенте применён код, записывает SetCodeTarget.
func (s *Store) RedeemCode(ctx context.Context, code string, userID *int64, now int64) (Code, error) {
	norm, ok := NormalizeCode(code)
	if !ok {
		return Code{}, ErrCodeInvalid
	}
	var uid any
	if userID != nil {
		uid = *userID
	}
	c, err := scanCode(s.db.QueryRowContext(ctx, `UPDATE unlock_codes SET used_at = ?
		WHERE hash = ? AND used_at IS NULL AND revoked = 0 AND valid_until >= ?
		  AND (user_id IS NULL OR user_id = ?)
		RETURNING `+codeCols, now, hashCode(norm), now, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return Code{}, ErrCodeInvalid
	}
	return c, err
}

// SetCodeTarget записывает в погашенный код, на каком клиенте его применили.
func (s *Store) SetCodeTarget(ctx context.Context, id, node int64, client string) error {
	return s.setFields(ctx, `UPDATE unlock_codes SET used_node = ?, used_client = ? WHERE id = ? AND used_at IS NOT NULL`, node, client, id)
}
