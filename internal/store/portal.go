package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// ErrLinkGone — ссылки нет, она просрочена, использована или закрыта; причину
// наружу не отличаем.
var ErrLinkGone = errors.New("ссылка недействительна")

// ErrPINWrong — неверный PIN одноразовой ссылки.
var ErrPINWrong = errors.New("неверный PIN")

// MaxPINFails — столько неверных PIN закрывают ссылку навсегда.
const MaxPINFails = 5

// Виды ссылки портала.
const (
	LinkClient = "c" // один клиент
	LinkUser   = "u" // все клиенты пользователя
)

// NewToken — 32 случайных байта в base64url (без дополнения).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken — SHA-256 токена в hex; в базе лежит только он.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// PortalLink — ссылка портала. Для LinkClient заданы Node и Client, для
// LinkUser — UserID.
type PortalLink struct {
	Hash    string
	Kind    string
	Node    int64
	Client  string
	UserID  int64
	Created int64
}

// CreateClientLink выпускает ссылку клиента, заменяя прежнюю; возвращает токен
// (открытым он нигде не хранится).
func (s *Store) CreateClientLink(ctx context.Context, node int64, client string, now int64) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	err = s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `DELETE FROM portal_links WHERE kind = 'c' AND node_id = ? AND client = ?`, node, client); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx, `INSERT INTO portal_links (hash, kind, node_id, client, created) VALUES (?, 'c', ?, ?, ?)`,
			HashToken(token), node, client, now)
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// CreateUserLink выпускает ссылку пользователя, заменяя прежнюю.
func (s *Store) CreateUserLink(ctx context.Context, userID, now int64) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	err = s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `DELETE FROM portal_links WHERE kind = 'u' AND user_id = ?`, userID); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx, `INSERT INTO portal_links (hash, kind, user_id, created) VALUES (?, 'u', ?, ?)`,
			HashToken(token), userID, now)
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// PortalLinkByToken — ссылка по токену; ErrLinkGone, если нет.
func (s *Store) PortalLinkByToken(ctx context.Context, token string) (PortalLink, error) {
	var l PortalLink
	var node, uid sql.NullInt64
	var client sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT hash, kind, node_id, client, user_id, created FROM portal_links WHERE hash = ?`,
		HashToken(token)).Scan(&l.Hash, &l.Kind, &node, &client, &uid, &l.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return PortalLink{}, ErrLinkGone
	}
	if err != nil {
		return PortalLink{}, err
	}
	l.Node, l.Client, l.UserID = node.Int64, client.String, uid.Int64
	return l, nil
}

// DeleteClientLink снимает ссылку клиента (если была).
func (s *Store) DeleteClientLink(ctx context.Context, node int64, client string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM portal_links WHERE kind = 'c' AND node_id = ? AND client = ?`, node, client)
	return err
}

// DeleteUserLink снимает ссылку пользователя (если была).
func (s *Store) DeleteUserLink(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM portal_links WHERE kind = 'u' AND user_id = ?`, userID)
	return err
}

// DeleteDownloadLinks снимает все одноразовые ссылки клиента: после удаления
// и пересоздания клиента с тем же именем старая ссылка не должна отдавать
// новые ключи.
func (s *Store) DeleteDownloadLinks(ctx context.Context, node int64, client string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM download_links WHERE node_id = ? AND client = ?`, node, client)
	return err
}

// LinkedClients — имена клиентов узла, у которых есть ссылка портала или
// одноразовая ссылка.
func (s *Store) LinkedClients(ctx context.Context, node int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client FROM portal_links WHERE kind = 'c' AND node_id = ?
		UNION SELECT client FROM download_links WHERE node_id = ? ORDER BY 1`, node, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DownloadLink — одноразовая ссылка на скачивание файла конфигурации.
type DownloadLink struct {
	Hash     string
	Node     int64
	Client   string
	PKind    string // вид протокола
	Variant  string
	File     string
	HasPIN   bool
	PINFails int64
	Expires  int64
	Created  int64
}

// DownloadParams — параметры выпуска одноразовой ссылки. PIN пустой — без PIN.
type DownloadParams struct {
	Node    int64
	Client  string
	PKind   string
	Variant string
	File    string
	PIN     string
	Expires int64
	Now     int64
}

// pinHash привязывает PIN к токену ссылки, чтобы одинаковые PIN не совпадали.
func pinHash(token, pin string) string {
	h := sha256.Sum256([]byte(token + ":" + pin))
	return hex.EncodeToString(h[:])
}

// CreateDownloadLink выпускает одноразовую ссылку и возвращает токен.
func (s *Store) CreateDownloadLink(ctx context.Context, p DownloadParams) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	var pin any
	if p.PIN != "" {
		pin = pinHash(token, p.PIN)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO download_links (hash, node_id, client, pkind, variant, file, pin_hash, expires, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		HashToken(token), p.Node, p.Client, p.PKind, p.Variant, p.File, pin, p.Expires, p.Now)
	if err != nil {
		return "", err
	}
	return token, nil
}

// DownloadLinkByToken — живая ссылка: не использована, не просрочена на
// момент now, не закрыта ошибками PIN; иначе ErrLinkGone.
func (s *Store) DownloadLinkByToken(ctx context.Context, token string, now int64) (DownloadLink, error) {
	var l DownloadLink
	var pin sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT hash, node_id, client, pkind, variant, file, pin_hash, pin_fails, expires, created
		FROM download_links WHERE hash = ? AND used = 0 AND expires >= ? AND pin_fails < ?`,
		HashToken(token), now, MaxPINFails).
		Scan(&l.Hash, &l.Node, &l.Client, &l.PKind, &l.Variant, &l.File, &pin, &l.PINFails, &l.Expires, &l.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return DownloadLink{}, ErrLinkGone
	}
	l.HasPIN = pin.Valid
	return l, err
}

// CheckDownloadPIN проверяет PIN. Неверный PIN растит счётчик (MaxPINFails
// ошибок закрывают ссылку навсегда) и даёт ErrPINWrong; мёртвая ссылка —
// ErrLinkGone. У ссылки без PIN проверка проходит.
func (s *Store) CheckDownloadPIN(ctx context.Context, token, pin string, now int64) error {
	h, ph := HashToken(token), pinHash(token, pin)
	res, err := s.db.ExecContext(ctx, `UPDATE download_links SET pin_fails = pin_fails + 1
		WHERE hash = ? AND used = 0 AND expires >= ? AND pin_fails < ? AND pin_hash IS NOT NULL AND pin_hash <> ?`,
		h, now, MaxPINFails, ph)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return ErrPINWrong
	}
	var one int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM download_links
		WHERE hash = ? AND used = 0 AND expires >= ? AND pin_fails < ? AND (pin_hash IS NULL OR pin_hash = ?)`,
		h, now, MaxPINFails, ph).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLinkGone
	}
	return err
}

// MarkDownloadUsed атомарно отмечает использование; второй вызов даёт ErrLinkGone.
func (s *Store) MarkDownloadUsed(ctx context.Context, token string, now int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE download_links SET used = 1
		WHERE hash = ? AND used = 0 AND expires >= ? AND pin_fails < ?`, HashToken(token), now, MaxPINFails)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLinkGone
	}
	return nil
}

// Attempt записывает попытку под ключом key (например, «code:<хеш токена>»).
func (s *Store) Attempt(ctx context.Context, key string, now int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO attempts (key, ts) VALUES (?, ?)`, key, now)
	return err
}

// Attempts — число попыток под ключом начиная с момента since включительно.
func (s *Store) Attempts(ctx context.Context, key string, since int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM attempts WHERE key = ? AND ts >= ?`, key, since).Scan(&n)
	return n, err
}

// LastAttempt — время самой поздней попытки под ключом начиная с since
// включительно; ok=false — попыток нет.
func (s *Store) LastAttempt(ctx context.Context, key string, since int64) (ts int64, ok bool, err error) {
	var v sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT max(ts) FROM attempts WHERE key = ? AND ts >= ?`, key, since).Scan(&v)
	return v.Int64, v.Valid, err
}

// RefundAttempt снимает одну попытку под ключом key, записанную в момент ts
// (резерв, не оправдавшийся ошибкой кода).
func (s *Store) RefundAttempt(ctx context.Context, key string, ts int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM attempts WHERE rowid = (SELECT rowid FROM attempts WHERE key = ? AND ts = ? LIMIT 1)`, key, ts)
	return err
}

// PurgeAttempts стирает попытки старше before.
func (s *Store) PurgeAttempts(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM attempts WHERE ts < ?`, before)
	return err
}

// EffectiveUntil — действующий срок клиента: меньший из срока карточки и срока
// владельца; nil — ограничения нет (любой NULL не ограничивает).
func (s *Store) EffectiveUntil(ctx context.Context, node int64, client string) (*int64, error) {
	var card, owner sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT c.access_until, u.access_until FROM client_cards c
		LEFT JOIN users u ON u.id = c.owner_id WHERE c.node_id = ? AND c.name = ?`, node, client).Scan(&card, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case card.Valid && owner.Valid:
		v := min(card.Int64, owner.Int64)
		return &v, nil
	case card.Valid:
		return &card.Int64, nil
	case owner.Valid:
		return &owner.Int64, nil
	}
	return nil, nil
}

// ClientLinkCreated — когда выпущена ссылка клиента; ok=false — ссылки нет.
func (s *Store) ClientLinkCreated(ctx context.Context, node int64, client string) (created int64, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT created FROM portal_links WHERE kind = 'c' AND node_id = ? AND client = ?`, node, client).Scan(&created)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return created, err == nil, err
}

// UserLinkCreated — когда выпущена ссылка пользователя; ok=false — ссылки нет.
func (s *Store) UserLinkCreated(ctx context.Context, userID int64) (created int64, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT created FROM portal_links WHERE kind = 'u' AND user_id = ?`, userID).Scan(&created)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return created, err == nil, err
}
