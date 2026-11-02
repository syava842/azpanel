package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Роли пользователей панели.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

var (
	// ErrNotFound — нет такой записи.
	ErrNotFound = errors.New("не найдено")
	// ErrLoginTaken — логин уже занят.
	ErrLoginTaken = errors.New("логин уже занят")
	// ErrPasswordChanged — пароль изменили, пока шла смена.
	ErrPasswordChanged = errors.New("пароль уже изменён, повторите")
	// ErrTOTPAlreadyOn — двухфакторная проверка уже включена.
	ErrTOTPAlreadyOn = errors.New("двухфакторная проверка уже включена")
)

// User — пользователь панели. TOTPSecret — зашифрованный секрет (nil — 2FA
// выключена); TOTPLastStep — последний принятый шаг TOTP.
type User struct {
	ID           int64
	Login        string
	Hash         string
	Role         string
	Disabled     bool
	MustChange   bool
	TOTPSecret   []byte
	TOTPLastStep int64
	Created      int64
	// AccessUntil — срок доступа пользователя (nil — без срока); пишется
	// только SetUserAccessUntil.
	AccessUntil *int64
}

// ClientRef — ссылка на клиента: узел и имя.
type ClientRef struct {
	Node int64
	Name string
}

const userCols = `id, login, hash, role, disabled, must_change, totp_secret, totp_last_step, created, access_until`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var until sql.NullInt64
	if err := sc.Scan(&u.ID, &u.Login, &u.Hash, &u.Role, &u.Disabled, &u.MustChange, &u.TOTPSecret, &u.TOTPLastStep, &u.Created, &until); err != nil {
		return User{}, err
	}
	if until.Valid {
		v := until.Int64
		u.AccessUntil = &v
	}
	return u, nil
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateUser добавляет пользователя и возвращает его с присвоенным ID.
func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (login, hash, role, disabled, must_change, totp_secret, totp_last_step, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Login, u.Hash, u.Role, u.Disabled, u.MustChange, u.TOTPSecret, u.TOTPLastStep, u.Created)
	if isUnique(err) {
		return User{}, ErrLoginTaken
	}
	if err != nil {
		return User{}, err
	}
	u.ID, err = res.LastInsertId()
	return u, err
}

// UserByLogin — пользователь по логину; ErrNotFound, если нет.
func (s *Store) UserByLogin(ctx context.Context, login string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE login = ?`, login))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// UserByID — пользователь по ID; ErrNotFound, если нет.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// Users — все пользователи по логину.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY login`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser меняет все изменяемые поля строки разом. Для работы панели не
// годится: запись из давно прочитанной структуры затирает чужие правки. Панель
// пользуется точечными методами ниже; этот остаётся для тестов и подготовки данных.
func (s *Store) UpdateUser(ctx context.Context, u User) error {
	return s.setFields(ctx, `UPDATE users SET role = ?, disabled = ?, must_change = ?, hash = ?,
		totp_secret = ?, totp_last_step = ? WHERE id = ?`,
		u.Role, u.Disabled, u.MustChange, u.Hash, u.TOTPSecret, u.TOTPLastStep, u.ID)
}

// setFields выполняет точечный UPDATE; ErrNotFound, если строки нет.
func (s *Store) setFields(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword безусловно задаёт хеш и признак обязательной смены (сброс
// администратором, командная строка).
func (s *Store) SetPassword(ctx context.Context, id int64, hash string, mustChange bool) error {
	return s.setFields(ctx, `UPDATE users SET hash = ?, must_change = ? WHERE id = ?`, hash, mustChange, id)
}

// ChangePassword меняет пароль, только если хеш всё ещё равен oldHash, то
// есть с момента проверки старого пароля никто его не менял (иначе
// ErrPasswordChanged): сброс, сделанный параллельно, не теряется.
func (s *Store) ChangePassword(ctx context.Context, id int64, oldHash, newHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET hash = ?, must_change = 0 WHERE id = ? AND hash = ?`, newHash, id, oldHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPasswordChanged
	}
	return nil
}

// SetRole меняет только роль.
func (s *Store) SetRole(ctx context.Context, id int64, role string) error {
	return s.setFields(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id)
}

// SetUserAccessUntil меняет только срок доступа пользователя (nil — снять срок).
func (s *Store) SetUserAccessUntil(ctx context.Context, id int64, until *int64) error {
	var v any
	if until != nil {
		v = *until
	}
	return s.setFields(ctx, `UPDATE users SET access_until = ? WHERE id = ?`, v, id)
}

// SetDisabled меняет только признак отключения.
func (s *Store) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	return s.setFields(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id)
}

// SetTOTP безусловно задаёт секрет 2FA и последний шаг (nil, 0 — выключить).
func (s *Store) SetTOTP(ctx context.Context, id int64, secret []byte, lastStep int64) error {
	return s.setFields(ctx, `UPDATE users SET totp_secret = ?, totp_last_step = ? WHERE id = ?`, secret, lastStep, id)
}

// EnableTOTP включает 2FA, только если она ещё выключена (ErrTOTPAlreadyOn).
func (s *Store) EnableTOTP(ctx context.Context, id int64, secret []byte, lastStep int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_last_step = ?
		WHERE id = ? AND (totp_secret IS NULL OR length(totp_secret) = 0)`, secret, lastStep, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTOTPAlreadyOn
	}
	return nil
}

// AdvanceTOTPStep продвигает последний принятый шаг, только если он больше
// прежнего и 2FA включена. false — шаг уже принят другим запросом или 2FA
// успели выключить.
func (s *Store) AdvanceTOTPStep(ctx context.Context, id, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step = ?
		WHERE id = ? AND totp_last_step < ? AND totp_secret IS NOT NULL AND length(totp_secret) > 0`, step, id, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DeleteUser удаляет пользователя; сессии и коды уходят каскадом, у его
// клиентов владелец снимается.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// AdminCount — число не отключённых администраторов.
func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// SetBackupCodes заменяет все резервные коды пользователя; hashes — bcrypt.
func (s *Store) SetBackupCodes(ctx context.Context, userID int64, hashes []string) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `DELETE FROM backup_codes WHERE user_id = ?`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := t.ExecContext(ctx, `INSERT INTO backup_codes (user_id, hash) VALUES (?, ?)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// UseBackupCode сверяет код с неиспользованными и атомарно помечает
// совпавший использованным: из двух параллельных вызовов true получит один.
func (s *Store) UseBackupCode(ctx context.Context, userID int64, code string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rowid, hash FROM backup_codes WHERE user_id = ? AND used = 0`, userID)
	if err != nil {
		return false, err
	}
	var match int64
	for rows.Next() {
		var id int64
		var h string
		if err := rows.Scan(&id, &h); err != nil {
			rows.Close()
			return false, err
		}
		if match == 0 && bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			match = id
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || match == 0 {
		return false, err
	}
	// used = 0 в условии: проигравший гонку получит 0 изменённых строк.
	res, err := s.db.ExecContext(ctx, `UPDATE backup_codes SET used = 1 WHERE rowid = ? AND used = 0`, match)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// SetOwner назначает владельца клиента (nil — снимает). Назначение создаёт
// карточку по умолчанию, если её нет; снятие без карточки ничего не делает.
func (s *Store) SetOwner(ctx context.Context, node int64, client string, userID *int64) error {
	if userID != nil {
		_, err := s.db.ExecContext(ctx, `INSERT INTO client_cards (node_id, name, owner_id) VALUES (?, ?, ?)
			ON CONFLICT(node_id, name) DO UPDATE SET owner_id = excluded.owner_id`, node, client, *userID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE client_cards SET owner_id = NULL WHERE node_id = ? AND name = ?`, node, client)
	return err
}

// ClientsOf — клиенты пользователя по узлу и имени.
func (s *Store) ClientsOf(ctx context.Context, userID int64) ([]ClientRef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, name FROM client_cards WHERE owner_id = ? ORDER BY node_id, name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientRef{}
	for rows.Next() {
		var r ClientRef
		if err := rows.Scan(&r.Node, &r.Name); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OwnedClients — имена клиентов узла, у которых есть владелец.
func (s *Store) OwnedClients(ctx context.Context, node int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM client_cards WHERE node_id = ? AND owner_id IS NOT NULL ORDER BY name`, node)
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

// OwnerOf — владелец клиента; ok=false, если владельца нет.
func (s *Store) OwnerOf(ctx context.Context, node int64, client string) (userID int64, ok bool, err error) {
	var id sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT owner_id FROM client_cards WHERE node_id = ? AND name = ?`, node, client).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id.Int64, id.Valid, nil
}
