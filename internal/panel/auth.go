// Package panel — веб-панель: вход, сессии, страницы клиентов и
// мониторинга. Пользователи и сессии лежат в базе (internal/store).
package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/syava842/azpanel/internal/store"
)

const (
	SecretAdminUser = "PANEL_ADMIN_USER"
	SecretAdminHash = "PANEL_ADMIN_HASH"
	SecretDataKey   = "PANEL_DATA_KEY"
	cookieName      = "azpanel_session"
	bcryptCost      = 12

	minPasswordLen = 10
	maxPasswordLen = 72 // предел bcrypt, байт
)

// HashPassword — bcrypt с bcryptCost.
func HashPassword(pw string) (string, error) {
	if utf8.RuneCountInString(pw) < minPasswordLen {
		return "", errors.New("пароль короче 10 символов")
	}
	if len(pw) > maxPasswordLen {
		return "", errors.New("пароль длиннее 72 байт")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// dummyHash — фиктивный хеш для выравнивания времени ответа.
var dummyHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("azpanel-dummy-password"), bcryptCost)
	if err != nil {
		panic(err)
	}
	return h
}()

// CheckPassword: имя сверяется за постоянное время, пароль — bcrypt;
// bcrypt выполняется всегда, чтобы время ответа не выдавало, есть ли имя.
func CheckPassword(wantUser, hash, user, pw string) bool {
	nameOK := subtle.ConstantTimeCompare([]byte(wantUser), []byte(user)) == 1
	h := []byte(hash)
	if hash == "" {
		h = dummyHash
	}
	passOK := bcrypt.CompareHashAndPassword(h, []byte(pw)) == nil
	return hash != "" && nameOK && passOK
}

// SameCSRF — сравнение за постоянное время, пустые — не равны.
func SameCSRF(want, got string) bool {
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func randomHex() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Session — сессия запроса: то, что нужно обработчикам. В базе лежит
// store.Session (хеш идентификатора); здесь к ней добавлены данные
// пользователя, прочитанные на этом запросе.
type Session struct {
	IDHash     string // SHA-256 от cookie, hex
	CSRF       string
	UserID     int64
	User       string // логин
	Role       string // store.RoleAdmin | store.RoleUser
	MustChange bool   // нужно сменить пароль
	Has2FA     bool   // у пользователя включена 2FA
	MFAPending bool   // пароль верен, код 2FA ещё не введён
	Expires    time.Time
}

// IsAdmin — роль «администратор».
func (s Session) IsAdmin() bool { return s.Role == store.RoleAdmin }

// hashSessionID — то, что хранится в базе вместо идентификатора из cookie.
func hashSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// Limiter — попытки входа по адресу.
type Limiter struct {
	Max    int           // 5
	Window time.Duration // 15 мин
	Now    func() time.Time

	mu sync.Mutex
	m  map[string][]time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{Max: 5, Window: 15 * time.Minute, Now: time.Now, m: map[string][]time.Time{}}
}

// prune оставляет попытки внутри окна; зовётся под l.mu.
func (l *Limiter) prune(now time.Time) {
	for addr, ts := range l.m {
		keep := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < l.Window {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(l.m, addr)
		} else {
			l.m[addr] = keep
		}
	}
}

// Begin засчитывает попытку входа ДО проверки пароля, в одной критической
// секции с проверкой лимита: параллельные запросы не обходят ограничение.
// false — лимит исчерпан, пароль проверять нельзя. Успешный вход снимает
// счётчик через Reset; неудачный оставляет отметку как есть.
func (l *Limiter) Begin(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	l.prune(now)
	if len(l.m[addr]) >= l.Max {
		return false
	}
	l.m[addr] = append(l.m[addr], now)
	return true
}

func (l *Limiter) Reset(addr string) {
	l.mu.Lock()
	delete(l.m, addr)
	l.mu.Unlock()
}
