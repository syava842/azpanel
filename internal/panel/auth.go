// Package panel — веб-панель администратора: вход, сессии, страницы
// клиентов и мониторинга. Своего хранилища нет, состояние берётся у агента.
package panel

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	SecretAdminUser = "PANEL_ADMIN_USER"
	SecretAdminHash = "PANEL_ADMIN_HASH"
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

type Session struct {
	ID      string // 32 случайных байта, hex
	CSRF    string // 32 случайных байта, hex
	User    string
	Expires time.Time
}

// Sessions — сессии в памяти: перезапуск панели выводит всех.
type Sessions struct {
	TTL time.Duration
	Now func() time.Time

	mu sync.Mutex
	m  map[string]Session
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{TTL: ttl, Now: time.Now, m: map[string]Session{}}
}

func (s *Sessions) Create(user string) (Session, error) {
	id, err := randomHex()
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomHex()
	if err != nil {
		return Session{}, err
	}
	now := s.Now()
	sess := Session{ID: id, CSRF: csrf, User: user, Expires: now.Add(s.TTL)}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m { // истёкшие вычищаются при обращении
		if !now.Before(v.Expires) {
			delete(s.m, k)
		}
	}
	s.m[id] = sess
	return sess, nil
}

// Get: истёкшую сессию удаляет и не отдаёт.
func (s *Sessions) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return Session{}, false
	}
	if !s.Now().Before(sess.Expires) {
		delete(s.m, id)
		return Session{}, false
	}
	return sess, true
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// Limiter — неверные попытки входа по адресу.
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

func (l *Limiter) Blocked(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(l.Now())
	return len(l.m[addr]) >= l.Max
}

func (l *Limiter) Fail(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	l.prune(now)
	l.m[addr] = append(l.m[addr], now)
}

func (l *Limiter) Reset(addr string) {
	l.mu.Lock()
	delete(l.m, addr)
	l.mu.Unlock()
}
