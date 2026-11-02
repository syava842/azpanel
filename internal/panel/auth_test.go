package panel

import (
	"strings"
	"testing"
	"time"
)

func TestHashPasswordAndCheck(t *testing.T) {
	if _, err := HashPassword("короткий"); err == nil {
		t.Fatal("короткий пароль должен отклоняться")
	}
	if _, err := HashPassword(strings.Repeat("a", 73)); err == nil {
		t.Fatal("пароль длиннее 72 байт должен отклоняться")
	}
	h, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("admin", h, "admin", "correct-horse-battery") {
		t.Error("верная пара не прошла")
	}
	if CheckPassword("admin", h, "admin", "wrong-password-1") {
		t.Error("неверный пароль прошёл")
	}
	if CheckPassword("admin", h, "root", "correct-horse-battery") {
		t.Error("неверное имя прошло")
	}
	if CheckPassword("admin", "", "admin", "correct-horse-battery") {
		t.Error("пустой hash прошёл")
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions(time.Hour)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	a, err := s.Create("admin")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.Create("admin")
	if a.ID == b.ID || a.CSRF == b.CSRF || len(a.ID) != 64 || len(a.CSRF) != 64 || a.ID == a.CSRF {
		t.Fatalf("идентификаторы: %q %q", a.ID, a.CSRF)
	}
	if got, ok := s.Get(a.ID); !ok || got.User != "admin" {
		t.Fatal("сессия до срока не найдена")
	}
	now = now.Add(time.Hour + time.Second)
	if _, ok := s.Get(a.ID); ok {
		t.Fatal("истёкшая сессия отдана")
	}
	if _, ok := s.m[a.ID]; ok {
		t.Fatal("истёкшая сессия не удалена")
	}
	c, _ := s.Create("admin")
	s.Delete(c.ID)
	if _, ok := s.Get(c.ID); ok {
		t.Fatal("удалённая сессия найдена")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		l.Fail("1.1.1.1")
	}
	if l.Blocked("1.1.1.1") {
		t.Fatal("заблокирован после 4 попыток")
	}
	l.Fail("1.1.1.1")
	if !l.Blocked("1.1.1.1") {
		t.Fatal("не заблокирован после 5 попыток")
	}
	if l.Blocked("2.2.2.2") {
		t.Fatal("чужой адрес задет")
	}
	now = now.Add(l.Window + time.Second)
	if l.Blocked("1.1.1.1") {
		t.Fatal("блокировка не снялась по окну")
	}
	for i := 0; i < 5; i++ {
		l.Fail("3.3.3.3")
	}
	l.Reset("3.3.3.3")
	if l.Blocked("3.3.3.3") {
		t.Fatal("Reset не снял блокировку")
	}
}

func TestSameCSRF(t *testing.T) {
	if SameCSRF("", "") {
		t.Error("пустые равны")
	}
	if !SameCSRF("abc", "abc") {
		t.Error("равные не равны")
	}
	if SameCSRF("abc", "abd") {
		t.Error("разные равны")
	}
}
