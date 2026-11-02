package panel

import (
	"strings"
	"sync"
	"sync/atomic"
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

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if !l.Begin("1.1.1.1") {
			t.Fatalf("попытка %d отклонена", i+1)
		}
	}
	if l.Begin("1.1.1.1") {
		t.Fatal("шестая попытка прошла")
	}
	if !l.Begin("2.2.2.2") {
		t.Fatal("чужой адрес задет")
	}
	now = now.Add(l.Window + time.Second)
	if !l.Begin("1.1.1.1") {
		t.Fatal("блокировка не снялась по окну")
	}
	for i := 0; i < 4; i++ {
		l.Begin("3.3.3.3")
	}
	l.Reset("3.3.3.3")
	for i := 0; i < 5; i++ {
		if !l.Begin("3.3.3.3") {
			t.Fatalf("после Reset попытка %d отклонена", i+1)
		}
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter()
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Begin("1.1.1.1") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 5 {
		t.Fatalf("разрешено %d попыток, ждали 5", allowed.Load())
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
