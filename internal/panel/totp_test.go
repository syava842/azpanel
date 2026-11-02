package panel

import (
	"strings"
	"testing"
	"time"
)

var rfcSecret = []byte("12345678901234567890")

func TestTOTPRFC6238Vectors(t *testing.T) {
	for unix, want := range map[int64]string{
		59: "287082", 1111111109: "081804", 1111111111: "050471",
		1234567890: "005924", 2000000000: "279037",
	} {
		if got := TOTPCode(rfcSecret, unix/30); got != want {
			t.Errorf("t=%d: %s, ждали %s", unix, got, want)
		}
	}
}

func TestCheckTOTPReplayAndWindow(t *testing.T) {
	now := time.Unix(1234567890, 0)
	step := int64(1234567890 / 30)
	st, ok := CheckTOTP(rfcSecret, TOTPCode(rfcSecret, step), now, 0)
	if !ok || st != step {
		t.Fatalf("текущий шаг: %d %v", st, ok)
	}
	if _, ok := CheckTOTP(rfcSecret, TOTPCode(rfcSecret, step), now, step); ok {
		t.Fatal("повтор шага принят")
	}
	if st, ok := CheckTOTP(rfcSecret, TOTPCode(rfcSecret, step-1), now, 0); !ok || st != step-1 {
		t.Fatalf("-1: %d %v", st, ok)
	}
	if st, ok := CheckTOTP(rfcSecret, TOTPCode(rfcSecret, step+1), now, 0); !ok || st != step+1 {
		t.Fatalf("+1: %d %v", st, ok)
	}
	if _, ok := CheckTOTP(rfcSecret, TOTPCode(rfcSecret, step+2), now, 0); ok {
		t.Fatal("+2 принят")
	}
	if _, ok := CheckTOTP(rfcSecret, TOTPCode(rfcSecret, step-2), now, 0); ok {
		t.Fatal("-2 принят")
	}
	// шаг не больше lastStep отвергается, даже если код верен для окна
	if _, ok := CheckTOTP(rfcSecret, TOTPCode(rfcSecret, step-1), now, step); ok {
		t.Fatal("старый шаг принят после нового")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if _, ok := CheckTOTP(rfcSecret, bad, now, 0); ok && bad != TOTPCode(rfcSecret, step) {
			t.Errorf("принят %q", bad)
		}
	}
}

func TestNewTOTPSecretAndURL(t *testing.T) {
	a, err := NewTOTPSecret()
	b, _ := NewTOTPSecret()
	if err != nil || len(a) != 20 || string(a) == string(b) {
		t.Fatalf("%x %x %v", a, b, err)
	}
	u := TOTPURL("AZPanel", "bob", rfcSecret)
	want := "otpauth://totp/AZPanel:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=AZPanel&digits=6&period=30"
	if u != want {
		t.Fatalf("%s", u)
	}
	if strings.Contains(u, "=&") || strings.Contains(strings.SplitN(u, "&", 2)[0], "==") {
		t.Fatal("в секрете остался padding")
	}
}

func TestSealOpen(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sealed, err := Seal(key, []byte("секрет"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, sealed)
	if err != nil || string(got) != "секрет" {
		t.Fatalf("%q %v", got, err)
	}
	s2, _ := Seal(key, []byte("секрет"))
	if string(s2) == string(sealed) {
		t.Fatal("nonce повторился")
	}
	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 1
	if _, err := Open(key, bad); err == nil {
		t.Fatal("подмена не замечена")
	}
	if _, err := Open(key, sealed[:5]); err == nil {
		t.Fatal("короткий вход принят")
	}
	if _, err := Seal(key[:16], []byte("x")); err == nil {
		t.Fatal("короткий ключ принят")
	}
}
