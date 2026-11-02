package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	totpPeriod = 30 // шаг TOTP, секунд
	totpDigits = 6
)

// NewTOTPSecret — новый случайный секрет TOTP (20 байт).
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// TOTPURL — адрес otpauth:// для QR-кода приложения-аутентификатора.
func TOTPURL(issuer, login string, secret []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		url.PathEscape(issuer), url.PathEscape(login), enc, url.QueryEscape(issuer), totpDigits, totpPeriod)
}

// TOTPCode — шестизначный код RFC 6238 (HMAC-SHA1) для номера шага.
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1000000)
}

// CheckTOTP проверяет код в окне ±1 шаг от now. Шаг не больше lastStep
// отвергается: принятый код повторно не проходит. Возвращает принятый шаг.
func CheckTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for step := cur - 1; step <= cur+1; step++ {
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(TOTPCode(secret, step))) == 1 {
			return step, true
		}
	}
	return 0, false
}
