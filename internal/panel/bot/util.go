package bot

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/telegram"
)

func randToken() string {
	var x [6]byte
	if _, err := rand.Read(x[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(x[:])
}

// humanBytes: Б, КБ, МБ, ГБ, ТБ; один знак после точки, кроме байтов.
func humanBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d Б", n)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ"}
	v := float64(n) / 1024
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func humanDuration(d time.Duration) string {
	s := int64(d / time.Second)
	if s < 0 {
		s = 0
	}
	days, hours, mins := s/86400, s%86400/3600, s%3600/60
	switch {
	case days > 0:
		return fmt.Sprintf("%d д %d ч", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d ч %d мин", hours, mins)
	}
	return fmt.Sprintf("%d мин", mins)
}

func untilText(until *int64) string {
	if until == nil {
		return "без срока"
	}
	return time.Unix(*until, 0).UTC().Format("2006-01-02 15:04") + " UTC"
}

// keyboard собирает клавиатуру из рядов кнопок.
func keyboard(rows ...[]telegram.InlineKeyboardButton) *telegram.InlineKeyboardMarkup {
	return &telegram.InlineKeyboardMarkup{InlineKeyboard: rows}
}

func btn(text, data string) telegram.InlineKeyboardButton {
	return telegram.InlineKeyboardButton{Text: text, CallbackData: data}
}

func row(bs ...telegram.InlineKeyboardButton) []telegram.InlineKeyboardButton { return bs }

// cb склеивает данные кнопки: операция и аргументы через двоеточие. Имена
// клиентов двоеточий не содержат, а длина данных не больше 64 байт.
func cb(op string, args ...any) string {
	parts := []string{op}
	for _, a := range args {
		parts = append(parts, fmt.Sprint(a))
	}
	return strings.Join(parts, ":")
}

func displayName(u *telegram.User) string {
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name == "" {
		name = u.Username
	}
	return name
}
