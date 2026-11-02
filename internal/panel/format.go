package panel

import (
	"fmt"
	"time"
)

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

// humanDuration: «3 д 4 ч», «5 ч 12 мин», «40 с»; две старшие единицы.
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
	case mins > 0:
		return fmt.Sprintf("%d мин %d с", mins, s%60)
	}
	return fmt.Sprintf("%d с", s)
}

// formatTime — время UTC, до минуты, с подписью; nil — прочерк.
func formatTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}
