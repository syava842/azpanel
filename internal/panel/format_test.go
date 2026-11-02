package panel

import (
	"testing"
	"time"
)

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{0: "0 Б", 1023: "1023 Б", 1536: "1.5 КБ", 5 << 30: "5.0 ГБ", 3 << 40: "3.0 ТБ", 2048 << 40: "2048.0 ТБ"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, нужно %q", in, got, want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		40 * time.Second:              "40 с",
		5*time.Hour + 12*time.Minute:  "5 ч 12 мин",
		76 * time.Hour:                "3 д 4 ч",
		2*time.Minute + 3*time.Second: "2 мин 3 с",
		-time.Second:                  "0 с",
	}
	for in, want := range cases {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%v) = %q, нужно %q", in, got, want)
		}
	}
}
