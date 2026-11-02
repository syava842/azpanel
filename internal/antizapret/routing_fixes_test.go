package antizapret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Комментарии hosts и ips — любая строка со знака препинания (parse.sh:
// /^[[:punct:]]/d); одиночная точка — запись только в include-hosts и
// include-warp-hosts.
func TestIsEntryPunctuationComments(t *testing.T) {
	for _, line := range []string{"# c", "; c", "// c", "! c", "  ; c", "-x.com", "*.x.com", "[x]", "."} {
		if isEntry(KindHosts, "exclude-hosts.txt", line) {
			t.Errorf("hosts: %q должно быть комментарием", line)
		}
		if isEntry(KindIPs, "include-ips.txt", line) {
			t.Errorf("ips: %q должно быть комментарием", line)
		}
	}
	for _, n := range []string{"include-hosts.txt", "include-warp-hosts.txt"} {
		if !isEntry(KindHosts, n, " . ") {
			t.Errorf("%s: точка — запись", n)
		}
	}
	if !isEntry(KindHosts, "include-hosts.txt", "example.com") || !isEntry(KindIPs, "include-ips.txt", "1.2.3.0/24") {
		t.Error("обычные записи должны оставаться записями")
	}
	// rpz: комментарий только «;».
	if isEntry(KindRPZ, "deny-rpz.txt", "; z") || !isEntry(KindRPZ, "deny-rpz.txt", "$TTL 86400") || !isEntry(KindRPZ, "deny-rpz.txt", "# x CNAME .") {
		t.Error("rpz: комментарий — только строка на «;»")
	}
}

// «Целиком» сохраняет файл, где комментарии написаны на «//» и «!».
func TestReplaceKeepsPunctuationComments(t *testing.T) {
	orig := "// раздел\n! заметка\n; ещё\nexample.com\n"
	r := newRouting(t, map[string]string{"exclude-hosts.txt": orig})
	n, errs, err := r.Replace("exclude-hosts.txt", orig, "")
	if err != nil || len(errs) != 0 || n != 1 {
		t.Fatalf("%d %v %v", n, errs, err)
	}
	if got := readFile(t, r, "exclude-hosts.txt"); got != orig {
		t.Fatalf("комментарии потеряны: %q", got)
	}
	if pg, _ := r.Lines("exclude-hosts.txt", "", 0, 10); pg.Total != 1 {
		t.Fatalf("в просмотре записей %d, ожидалась одна", pg.Total)
	}
}

func TestRawAndBaseSHA(t *testing.T) {
	orig := "# заметка\n\nexample.com\n"
	r := newRouting(t, map[string]string{"include-hosts.txt": orig})
	content, sum, err := r.Raw("include-hosts.txt")
	if err != nil || content != orig || sum != SHA256([]byte(orig)) || len(sum) != 64 {
		t.Fatalf("%q %q %v", content, sum, err)
	}
	// Другой администратор дописал строку после чтения.
	if _, err := r.Patch("include-hosts.txt", []string{"new.example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, r, "include-hosts.txt")
	if _, _, err := r.Replace("include-hosts.txt", "x.example.com\n", sum); !errors.Is(err, ErrChanged) {
		t.Fatalf("ожидался ErrChanged, получено %v", err)
	}
	if readFile(t, r, "include-hosts.txt") != before {
		t.Fatal("файл изменён при расхождении")
	}
	_, sum2, _ := r.Raw("include-hosts.txt")
	if _, _, err := r.Replace("include-hosts.txt", "x.example.com\n", sum2); err != nil {
		t.Fatal(err)
	}
	big := newRouting(t, map[string]string{"include-hosts.txt": strings.Repeat("a.example.com\n", MaxReplaceBytes/14+10)})
	if _, _, err := big.Raw("include-hosts.txt"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ожидался ErrTooLarge: %v", err)
	}
	if _, _, err := r.Raw("../setup"); !errors.Is(err, ErrNoList) {
		t.Fatalf("%v", err)
	}
}

func TestWritesRefusedWhileBusy(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	stamp, err := r.Backups.Save("include-hosts.txt", []byte("old.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	r.Busy = func() error { return &BusyError{Reason: "идёт doall"} }
	var be *BusyError
	if _, err := r.Patch("include-hosts.txt", []string{"b.example.com"}, nil); !errors.As(err, &be) {
		t.Errorf("Patch: %v", err)
	}
	if _, _, err := r.Replace("include-hosts.txt", "b.example.com\n", ""); !errors.As(err, &be) {
		t.Errorf("Replace: %v", err)
	}
	if err := r.Restore("include-hosts.txt", stamp); !errors.As(err, &be) {
		t.Errorf("Restore: %v", err)
	}
	if got := readFile(t, r, "include-hosts.txt"); got != "a.example.com\n" {
		t.Fatalf("файл тронут: %q", got)
	}
	r.Busy = nil
	if res, err := r.Patch("include-hosts.txt", []string{"b.example.com"}, nil); err != nil || !res.Applied {
		t.Fatalf("после задачи правка должна проходить: %+v %v", res, err)
	}
}

// Копии не доступны никому, кроме владельца: в них бывают секреты.
func TestBackupFileMode(t *testing.T) {
	b := &Backups{Dir: t.TempDir()}
	stamp, err := b.Save("setup", []byte("X=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(b.Dir, "setup."+stamp))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("права копии %v, ожидалось 0600", fi.Mode().Perm())
	}
}

// Часы ушли назад: новая копия всё равно новее прежних и не вытесняется первой.
func TestBackupsOrderSurvivesClockStepBack(t *testing.T) {
	clock := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	b := &Backups{Dir: t.TempDir(), Now: func() time.Time { return clock }}
	for i := 0; i < KeepBackups; i++ {
		clock = clock.Add(time.Second)
		if _, err := b.Save("x.txt", []byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	clock = clock.Add(-2 * time.Hour) // NTP отмотал часы
	stamp, err := b.Save("x.txt", []byte("newest"))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := b.List("x.txt")
	if len(list) != KeepBackups || list[0].Stamp != stamp {
		t.Fatalf("новая копия не наверху: %v, копий %d", list, len(list))
	}
	if data, _ := b.Read("x.txt", stamp); string(data) != "newest" {
		t.Fatalf("новая копия вытеснена: %q", data)
	}
	if data, _ := b.Read("x.txt", list[len(list)-1].Stamp); string(data) == "0" {
		t.Fatal("самая старая копия не вытеснена")
	}
}

func TestSetupBusyRefusesWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "setup")
	if err := os.WriteFile(p, []byte("ROUTE_ALL=n\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	s := &SetupFile{Path: p, Backups: &Backups{Dir: filepath.Join(t.TempDir(), "b")},
		Busy: func() error { return &BusyError{Reason: "идёт restart"} }}
	var be *BusyError
	if _, err := s.Set(map[string]string{"ROUTE_ALL": "y"}); !errors.As(err, &be) {
		t.Fatalf("ожидался BusyError: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "ROUTE_ALL=n\n" {
		t.Fatalf("файл тронут: %q", b)
	}
}
