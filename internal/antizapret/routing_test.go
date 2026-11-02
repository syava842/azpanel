package antizapret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRouting(t *testing.T, files map[string]string) *Routing {
	t.Helper()
	root := t.TempDir()
	cfg := filepath.Join(root, "config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(cfg, n), []byte(c), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	clock := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	return &Routing{
		ConfigDir: cfg,
		Backups: &Backups{Dir: filepath.Join(root, "backup", "antizapret"), Now: func() time.Time {
			clock = clock.Add(time.Second)
			return clock
		}},
	}
}

func readFile(t *testing.T, r *Routing, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.ConfigDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestKindOf(t *testing.T) {
	for name, want := range map[string]string{
		"include-hosts.txt": KindHosts, "include-adblock-hosts.txt": KindHosts,
		"allow-ips.txt": KindIPs, "deny3-rpz.txt": KindRPZ, "notes.txt": "",
	} {
		if got := KindOf(name); got != want {
			t.Errorf("%s: %q, ожидалось %q", name, got, want)
		}
	}
}

func TestNormalizeHosts(t *testing.T) {
	ok := map[string]string{
		"example.com":                   "example.com",
		"Example.COM":                   "example.com",
		"a-b.c1.example.org":            "a-b.c1.example.org",
		"xn--80asehdb.xn--p1ai":         "xn--80asehdb.xn--p1ai",
		strings.Repeat("a", 63) + ".ru": strings.Repeat("a", 63) + ".ru",
	}
	for in, want := range ok {
		got, err := normalizeEntry(KindHosts, "exclude-hosts.txt", in)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; ожидалось %q", in, got, err, want)
		}
	}
	bad := []string{
		"localhost",                       // нет точки
		".example.com",                    // ведущая точка: parse.sh пропустит
		"example..com",                    // пустая метка
		"example.com.",                    // точка на конце
		"-bad.example.com",                // дефис в начале метки
		"exa_mple.com",                    // подчёркивание: sed обрежет
		"example.com/path",                // косая: sed обрежет
		"*.example.com",                   // звёздочка
		"exa mple.com",                    // пробел внутри
		"пример.рф",                       // не punycode
		strings.Repeat("a", 64) + ".ru",   // метка длиннее 63
		strings.Repeat("a.", 127) + "com", // длиннее 253
		"example.com:8080",
	}
	for _, in := range bad {
		if got, err := normalizeEntry(KindHosts, "exclude-hosts.txt", in); err == nil {
			t.Errorf("%q должно отклоняться, получено %q", in, got)
		}
	}
	// Одиночная точка — только в двух файлах.
	for _, n := range []string{"include-hosts.txt", "include-warp-hosts.txt"} {
		if got, err := normalizeEntry(KindHosts, n, "."); err != nil || got != "." {
			t.Errorf("%s: точка должна приниматься: %q %v", n, got, err)
		}
	}
	if _, err := normalizeEntry(KindHosts, "exclude-hosts.txt", "."); err == nil {
		t.Error("точка в exclude-hosts.txt должна отклоняться")
	}
}

func TestNormalizeIPs(t *testing.T) {
	ok := map[string]string{
		"1.2.3.0/24":      "1.2.3.0/24",
		"1.2.3.4/24":      "1.2.3.0/24", // адрес приводится к сети
		"8.8.8.8":         "8.8.8.8/32",
		"10.0.0.0/8":      "10.0.0.0/8",
		"1.2.3.4/32":      "1.2.3.4/32",
		"255.255.255.0/1": "128.0.0.0/1",
	}
	for in, want := range ok {
		got, err := normalizeEntry(KindIPs, "include-ips.txt", in)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; ожидалось %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"1.2.3.256", "1.2.3", "1.2.3.4/33", "1.2.3.4/0", "0.0.0.0/0", "::1", "2001:db8::/32",
		"example.com", "1.2.3.4/abc", "1.2.3.4 /24", "01.2.3.4", "::ffff:1.2.3.4",
	} {
		if got, err := normalizeEntry(KindIPs, "include-ips.txt", in); err == nil {
			t.Errorf("%q должно отклоняться, получено %q", in, got)
		}
	}
}

func TestNormalizeRPZ(t *testing.T) {
	ok := map[string]string{
		"example.com CNAME .":                      "example.com CNAME .",
		"*.Example.com  cname\trpz-passthru.":      "*.example.com CNAME rpz-passthru.",
		"ads.example.com CNAME target.example.org": "ads.example.com CNAME target.example.org",
		"a.example.com CNAME target.example.org.":  "a.example.com CNAME target.example.org.",
	}
	for in, want := range ok {
		got, err := normalizeEntry(KindRPZ, "deny-rpz.txt", in)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; ожидалось %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"example.com", "example.com CNAME", "example.com A 1.2.3.4", "example.com CNAME a b",
		"localhost CNAME .", "example.com CNAME bad_target.com", "*.*.example.com CNAME .",
		"$TTL 3600", "example.com CNAME localhost",
	} {
		if got, err := normalizeEntry(KindRPZ, "deny-rpz.txt", in); err == nil {
			t.Errorf("%q должно отклоняться, получено %q", in, got)
		}
	}
}

func TestFilesAndLines(t *testing.T) {
	r := newRouting(t, map[string]string{
		"include-hosts.txt": "# комментарий\nexample.com\n\nfoo.example.org\r\nbar.net\n",
		"deny-rpz.txt":      "; c\nexample.com CNAME .\n",
		"notes.txt":         "x\n",
		"README":            "не список",
		"Bad Name.txt":      "x",
	})
	files, err := r.Files()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "deny-rpz.txt,include-hosts.txt,notes.txt" {
		t.Fatalf("файлы: %v", names)
	}
	h := files[1]
	if h.Kind != KindHosts || h.Lines != 3 || h.Title != "Домены через AntiZapret" || h.Bytes == 0 {
		t.Fatalf("%+v", h)
	}
	if files[0].Kind != KindRPZ || files[0].Lines != 1 {
		t.Fatalf("%+v", files[0])
	}
	if files[2].Kind != "" || files[2].Title != "" {
		t.Fatalf("неизвестный файл: %+v", files[2])
	}

	pg, err := r.Lines("include-hosts.txt", "", 0, 100)
	if err != nil || pg.Total != 3 || strings.Join(pg.Lines, ",") != "example.com,foo.example.org,bar.net" {
		t.Fatalf("%+v %v", pg, err)
	}
	pg, _ = r.Lines("include-hosts.txt", "EXAMPLE", 0, 100)
	if pg.Total != 2 {
		t.Fatalf("поиск без учёта регистра: %+v", pg)
	}
	pg, _ = r.Lines("include-hosts.txt", "", 1, 1)
	if pg.Total != 3 || len(pg.Lines) != 1 || pg.Lines[0] != "foo.example.org" {
		t.Fatalf("страница: %+v", pg)
	}
	pg, _ = r.Lines("include-hosts.txt", "nope", 0, 10)
	if pg.Total != 0 || pg.Lines == nil || len(pg.Lines) != 0 {
		t.Fatalf("%+v", pg)
	}
}

func TestNameValidation(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "a.com\n"})
	for _, n := range []string{"../setup", "..%2fsetup", "setup", "nope.txt", "a/b.txt", "include-hosts.txt/", "", "Include-Hosts.txt"} {
		if _, err := r.Lines(n, "", 0, 10); !errors.Is(err, ErrNoList) {
			t.Errorf("Lines(%q): %v", n, err)
		}
		if _, err := r.Patch(n, []string{"a.com"}, nil); !errors.Is(err, ErrNoList) {
			t.Errorf("Patch(%q): %v", n, err)
		}
		if _, _, err := r.Replace(n, "a.com"); !errors.Is(err, ErrNoList) {
			t.Errorf("Replace(%q): %v", n, err)
		}
		if _, err := r.BackupList(n); !errors.Is(err, ErrNoList) {
			t.Errorf("BackupList(%q): %v", n, err)
		}
		if err := r.Restore(n, "20261102T100000.000Z"); !errors.Is(err, ErrNoList) {
			t.Errorf("Restore(%q): %v", n, err)
		}
	}
	// Каталог с именем .txt — не список.
	os.Mkdir(filepath.Join(r.ConfigDir, "dir.txt"), 0o755)
	if _, err := r.Lines("dir.txt", "", 0, 1); !errors.Is(err, ErrNoList) {
		t.Errorf("каталог: %v", err)
	}
}

func TestPatchKeepsCommentsAndOrder(t *testing.T) {
	orig := "# мои домены\nzzz.example.com\n\n# отдельно\naaa.example.com\r\nmmm.example.com\n"
	r := newRouting(t, map[string]string{"include-hosts.txt": orig})
	res, err := r.Patch("include-hosts.txt",
		[]string{"New.Example.com", "aaa.example.com", "new.example.com", "  ", "other.example.org"},
		[]string{"zzz.example.com", "absent.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.Added != 2 || res.Removed != 1 || res.Skipped != 3 || len(res.Errors) != 0 {
		t.Fatalf("%+v", res)
	}
	want := "# мои домены\n\n# отдельно\naaa.example.com\r\nmmm.example.com\nnew.example.com\nother.example.org\n"
	if got := readFile(t, r, "include-hosts.txt"); got != want {
		t.Fatalf("файл:\n%q\nожидалось:\n%q", got, want)
	}
	// Копия прежнего содержимого сделана.
	list, _ := r.BackupList("include-hosts.txt")
	if len(list) != 1 || list[0].Bytes != int64(len(orig)) {
		t.Fatalf("копии: %+v", list)
	}
}

func TestPatchRemoveIsCaseInsensitiveForHosts(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "Old.Example.com\n"})
	res, _ := r.Patch("include-hosts.txt", nil, []string{"old.example.com"})
	if res.Removed != 1 || readFile(t, r, "include-hosts.txt") != "" {
		t.Fatalf("%+v %q", res, readFile(t, r, "include-hosts.txt"))
	}
}

func TestPatchErrorLeavesFileUntouched(t *testing.T) {
	orig := "a.example.com\n"
	r := newRouting(t, map[string]string{"include-hosts.txt": orig})
	res, err := r.Patch("include-hosts.txt", []string{"ok.example.com", "bad_host", "# коммент", "x y"}, []string{"a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || res.Added != 0 || res.Removed != 0 || len(res.Errors) != 3 {
		t.Fatalf("%+v", res)
	}
	if res.Errors[0].Line != 2 || res.Errors[0].Value != "bad_host" || res.Errors[0].Reason == "" || res.Errors[1].Line != 3 || res.Errors[2].Line != 4 {
		t.Fatalf("номера строк: %+v", res.Errors)
	}
	if got := readFile(t, r, "include-hosts.txt"); got != orig {
		t.Fatalf("файл изменён: %q", got)
	}
	if list, _ := r.BackupList("include-hosts.txt"); len(list) != 0 {
		t.Fatalf("копия при отказе не нужна: %+v", list)
	}
}

func TestPatchNothingChangedNoBackup(t *testing.T) {
	r := newRouting(t, map[string]string{"include-ips.txt": "1.2.3.0/24\n"})
	res, _ := r.Patch("include-ips.txt", []string{"1.2.3.9/24"}, []string{"9.9.9.9"})
	if res.Applied || res.Added != 0 || res.Skipped != 2 {
		t.Fatalf("%+v", res)
	}
	if list, _ := r.BackupList("include-ips.txt"); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestPatchAppendsAfterMissingFinalNewline(t *testing.T) {
	r := newRouting(t, map[string]string{"include-ips.txt": "1.2.3.0/24"})
	r.Patch("include-ips.txt", []string{"5.6.7.8"}, nil)
	if got := readFile(t, r, "include-ips.txt"); got != "1.2.3.0/24\n5.6.7.8/32\n" {
		t.Fatalf("%q", got)
	}
}

func TestPatchRPZ(t *testing.T) {
	r := newRouting(t, map[string]string{"deny-rpz.txt": "; зона\nexample.com CNAME .\n"})
	res, _ := r.Patch("deny-rpz.txt", []string{"*.Example.com cname .", "example.com  CNAME  ."}, nil)
	if res.Added != 1 || res.Skipped != 1 {
		t.Fatalf("%+v", res)
	}
	if got := readFile(t, r, "deny-rpz.txt"); got != "; зона\nexample.com CNAME .\n*.example.com CNAME .\n" {
		t.Fatalf("%q", got)
	}
}

func TestPatchUnknownKindReadOnly(t *testing.T) {
	r := newRouting(t, map[string]string{"notes.txt": "x\n"})
	if _, err := r.Patch("notes.txt", []string{"a.com"}, nil); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	if _, _, err := r.Replace("notes.txt", "a"); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
}

func TestPatchKeepsFileMode(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	p := filepath.Join(r.ConfigDir, "include-hosts.txt")
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	r.Patch("include-hosts.txt", []string{"b.example.com"}, nil)
	info, _ := os.Stat(p)
	if runtimeHasUnixModes() && info.Mode().Perm() != 0o600 {
		t.Fatalf("права: %v", info.Mode().Perm())
	}
	// Временных файлов не осталось.
	entries, _ := os.ReadDir(r.ConfigDir)
	if len(entries) != 1 {
		t.Fatalf("мусор в каталоге: %v", entries)
	}
}

func runtimeHasUnixModes() bool { return os.PathSeparator == '/' }

func TestReplace(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "old.example.com\n"})
	n, errs, err := r.Replace("include-hosts.txt", "# новый\r\nA.Example.com\r\n\r\n   \r\nb.example.com\r\n")
	if err != nil || len(errs) != 0 || n != 2 {
		t.Fatal(n, errs, err)
	}
	if got := readFile(t, r, "include-hosts.txt"); got != "# новый\na.example.com\n\n\nb.example.com\n" {
		t.Fatalf("%q", got)
	}
	// Ошибки — построчно, файл цел.
	before := readFile(t, r, "include-hosts.txt")
	n, errs, err = r.Replace("include-hosts.txt", "ok.example.com\nbad_host\n\nx\n")
	if err != nil || n != 0 || len(errs) != 2 || errs[0].Line != 2 || errs[1].Line != 4 {
		t.Fatal(n, errs, err)
	}
	if readFile(t, r, "include-hosts.txt") != before {
		t.Fatal("файл изменён при ошибке")
	}
	// Пустой текст очищает файл.
	if _, errs, err := r.Replace("include-hosts.txt", ""); err != nil || len(errs) != 0 || readFile(t, r, "include-hosts.txt") != "" {
		t.Fatal(errs, err)
	}
}

func TestReplaceTooLarge(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	big := strings.Repeat("a.example.com\n", MaxReplaceBytes/14+10)
	if _, _, err := r.Replace("include-hosts.txt", big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("содержимое больше 1 МБ: %v", err)
	}
	// Файл на диске больше 1 МБ — тоже отказ.
	os.WriteFile(filepath.Join(r.ConfigDir, "include-hosts.txt"), []byte(big), 0o640)
	if _, _, err := r.Replace("include-hosts.txt", "a.example.com\n"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("большой файл: %v", err)
	}
}

func TestBackupsEvictAfter20AndRestore(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "v0.example.com\n"})
	for i := 1; i <= 21; i++ {
		if _, errs, err := r.Replace("include-hosts.txt", fmt.Sprintf("v%d.example.com\n", i)); err != nil || len(errs) != 0 {
			t.Fatal(errs, err)
		}
	}
	list, err := r.BackupList("include-hosts.txt")
	if err != nil || len(list) != KeepBackups {
		t.Fatalf("копий %d, %v", len(list), err)
	}
	// 21 запись → 21 копия, первая (v0) вытеснена: самая старая из оставшихся — v1.
	oldest, _ := r.Backups.Read("include-hosts.txt", list[len(list)-1].Stamp)
	newest, _ := r.Backups.Read("include-hosts.txt", list[0].Stamp)
	if string(oldest) != "v1.example.com\n" || string(newest) != "v20.example.com\n" {
		t.Fatalf("старая %q, новая %q", oldest, newest)
	}
	// Метки идут от новых к старым.
	for i := 1; i < len(list); i++ {
		if list[i-1].Stamp <= list[i].Stamp {
			t.Fatalf("порядок: %v", list)
		}
	}

	// Возврат копии v10: текущая версия (v21) перед этим тоже копируется.
	var v10 string
	for _, b := range list {
		if data, _ := r.Backups.Read("include-hosts.txt", b.Stamp); string(data) == "v10.example.com\n" {
			v10 = b.Stamp
		}
	}
	if err := r.Restore("include-hosts.txt", v10); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, r, "include-hosts.txt"); got != "v10.example.com\n" {
		t.Fatalf("%q", got)
	}
	list, _ = r.BackupList("include-hosts.txt")
	top, _ := r.Backups.Read("include-hosts.txt", list[0].Stamp)
	if string(top) != "v21.example.com\n" || len(list) != KeepBackups {
		t.Fatalf("версия перед возвратом не сохранена: %q, копий %d", top, len(list))
	}
}

func TestRestoreBadStamp(t *testing.T) {
	r := newRouting(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	for _, st := range []string{"../../etc/passwd", "20261102T100000.000Z/x", "", "x", "20261102T100000.001Z"} {
		err := r.Restore("include-hosts.txt", st)
		if err == nil {
			t.Errorf("метка %q должна отклоняться", st)
		}
	}
	if got := readFile(t, r, "include-hosts.txt"); got != "a.example.com\n" {
		t.Fatal("файл изменён")
	}
}

func TestBackupsSameMillisecond(t *testing.T) {
	b := &Backups{Dir: t.TempDir(), Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	s1, err1 := b.Save("x.txt", []byte("1"))
	s2, err2 := b.Save("x.txt", []byte("2"))
	if err1 != nil || err2 != nil || s1 == s2 {
		t.Fatal(s1, s2, err1, err2)
	}
	if s1 != "20260101T000000.000Z" {
		t.Fatalf("формат метки: %q", s1)
	}
}

// Большой файл: 200 000 строк — PATCH укладывается в 2 с, поиск работает.
func TestPatchLargeFile(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("# большой список\n")
	for i := 0; i < 200000; i++ {
		fmt.Fprintf(&sb, "host%d.example.com\n", i)
	}
	r := newRouting(t, map[string]string{"include-adblock-hosts.txt": sb.String()})

	start := time.Now()
	res, err := r.Patch("include-adblock-hosts.txt", []string{"azpanel-test.example.com", "host5.example.com"}, []string{"host199999.example.com"})
	took := time.Since(start)
	if err != nil || !res.Applied || res.Added != 1 || res.Removed != 1 || res.Skipped != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if took > 2*time.Second {
		t.Fatalf("PATCH занял %v", took)
	}
	pg, err := r.Lines("include-adblock-hosts.txt", "azpanel-test", 0, 200)
	if err != nil || pg.Total != 1 || pg.Lines[0] != "azpanel-test.example.com" {
		t.Fatalf("%+v %v", pg, err)
	}
	pg, _ = r.Lines("include-adblock-hosts.txt", "", 100000, 200)
	if pg.Total != 200000 || len(pg.Lines) != 200 || pg.Lines[0] != "host100000.example.com" {
		t.Fatalf("страница: total %d, %d строк, первая %q", pg.Total, len(pg.Lines), pg.Lines[0])
	}
}
