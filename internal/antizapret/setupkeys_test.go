package antizapret

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleSetup = `# setup AntiZapret
SETUP_DATE=2026-08-01
OPENVPN_HOST='vpn.example.com'
WIREGUARD_HOST=
ROUTE_ALL=n
CLEAR_HOSTS=y
SCAN_PROTECTION=y
TXQUEUELEN=10000
ANTIZAPRET_WARP=n
ANTIZAPRET_WARP_PRIVATE_KEY=SECRETPRIVATE
ANTIZAPRET_WARP_PUBLIC_KEY=PUB
ANTIZAPRET_WARP_ENDPOINT=engage.cloudflareclient.com:2408
ALTERNATIVE_FAKE_IP=n
WIREGUARD_ENABLE=y
SOME_NEW_KEY=abc
`

func newSetup(t *testing.T, content string) *SetupFile {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "setup")
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return &SetupFile{Path: p, Backups: &Backups{Dir: filepath.Join(root, "backup"), Now: time.Now}}
}

func readSetupFile(t *testing.T, s *SetupFile) string {
	t.Helper()
	b, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetupKeyTable(t *testing.T) {
	cases := []struct {
		key      string
		kind     string
		apply    string
		editable bool
	}{
		{"ANTIZAPRET_WARP", SetupEnum, "doall,restart", true},
		{"VPN_WARP", SetupEnum, "doall,restart", true},
		{"DNS_WARP", SetupYN, "restart", true},
		{"WARP_MTU", SetupInt, "restart", true},
		{"ROUTE_ALL", SetupYN, "doall", true},
		{"CLEAR_HOSTS", SetupYN, "doall", true},
		{"ANTIZAPRET_ADBLOCK", SetupYN, "doall", true},
		{"VPN_ADBLOCK", SetupYN, "doall", true},
		{"DISCORD_INCLUDE", SetupYN, "doall", true},
		{"ROBLOX_INCLUDE", SetupYN, "doall", true},
		{"ATTACK_PROTECTION", SetupYN, "doall,restart", true},
		{"SSH_PROTECTION", SetupYN, "restart", true},
		{"SCAN_PROTECTION", SetupYN, "restart", true},
		{"TORRENT_GUARD", SetupYN, "restart", true},
		{"RESTRICT_FORWARD", SetupYN, "restart", true},
		{"CLIENT_ISOLATION", SetupYN, "restart", true},
		{"OPENVPN_BACKUP_UDP", SetupYN, "restart", true},
		{"OPENVPN_BACKUP_TCP", SetupYN, "restart", true},
		{"WIREGUARD_BACKUP", SetupYN, "restart", true},
		{"WARP_PROTECTION", SetupYN, "restart", true},
		{"TXQUEUELEN", SetupInt, "restart", true},
		{"OPENVPN_HOST", SetupHost, "profiles", true},
		{"WIREGUARD_HOST", SetupHost, "profiles", true},
		{"ALTERNATIVE_CLIENT_IP", "", "reinstall", false},
		{"ALTERNATIVE_FAKE_IP", "", "reinstall", false},
		{"MTU", "", "reinstall", false},
		{"ANTIZAPRET_DNS", "", "reinstall", false},
		{"OPENVPN_DCO", "", "reinstall", false},
		{"SETUP_DATE", "", "reinstall", false},
		{"OPENVPN_ENABLE", "", "reinstall", false},
		{"VPN_WARP_PUBLIC_KEY", "", "reinstall", false},
		{"DNS_WARP_ENDPOINT", "", "reinstall", false},
		{"ANTIZAPRET_WARP_ADDRESS", "", "reinstall", false},
	}
	for _, c := range cases {
		k, ok := LookupSetupKey(c.key)
		if !ok || k.Kind != c.kind || strings.Join(k.Apply, ",") != c.apply || k.Editable != c.editable || k.Title == "" {
			t.Errorf("%s: %+v ok=%v", c.key, k, ok)
		}
	}
	// Неизвестный ключ.
	if _, ok := LookupSetupKey("SOME_NEW_KEY"); ok {
		t.Error("неизвестный ключ не должен находиться")
	}
}

func TestSetupValueValidation(t *testing.T) {
	good := map[[2]string]string{
		{"ROUTE_ALL", "y"}: "y", {"ROUTE_ALL", "n"}: "n",
		{"ANTIZAPRET_WARP", "4"}: "4", {"ANTIZAPRET_WARP", "n"}: "n", {"VPN_WARP", "3"}: "3",
		{"WARP_MTU", "1280"}: "1280", {"WARP_MTU", "1500"}: "1500",
		{"TXQUEUELEN", "0"}: "0", {"TXQUEUELEN", "100000"}: "100000",
		{"VPN_DNS", "1"}:     "1",
		{"OPENVPN_HOST", ""}: "", {"OPENVPN_HOST", "VPN.Example.com"}: "vpn.example.com",
		{"WIREGUARD_HOST", "203.0.113.5"}: "203.0.113.5", {"WIREGUARD_HOST", "2001:db8::1"}: "2001:db8::1",
	}
	for in, want := range good {
		got, err := checkSetupValue(in[0], in[1])
		if err != nil || got != want {
			t.Errorf("%v: %q, %v; ожидалось %q", in, got, err, want)
		}
	}
	bad := [][2]string{
		{"ROUTE_ALL", "yes"}, {"ROUTE_ALL", ""}, {"ROUTE_ALL", "Y"}, {"ROUTE_ALL", "y\n"},
		{"ANTIZAPRET_WARP", "5"}, {"VPN_WARP", "4"}, {"ANTIZAPRET_WARP", ""},
		{"WARP_MTU", "1279"}, {"WARP_MTU", "1501"}, {"WARP_MTU", "abc"}, {"WARP_MTU", "1280.5"}, {"WARP_MTU", "01300"}, {"WARP_MTU", "+1300"},
		{"TXQUEUELEN", "-1"}, {"TXQUEUELEN", "100001"},
		{"VPN_DNS", "0"}, {"VPN_DNS", "10"},
		{"OPENVPN_HOST", "vpn"}, {"OPENVPN_HOST", "a b.example.com"}, {"OPENVPN_HOST", "x.com;rm -rf"}, {"OPENVPN_HOST", "fe80::1%eth0"},
		{"OPENVPN_HOST", "vpn.example.com\nX=1"}, {"OPENVPN_HOST", "$(id).example.com"},
		// Только показ, секреты и неизвестные.
		{"ALTERNATIVE_FAKE_IP", "y"}, {"MTU", "1400"}, {"WIREGUARD_ENABLE", "n"}, {"SETUP_DATE", "x"},
		{"ANTIZAPRET_WARP_PRIVATE_KEY", "x"}, {"VPN_WARP_PRIVATE_KEY", "x"}, {"NO_SUCH_KEY", "y"},
	}
	for _, in := range bad {
		if got, err := checkSetupValue(in[0], in[1]); err == nil {
			t.Errorf("%v должно отклоняться, получено %q", in, got)
		}
	}
}

func TestSetupListHidesSecrets(t *testing.T) {
	s := newSetup(t, sampleSetup)
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]SetupEntry{}
	var order []string
	for _, e := range list {
		byKey[e.Key] = e
		order = append(order, e.Key)
		if strings.Contains(e.Key, "PRIVATE_KEY") || strings.Contains(e.Value, "SECRETPRIVATE") {
			t.Fatalf("секрет в ответе: %+v", e)
		}
	}
	if order[0] != "SETUP_DATE" || order[1] != "OPENVPN_HOST" {
		t.Fatalf("порядок файла нарушен: %v", order)
	}
	if e := byKey["OPENVPN_HOST"]; e.Value != "vpn.example.com" || e.Kind != SetupHost || !e.Editable || strings.Join(e.Apply, ",") != "profiles" || e.Title == "" {
		t.Fatalf("кавычки должны сниматься: %+v", e)
	}
	if e := byKey["ANTIZAPRET_WARP"]; len(e.Options) != 5 || e.Kind != SetupEnum {
		t.Fatalf("%+v", e)
	}
	if e := byKey["TXQUEUELEN"]; e.Min != 0 || e.Max != 100000 || e.Value != "10000" {
		t.Fatalf("%+v", e)
	}
	if e := byKey["ALTERNATIVE_FAKE_IP"]; e.Editable || strings.Join(e.Apply, ",") != "reinstall" {
		t.Fatalf("%+v", e)
	}
	if e := byKey["SOME_NEW_KEY"]; e.Editable || e.Kind != "" || len(e.Apply) != 0 || e.Value != "abc" {
		t.Fatalf("неизвестный ключ: %+v", e)
	}
	if _, ok := byKey["ANTIZAPRET_WARP_PUBLIC_KEY"]; !ok {
		t.Fatal("публичный ключ должен показываться")
	}
}

func TestSetupSetPreservesOtherLinesByteForByte(t *testing.T) {
	s := newSetup(t, sampleSetup)
	res, err := s.Set(map[string]string{"ROUTE_ALL": "y", "OPENVPN_HOST": "new.example.com", "SCAN_PROTECTION": "y", "ANTIZAPRET_WARP": "3"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Changed, ",") != "ANTIZAPRET_WARP,OPENVPN_HOST,ROUTE_ALL" {
		t.Fatalf("изменённые: %v (SCAN_PROTECTION не менялся)", res.Changed)
	}
	if strings.Join(res.Apply, ",") != "doall,restart,profiles" {
		t.Fatalf("способы: %v", res.Apply)
	}
	want := strings.NewReplacer(
		"ROUTE_ALL=n", "ROUTE_ALL=y",
		"OPENVPN_HOST='vpn.example.com'", "OPENVPN_HOST='new.example.com'", // кавычки сохраняются
		"ANTIZAPRET_WARP=n", "ANTIZAPRET_WARP=3",
	).Replace(sampleSetup)
	if got := readSetupFile(t, s); got != want {
		t.Fatalf("файл:\n%s\nожидалось:\n%s", got, want)
	}
	// Прежняя версия сохранена в копии байт в байт.
	list, _ := s.BackupList()
	if len(list) != 1 {
		t.Fatalf("%+v", list)
	}
	b, _ := s.Backups.Read("setup", list[0].Stamp)
	if string(b) != sampleSetup {
		t.Fatal("копия не совпадает с прежним файлом")
	}
}

func TestSetupSetApplyMethods(t *testing.T) {
	for _, c := range []struct {
		vals map[string]string
		want string
	}{
		{map[string]string{"SCAN_PROTECTION": "n"}, "restart"},
		{map[string]string{"CLEAR_HOSTS": "n"}, "doall"},
		{map[string]string{"WIREGUARD_HOST": "1.2.3.4"}, "profiles"},
		{map[string]string{"TXQUEUELEN": "5000", "CLEAR_HOSTS": "n"}, "doall,restart"},
		{map[string]string{"ANTIZAPRET_WARP": "2"}, "doall,restart"},
	} {
		s := newSetup(t, sampleSetup)
		res, err := s.Set(c.vals)
		if err != nil || strings.Join(res.Apply, ",") != c.want {
			t.Errorf("%v: %+v, %v; ожидалось %s", c.vals, res, err, c.want)
		}
	}
}

func TestSetupSetRejectsAllOrNothing(t *testing.T) {
	s := newSetup(t, sampleSetup)
	_, err := s.Set(map[string]string{
		"ROUTE_ALL": "y", "ALTERNATIVE_FAKE_IP": "y", "WARP_MTU": "9999",
		"ANTIZAPRET_WARP_PRIVATE_KEY": "x", "NO_SUCH": "1",
	})
	var se *SetupError
	if !errors.As(err, &se) || len(se.Errors) != 4 {
		t.Fatalf("%v", err)
	}
	reasons := map[string]string{}
	for _, e := range se.Errors {
		reasons[e.Key] = e.Reason
	}
	if !strings.Contains(reasons["ALTERNATIVE_FAKE_IP"], "переустановк") || !strings.Contains(reasons["ANTIZAPRET_WARP_PRIVATE_KEY"], "секрет") ||
		!strings.Contains(reasons["NO_SUCH"], "неизвестный") || reasons["WARP_MTU"] == "" {
		t.Fatalf("%v", reasons)
	}
	if !strings.Contains(err.Error(), "ALTERNATIVE_FAKE_IP: ") {
		t.Fatalf("сообщение: %v", err)
	}
	if got := readSetupFile(t, s); got != sampleSetup {
		t.Fatal("файл изменён при ошибке")
	}
	if list, _ := s.BackupList(); len(list) != 0 {
		t.Fatalf("копия при отказе не нужна: %+v", list)
	}
}

func TestSetupSetNoChangeNoWrite(t *testing.T) {
	s := newSetup(t, sampleSetup)
	res, err := s.Set(map[string]string{"ROUTE_ALL": "n", "OPENVPN_HOST": "vpn.example.com"})
	if err != nil || len(res.Changed) != 0 || len(res.Apply) != 0 || res.Changed == nil || res.Apply == nil {
		t.Fatalf("%+v, %v", res, err)
	}
	if list, _ := s.BackupList(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestSetupSetAppendsMissingKeyAndKeepsMissingFinalNewline(t *testing.T) {
	s := newSetup(t, "ROUTE_ALL=n")
	// Без изменений в существующих строках: конец файла прежний.
	if _, err := s.Set(map[string]string{"ROUTE_ALL": "y"}); err != nil {
		t.Fatal(err)
	}
	if got := readSetupFile(t, s); got != "ROUTE_ALL=y" {
		t.Fatalf("%q", got)
	}
	// Нового ключа в файле нет — дописывается.
	if _, err := s.Set(map[string]string{"TORRENT_GUARD": "y"}); err != nil {
		t.Fatal(err)
	}
	if got := readSetupFile(t, s); got != "ROUTE_ALL=y\nTORRENT_GUARD=y\n" {
		t.Fatalf("%q", got)
	}
	// Пустое значение отсутствующего ключа — ничего не пишет.
	res, _ := s.Set(map[string]string{"OPENVPN_HOST": ""})
	if len(res.Changed) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestSetupSetCRLFAndDuplicates(t *testing.T) {
	s := newSetup(t, "ROUTE_ALL=n\r\nCLEAR_HOSTS=y\r\nROUTE_ALL=n\r\n")
	if _, err := s.Set(map[string]string{"ROUTE_ALL": "y"}); err != nil {
		t.Fatal(err)
	}
	if got := readSetupFile(t, s); got != "ROUTE_ALL=y\r\nCLEAR_HOSTS=y\r\nROUTE_ALL=y\r\n" {
		t.Fatalf("%q", got)
	}
}

func TestSetupSetKeepsMode(t *testing.T) {
	s := newSetup(t, sampleSetup)
	if err := os.Chmod(s.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(map[string]string{"ROUTE_ALL": "y"}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(s.Path)
	if os.PathSeparator == '/' && info.Mode().Perm() != 0o600 {
		t.Fatalf("права: %v", info.Mode().Perm())
	}
}

func TestSetupListShowsMissingTableKeys(t *testing.T) {
	s := newSetup(t, sampleSetup)
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]SetupEntry{}
	seenMissing := false
	for _, e := range list {
		byKey[e.Key] = e
		if !e.Present {
			seenMissing = true
		} else if seenMissing {
			t.Fatalf("ключ из файла %s после отсутствующих", e.Key)
		}
		if IsSecretSetupKey(e.Key) {
			t.Fatalf("секрет в ответе: %+v", e)
		}
	}
	for k := range setupKeys {
		if _, ok := byKey[k]; !ok && !IsSecretSetupKey(k) {
			t.Errorf("ключ таблицы %s не показан", k)
		}
	}
	if e := byKey["VPN_ADBLOCK"]; e.Present || e.Value != "" || !e.Editable || e.Kind != SetupYN {
		t.Fatalf("отсутствующий ключ: %+v", e)
	}
	if e := byKey["ROUTE_ALL"]; !e.Present || e.Value != "n" {
		t.Fatalf("ключ из файла: %+v", e)
	}
	if e := byKey["SOME_NEW_KEY"]; !e.Present {
		t.Fatalf("неизвестный ключ из файла: %+v", e)
	}
	// Отсутствующий ключ можно задать: строка дописывается в конец.
	if _, err := s.Set(map[string]string{"VPN_ADBLOCK": "y"}); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List()
	for _, e := range list {
		if e.Key == "VPN_ADBLOCK" && (!e.Present || e.Value != "y") {
			t.Fatalf("после записи: %+v", e)
		}
	}
}
