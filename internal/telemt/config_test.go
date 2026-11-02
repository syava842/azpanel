package telemt

import (
	"os"
	"strings"
	"testing"
)

const testSecret = "00112233445566778899aabbccddeeff"

func loadExample(t *testing.T) (*Doc, string) {
	t.Helper()
	data, err := os.ReadFile("testdata/config-example.toml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	return d, string(data)
}

func TestConfigRead(t *testing.T) {
	d, _ := loadExample(t)
	if got := d.Port(); got != 902 {
		t.Fatalf("порт %d, ждали 902 (закомментированный слушатель не считается)", got)
	}
	if got := d.TLSDomain(); got != "www.example.com" {
		t.Fatalf("tls_domain %q", got)
	}
	us := d.Users()
	if len(us) != 1 || us[0].Name != "user" || us[0].Secret != testSecret {
		t.Fatalf("пользователи %+v", us)
	}
}

func TestConfigPortFromServerSection(t *testing.T) {
	d, err := ParseConfig([]byte("[server]\nport = 443 # свой\n[[server.listeners]]\nport = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Port() != 443 {
		t.Fatalf("порт %d", d.Port())
	}
}

// Точечная правка меняет только нужные строки: остальной файл побайтно тот же.
func TestAddUserTouchesOnlyOneLine(t *testing.T) {
	d, orig := loadExample(t)
	const second = "ffeeddccbbaa99887766554433221100"
	if err := d.AddUser("azpanel-test", second); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(orig, "user = \""+testSecret+"\"\n", "user = \""+testSecret+"\"\nazpanel-test = \""+second+"\"\n", 1)
	if string(d.Bytes()) != want {
		t.Fatalf("изменилось больше одной строки:\n%s", d.Bytes())
	}
	if err := d.RemoveUser("azpanel-test"); err != nil {
		t.Fatal(err)
	}
	if string(d.Bytes()) != orig {
		t.Fatal("после удаления файл не совпал с исходным")
	}
}

func TestAddUserRejects(t *testing.T) {
	d, _ := loadExample(t)
	cases := map[string][2]string{
		"дубль имени":      {"user", "ffeeddccbbaa99887766554433221100"},
		"дубль секрета":    {"other", testSecret},
		"короткий секрет":  {"other", "abcd"},
		"верхний регистр":  {"other", strings.ToUpper("ffeeddccbbaa99887766554433221100")},
		"плохое имя":       {"a b", "ffeeddccbbaa99887766554433221100"},
		"имя с кавычкой":   {"a\"b", "ffeeddccbbaa99887766554433221100"},
		"имя с переводом ": {"a\nb", "ffeeddccbbaa99887766554433221100"},
	}
	for name, c := range cases {
		if err := d.AddUser(c[0], c[1]); err == nil {
			t.Errorf("%s: ждали отказ", name)
		}
	}
	if len(d.Users()) != 1 {
		t.Fatal("отказ изменил список")
	}
}

func TestRemoveUserMissing(t *testing.T) {
	d, _ := loadExample(t)
	if err := d.RemoveUser("нет"); err == nil {
		t.Fatal("ждали ошибку")
	}
}

func TestAddUserCreatesSection(t *testing.T) {
	d, err := ParseConfig([]byte("[censorship]\ntls_domain = \"a.example\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser("u", testSecret); err != nil {
		t.Fatal(err)
	}
	if got := string(d.Bytes()); !strings.Contains(got, "\n[access.users]\nu = \""+testSecret+"\"\n") {
		t.Fatalf("раздел не создан:\n%s", got)
	}
}

func TestSetReplacesOrInserts(t *testing.T) {
	d, _ := loadExample(t)
	if err := d.Set("server", "max_connections", "100"); err != nil {
		t.Fatal(err)
	}
	if err := d.Set("timeouts", "extra", "1"); err != nil {
		t.Fatal(err)
	}
	if err := d.Set("новый.раздел", "k", "true"); err == nil {
		// Кириллица в имени раздела — не простой ключ TOML: правка обязана откатиться.
		t.Fatal("ждали отказ для неверного имени раздела")
	}
	got := string(d.Bytes())
	for _, w := range []string{"max_connections = 100\n", "[timeouts]\nextra = 1\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("нет %q:\n%s", w, got)
		}
	}
	if strings.Contains(got, "новый") {
		t.Fatal("неудачная правка не откатилась")
	}
}

func TestDisableIPv6Listener(t *testing.T) {
	src := "[server]\nmax_connections = 1\n\n[[server.listeners]]\nip = \"::\"\nport = 902\n\n[[server.listeners]]\nip = \"0.0.0.0\"\nport = 902\n"
	d, err := ParseConfig([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DisableIPv6Listener(); err != nil {
		t.Fatal(err)
	}
	want := "[server]\nmax_connections = 1\n\n#[[server.listeners]]\n#ip = \"::\"\n#port = 902\n\n[[server.listeners]]\nip = \"0.0.0.0\"\nport = 902\n"
	if string(d.Bytes()) != want {
		t.Fatalf("получилось:\n%s", d.Bytes())
	}
}

func TestConfigCRLFPreserved(t *testing.T) {
	d, err := ParseConfig([]byte("[access.users]\r\nu = \"" + testSecret + "\"\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser("v", "ffeeddccbbaa99887766554433221100"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ReplaceAll(string(d.Bytes()), "\r\n", ""), "\n") {
		t.Fatal("появился одиночный LF")
	}
}

func TestParseConfigRejectsBrokenTOML(t *testing.T) {
	if _, err := ParseConfig([]byte("[a\nb = ")); err == nil {
		t.Fatal("ждали ошибку")
	}
}
