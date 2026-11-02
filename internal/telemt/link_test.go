package telemt

import (
	"os"
	"strings"
	"testing"
)

const (
	testDomain = "www.example.com"
	testKey    = "ee" + testSecret + "7777772e6578616d706c652e636f6d"
)

func TestSecretKeyMatchesJournalFormat(t *testing.T) {
	if got := SecretKey(testSecret, testDomain); got != testKey {
		t.Fatalf("ключ %s", got)
	}
	l := Link("192.0.2.94", 902, testSecret, testDomain)
	if l != "tg://proxy?server=192.0.2.94&port=902&secret="+testKey {
		t.Fatal(l)
	}
	if !strings.HasPrefix(WebLink("h", 1, testSecret, testDomain), "https://t.me/proxy?") {
		t.Fatal("web-ссылка")
	}
}

func TestParseKey(t *testing.T) {
	k, err := ParseKey(testKey)
	if err != nil || k.Secret != testSecret || k.Domain != testDomain {
		t.Fatalf("%+v %v", k, err)
	}
	k, err = ParseKey("tg://proxy?server=1.2.3.4&port=902&secret=" + strings.ToUpper(testKey))
	if err != nil || k.Server != "1.2.3.4" || k.Port != 902 || k.Secret != testSecret {
		t.Fatalf("ссылка: %+v %v", k, err)
	}
	bad := map[string]string{
		"неверная длина":   "ee" + testSecret + "7777772e6578616d706c652e636f6d0",
		"только секрет":    "ee" + testSecret,
		"dd-вид":           "dd" + testSecret,
		"без префикса":     testSecret + "7777772e6578616d706c652e636f6d",
		"не hex":           "ee" + testSecret + "zz",
		"ссылка без ключа": "tg://proxy?server=1.2.3.4&port=902",
		"домен с пробелом": "ee" + testSecret + "612062",
	}
	for name, s := range bad {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("%s: ждали ошибку", name)
		}
	}
}

func TestSecretFromInput(t *testing.T) {
	if s, err := SecretFromInput(strings.ToUpper(testSecret), testDomain); err != nil || s != testSecret {
		t.Fatalf("%q %v", s, err)
	}
	if s, err := SecretFromInput(testKey, "WWW.EXAMPLE.COM"); err != nil || s != testSecret {
		t.Fatalf("домен без учёта регистра: %q %v", s, err)
	}
	if _, err := SecretFromInput(testKey, "other.example"); err == nil {
		t.Fatal("чужой домен должен отклоняться")
	}
	if _, err := SecretFromInput("ee1234", testDomain); err == nil {
		t.Fatal("неверная длина должна отклоняться")
	}
}

func TestJournalLinkFromTestdata(t *testing.T) {
	data, err := os.ReadFile("testdata/journal-link.txt")
	if err != nil {
		t.Fatal(err)
	}
	keys := JournalLinks(string(data))
	if len(keys) != 1 || keys[0].Secret != testSecret || keys[0].Domain != testDomain || keys[0].Port != 902 {
		t.Fatalf("%+v", keys)
	}
	users := []User{{Name: "user", Secret: testSecret}}
	if found, err := CheckJournal(string(data), users, testDomain); !found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
	// Несовпавший секрет и несовпавший домен.
	if _, err := CheckJournal(string(data), []User{{Name: "u", Secret: strings.Repeat("a", 32)}}, testDomain); err == nil {
		t.Fatal("чужой секрет должен давать ошибку")
	}
	if _, err := CheckJournal(string(data), users, "other.example"); err == nil {
		t.Fatal("чужой домен должен давать ошибку")
	}
	if found, err := CheckJournal("MAESTRO: ничего\n", users, testDomain); found || err != nil {
		t.Fatal("пустой журнал — не ошибка")
	}
}

func TestMaskSecret(t *testing.T) {
	m := MaskSecret(testSecret)
	if strings.Contains(m, testSecret) || strings.Contains(m, "4455") || !strings.HasPrefix(m, "0011") {
		t.Fatal(m)
	}
}
