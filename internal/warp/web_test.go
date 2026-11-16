package warp

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Все вопросы реального install-web.sh покрыты таблицей, кроме выбора при
// Let's Encrypt: сертификат самоподписанный, до него установщик не доходит.
func TestWebRulesCoverInstallScript(t *testing.T) {
	data, err := os.ReadFile("testdata/install-web.sh")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`read -r (?:-[es] )?-p "([^"]*)"`)
	a := WebAnswers{User: "admin", Password: "secret1"}
	d := a.NewDialog(nil)
	repl := strings.NewReplacer("$DEFAULT_PORT", "6060", "$DEFAULT_BACKEND_PORT", "16060")
	n := 0
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		prompt := repl.Replace(m[1])
		if strings.HasPrefix(prompt, "Выбор [1/2/3") {
			continue
		}
		n++
		if r, _ := d.match(prompt, ""); r == nil {
			t.Errorf("нет правила для вопроса установщика: %q", prompt)
		}
	}
	if n < 7 {
		t.Fatalf("найдено всего %d вопросов — разбор install-web.sh сломан", n)
	}
}

func TestWebDialogAnswersAndHidesPassword(t *testing.T) {
	a := WebAnswers{User: "boss", Password: "Pa55word!"}
	log, got, err := runScript(t, a.NewDialog(nil), []step{
		{out: "Внешний порт веб-панели [6060]: "},
		{out: "Внутренний порт (gunicorn) [16060]: "},
		{out: "Логин администратора [admin]: "},
		{out: "Пароль: "},
		{out: "Подтвердите пароль: "},
		{out: "Включить HTTPS? (y/N): "},
		{out: "Доменное имя (для Let's Encrypt) или Enter для самоподписанного: "},
		{out: "=== Установка ===\r\n", noRead: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "||boss|Pa55word!|Pa55word!|y|"; strings.Join(got, "|") != want {
		t.Fatalf("ответы %q, ждали %q", strings.Join(got, "|"), want)
	}
	if strings.Contains(log, "Pa55word!") {
		t.Fatalf("пароль в журнале:\n%s", log)
	}
}

// Занятый порт: установщик спрашивает снова — диалог останавливается, а не
// отвечает по кругу.
func TestWebDialogBusyPortStops(t *testing.T) {
	a := WebAnswers{User: "boss", Password: "Pa55word!"}
	_, _, err := runScript(t, a.NewDialog(nil), []step{
		{out: "Внешний порт веб-панели [6060]: "},
		{out: "⚠ Порт 6060 уже занят процессом: nginx\r\nВнешний порт веб-панели [6060]: "},
	})
	if err == nil {
		t.Fatal("повтор вопроса о порте не остановил установку")
	}
}

func TestWebAnswersValidate(t *testing.T) {
	for _, a := range []WebAnswers{
		{User: "ad", Password: "secret1"},
		{User: "ад мин", Password: "secret1"},
		{User: "admin", Password: "12345"},
		{User: "admin", Password: "secret\n1"},
	} {
		if a.Validate() == nil {
			t.Errorf("приняты неверные ответы %+v", a)
		}
	}
	if err := (&WebAnswers{User: "admin_1", Password: "secret1"}).Validate(); err != nil {
		t.Fatal(err)
	}
	// Ответы установки AZ-WARP проверяют и веб-панель.
	if (&InstallAnswers{Mode: "warp", Web: &WebAnswers{User: "a", Password: "secret1"}}).Validate() == nil {
		t.Fatal("неверный логин веб-панели принят в ответах установки")
	}
	if s := (&InstallAnswers{Mode: "warp", Web: &WebAnswers{User: "admin", Password: "secret1"}}).SecretValues(); len(s) != 1 || s[0] != "secret1" {
		t.Fatalf("пароль веб-панели не в секретах: %q", s)
	}
}

func TestParseWebStatus(t *testing.T) {
	st := parseWebStatus([]byte("installed=true\nactive=active\nenabled=enabled\nmode=nginx\nexternal_port=6060\n"))
	if !st.Installed || !st.Active || st.Port != 6060 {
		t.Fatalf("%+v", st)
	}
	if st := parseWebStatus([]byte("installed=false\nactive=inactive\n")); st.Installed || st.Active {
		t.Fatalf("%+v", st)
	}
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("PORT=16060\nDEBUG=false\n"), 0o600)
	if p := envPort(env); p != 16060 {
		t.Fatalf("PORT из .env: %d", p)
	}
	if p := envPort(filepath.Join(dir, "нет")); p != 0 {
		t.Fatalf("нет файла: %d", p)
	}
}
