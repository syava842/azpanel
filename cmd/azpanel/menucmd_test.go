package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/store"
)

// fakeConsole — ввод строками (пароли тоже строкой: secret == nil), вывод в буфер.
func fakeConsole(input string) (*console, *bytes.Buffer, *[]string) {
	out := &bytes.Buffer{}
	var calls []string
	c := &console{
		in: bufio.NewReader(strings.NewReader(input)), out: out,
		sub:       func(args ...string) int { calls = append(calls, "sub "+strings.Join(args, " ")); return 0 },
		systemctl: func(args ...string) error { calls = append(calls, "systemctl "+strings.Join(args, " ")); return nil },
	}
	return c, out, &calls
}

func passwordOK(t *testing.T, st *store.Store, login, pw string) store.User {
	t.Helper()
	u, err := st.UserByLogin(context.Background(), login)
	if err != nil {
		t.Fatalf("%s: %v", login, err)
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(pw)) != nil {
		t.Fatalf("пароль %s не подходит", login)
	}
	return u
}

// Меню: добавить администратора со своим паролем, сменить пароль на
// сгенерированный, перезапуск служб, проверка установки, выход.
func TestMenuAdminsAndPasswords(t *testing.T) {
	st, admin := userEnv(t)
	input := strings.Join([]string{
		"4", "Boss", "2", "Own-Password-42", "Own-Password-42", // новый администратор, свой пароль
		"3", "", "1", // пароль первого администратора (Enter — admin), сгенерировать
		"6", "1", "9", "0",
	}, "\n") + "\n"
	c, out, calls := fakeConsole(input)
	if err := cmdMenu(c); err != nil {
		t.Fatal(err)
	}
	text := out.String()

	boss := passwordOK(t, st, "boss", "Own-Password-42")
	if boss.Role != store.RoleAdmin || boss.MustChange {
		t.Fatalf("boss: %+v", boss)
	}
	if strings.Contains(text, "Own-Password-42") {
		t.Fatal("свой пароль напечатан")
	}

	const mark = "Пароль пользователя admin изменён. Пароль: "
	i := strings.Index(text, mark)
	if i < 0 {
		t.Fatalf("нет сгенерированного пароля:\n%s", text)
	}
	gen := strings.SplitN(text[i+len(mark):], "\n", 2)[0]
	if u := passwordOK(t, st, "admin", gen); !u.MustChange || len(u.TOTPSecret) != 0 {
		t.Fatalf("admin после сброса: %+v", u)
	}
	if ss, _ := st.UserSessions(context.Background(), admin.ID); len(ss) != 0 {
		t.Fatalf("сессии не завершены: %d", len(ss))
	}
	if got := strings.Join(*calls, "|"); got != "systemctl restart azpanel-node azpanel-panel|sub doctor" {
		t.Fatalf("вызовы: %s", got)
	}
	if !strings.Contains(text, `Нет пункта "9"`) {
		t.Fatal("неизвестный пункт не отмечен")
	}
}

// Плохой свой пароль и занятый логин — ошибка в меню, а не выход из него;
// конец ввода закрывает меню без действий.
func TestMenuErrorsKeepMenuOpen(t *testing.T) {
	st, _ := userEnv(t)
	c, out, _ := fakeConsole("4\nbob\n1\n4\nnewadmin\n2\nshort\n3\nnobody\n1\n")
	if err := cmdMenu(c); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"уже занят", "пароль короче 10 символов", `пользователь "nobody" не найден`} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q в выводе:\n%s", want, text)
		}
	}
	if _, err := st.UserByLogin(context.Background(), "newadmin"); err == nil {
		t.Fatal("пользователь создан с негодным паролем")
	}
}

func TestUserPasswdAndAddOwnPassword(t *testing.T) {
	st, _ := userEnv(t)
	c, out, _ := fakeConsole("Second-Pass-77\nSecond-Pass-77\n")
	if err := cmdUserWith([]string{"add", "carol", "--admin", "--password"}, c); err != nil {
		t.Fatal(err)
	}
	if u := passwordOK(t, st, "carol", "Second-Pass-77"); u.Role != store.RoleAdmin || u.MustChange {
		t.Fatalf("carol: %+v", u)
	}
	if strings.Contains(out.String(), "Second-Pass-77") {
		t.Fatal("свой пароль напечатан")
	}

	c, _, _ = fakeConsole("Third-Pass-88\nThird-Pass-88\n")
	if err := cmdUserWith([]string{"passwd", "carol"}, c); err != nil {
		t.Fatal(err)
	}
	passwordOK(t, st, "carol", "Third-Pass-88")

	c, _, _ = fakeConsole("Fourth-Pass-99\nдругой-пароль-1\n")
	if err := cmdUserWith([]string{"passwd", "carol"}, c); err == nil || !strings.Contains(err.Error(), "не совпадают") {
		t.Fatalf("разные пароли: %v", err)
	}
	passwordOK(t, st, "carol", "Third-Pass-88")

	c, out, _ = fakeConsole("")
	if err := cmdUserWith([]string{"passwd", "carol", "--generate"}, c); err != nil {
		t.Fatal(err)
	}
	gen := strings.SplitN(strings.SplitN(out.String(), "Пароль: ", 2)[1], "\n", 2)[0]
	if u := passwordOK(t, st, "carol", gen); !u.MustChange {
		t.Fatal("сгенерированный пароль не требует смены")
	}
	for _, args := range [][]string{{"passwd"}, {"passwd", "carol", "--x"}, {"add", "dave", "--password", "--x"}} {
		if err := cmdUserWith(args, c); err == nil {
			t.Errorf("%v принят", args)
		}
	}
}

func TestPanelAddress(t *testing.T) {
	panelEnv(t)
	save := func(mut func(*config.Config)) {
		cfg := config.Default()
		mut(&cfg)
		if err := config.Save(paths.ConfigFile(), cfg); err != nil {
			t.Fatal(err)
		}
	}
	env := func(body string) {
		if err := os.WriteFile(filepath.Join(paths.Etc(), "install.env"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	save(func(c *config.Config) { c.Panel.BasePath = "/azpanel/" })
	env("ACCESS=path\nDOMAIN=vpn.example.com\n")
	if got := panelAddress(); got != "https://vpn.example.com/azpanel/" {
		t.Errorf("путь: %s", got)
	}
	save(func(c *config.Config) {})
	env("ACCESS=port\nADDRESS=203.0.113.5\nPORT=9443\n")
	if got := panelAddress(); got != "https://203.0.113.5:9443/" {
		t.Errorf("порт: %s", got)
	}
	env("ACCESS=local\n")
	if got := panelAddress(); !strings.HasPrefix(got, "http://127.0.0.1:") || !strings.Contains(got, "SSH-туннель") {
		t.Errorf("локально: %s", got)
	}
	// public_url — адрес сайта без префикса: префикс берётся из base_path.
	save(func(c *config.Config) { c.Panel.PublicURL, c.Panel.BasePath = "https://panel.example.org", "/x/" })
	if got := panelAddress(); got != "https://panel.example.org/x/" {
		t.Errorf("public_url: %s", got)
	}
}
