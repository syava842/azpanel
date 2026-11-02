package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/store"
)

// userEnv — корень во временном каталоге и база с администратором
// (с 2FA, резервными кодами и двумя сессиями) и обычным пользователем.
func userEnv(t *testing.T) (*store.Store, store.User) {
	t.Helper()
	panelEnv(t)
	os.MkdirAll(paths.Data(), 0o700)
	st, err := store.Open(panelDBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	old, _ := bcrypt.GenerateFromPassword([]byte("old-password-1"), 4)
	admin, err := st.CreateUser(ctx, store.User{Login: "admin", Hash: string(old), Role: store.RoleAdmin, TOTPSecret: []byte("sealed"), TOTPLastStep: 7})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.User{Login: "bob", Hash: string(old), Role: store.RoleUser, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	bc, _ := bcrypt.GenerateFromPassword([]byte("code"), 4)
	if err := st.SetBackupCodes(ctx, admin.ID, []string{string(bc)}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"h1", "h2"} {
		if err := st.CreateSession(ctx, store.Session{IDHash: h, UserID: admin.ID, CSRF: "c", Expires: time.Now().Add(time.Hour).Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	return st, admin
}

func TestUserReset(t *testing.T) {
	st, admin := userEnv(t)
	ctx := context.Background()
	var out bytes.Buffer
	if err := cmdUser([]string{"reset", " Admin "}, &out); err != nil {
		t.Fatal(err)
	}
	// Пароль берём из вывода: «... admin: ПАРОЛЬ».
	line := strings.SplitN(out.String(), "\n", 2)[0]
	pw := line[strings.LastIndex(line, " ")+1:]
	if len(pw) != 16 {
		t.Fatalf("пароль %q: нужно 16 символов", pw)
	}
	u, err := st.UserByID(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(pw)) != nil {
		t.Fatal("новый пароль не подходит к хешу")
	}
	if !u.MustChange || len(u.TOTPSecret) != 0 || u.TOTPLastStep != 0 {
		t.Fatalf("состояние после сброса: %+v", u)
	}
	if ok, _ := st.UseBackupCode(ctx, admin.ID, "code"); ok {
		t.Fatal("резервные коды не удалены")
	}
	if ss, _ := st.UserSessions(ctx, admin.ID); len(ss) != 0 {
		t.Fatalf("сессий осталось %d", len(ss))
	}
	list, _, _ := st.AuditList(ctx, 10, 0, "user_reset")
	if len(list) != 1 || list[0].User != "root (консоль)" || list[0].Target != "admin" {
		t.Fatalf("журнал: %+v", list)
	}
	if strings.Contains(list[0].After, pw) {
		t.Fatal("пароль попал в журнал")
	}
}

func TestUserResetUnknown(t *testing.T) {
	userEnv(t)
	err := cmdUser([]string{"reset", "ghost"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "не найден") {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestUserResetNoDB(t *testing.T) {
	panelEnv(t)
	err := cmdUser([]string{"reset", "admin"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "база панели не найдена") {
		t.Fatalf("ошибка = %v", err)
	}
	if _, serr := os.Stat(panelDBPath()); serr == nil {
		t.Fatal("команда создала базу")
	}
}

func TestUserUsage(t *testing.T) {
	for _, a := range [][]string{nil, {"reset"}, {"reset", "a", "b"}, {"list", "x"}, {"oops"}} {
		if err := cmdUser(a, &bytes.Buffer{}); err != errUsage {
			t.Errorf("%v: ошибка %v", a, err)
		}
	}
}

func TestUserList(t *testing.T) {
	userEnv(t)
	var out bytes.Buffer
	if err := cmdUser([]string{"list"}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"ЛОГИН", "admin", "администратор", "bob", "пользователь", "отключён"} {
		if !strings.Contains(s, want) {
			t.Errorf("в списке нет %q:\n%s", want, s)
		}
	}
}

func TestResetPasswordShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := newResetPassword()
		if err != nil {
			t.Fatal(err)
		}
		var letter, digit bool
		for _, r := range p {
			letter = letter || unicode.IsLetter(r)
			digit = digit || unicode.IsDigit(r)
		}
		if len(p) != 16 || !letter || !digit {
			t.Fatalf("пароль %q не подходит", p)
		}
		seen[p] = true
	}
	if len(seen) < 200 {
		t.Fatal("пароли повторяются")
	}
}

// panel passwd — сброс первого администратора, когда в базе уже есть пользователи.
func TestPasswdResetsFirstAdminInDB(t *testing.T) {
	st, admin := userEnv(t)
	if err := cmdPanelPasswd(nil, strings.NewReader("brand-new-pass1\n"), nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByID(context.Background(), admin.ID)
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte("brand-new-pass1")) != nil {
		t.Fatal("пароль администратора в базе не обновлён")
	}
	if u.MustChange || len(u.TOTPSecret) != 0 {
		t.Fatalf("состояние: %+v", u)
	}
}
