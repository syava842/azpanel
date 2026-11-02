package panel

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/panel/bot"
	"github.com/syava842/azpanel/internal/store"
)

// --- I3: привязка требует пароль и код 2FA ---

func TestTelegramLinkRequiresPassword(t *testing.T) {
	e, _, user, csrf, bob := userEnv(t)
	e.srv.BotName = func() string { return "testbot" }
	e.srv.CheckPassword = func(_, _, _, pw string) bool { return pw == testPassword }
	for _, pw := range []string{"", "wrong-password"} {
		rec := post(e, user, "/account/telegram", url.Values{"csrf": {csrf}, "password": {pw}})
		if rec.Code != 401 {
			t.Fatalf("пароль %q: %d", pw, rec.Code)
		}
	}
	if list, _, _ := e.st.AuditList(context.Background(), 10, 0, "tg_link_code"); len(list) != 0 {
		t.Fatalf("ссылка выпущена без пароля: %+v", list)
	}
	if _, err := e.st.RedeemLinkCode(context.Background(), "x", 1); err == nil {
		t.Fatal("код выпущен")
	}
	_ = bob
}

func TestTelegramLinkRequiresSecondFactor(t *testing.T) {
	e, c, csrf := accEnv(t)
	e.srv.BotName = func() string { return "testbot" }
	secret, _ := enableViaPages(t, e, c, csrf)
	if rec := post(e, c, "/account/telegram", form(csrf, "password", testPassword)); rec.Code != 401 {
		t.Fatalf("без кода 2FA: %d", rec.Code)
	}
	if rec := post(e, c, "/account/telegram", form(csrf, "password", testPassword, "code", "000000")); rec.Code != 401 {
		t.Fatalf("неверный код: %d", rec.Code)
	}
	rec := post(e, c, "/account/telegram", form(csrf, "password", testPassword, "code", totpNow(secret, 1)))
	if rec.Code != 303 {
		t.Fatalf("верные пароль и код: %d", rec.Code)
	}
}

// --- I3: смена и сброс пароля и «выйти везде» снимают привязку ---

func TestPasswordChangeUnlinksTelegram(t *testing.T) {
	e, c, csrf := accEnv(t)
	if err := e.st.SetTelegramID(context.Background(), e.admin.ID, 4242); err != nil {
		t.Fatal(err)
	}
	rec := post(e, c, "/account/password", form(csrf, "old", testPassword, "new", "newpassw0rd1", "new2", "newpassw0rd1"))
	if rec.Code != 303 {
		t.Fatalf("смена пароля: %d", rec.Code)
	}
	if u, _ := e.st.UserByID(context.Background(), e.admin.ID); u.TelegramID != nil {
		t.Fatal("привязка Telegram пережила смену пароля")
	}
	if list, _, _ := e.st.AuditList(context.Background(), 10, 0, "tg_unlink"); len(list) != 1 {
		t.Fatalf("отвязка не в журнале: %+v", list)
	}
}

func TestLogoutAllUnlinksTelegram(t *testing.T) {
	e, c, csrf := accEnv(t)
	if err := e.st.SetTelegramID(context.Background(), e.admin.ID, 4242); err != nil {
		t.Fatal(err)
	}
	if rec := post(e, c, "/account/sessions/all", form(csrf)); rec.Code != 303 {
		t.Fatalf("выход везде: %d", rec.Code)
	}
	if u, _ := e.st.UserByID(context.Background(), e.admin.ID); u.TelegramID != nil {
		t.Fatal("привязка Telegram пережила «выйти везде»")
	}
}

func TestAdminPasswordResetUnlinksTelegram(t *testing.T) {
	e, admin, _, _, bob := userEnv(t)
	if err := e.st.SetTelegramID(context.Background(), bob.ID, 777); err != nil {
		t.Fatal(err)
	}
	asess, _ := e.lookup(admin.Value)
	if rec := post(e, admin, "/users/"+itoa(bob.ID)+"/password", url.Values{"csrf": {asess.CSRF}}); rec.Code != 303 {
		t.Fatalf("сброс пароля: %d", rec.Code)
	}
	if u, _ := e.st.UserByID(context.Background(), bob.ID); u.TelegramID != nil {
		t.Fatal("привязка пережила сброс пароля")
	}
}

// Невыпущенный код привязки гаснет вместе с привязкой: иначе тот, кто успел
// получить ссылку, привяжет свой Telegram после смены пароля.
func TestPasswordChangeKillsUnusedLinkCodes(t *testing.T) {
	e, c, csrf := accEnv(t)
	code, err := e.st.CreateLinkCode(context.Background(), e.admin.ID, e.srv.now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if rec := post(e, c, "/account/password", form(csrf, "old", testPassword, "new", "newpassw0rd1", "new2", "newpassw0rd1")); rec.Code != 303 {
		t.Fatalf("смена пароля: %d", rec.Code)
	}
	if _, err := e.st.RedeemLinkCode(context.Background(), code, e.srv.now().Unix()); err == nil {
		t.Fatal("код привязки пережил смену пароля")
	}
}

func TestLogoutAllKillsUnusedLinkCodes(t *testing.T) {
	e, c, csrf := accEnv(t)
	code, _ := e.st.CreateLinkCode(context.Background(), e.admin.ID, e.srv.now().Unix())
	if rec := post(e, c, "/account/sessions/all", form(csrf)); rec.Code != 303 {
		t.Fatalf("выход везде: %d", rec.Code)
	}
	if _, err := e.st.RedeemLinkCode(context.Background(), code, e.srv.now().Unix()); err == nil {
		t.Fatal("код привязки пережил «выйти везде»")
	}
}

func TestAdminPasswordResetKillsUnusedLinkCodes(t *testing.T) {
	e, admin, _, _, bob := userEnv(t)
	code, _ := e.st.CreateLinkCode(context.Background(), bob.ID, e.srv.now().Unix())
	asess, _ := e.lookup(admin.Value)
	if rec := post(e, admin, "/users/"+itoa(bob.ID)+"/password", url.Values{"csrf": {asess.CSRF}}); rec.Code != 303 {
		t.Fatalf("сброс пароля: %d", rec.Code)
	}
	if _, err := e.st.RedeemLinkCode(context.Background(), code, e.srv.now().Unix()); err == nil {
		t.Fatal("код привязки пережил сброс пароля")
	}
}

// --- M1: счётчик кодов бота — общий с вебом ---

func TestBotBackendAttemptsSharedWithWeb(t *testing.T) {
	e, _, _, _, bob := userEnv(t)
	ctx := context.Background()
	b := e.srv.BotBackend()
	for i := 0; i < unlockMax; i++ { // пять неверных кодов в вебе по тому же ключу
		tk, retry, err := e.srv.openAttempt(ctx, "code:user:"+itoa(bob.ID), e.srv.now())
		if err != nil || retry > 0 {
			t.Fatalf("попытка %d: %v %v", i, retry, err)
		}
		e.srv.failAttempt(ctx, tk, e.srv.now())
	}
	if _, retry, err := b.OpenAttempt(ctx, bob.ID); err != nil || retry <= 0 {
		t.Fatalf("бот должен видеть закрытие ввода веба: %v %v", retry, err)
	}
	// и наоборот: ошибки бота закрывают веб
	other, _ := e.st.CreateUser(ctx, store.User{Login: "other", Hash: "x", Role: store.RoleUser})
	for i := 0; i < unlockMax; i++ {
		tk, retry, err := b.OpenAttempt(ctx, other.ID)
		if err != nil || retry > 0 {
			t.Fatalf("попытка бота %d: %v %v", i, retry, err)
		}
		b.FailAttempt(ctx, tk)
	}
	if _, retry, _ := e.srv.openAttempt(ctx, "code:user:"+itoa(other.ID), e.srv.now()); retry <= 0 {
		t.Fatal("веб не видит ошибок бота")
	}
}

// --- I2: страница «Telegram-бот» ---

func TestTelegramPageBackupGroupsAndUnban(t *testing.T) {
	e, admin, user, ucsrf, _ := userEnv(t)
	e.srv.Telegram.BackupChats = []int64{-100, -200, 555}
	asess, _ := e.lookup(admin.Value)
	ctx := context.Background()

	if rec := get(e, user, "/users/telegram"); rec.Code != 403 {
		t.Fatalf("пользователь открыл страницу: %d", rec.Code)
	}
	if rec := post(e, user, "/users/telegram/backup-groups", url.Values{"csrf": {ucsrf}, "group": {"-100"}}); rec.Code != 403 {
		t.Fatalf("пользователь подтвердил группу: %d", rec.Code)
	}
	body := get(e, admin, "/users/telegram").Body.String()
	for _, w := range []string{"-100", "-200", "555", "не получит"} {
		if !strings.Contains(body, w) {
			t.Fatalf("на странице нет %q: %s", w, body)
		}
	}
	// -999 не назван в backup_chats, 555 — личный: подтвердить можно только группу из списка
	rec := post(e, admin, "/users/telegram/backup-groups", url.Values{"csrf": {asess.CSRF}, "group": {"-200", "-999", "555"}})
	if rec.Code != 303 {
		t.Fatalf("сохранение: %d", rec.Code)
	}
	if v, _, _ := e.st.Meta(ctx, bot.BackupGroupsKey); v != "-200" {
		t.Fatalf("подтверждено %q", v)
	}
	if list, _, _ := e.st.AuditList(ctx, 10, 0, "tg_backup_groups"); len(list) != 1 {
		t.Fatalf("журнал: %+v", list)
	}
	// блокировки
	if err := e.st.BanTelegram(ctx, 31337, 1); err != nil {
		t.Fatal(err)
	}
	if body := get(e, admin, "/users/telegram").Body.String(); !strings.Contains(body, "31337") {
		t.Fatal("блокировка не показана")
	}
	if rec := post(e, admin, "/users/telegram/unban", url.Values{"csrf": {asess.CSRF}, "id": {"31337"}}); rec.Code != 303 {
		t.Fatalf("разблокировка: %d", rec.Code)
	}
	if banned, _ := e.st.TelegramBanned(ctx, 31337); banned {
		t.Fatal("ID остался заблокированным")
	}
}

// --- M15 ---

func TestDeleteClientDropsClientKinds(t *testing.T) {
	e, _, _, _, _ := userEnv(t)
	ctx := context.Background()
	if err := e.st.SetClientKinds(ctx, store.LocalNode, ownClient, []string{"wireguard"}); err != nil {
		t.Fatal(err)
	}
	e.node.DeleteClientFn = func(context.Context, string, string) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	if err := e.srv.BotBackend().Delete(ctx, nodeapi.Client{Name: ownClient, WireGuard: true}, nodeapi.KindWireGuard); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := e.st.ClientKinds(ctx, store.LocalNode, ownClient); found {
		t.Fatal("ограничение профилей пережило удаление клиента")
	}
}

// --- M6: снимок ресурсов для бота ---

func TestCollectorKeepsLastSystemForBot(t *testing.T) {
	e := alertEnv(t)
	if _, ok := e.c.LastSystem(); ok {
		t.Fatal("снимок есть до первого прохода")
	}
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) {
		var s nodeapi.System
		s.Resources.CPUPercent = 42
		return s, nil
	}
	e.tick(t)
	if s, ok := e.c.LastSystem(); !ok || s.Resources.CPUPercent != 42 {
		t.Fatalf("снимок: %+v %v", s, ok)
	}
	e.node.SystemFn = func(context.Context) (nodeapi.System, error) { return nodeapi.System{}, context.DeadlineExceeded }
	e.advance(time.Minute)
	e.tickAny()
	if s, ok := e.c.LastSystem(); !ok || s.Resources.CPUPercent != 42 {
		t.Fatal("неудачный проход стёр последний удачный снимок")
	}
}
