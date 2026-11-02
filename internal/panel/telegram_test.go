package panel

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

var tgLinkRe = regexp.MustCompile(`https://t\.me/testbot\?start=([A-Za-z0-9_-]{22})`)

func TestAccountTelegramLinkShownOnceAndRedeemable(t *testing.T) {
	e, _, user, csrf, bob := userEnv(t)
	e.srv.BotName = func() string { return "testbot" }

	rec := post(e, user, "/account/telegram", url.Values{"csrf": {csrf}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/account/once" {
		t.Fatalf("выпуск: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	page := get(e, user, "/account/once").Body.String()
	m := tgLinkRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("ссылки привязки нет на странице: %s", page)
	}
	id, err := e.st.RedeemLinkCode(context.Background(), m[1], e.srv.now().Unix())
	if err != nil || id != bob.ID {
		t.Fatalf("код привязки: %d, %v", id, err)
	}
	// второй раз ссылку не показывают
	if again := get(e, user, "/account/once"); again.Code != 303 {
		t.Fatalf("повторный показ: %d", again.Code)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "tg_link_code")
	if len(list) != 1 || strings.Contains(list[0].After, m[1]) {
		t.Fatalf("журнал выпуска: %+v", list)
	}
}

func TestAccountTelegramNeedsRunningBot(t *testing.T) {
	e, _, user, csrf, _ := userEnv(t)
	if rec := post(e, user, "/account/telegram", url.Values{"csrf": {csrf}}); rec.Code != 503 {
		t.Fatalf("без бота: %d", rec.Code)
	}
	if body := get(e, user, "/account").Body.String(); strings.Contains(body, "Привязать Telegram") || !strings.Contains(body, "Бот не запущен") {
		t.Fatal("кнопка привязки при остановленном боте")
	}
	e.srv.BotName = func() string { return "testbot" }
	if body := get(e, user, "/account").Body.String(); !strings.Contains(body, "Привязать Telegram") {
		t.Fatal("нет кнопки привязки")
	}
}

func TestTelegramUnlinkSelfAndByAdmin(t *testing.T) {
	e, admin, user, csrf, bob := userEnv(t)
	e.srv.BotName = func() string { return "testbot" }
	if err := e.st.SetTelegramID(context.Background(), bob.ID, 777); err != nil {
		t.Fatal(err)
	}
	if body := get(e, user, "/account").Body.String(); !strings.Contains(body, "ID 777") {
		t.Fatal("привязка не показана в аккаунте")
	}
	// уже привязанный не может выпустить ещё одну ссылку
	if rec := post(e, user, "/account/telegram", url.Values{"csrf": {csrf}}); rec.Code != 400 {
		t.Fatalf("повторная ссылка: %d", rec.Code)
	}
	if body := get(e, admin, "/users/"+itoa(bob.ID)).Body.String(); !strings.Contains(body, "ID 777") {
		t.Fatal("администратор не видит привязку")
	}
	asess, _ := e.lookup(admin.Value)
	if rec := post(e, admin, "/users/"+itoa(bob.ID)+"/telegram/unlink", url.Values{"csrf": {asess.CSRF}}); rec.Code != 303 {
		t.Fatalf("отвязка администратором: %d", rec.Code)
	}
	if u, _ := e.st.UserByID(context.Background(), bob.ID); u.TelegramID != nil {
		t.Fatal("привязка осталась")
	}
	e.st.SetTelegramID(context.Background(), bob.ID, 777)
	if rec := post(e, user, "/account/telegram/unlink", url.Values{"csrf": {csrf}}); rec.Code != 303 {
		t.Fatalf("самоотвязка: %d", rec.Code)
	}
	if u, _ := e.st.UserByID(context.Background(), bob.ID); u.TelegramID != nil {
		t.Fatal("самоотвязка не сработала")
	}
	// пользователь не отвязывает других
	if rec := post(e, user, "/users/"+itoa(bob.ID)+"/telegram/unlink", url.Values{"csrf": {csrf}}); rec.Code != 403 {
		t.Fatalf("отвязка пользователем: %d", rec.Code)
	}
}

func TestClientKindsForm(t *testing.T) {
	e, admin, user, ucsrf, _ := userEnv(t)
	asess, _ := e.lookup(admin.Value)
	if rec := post(e, user, "/clients/"+ownClient+"/kinds", url.Values{"csrf": {ucsrf}, "kinds": {"vpn"}}); rec.Code != 403 {
		t.Fatalf("пользователь меняет типы: %d", rec.Code)
	}
	if body := get(e, admin, "/clients/"+ownClient).Body.String(); !strings.Contains(body, "Профили в Telegram") {
		t.Fatal("нет формы типов профилей")
	}
	rec := post(e, admin, "/clients/"+ownClient+"/kinds", url.Values{"csrf": {asess.CSRF}, "kinds": {"wireguard", "vpn"}})
	if rec.Code != 303 {
		t.Fatalf("сохранение: %d %s", rec.Code, rec.Body)
	}
	got, found, err := e.st.ClientKinds(context.Background(), store.LocalNode, ownClient)
	if err != nil || !found || strings.Join(got, ",") != "vpn,wireguard" {
		t.Fatalf("сохранено: %v %v %v", got, found, err)
	}
	if rec := post(e, admin, "/clients/"+ownClient+"/kinds", url.Values{"csrf": {asess.CSRF}, "kinds": {"bogus"}}); rec.Code != 400 {
		t.Fatalf("неизвестный тип: %d", rec.Code)
	}
	post(e, admin, "/clients/"+ownClient+"/kinds", url.Values{"csrf": {asess.CSRF}})
	if _, found, _ := e.st.ClientKinds(context.Background(), store.LocalNode, ownClient); found {
		t.Fatal("пустой выбор не снял ограничение")
	}
}

func TestBotBackendActions(t *testing.T) {
	e, _, _, _, bob := userEnv(t)
	ctx := context.Background()
	b := e.srv.BotBackend()
	var blocked []bool
	e.node.SetBlockedFn = func(_ context.Context, name string, v bool) (nodeapi.Result, error) {
		blocked = append(blocked, v)
		return nodeapi.Result{Killed: 3}, nil
	}
	n, err := b.Block(ctx, nodeapi.Client{Name: ownClient}, true)
	if err != nil || n != 3 || len(blocked) != 1 || !blocked[0] {
		t.Fatalf("блокировка: %d %v %v", n, blocked, err)
	}
	// ручной блок поверх автоблока снимает отметку автоблока
	e.st.SetAutoBlock(ctx, store.LocalNode, ownClient, "срок действия истёк", "")
	if _, err := b.Block(ctx, nodeapi.Client{Name: ownClient}, true); err != nil {
		t.Fatal(err)
	}
	if card, _ := e.st.Card(ctx, store.LocalNode, ownClient); card.AutoBlock != "" {
		t.Fatalf("блок остался автоматическим: %+v", card)
	}
	e.node.SetBlockedFn = func(context.Context, string, bool) (nodeapi.Result, error) {
		return nodeapi.Result{}, errors.New("агент не ответил")
	}
	if _, err := b.Block(ctx, nodeapi.Client{Name: ownClient}, false); err == nil {
		t.Fatal("ошибка агента потеряна")
	}

	u, err := b.NewUser(ctx, "tg-new")
	if err != nil || u.Role != store.RoleUser || !u.MustChange || u.Hash == "" || u.ID == bob.ID {
		t.Fatalf("новый пользователь: %+v %v", u, err)
	}
	if _, ok := b.QR([]byte("x")); !ok {
		t.Fatal("QR не нарисован")
	}
}
