package bot

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/telegram"
)

const (
	textClosed   = "Эта учётная запись отключена."
	textNoRights = "Недостаточно прав."
	textBadLink  = "Код привязки недействителен или истёк. Получите новый в панели: Аккаунт, «Привязать Telegram»."
	textGone     = "Клиент не найден."
)

var loginSan = regexp.MustCompile(`[^a-z0-9_.-]`)

// parseStart разбирает «/start» и «/start код».
func parseStart(text string) (isStart bool, code string) {
	f := strings.Fields(text)
	if len(f) == 0 || (f[0] != "/start" && !strings.HasPrefix(f[0], "/start@")) {
		return false, ""
	}
	if len(f) > 1 {
		code = f[1]
	}
	return true, code
}

func (b *Bot) onMessage(ctx context.Context, m *telegram.Message) {
	// Только личные чаты: группы и каналы бот не слушает.
	if m.Chat.Type != "private" || m.From == nil || m.From.IsBot {
		return
	}
	tg := m.From.ID
	if banned, err := b.Store.TelegramBanned(ctx, tg); err != nil {
		b.log().Warn("бот: блокировка не проверена", "err", err)
		return
	} else if banned {
		return
	}
	text := strings.TrimSpace(m.Text)
	_, code := parseStart(text)
	u, err := b.Store.UserByTelegramID(ctx, tg)
	switch {
	case errors.Is(err, store.ErrNotFound):
		b.onStranger(ctx, m, text, code)
		return
	case err != nil:
		b.log().Warn("бот: пользователь не прочитан", "err", err)
		return
	}
	if u.Disabled {
		b.send(ctx, m.Chat.ID, textClosed, nil)
		return
	}
	a := actor{tg: tg, chat: m.Chat.ID, user: u, admin: u.Role == store.RoleAdmin}
	if isStart, code := parseStart(text); isStart && code != "" {
		b.send(ctx, a.chat, "Этот Telegram уже привязан к «"+u.Login+"».", b.mainMenu(a))
		return
	}
	b.onText(ctx, a, text)
}

// onStranger — сообщение от непривязанного Telegram.
func (b *Bot) onStranger(ctx context.Context, m *telegram.Message, text, code string) {
	chat := m.Chat.ID
	if code != "" {
		b.link(ctx, m, code)
		return
	}
	if b.Cfg.Strangers != "request" {
		return // closed: молчим
	}
	reqs, err := b.Store.TelegramRequests(ctx)
	if err != nil {
		b.log().Warn("бот: заявки не прочитаны", "err", err)
		return
	}
	known := false
	for _, r := range reqs {
		if r.ID == m.From.ID {
			known = true
		}
	}
	req := store.TelegramRequest{ID: m.From.ID, Username: m.From.Username, Name: displayName(m.From), Created: b.now().Unix()}
	if err := b.Store.AddTelegramRequest(ctx, req); err != nil {
		b.log().Warn("бот: заявка не записана", "err", err)
		return
	}
	b.send(ctx, chat, "Заявка отправлена администратору. Ответ придёт сюда.", nil)
	if known {
		return
	}
	who := req.Name
	if req.Username != "" {
		who += " (@" + req.Username + ")"
	}
	kb := keyboard(
		row(btn("Одобрить", cb("ra", req.ID)), btn("Отклонить", cb("rd", req.ID))),
		row(btn("Заблокировать ID", cb("rx", req.ID))),
	)
	for _, ad := range b.admins(ctx) {
		b.send(ctx, *ad.TelegramID, fmt.Sprintf("Заявка на доступ к панели: %s, Telegram ID %d.", who, req.ID), kb)
	}
}

// link привязывает Telegram по коду из панели.
func (b *Bot) link(ctx context.Context, m *telegram.Message, code string) {
	tg, chat := m.From.ID, m.Chat.ID
	key := fmt.Sprintf("tglink:%d", tg)
	now := b.now()
	n, err := b.Store.Attempts(ctx, key, now.Add(-codeWindow).Unix())
	if err != nil {
		b.log().Warn("бот: попытки не прочитаны", "err", err)
		return
	}
	if n >= linkMax {
		return
	}
	uid, err := b.Store.RedeemLinkCode(ctx, code, now.Unix())
	if errors.Is(err, store.ErrCodeInvalid) {
		if aerr := b.Store.Attempt(ctx, key, now.Unix()); aerr != nil {
			b.log().Warn("бот: попытка не записана", "err", aerr)
		}
		b.send(ctx, chat, textBadLink, nil)
		return
	}
	if err != nil {
		b.log().Warn("бот: код привязки не принят", "err", err)
		return
	}
	u, err := b.Store.UserByID(ctx, uid)
	if err != nil {
		b.log().Warn("бот: пользователь привязки не прочитан", "err", err)
		return
	}
	if err := b.Store.SetTelegramID(ctx, uid, tg); err != nil {
		if errors.Is(err, store.ErrTelegramTaken) {
			b.send(ctx, chat, err.Error()+".", nil)
			return
		}
		b.log().Warn("бот: Telegram не привязан", "err", err)
		return
	}
	if err := b.Store.DeleteTelegramRequest(ctx, tg); err != nil {
		b.log().Warn("бот: заявка не снята", "err", err)
	}
	u.TelegramID = &tg
	a := actor{tg: tg, chat: chat, user: u, admin: u.Role == store.RoleAdmin}
	b.audit(ctx, a, "tg_link", u.Login, "", fmt.Sprintf("привязан Telegram %d", tg))
	b.send(ctx, chat, "Готово: Telegram привязан к «"+u.Login+"».", b.mainMenu(a))
}

// onText — сообщение привязанного пользователя.
func (b *Bot) onText(ctx context.Context, a actor, text string) {
	f := strings.Fields(text)
	cmd := ""
	if len(f) > 0 && strings.HasPrefix(f[0], "/") {
		cmd = strings.TrimPrefix(strings.SplitN(f[0], "@", 2)[0], "/")
	}
	switch cmd {
	case "start", "menu":
		b.setDialog(a.tg, nil)
		b.send(ctx, a.chat, b.menuTitle(a), b.mainMenu(a))
		return
	case "help":
		b.send(ctx, a.chat, helpText(a), b.mainMenu(a))
		return
	case "cancel":
		b.setDialog(a.tg, nil)
		b.send(ctx, a.chat, "Отменено.", b.mainMenu(a))
		return
	case "clients":
		b.showClients(ctx, a, 0, 0)
		return
	case "code":
		b.startCode(ctx, a, 0, "")
		return
	case "node":
		if a.admin {
			b.showNode(ctx, a, 0)
			return
		}
	}
	if d := b.getDialog(a.tg); d != nil && cmd == "" {
		b.onDialog(ctx, a, d, text)
		return
	}
	if a.admin && cmd == "" && text != "" {
		b.search(ctx, a, text)
		return
	}
	b.send(ctx, a.chat, "Выберите действие.", b.mainMenu(a))
}

func helpText(a actor) string {
	s := "Команды: /menu, /clients, /code, /cancel."
	if a.admin {
		s += " Название клиента, отправленное сообщением, ищет его по подстроке. /node показывает состояние узла."
	}
	return s
}

func (b *Bot) menuTitle(a actor) string {
	role := "пользователь"
	if a.admin {
		role = "администратор"
	}
	return "Меню. Вы вошли как «" + a.user.Login + "» (" + role + ")."
}

func (b *Bot) mainMenu(a actor) *telegram.InlineKeyboardMarkup {
	if a.admin {
		return keyboard(
			row(btn("Клиенты", cb("l", 0)), btn("Создать клиента", "n")),
			row(btn("Узел", "s"), btn("Бэкап", "u")),
			row(btn("Перезагрузка сервера", "z")),
		)
	}
	return keyboard(row(btn("Мои клиенты", cb("l", 0)), btn("Ввести код", "k")))
}

// onCallback — нажатие кнопки.
func (b *Bot) onCallback(ctx context.Context, q *telegram.CallbackQuery) {
	if q.Message == nil || q.Message.Chat.Type != "private" || q.From.ID != q.Message.Chat.ID {
		_ = b.TG.AnswerCallbackQuery(ctx, q.ID, "", false)
		return
	}
	tg := q.From.ID
	if banned, err := b.Store.TelegramBanned(ctx, tg); err != nil || banned {
		_ = b.TG.AnswerCallbackQuery(ctx, q.ID, "", false)
		return
	}
	u, err := b.Store.UserByTelegramID(ctx, tg)
	if err != nil || u.Disabled {
		_ = b.TG.AnswerCallbackQuery(ctx, q.ID, "Нет доступа.", true)
		return
	}
	a := actor{tg: tg, chat: q.Message.Chat.ID, user: u, admin: u.Role == store.RoleAdmin}
	args := strings.Split(q.Data, ":")
	toast := b.dispatch(ctx, a, q.Message.MessageID, args[0], args[1:])
	if err := b.TG.AnswerCallbackQuery(ctx, q.ID, toast, false); err != nil {
		b.log().Warn("бот: ответ на кнопку не отправлен", "err", err)
	}
}

func argInt(args []string, i int) (int, bool) {
	if i >= len(args) {
		return 0, false
	}
	n, err := strconv.Atoi(args[i])
	return n, err == nil
}

func argName(args []string, i int) (string, bool) {
	if i >= len(args) || !limits.ValidName(args[i]) {
		return "", false
	}
	return args[i], true
}

// adminOps — операции, которые видит и выполняет только администратор.
var adminOps = map[string]bool{
	"n": true, "t": true, "g": true, "s": true, "u": true, "z": true,
	"e": true, "i": true, "b": true, "d": true,
	"ra": true, "rb": true, "rc": true, "rd": true, "rx": true,
}

// dispatch выполняет кнопку и возвращает короткий текст-всплывашку.
func (b *Bot) dispatch(ctx context.Context, a actor, msgID int64, op string, args []string) string {
	if adminOps[op] && !a.admin {
		return textNoRights
	}
	switch op {
	case "m":
		b.setDialog(a.tg, nil)
		b.show(ctx, a.chat, msgID, b.menuTitle(a), b.mainMenu(a))
	case "l":
		page, _ := argInt(args, 0)
		b.showClients(ctx, a, msgID, page)
	case "c":
		name, ok := argName(args, 0)
		if !ok {
			return textGone
		}
		return b.showCard(ctx, a, msgID, name, "")
	case "p":
		name, ok := argName(args, 0)
		if !ok {
			return textGone
		}
		return b.showProfiles(ctx, a, msgID, name)
	case "f", "q":
		i, ok1 := argInt(args, 0)
		name, ok2 := argName(args, 1)
		if !ok1 || !ok2 {
			return textGone
		}
		return b.sendProfile(ctx, a, name, i, op == "q")
	case "k":
		if name, ok := argName(args, 0); ok {
			return b.startCode(ctx, a, msgID, name)
		}
		return b.startCode(ctx, a, msgID, "")
	case "e":
		days, ok1 := argInt(args, 0)
		name, ok2 := argName(args, 1)
		if !ok1 || !ok2 {
			return textGone
		}
		return b.renew(ctx, a, msgID, name, days)
	case "i":
		n, ok1 := argInt(args, 0)
		name, ok2 := argName(args, 1)
		if !ok1 || !ok2 {
			return textGone
		}
		return b.setLimit(ctx, a, msgID, name, n)
	case "b":
		on, ok1 := argInt(args, 0)
		name, ok2 := argName(args, 1)
		if !ok1 || !ok2 {
			return textGone
		}
		return b.block(ctx, a, msgID, name, on == 1)
	case "d":
		name, ok := argName(args, 0)
		if !ok {
			return textGone
		}
		return b.askDelete(ctx, a, msgID, name)
	case "y":
		if len(args) < 1 {
			return "Подтверждение не найдено."
		}
		return b.confirmed(ctx, a, msgID, args[0])
	case "n":
		b.setDialog(a.tg, &dialog{kind: "create", step: "name"})
		b.show(ctx, a.chat, msgID, "Имя нового клиента: латиница, цифры, «_» и «-», до 32 знаков. /cancel — отмена.", nil)
	case "t":
		return b.createType(ctx, a, msgID, args)
	case "g":
		return b.createDays(ctx, a, msgID, args)
	case "s":
		b.showNode(ctx, a, msgID)
	case "u":
		return b.startBackup(ctx, a)
	case "z":
		tok := b.newConfirm(a.tg, "reboot", "")
		b.show(ctx, a.chat, msgID, "Перезагрузить сервер? Все подключения прервутся. Подтверждение действует 60 секунд.",
			keyboard(row(btn("Да, перезагрузить", cb("y", tok)), btn("Отмена", "m"))))
	case "ra", "rb", "rc", "rd", "rx":
		return b.request(ctx, a, msgID, op, args)
	}
	return ""
}

// onDialog — очередной ответ в диалоге.
func (b *Bot) onDialog(ctx context.Context, a actor, d *dialog, text string) {
	switch d.kind {
	case "create":
		if !a.admin || d.step != "name" {
			b.send(ctx, a.chat, "Выберите кнопку под сообщением или /cancel.", nil)
			return
		}
		if !limits.ValidName(text) {
			b.send(ctx, a.chat, "Имя не подходит: латиница, цифры, «_» и «-», до 32 знаков. Повторите или /cancel.", nil)
			return
		}
		d.name, d.step = text, "type"
		b.setDialog(a.tg, d)
		b.send(ctx, a.chat, "Тип клиента «"+text+"»:", keyboard(
			row(btn("OpenVPN", cb("t", nodeapi.KindOpenVPN)), btn("WireGuard", cb("t", nodeapi.KindWireGuard)))))
	case "code":
		b.enterCode(ctx, a, d.client, text)
	}
}

// search — поиск клиента по подстроке имени (администратор).
func (b *Bot) search(ctx context.Context, a actor, q string) {
	list, err := b.Node.Clients(ctx)
	if err != nil {
		b.send(ctx, a.chat, "Агент недоступен: "+err.Error(), nil)
		return
	}
	q = strings.ToLower(q)
	var rows [][]telegram.InlineKeyboardButton
	for _, c := range sortedClients(list) {
		if strings.Contains(strings.ToLower(c.Name), q) {
			rows = append(rows, row(btn(c.Name, cb("c", c.Name))))
			if len(rows) >= pageSize {
				break
			}
		}
	}
	if len(rows) == 0 {
		b.send(ctx, a.chat, "Клиентов по «"+q+"» нет.", b.mainMenu(a))
		return
	}
	b.send(ctx, a.chat, "Найдено по «"+q+"»:", keyboard(rows...))
}

// request — кнопки заявки на доступ.
func (b *Bot) request(ctx context.Context, a actor, msgID int64, op string, args []string) string {
	idv, ok := argInt(args, 0)
	if !ok {
		return "Заявка не найдена."
	}
	id := int64(idv)
	reqs, err := b.Store.TelegramRequests(ctx)
	if err != nil {
		return "Заявки не прочитаны."
	}
	var req *store.TelegramRequest
	for i := range reqs {
		if reqs[i].ID == id {
			req = &reqs[i]
		}
	}
	if req == nil {
		b.show(ctx, a.chat, msgID, "Заявка уже обработана.", nil)
		return ""
	}
	switch op {
	case "ra":
		us, err := b.Store.Users(ctx)
		if err != nil {
			return "Пользователи не прочитаны."
		}
		var rows [][]telegram.InlineKeyboardButton
		for _, u := range us {
			if u.TelegramID == nil && !u.Disabled && len(rows) < 30 {
				rows = append(rows, row(btn(u.Login, cb("rb", id, u.ID))))
			}
		}
		rows = append(rows, row(btn("Создать нового пользователя", cb("rc", id))), row(btn("Отмена", "m")))
		b.show(ctx, a.chat, msgID, "Кому привязать Telegram ID "+strconv.FormatInt(id, 10)+"?", keyboard(rows...))
	case "rb":
		uid, ok := argInt(args, 1)
		if !ok {
			return "Пользователь не найден."
		}
		u, err := b.Store.UserByID(ctx, int64(uid))
		if err != nil {
			return "Пользователь не найден."
		}
		return b.approve(ctx, a, msgID, *req, u)
	case "rc":
		login := loginSan.ReplaceAllString(strings.ToLower(req.Username), "")
		if len(login) < 3 {
			login = fmt.Sprintf("tg%d", id)
		}
		if len(login) > 32 {
			login = login[:32]
		}
		u, err := b.Back.NewUser(ctx, login)
		if errors.Is(err, store.ErrLoginTaken) {
			u, err = b.Back.NewUser(ctx, fmt.Sprintf("tg%d", id))
		}
		if err != nil {
			b.log().Warn("бот: пользователь не создан", "err", err)
			return "Пользователь не создан: " + err.Error()
		}
		b.audit(ctx, a, "user_create", u.Login, "", "создан из заявки Telegram")
		return b.approve(ctx, a, msgID, *req, u)
	case "rd":
		if err := b.Store.DeleteTelegramRequest(ctx, id); err != nil {
			return "Заявка не снята."
		}
		b.audit(ctx, a, "tg_request", strconv.FormatInt(id, 10), "", "отклонена")
		b.send(ctx, id, "Заявка отклонена.", nil)
		b.show(ctx, a.chat, msgID, "Заявка "+strconv.FormatInt(id, 10)+" отклонена.", nil)
	case "rx":
		if err := b.Store.BanTelegram(ctx, id, b.now().Unix()); err != nil {
			return "ID не заблокирован."
		}
		b.audit(ctx, a, "tg_ban", strconv.FormatInt(id, 10), "", "ID заблокирован")
		b.show(ctx, a.chat, msgID, "Telegram ID "+strconv.FormatInt(id, 10)+" заблокирован: бот ему не отвечает.", nil)
	}
	return ""
}

func (b *Bot) approve(ctx context.Context, a actor, msgID int64, req store.TelegramRequest, u store.User) string {
	if err := b.Store.SetTelegramID(ctx, u.ID, req.ID); err != nil {
		return err.Error()
	}
	if err := b.Store.DeleteTelegramRequest(ctx, req.ID); err != nil {
		b.log().Warn("бот: заявка не снята", "err", err)
	}
	b.audit(ctx, a, "tg_request", strconv.FormatInt(req.ID, 10), "", "одобрена, пользователь "+u.Login)
	b.send(ctx, req.ID, "Заявка одобрена: вы вошли как «"+u.Login+"».", b.mainMenu(actor{user: u, admin: u.Role == store.RoleAdmin}))
	b.show(ctx, a.chat, msgID, "Telegram ID "+strconv.FormatInt(req.ID, 10)+" привязан к «"+u.Login+"».", nil)
	return ""
}
