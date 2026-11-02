package bot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/telegram"
)

func sortedClients(list []nodeapi.Client) []nodeapi.Client {
	out := append([]nodeapi.Client(nil), list...)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// ownClients — имена клиентов пользователя на этом узле.
func (b *Bot) ownClients(ctx context.Context, userID int64) (map[string]bool, error) {
	refs, err := b.Store.ClientsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range refs {
		if r.Node == b.NodeID {
			out[r.Name] = true
		}
	}
	return out, nil
}

// visible находит клиента среди клиентов агента: администратору виден любой,
// пользователю только свой. Чужой отвечает так же, как несуществующий.
func (b *Bot) visible(ctx context.Context, a actor, name string) (nodeapi.Client, bool, error) {
	list, err := b.Node.Clients(ctx)
	if err != nil {
		return nodeapi.Client{}, false, err
	}
	for _, c := range list {
		if c.Name != name {
			continue
		}
		if a.admin {
			return c, true, nil
		}
		owner, has, err := b.Store.OwnerOf(ctx, b.NodeID, name)
		if err != nil {
			return nodeapi.Client{}, false, err
		}
		return c, has && owner == a.user.ID, nil
	}
	return nodeapi.Client{}, false, nil
}

func (b *Bot) showClients(ctx context.Context, a actor, msgID int64, page int) {
	list, err := b.Node.Clients(ctx)
	if err != nil {
		b.show(ctx, a.chat, msgID, "Клиенты недоступны: "+b.agentErr(err), b.mainMenu(a))
		return
	}
	var own map[string]bool
	if !a.admin {
		if own, err = b.ownClients(ctx, a.user.ID); err != nil {
			b.log().Warn("бот: клиенты пользователя не прочитаны", "err", err)
			b.show(ctx, a.chat, msgID, "Клиенты не прочитаны.", b.mainMenu(a))
			return
		}
	}
	online := map[string]int{}
	if ss, err := b.Node.Sessions(ctx); err == nil {
		for _, s := range ss {
			online[s.Name]++
		}
	}
	var shown []nodeapi.Client
	for _, c := range sortedClients(list) {
		if own == nil || own[c.Name] {
			shown = append(shown, c)
		}
	}
	if len(shown) == 0 {
		text := "Клиентов нет."
		if !a.admin {
			text = "У вас пока нет клиентов. Если у вас есть код продления, нажмите «Ввести код»."
		}
		b.show(ctx, a.chat, msgID, text, b.mainMenu(a))
		return
	}
	pages := (len(shown) + pageSize - 1) / pageSize
	page = max(0, min(page, pages-1))
	end := min(len(shown), (page+1)*pageSize)
	var rows [][]telegram.InlineKeyboardButton
	for _, c := range shown[page*pageSize : end] {
		label := c.Name
		if n := online[c.Name]; n > 0 {
			label = "● " + label
		}
		if c.Blocked {
			label += " (блок)"
		}
		rows = append(rows, row(btn(label, cb("c", c.Name))))
	}
	var nav []telegram.InlineKeyboardButton
	if page > 0 {
		nav = append(nav, btn("◀ Назад", cb("l", page-1)))
	}
	if page < pages-1 {
		nav = append(nav, btn("Вперёд ▶", cb("l", page+1)))
	}
	if len(nav) > 0 {
		rows = append(rows, nav)
	}
	rows = append(rows, row(btn("Меню", "m")))
	head := fmt.Sprintf("Клиенты: %d, страница %d из %d. ● — сейчас онлайн.", len(shown), page+1, pages)
	if a.admin {
		head += " Чтобы найти клиента, отправьте часть имени сообщением."
	}
	b.show(ctx, a.chat, msgID, head, keyboard(rows...))
}

// cardText — текст карточки клиента.
func (b *Bot) cardText(ctx context.Context, c nodeapi.Client) string {
	var kinds []string
	if c.OpenVPN {
		kinds = append(kinds, "OpenVPN")
	}
	if c.WireGuard {
		kinds = append(kinds, "WireGuard")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Клиент: %s\nТип: %s\n", c.Name, strings.Join(kinds, ", "))
	state := "активен"
	if c.Blocked {
		state = "заблокирован"
	}
	online := 0
	if ss, err := b.Node.Sessions(ctx); err == nil {
		for _, s := range ss {
			if s.Name == c.Name {
				online++
			}
		}
	}
	fmt.Fprintf(&sb, "Статус: %s, сессий сейчас: %d\n", state, online)
	if eff, err := b.Store.EffectiveUntil(ctx, b.NodeID, c.Name); err == nil {
		fmt.Fprintf(&sb, "Доступ до: %s\n", untilText(eff))
	}
	if c.CertExpires != nil {
		fmt.Fprintf(&sb, "Сертификат: до %s UTC\n", c.CertExpires.UTC().Format("2006-01-02"))
	}
	if c.Limit > 0 {
		fmt.Fprintf(&sb, "Лимит подключений: %d\n", c.Limit)
	}
	now := b.now()
	if tr, err := b.Store.TrafficTotals(ctx, b.NodeID, now.Add(-30*24*time.Hour).Unix(), now.Unix()+1); err == nil {
		t := tr[c.Name]
		fmt.Fprintf(&sb, "Трафик за 30 дн.: %s\n", humanBytes(uint64(max(t.Rx+t.Tx, 0))))
	}
	return sb.String()
}

func (b *Bot) showCard(ctx context.Context, a actor, msgID int64, name, note string) string {
	c, ok, err := b.visible(ctx, a, name)
	if err != nil {
		return b.agentErr(err)
	}
	if !ok {
		return textGone
	}
	text := b.cardText(ctx, c)
	if note != "" {
		text = note + "\n\n" + text
	}
	rows := [][]telegram.InlineKeyboardButton{
		row(btn("Профили", cb("p", name)), btn("Ввести код", cb("k", name))),
	}
	if a.admin {
		blockText, blockOn := "Заблокировать", 1
		if c.Blocked {
			blockText, blockOn = "Разблокировать", 0
		}
		rows = append(rows, row(btn(blockText, cb("b", blockOn, name)), btn("Удалить", cb("d", name))))
		if c.OpenVPN {
			rows = append(rows, row(btn("+30 дн.", cb("e", 30, name)), btn("+90 дн.", cb("e", 90, name)), btn("+365 дн.", cb("e", 365, name))))
		}
		rows = append(rows, row(btn("Лимит: 1", cb("i", 1, name)), btn("2", cb("i", 2, name)), btn("3", cb("i", 3, name)),
			btn("5", cb("i", 5, name)), btn("Снять", cb("i", 0, name))))
	}
	rows = append(rows, row(btn("К списку", cb("l", 0)), btn("Меню", "m")))
	b.show(ctx, a.chat, msgID, text, keyboard(rows...))
	return ""
}

// profileAllowed: пользователю доступны профили по списку client_kinds.
// Значения openvpn, wireguard и amneziawg отбирают по типу, antizapret и vpn
// по варианту; если названы оба вида, профиль должен подойти под оба.
func profileAllowed(allowed []string, p nodeapi.Profile) bool {
	if len(allowed) == 0 {
		return true
	}
	var byKind, byVariant, okKind, okVariant bool
	for _, k := range allowed {
		switch k {
		case "openvpn", "wireguard", "amneziawg":
			byKind = true
			okKind = okKind || p.Kind == k
		case "antizapret", "vpn":
			byVariant = true
			okVariant = okVariant || p.Variant == k || strings.HasPrefix(p.Variant, k+"-")
		}
	}
	return (!byKind || okKind) && (!byVariant || okVariant)
}

func (b *Bot) profilesFor(ctx context.Context, a actor, name string) ([]nodeapi.Profile, error) {
	ps, err := b.Node.Profiles(ctx, name)
	if err != nil {
		return nil, err
	}
	if a.admin {
		return ps, nil
	}
	allowed, _, err := b.Store.ClientKinds(ctx, b.NodeID, name)
	if err != nil {
		return nil, err
	}
	var out []nodeapi.Profile
	for _, p := range ps {
		if profileAllowed(allowed, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (b *Bot) showProfiles(ctx context.Context, a actor, msgID int64, name string) string {
	if _, ok, err := b.visible(ctx, a, name); err != nil {
		return b.agentErr(err)
	} else if !ok {
		return textGone
	}
	ps, err := b.profilesFor(ctx, a, name)
	if err != nil {
		return b.agentErr(err)
	}
	if len(ps) == 0 {
		return "Профилей нет."
	}
	var rows [][]telegram.InlineKeyboardButton
	for i, p := range ps {
		if i >= 40 {
			break
		}
		label := p.Kind + "/" + p.Variant
		r := row(btn(label, cb("f", i, name)))
		if p.Kind == nodeapi.KindWireGuard {
			r = append(r, btn("QR", cb("q", i, name)))
		}
		rows = append(rows, r)
	}
	rows = append(rows, row(btn("К клиенту", cb("c", name))))
	b.show(ctx, a.chat, msgID, "Профили клиента «"+name+"». Нажмите профиль, чтобы получить файл.", keyboard(rows...))
	return ""
}

func (b *Bot) sendProfile(ctx context.Context, a actor, name string, i int, qr bool) string {
	if _, ok, err := b.visible(ctx, a, name); err != nil {
		return b.agentErr(err)
	} else if !ok {
		return textGone
	}
	ps, err := b.profilesFor(ctx, a, name)
	if err != nil {
		return b.agentErr(err)
	}
	if i < 0 || i >= len(ps) {
		return "Профиль не найден: откройте список заново."
	}
	p := ps[i]
	data, err := b.Node.Profile(ctx, name, p)
	if err != nil {
		return b.agentErr(err)
	}
	if qr {
		if p.Kind != nodeapi.KindWireGuard {
			return "QR есть только у профилей WireGuard."
		}
		png, ok := b.Back.QR(data)
		if !ok {
			return "Профиль слишком велик для QR."
		}
		if _, err := b.TG.SendPhoto(ctx, a.chat, "qr.png", bytes.NewReader(png), name+": "+p.Variant); err != nil {
			b.log().Warn("бот: QR не отправлен", "err", err)
			return "QR не отправлен."
		}
		b.audit(ctx, a, "tg_qr", name, "", p.Kind+"/"+p.Variant)
		return ""
	}
	if _, err := b.TG.SendDocument(ctx, a.chat, p.File, bytes.NewReader(data), name+": "+p.Kind+"/"+p.Variant); err != nil {
		b.log().Warn("бот: профиль не отправлен", "err", err)
		return "Профиль не отправлен."
	}
	b.audit(ctx, a, "tg_profile", name, "", p.Kind+"/"+p.Variant+"/"+p.File)
	return ""
}

func (b *Bot) renew(ctx context.Context, a actor, msgID int64, name string, days int) string {
	if days < 1 || days > 3650 {
		return "Срок вне диапазона."
	}
	c, ok, err := b.visible(ctx, a, name)
	if err != nil {
		return b.agentErr(err)
	}
	if !ok {
		return textGone
	}
	if _, err := b.Node.Renew(ctx, name, days); err != nil {
		b.log().Warn("бот: продление не удалось", "client", name, "err", err)
		return b.agentErr(err)
	}
	before := "—"
	if c.CertExpires != nil {
		before = c.CertExpires.UTC().Format("2006-01-02")
	}
	b.audit(ctx, a, "renew", name, before, fmt.Sprintf("продлён на %d дн.", days))
	return b.showCard(ctx, a, msgID, name, fmt.Sprintf("Продлён на %d дн.", days))
}

func (b *Bot) setLimit(ctx context.Context, a actor, msgID int64, name string, limit int) string {
	c, ok, err := b.visible(ctx, a, name)
	if err != nil {
		return b.agentErr(err)
	}
	if !ok {
		return textGone
	}
	if limit < 0 || limit > 1000 {
		return "Лимит вне диапазона."
	}
	if err := b.Node.SetLimit(ctx, name, limit); err != nil {
		return b.agentErr(err)
	}
	before, after := "—", "—"
	if c.Limit > 0 {
		before = strconv.Itoa(c.Limit)
	}
	note := "Лимит снят."
	if limit > 0 {
		after = strconv.Itoa(limit)
		note = "Лимит подключений: " + after + "."
	}
	b.audit(ctx, a, "limit", name, before, after)
	return b.showCard(ctx, a, msgID, name, note)
}

func (b *Bot) block(ctx context.Context, a actor, msgID int64, name string, blocked bool) string {
	c, ok, err := b.visible(ctx, a, name)
	if err != nil {
		return b.agentErr(err)
	}
	if !ok {
		return textGone
	}
	killed, err := b.Back.Block(ctx, c, blocked)
	if err != nil {
		b.log().Warn("бот: блокировка не удалась", "client", name, "err", err)
		return b.agentErr(err)
	}
	if blocked {
		b.audit(ctx, a, "block", name, "не заблокирован", fmt.Sprintf("заблокирован, разорвано сессий: %d", killed))
		return b.showCard(ctx, a, msgID, name, fmt.Sprintf("Заблокирован, разорвано сессий: %d.", killed))
	}
	b.audit(ctx, a, "unblock", name, "заблокирован", "не заблокирован")
	return b.showCard(ctx, a, msgID, name, "Разблокирован.")
}

func (b *Bot) askDelete(ctx context.Context, a actor, msgID int64, name string) string {
	c, ok, err := b.visible(ctx, a, name)
	if err != nil {
		return b.agentErr(err)
	}
	if !ok {
		return textGone
	}
	var rows [][]telegram.InlineKeyboardButton
	if c.OpenVPN {
		tok := b.newConfirm(a.tg, "delete", nodeapi.KindOpenVPN+":"+name)
		rows = append(rows, row(btn("Да, удалить OpenVPN", cb("y", tok))))
	}
	if c.WireGuard {
		tok := b.newConfirm(a.tg, "delete", nodeapi.KindWireGuard+":"+name)
		rows = append(rows, row(btn("Да, удалить WireGuard", cb("y", tok))))
	}
	rows = append(rows, row(btn("Отмена", cb("c", name))))
	b.show(ctx, a.chat, msgID, "Удалить клиента «"+name+"»? Действие необратимо. Подтверждение действует 60 секунд.", keyboard(rows...))
	return ""
}

// confirmed выполняет подтверждённое действие.
func (b *Bot) confirmed(ctx context.Context, a actor, msgID int64, tok string) string {
	c, ok := b.takeConfirm(a.tg, tok)
	if !ok {
		b.show(ctx, a.chat, msgID, "Подтверждение истекло или уже использовано. Повторите действие.", b.mainMenu(a))
		return ""
	}
	if !a.admin {
		return textNoRights
	}
	switch c.op {
	case "delete":
		kind, name, _ := strings.Cut(c.arg, ":")
		cl, ok, err := b.visible(ctx, a, name)
		if err != nil {
			return b.agentErr(err)
		}
		if !ok {
			return textGone
		}
		if err := b.Back.Delete(ctx, cl, kind); err != nil {
			b.log().Warn("бот: удаление не удалось", "client", name, "err", err)
			return b.agentErr(err)
		}
		b.audit(ctx, a, "delete", name, kind, "удалён")
		b.show(ctx, a.chat, msgID, "Клиент «"+name+"» ("+kind+") удалён.", b.mainMenu(a))
	case "reboot":
		if _, err := b.Node.Reboot(ctx); err != nil {
			b.log().Warn("бот: перезагрузка не запущена", "err", err)
			return b.agentErr(err)
		}
		b.audit(ctx, a, "reboot", "сервер", "", "перезагрузка запущена")
		b.show(ctx, a.chat, msgID, "Перезагрузка запущена. Бот вернётся, когда сервер поднимется.", nil)
	}
	return ""
}

func (b *Bot) createType(ctx context.Context, a actor, msgID int64, args []string) string {
	if len(args) < 1 || (args[0] != nodeapi.KindOpenVPN && args[0] != nodeapi.KindWireGuard) {
		if d := b.getDialog(a.tg); d == nil || d.kind != "create" || d.step != "type" {
			return "Диалог устарел: начните заново."
		}
		return "Неизвестный тип."
	}
	kind := args[0]
	// Диалог забирается атомарно: двойное нажатие «WireGuard» не запустит два Create.
	d := b.takeDialog(a.tg, "create", "type")
	if d == nil {
		return "Диалог устарел: начните заново."
	}
	d.ckind = kind
	if kind == nodeapi.KindWireGuard {
		return b.finishCreate(ctx, a, msgID, d, 0)
	}
	d.step = "days"
	b.setDialog(a.tg, d)
	b.show(ctx, a.chat, msgID, "На сколько дней выпустить сертификат «"+d.name+"»?", keyboard(
		row(btn("30", cb("g", 30)), btn("90", cb("g", 90)), btn("365", cb("g", 365))),
		row(btn("3650 (по умолчанию)", cb("g", 3650))),
	))
	return ""
}

func (b *Bot) createDays(ctx context.Context, a actor, msgID int64, args []string) string {
	n, ok := argInt(args, 0)
	if !ok || n < 1 || n > 3650 {
		return "Диалог устарел: начните заново."
	}
	d := b.takeDialog(a.tg, "create", "days")
	if d == nil {
		return "Диалог устарел: начните заново."
	}
	return b.finishCreate(ctx, a, msgID, d, n)
}

// finishCreate вызывается только с диалогом, уже забранным takeDialog.
func (b *Bot) finishCreate(ctx context.Context, a actor, msgID int64, d *dialog, days int) string {
	list, err := b.Node.Clients(ctx)
	if err != nil {
		return b.agentErr(err)
	}
	for _, c := range list {
		if c.Name == d.name {
			b.show(ctx, a.chat, msgID, "Клиент «"+d.name+"» уже существует.", b.mainMenu(a))
			return ""
		}
	}
	if err := b.Back.Create(ctx, d.name, d.ckind, days); err != nil {
		b.log().Warn("бот: клиент не создан", "client", d.name, "err", err)
		b.show(ctx, a.chat, msgID, "Клиент не создан: "+b.agentErr(err), b.mainMenu(a))
		return ""
	}
	b.audit(ctx, a, "create", d.name, "", d.ckind)
	return b.showCard(ctx, a, msgID, d.name, "Клиент создан.")
}

// startCode запускает ввод кода продления для клиента; без имени пользователю
// с единственным клиентом выбор не нужен.
func (b *Bot) startCode(ctx context.Context, a actor, msgID int64, name string) string {
	if name == "" {
		own, err := b.ownClients(ctx, a.user.ID)
		if err != nil {
			return "Клиенты не прочитаны."
		}
		names := make([]string, 0, len(own))
		for n := range own {
			names = append(names, n)
		}
		sort.Strings(names)
		switch {
		case len(names) == 1:
			name = names[0]
		case len(names) == 0:
			b.show(ctx, a.chat, msgID, "За вами не закреплено клиентов: продлевать нечего. Обратитесь к администратору.", b.mainMenu(a))
			return ""
		default:
			var rows [][]telegram.InlineKeyboardButton
			for _, n := range names {
				rows = append(rows, row(btn(n, cb("k", n))))
			}
			b.show(ctx, a.chat, msgID, "Для какого клиента код?", keyboard(rows...))
			return ""
		}
	}
	if _, ok, err := b.visible(ctx, a, name); err != nil {
		return b.agentErr(err)
	} else if !ok {
		return textGone
	}
	b.setDialog(a.tg, &dialog{kind: "code", client: name})
	b.show(ctx, a.chat, msgID, "Отправьте код продления для «"+name+"» сообщением. /cancel — отмена.", nil)
	return ""
}

// enterCode применяет код: правила портала и тот же счётчик попыток, что в
// вебе и портале (по пользователю панели).
func (b *Bot) enterCode(ctx context.Context, a actor, name, code string) {
	c, ok, err := b.visible(ctx, a, name)
	if err != nil {
		b.send(ctx, a.chat, "Сервер временно недоступен: "+b.agentErr(err), nil)
		return
	}
	if !ok {
		b.setDialog(a.tg, nil)
		b.send(ctx, a.chat, textGone, b.mainMenu(a))
		return
	}
	ticket, retry, err := b.Back.OpenAttempt(ctx, a.user.ID)
	if err != nil {
		b.log().Warn("бот: попытки не прочитаны", "err", err)
		b.send(ctx, a.chat, "Внутренняя ошибка.", nil)
		return
	}
	if retry > 0 {
		b.setDialog(a.tg, nil)
		b.send(ctx, a.chat, "Слишком много неверных кодов: ввод закрыт, повторите через "+humanDuration(retry)+".", b.mainMenu(a))
		return
	}
	counted := false
	defer func() {
		if !counted {
			b.Back.RefundAttempt(context.WithoutCancel(ctx), ticket)
		}
	}()
	var owner *int64
	if id, has, err := b.Store.OwnerOf(ctx, b.NodeID, name); err != nil {
		b.send(ctx, a.chat, "Внутренняя ошибка.", nil)
		return
	} else if has {
		owner = &id
	}
	res, err := b.Back.Redeem(ctx, c, owner, strings.TrimSpace(code))
	switch {
	case errors.Is(err, store.ErrCodeInvalid):
		counted = true
		left := b.Back.FailAttempt(context.WithoutCancel(ctx), ticket)
		msg := fmt.Sprintf("%s. Осталось попыток: %d.", store.ErrCodeInvalid.Error(), left)
		if left == 0 {
			b.setDialog(a.tg, nil)
			msg = store.ErrCodeInvalid.Error() + ". Ввод закрыт на час."
		}
		b.send(ctx, a.chat, msg, nil)
		return
	case errors.Is(err, ErrBlocked):
		b.setDialog(a.tg, nil)
		b.send(ctx, a.chat, ErrBlocked.Error()+".", b.mainMenu(a))
		return
	case errors.Is(err, store.ErrNoLimit):
		b.setDialog(a.tg, nil)
		b.send(ctx, a.chat, "У клиента нет срока доступа: продлевать нечего.", b.mainMenu(a))
		return
	case err != nil:
		b.log().Error("бот: код не применён", "client", name, "err", err)
		b.send(ctx, a.chat, "Код не применён, обратитесь к администратору.", nil)
		return
	}
	b.setDialog(a.tg, nil)
	until := res.After
	detail := fmt.Sprintf("+%d дн., до %s", res.Days, untilText(&until))
	text := fmt.Sprintf("Доступ продлён на %d дн., до %s.", res.Days, untilText(&until))
	if res.CertRenewed {
		detail += "; сертификат перевыпущен"
	}
	if res.CertErr != nil {
		b.log().Warn("бот: сертификат не перевыпущен после продления", "client", name, "err", res.CertErr)
		detail += "; сертификат не перевыпущен"
		text += " Сертификат не перевыпущен, сообщите администратору."
	}
	prev := res.Before
	b.audit(ctx, a, "redeem", name, "до "+untilText(&prev), detail)
	b.send(ctx, a.chat, text, b.mainMenu(a))
}

func (b *Bot) showNode(ctx context.Context, a actor, msgID int64) {
	var sb strings.Builder
	if info, err := b.Node.Info(ctx); err == nil {
		fmt.Fprintf(&sb, "Узел: %s, агент %s\n", info.Hostname, info.Version)
	} else {
		fmt.Fprintf(&sb, "Агент недоступен: %s\n", b.agentErr(err))
		b.show(ctx, a.chat, msgID, sb.String(), keyboard(row(btn("Меню", "m"))))
		return
	}
	if sys, ok := b.lastSystem(); ok {
		r := sys.Resources
		mem := 0.0
		if r.Memory.TotalBytes > 0 {
			mem = float64(r.Memory.TotalBytes-min(r.Memory.AvailableBytes, r.Memory.TotalBytes)) / float64(r.Memory.TotalBytes) * 100
		}
		disk := 0.0
		if r.Disk.TotalBytes > 0 {
			disk = float64(r.Disk.TotalBytes-min(r.Disk.FreeBytes, r.Disk.TotalBytes)) / float64(r.Disk.TotalBytes) * 100
		}
		fmt.Fprintf(&sb, "ЦП %.0f%%, память %.0f%%, диск %.0f%%\nНагрузка: %.2f %.2f %.2f\nАптайм: %s\n",
			r.CPUPercent, mem, disk, r.Load[0], r.Load[1], r.Load[2], humanDuration(time.Duration(r.UptimeSec)*time.Second))
		sb.WriteString("Службы:\n")
		for _, s := range sys.Services {
			fmt.Fprintf(&sb, "  %s: %s\n", s.Unit, s.State)
		}
	}
	if ss, err := b.Node.Sessions(ctx); err == nil {
		fmt.Fprintf(&sb, "Сессий онлайн: %d\n", len(ss))
	}
	b.show(ctx, a.chat, msgID, sb.String(), keyboard(row(btn("Обновить", "s"), btn("Меню", "m"))))
}
