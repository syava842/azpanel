// Package bot — Telegram-бот панели: привязка аккаунтов, меню администратора
// и пользователя, уведомления, сводка и бэкапы. Зависит только от узких
// интерфейсов над агентом, базой и действиями панели, поэтому проверяется
// отдельно от Server.
package bot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/telegram"
)

const (
	confirmTTL    = 60 * time.Second // подтверждение опасного действия
	dialogTTL     = 10 * time.Minute // диалог «создать клиента», «ввести код»
	pageSize      = 20               // клиентов на страницу списка
	codeWindow    = time.Hour
	linkMax       = 10 // попыток привязки кодом за час на один Telegram ID
	maxRequests   = 20 // открытых заявок на доступ; сверх этого незнакомцам не отвечаем
	rejectQuiet   = 24 * time.Hour
	maxMessage    = 4000
	telegramLimit = 50 << 20 // предел sendDocument для ботов
)

// Node — то, что бот берёт у агента; *nodeapi.HTTPClient подходит.
type Node interface {
	Info(ctx context.Context) (nodeapi.Info, error)
	Clients(ctx context.Context) ([]nodeapi.Client, error)
	Sessions(ctx context.Context) ([]nodeapi.Session, error)
	Profiles(ctx context.Context, name string) ([]nodeapi.Profile, error)
	Profile(ctx context.Context, name string, p nodeapi.Profile) ([]byte, error)
	Renew(ctx context.Context, name string, days int) (nodeapi.Result, error)
	SetLimit(ctx context.Context, name string, limit int) error
	Reboot(ctx context.Context) (nodeapi.Task, error)
	CreateBackup(ctx context.Context) (nodeapi.Task, error)
	Task(ctx context.Context, id string) (nodeapi.TaskDetail, error)
	Backups(ctx context.Context) ([]nodeapi.Backup, error)
	Backup(ctx context.Context, name string) (io.ReadCloser, error)
}

// Store — то, что бот берёт из базы панели; *store.Store подходит.
type Store interface {
	UserByTelegramID(ctx context.Context, tgID int64) (store.User, error)
	UserByID(ctx context.Context, id int64) (store.User, error)
	Users(ctx context.Context) ([]store.User, error)
	RedeemLinkCode(ctx context.Context, code string, now int64) (int64, error)
	BindTelegramID(ctx context.Context, userID, tgID int64) error
	LinkTelegramID(ctx context.Context, userID, tgID int64) error
	TelegramBanned(ctx context.Context, tgID int64) (bool, error)
	BanTelegram(ctx context.Context, tgID, now int64) error
	TelegramRequests(ctx context.Context) ([]store.TelegramRequest, error)
	AddTelegramRequest(ctx context.Context, r store.TelegramRequest) error
	DeleteTelegramRequest(ctx context.Context, tgID int64) error
	OwnerOf(ctx context.Context, node int64, client string) (int64, bool, error)
	ClientsOf(ctx context.Context, userID int64) ([]store.ClientRef, error)
	ClientKinds(ctx context.Context, node int64, name string) ([]string, bool, error)
	EffectiveUntil(ctx context.Context, node int64, client string) (*int64, error)
	TrafficTotals(ctx context.Context, node int64, from, to int64) (map[string]store.Bytes, error)
	Audit(ctx context.Context, e store.AuditEntry) error
	Attempt(ctx context.Context, key string, now int64) error
	Attempts(ctx context.Context, key string, since int64) (int, error)
	Pending(ctx context.Context, limit int) ([]store.OutboxItem, error)
	MarkSent(ctx context.Context, id, now int64) error
	FailOutbox(ctx context.Context, id int64) (int, error)
	MarkSentBefore(ctx context.Context, before, now int64) (int64, error)
	Meta(ctx context.Context, key string) (string, bool, error)
	SetMeta(ctx context.Context, key, value string) error
}

// ErrBlocked — клиент заблокирован администратором вручную: код не потрачен.
var ErrBlocked = errors.New("клиент заблокирован администратором: код не потрачен, обратитесь к администратору")

// Extend — итог продления кодом (то же, что extendResult панели).
type Extend struct {
	Before, After int64
	Days          int64
	CertRenewed   bool
	CertErr       error
}

// Backend — действия панели, которые бот не дублирует: они тянут за собой
// карточки, историю и сроки. Реализует Server.
type Backend interface {
	// Redeem гасит код и продлевает доступ клиента (правила портала).
	Redeem(ctx context.Context, c nodeapi.Client, owner *int64, code string) (Extend, error)
	// Block блокирует или разблокирует клиента; возвращает число разорванных сессий.
	Block(ctx context.Context, c nodeapi.Client, blocked bool) (int, error)
	// Delete удаляет клиента данного типа вместе с карточкой.
	Delete(ctx context.Context, c nodeapi.Client, kind string) error
	// Create создаёт клиента; days — только для OpenVPN.
	Create(ctx context.Context, name, kind string, days int) error
	// NewUser создаёт пользователя без известного пароля (вход из панели — после сброса).
	NewUser(ctx context.Context, login string) (store.User, error)
	// QR рисует PNG профиля; false — не помещается.
	QR(data []byte) ([]byte, bool)
	// OpenAttempt резервирует попытку ввода кода пользователем панели — тем же
	// счётчиком, что и в вебе и портале (пять неверных за час закрывают ввод
	// на час). retry > 0 — ввод закрыт, столько ждать.
	OpenAttempt(ctx context.Context, userID int64) (t AttemptTicket, retry time.Duration, err error)
	// RefundAttempt возвращает резерв: код не оказался неверным.
	RefundAttempt(ctx context.Context, t AttemptTicket)
	// FailAttempt подтверждает неверный код; возвращает остаток попыток.
	FailAttempt(ctx context.Context, t AttemptTicket) (left int)
}

// AttemptTicket — резерв одной попытки ввода кода (устройство — у Backend).
type AttemptTicket struct {
	Key string
	TS  int64
}

// Bot — бот панели.
type Bot struct {
	TG     *telegram.Client
	Node   Node
	Store  Store
	Back   Backend
	Cfg    config.Telegram
	NodeID int64
	Log    *slog.Logger
	Now    func() time.Time
	// BackupDir — куда складывать копии бэкапов (хранятся 14 последних); пусто — не хранить.
	BackupDir string
	// PollEvery — как часто спрашивать агента о ходе задачи; по умолчанию 3 с.
	PollEvery time.Duration
	// NotifyEvery — период доставки очереди; по умолчанию 30 с.
	NotifyEvery time.Duration
	// Sync — выполнять долгие действия (бэкап) в том же потоке; нужно тестам.
	Sync bool
	// LastSystem — последний снимок ресурсов узла у сборщика панели: бот сам
	// агента о ресурсах не спрашивает (замер ЦП у агента считается от прошлого
	// вызова, и лишний вызов сбил бы замер сборщика). false — снимка ещё нет.
	LastSystem func() (nodeapi.System, bool)

	mu       sync.Mutex
	username string
	confirms map[string]confirm
	dialogs  map[int64]*dialog
	sentTo   map[int64]map[int64]bool // outbox id -> чаты, куда уже доставлено (после перезапуска доставка может повториться)
	backupMu sync.Mutex               // один бэкап за раз
	tasks    sync.WaitGroup           // фоновые действия
	outboxOK bool                     // первый проход очереди после запуска сделан
}

type confirm struct {
	tg      int64
	op, arg string
	exp     time.Time
}

type dialog struct {
	kind   string // create | code
	step   string // name | type | days
	name   string
	ckind  string
	client string
	exp    time.Time
}

func (b *Bot) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Bot) log() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Username — имя бота без @ (после Init); пусто — бот не запущен.
func (b *Bot) Username() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.username
}

// SetUsername задаёт имя бота (в тестах и после getMe).
func (b *Bot) SetUsername(u string) {
	b.mu.Lock()
	b.username = strings.TrimPrefix(u, "@")
	b.mu.Unlock()
}

// Init спрашивает getMe и запоминает имя бота для ссылок привязки.
func (b *Bot) Init(ctx context.Context) error {
	me, err := b.TG.GetMe(ctx)
	if err != nil {
		return err
	}
	b.SetUsername(me.Username)
	return nil
}

// Run опрашивает Telegram, доставляет очередь уведомлений и выполняет
// расписание, пока ctx не отменён.
func (b *Bot) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); b.notifyLoop(ctx) }()
	go func() { defer wg.Done(); b.scheduleLoop(ctx) }()
	b.pollLoop(ctx)
	wg.Wait()
	b.tasks.Wait()
}

// pollPause — пауза после n-й подряд ошибки Bot API (n с единицы): 5 с, дальше
// вдвое дольше, но не больше пяти минут.
func pollPause(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := 5 * time.Second
	for i := 1; i < n && d < pollPauseMax; i++ {
		d *= 2
	}
	return min(d, pollPauseMax)
}

// pollLogEvery — как часто повторять одну и ту же ошибку опроса в журнале.
const (
	pollPauseMax = 5 * time.Minute
	pollLogEvery = 10 * time.Minute
)

// pollShouldLog: первая ошибка серии пишется сразу, дальше — раз в pollLogEvery.
func pollShouldLog(n int, last, now time.Time) bool {
	return n <= 1 || now.Sub(last) >= pollLogEvery
}

func (b *Bot) pollLoop(ctx context.Context) {
	var offset int64
	var fails int
	var lastLog time.Time
	for ctx.Err() == nil {
		ups, err := b.TG.GetUpdates(ctx, offset, telegram.LongPollSeconds)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var api *telegram.APIError
			if errors.As(err, &api) {
				fails++
				if pollShouldLog(fails, lastLog, b.now()) {
					lastLog = b.now()
					b.log().Warn("бот: getUpdates отклонён", "err", err, "подряд", fails)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(pollPause(fails)):
				}
			}
			continue
		}
		fails = 0
		for _, up := range ups {
			b.HandleUpdate(ctx, up)
		}
		offset = telegram.NextOffset(ups, offset)
	}
}

// HandleUpdate разбирает одно обновление. Паника обработчика не должна
// останавливать бота.
func (b *Bot) HandleUpdate(ctx context.Context, up telegram.Update) {
	defer func() {
		if r := recover(); r != nil {
			b.log().Error("бот: сбой обработчика", "panic", fmt.Sprint(r))
		}
	}()
	switch {
	case up.Message != nil:
		b.onMessage(ctx, up.Message)
	case up.CallbackQuery != nil:
		b.onCallback(ctx, up.CallbackQuery)
	}
}

// actor — кто пишет боту.
type actor struct {
	tg   int64
	chat int64
	user store.User
	// admin — роль администратора.
	admin bool
}

// send отправляет текст в чат; ошибки идут в журнал (токена в них нет).
func (b *Bot) send(ctx context.Context, chat int64, text string, kb *telegram.InlineKeyboardMarkup) {
	if _, err := b.TG.SendMessage(ctx, telegram.SendMessageParams{ChatID: chat, Text: clip(text), ReplyMarkup: kb}); err != nil {
		b.log().Warn("бот: сообщение не отправлено", "chat", chat, "err", err)
	}
}

// agentErr — текст ошибки агента для чата: подробности (адрес, порт) только в
// журнале, человеку — общая фраза; ошибка самого агента (*nodeapi.Error) —
// его собственное сообщение.
func (b *Bot) agentErr(err error) string {
	var ne *nodeapi.Error
	if errors.As(err, &ne) {
		return ne.Message
	}
	b.log().Warn("бот: агент недоступен", "err", err)
	return "сервер временно недоступен"
}

// show заменяет сообщение msgID (кнопка под ним) или шлёт новое.
func (b *Bot) show(ctx context.Context, chat, msgID int64, text string, kb *telegram.InlineKeyboardMarkup) {
	if msgID != 0 {
		err := b.TG.EditMessageText(ctx, telegram.EditMessageTextParams{ChatID: chat, MessageID: msgID, Text: clip(text), ReplyMarkup: kb})
		if err == nil {
			return
		}
		var api *telegram.APIError
		if errors.As(err, &api) && strings.Contains(api.Description, "not modified") {
			return
		}
	}
	b.send(ctx, chat, text, kb)
}

func clip(s string) string {
	r := []rune(s)
	if len(r) <= maxMessage {
		return s
	}
	return string(r[:maxMessage-1]) + "…"
}

func (b *Bot) audit(ctx context.Context, a actor, action, target, before, after string) {
	err := b.Store.Audit(ctx, store.AuditEntry{
		TS: b.now().Unix(), User: a.user.Login, IP: fmt.Sprintf("tg:%d", a.tg),
		Action: action, Target: target, Before: before, After: after,
	})
	if err != nil {
		b.log().Warn("бот: запись в журнал действий не удалась", "action", action, "err", err)
	}
}

// adminsErr — активные администраторы с привязанным Telegram; роль читается
// из базы в момент вызова.
func (b *Bot) adminsErr(ctx context.Context) ([]store.User, error) {
	us, err := b.Store.Users(ctx)
	if err != nil {
		return nil, err
	}
	var out []store.User
	for _, u := range us {
		if u.Role == store.RoleAdmin && !u.Disabled && u.TelegramID != nil {
			out = append(out, u)
		}
	}
	return out, nil
}

// admins — то же без ошибки: при сбое чтения пусто, сбой в журнале.
func (b *Bot) admins(ctx context.Context) []store.User {
	out, err := b.adminsErr(ctx)
	if err != nil {
		b.log().Warn("бот: пользователи не прочитаны", "err", err)
	}
	return out
}

func (b *Bot) newConfirm(tg int64, op, arg string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.confirms == nil {
		b.confirms = map[string]confirm{}
	}
	now := b.now()
	for k, c := range b.confirms {
		if !c.exp.After(now) {
			delete(b.confirms, k)
		}
	}
	tok := randToken()
	b.confirms[tok] = confirm{tg: tg, op: op, arg: arg, exp: now.Add(confirmTTL)}
	return tok
}

// takeConfirm отдаёт подтверждение один раз; чужое и просроченное не отдаёт.
func (b *Bot) takeConfirm(tg int64, tok string) (confirm, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.confirms[tok]
	delete(b.confirms, tok)
	if !ok || c.tg != tg || !c.exp.After(b.now()) {
		return confirm{}, false
	}
	return c, true
}

func (b *Bot) setDialog(tg int64, d *dialog) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dialogs == nil {
		b.dialogs = map[int64]*dialog{}
	}
	if d == nil {
		delete(b.dialogs, tg)
		return
	}
	d.exp = b.now().Add(dialogTTL)
	b.dialogs[tg] = d
}

func (b *Bot) getDialog(tg int64) *dialog {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.dialogs[tg]
	if d != nil && !d.exp.After(b.now()) {
		delete(b.dialogs, tg)
		return nil
	}
	return d
}
