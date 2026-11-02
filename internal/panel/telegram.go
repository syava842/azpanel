package panel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/panel/bot"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/telegram"
)

// botName — имя бота для ссылки привязки; пусто — бот не запущен.
func (s *Server) botName() string {
	if s.BotName == nil {
		return ""
	}
	return s.BotName()
}

// reauth требует текущий пароль и, если у пользователя включена 2FA, код:
// действие с последствиями входа (привязка Telegram) не должно выполняться
// только по украденной сессии. false — ответ уже отправлен.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request, u store.User) bool {
	good, throttled := s.verifyPassword(u, r.PostForm.Get("password"))
	if throttled {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return false
	}
	if !good {
		s.auditAs(r, u.Login, "tg_link_denied", u.Login, "", "неверный пароль при привязке Telegram")
		s.accountView(w, r, http.StatusUnauthorized, "пароль неверен")
		return false
	}
	if len(u.TOTPSecret) == 0 {
		return true
	}
	mkey := mfaKey(u.ID)
	if !s.Limiter.Begin(mkey) {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return false
	}
	code, err := s.secondFactorOK(r, u.ID)
	if err != nil {
		s.internalError(w, r, "второй фактор не проверен", err)
		return false
	}
	if !code {
		s.Sleep(loginDelay)
		s.accountView(w, r, http.StatusUnauthorized, "неверный код")
		return false
	}
	s.Limiter.Reset(mkey)
	return true
}

// accountTelegram выпускает ссылку привязки Telegram: одноразовый код на 10
// минут, адрес показывается один раз. Привязка даёт вход в бота, поэтому нужны
// текущий пароль и (при 2FA) код.
func (s *Server) accountTelegram(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	name := s.botName()
	switch {
	case name == "":
		s.accountView(w, r, http.StatusServiceUnavailable, "бот не запущен: привязать Telegram нельзя")
		return
	case u.TelegramID != nil:
		s.accountView(w, r, http.StatusBadRequest, "Telegram уже привязан: сначала отвяжите")
		return
	}
	if !s.reauth(w, r, u) {
		return
	}
	code, err := s.Store.CreateLinkCode(r.Context(), u.ID, s.now().Unix())
	if err != nil {
		s.internalError(w, r, "код привязки не выпущен", err)
		return
	}
	s.audit(r, "tg_link_code", u.Login, "", "выпущена ссылка привязки Telegram")
	s.showOnce(w, r, "Привязка Telegram",
		"Откройте ссылку в Telegram и нажмите Start. Ссылка действует 10 минут и срабатывает один раз.",
		"/account", "К аккаунту", []string{"https://t.me/" + name + "?start=" + code})
}

// dropTelegram снимает привязку Telegram: смена пароля, сброс пароля и «выйти
// везде» означают потерю доверия к входам, а привязка — отдельный вход в бота.
func (s *Server) dropTelegram(r *http.Request, u store.User, why string) {
	if u.TelegramID == nil {
		return
	}
	if err := s.Store.ClearTelegramID(r.Context(), u.ID); err != nil {
		s.Log.Warn("привязка Telegram не снята", "user", u.Login, "err", err)
		return
	}
	s.audit(r, "tg_unlink", u.Login, tgText(u), why)
}

// accountTelegramUnlink отвязывает Telegram от своего аккаунта.
func (s *Server) accountTelegramUnlink(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	if err := s.Store.ClearTelegramID(r.Context(), u.ID); err != nil {
		s.internalError(w, r, "привязка не снята", err)
		return
	}
	s.audit(r, "tg_unlink", u.Login, tgText(u), "отвязан")
	s.redirectMsg(w, r, "/account", "tg_unlinked")
}

// userTelegramUnlink — администратор отвязывает Telegram пользователя.
func (s *Server) userTelegramUnlink(w http.ResponseWriter, r *http.Request) {
	u, ok := s.pathUser(w, r)
	if !ok {
		return
	}
	if err := s.Store.ClearTelegramID(r.Context(), u.ID); err != nil {
		s.internalError(w, r, "привязка не снята", err)
		return
	}
	s.audit(r, "tg_unlink", u.Login, tgText(u), "отвязан администратором")
	s.redirectMsg(w, r, userHref(u), "tg_unlinked")
}

func tgText(u store.User) string {
	if u.TelegramID == nil {
		return "не привязан"
	}
	return fmt.Sprintf("Telegram %d", *u.TelegramID)
}

// addTelegram кладёт в данные страницы состояние привязки.
func (s *Server) addTelegram(data map[string]any, u store.User) {
	data["TGLinked"] = u.TelegramID != nil
	if u.TelegramID != nil {
		data["TGID"] = *u.TelegramID
	}
	data["CanTG"] = s.botName() != ""
}

type kindOption struct {
	Name    string
	Checked bool
}

// addKinds кладёт в карточку клиента выбор типов профилей для бота.
func (s *Server) addKinds(r *http.Request, c nodeapi.Client, data map[string]any) {
	if s.Store == nil {
		return
	}
	allowed, found, err := s.Store.ClientKinds(r.Context(), s.NodeID, c.Name)
	if err != nil {
		s.Log.Warn("типы профилей клиента не прочитаны", "client", c.Name, "err", err)
		return
	}
	opts := make([]kindOption, 0, len(store.ClientKindsAll))
	for _, k := range store.ClientKindsAll {
		opts = append(opts, kindOption{Name: k, Checked: found && slices.Contains(allowed, k)})
	}
	data["KindOptions"], data["KindsAll"] = opts, !found
}

// setKinds сохраняет типы профилей, доступные клиенту в боте; пустой выбор — всё.
func (s *Server) setKinds(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.Store == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	before := "все"
	if old, found, err := s.Store.ClientKinds(r.Context(), s.NodeID, c.Name); err == nil && found {
		before = fmt.Sprint(old)
	}
	kinds := r.PostForm["kinds"]
	if err := s.Store.SetClientKinds(r.Context(), s.NodeID, c.Name, kinds); err != nil {
		s.card(w, r, c, http.StatusBadRequest, err.Error())
		return
	}
	after := "все"
	if len(kinds) > 0 {
		after = fmt.Sprint(kinds)
	}
	s.done(w, r, c, "client_kinds", before, after, "kinds_saved")
}

// --- страница «Telegram-бот» (администратор) ---

type tgChatRow struct {
	ID      int64
	Checked bool
	Note    string
}

type tgReqRow struct {
	ID            int64
	Name, Created string
}

type tgBanRow struct {
	ID      int64
	Created string
}

// telegramPage показывает получателей бэкапа, заявки и блокировки.
func (s *Server) telegramPage(w http.ResponseWriter, r *http.Request) {
	s.telegramView(w, r, http.StatusOK, "")
}

func (s *Server) telegramView(w http.ResponseWriter, r *http.Request, status int, errText string) {
	ctx := r.Context()
	confirmed := []int64{}
	if v, found, err := s.Store.Meta(ctx, bot.BackupGroupsKey); err != nil {
		s.internalError(w, r, "подтверждённые группы не прочитаны", err)
		return
	} else if found {
		confirmed = bot.ParseChatList(v)
	}
	admins := map[int64]bool{}
	if us, err := s.Store.Users(ctx); err == nil {
		for _, u := range us {
			if u.Role == store.RoleAdmin && !u.Disabled && u.TelegramID != nil {
				admins[*u.TelegramID] = true
			}
		}
	}
	var groups, personal []tgChatRow
	for _, c := range s.Telegram.BackupChats {
		if c < 0 {
			groups = append(groups, tgChatRow{ID: c, Checked: slices.Contains(confirmed, c)})
			continue
		}
		note := "получит бэкап: привязанный администратор"
		if !admins[c] {
			note = "не получит: это не привязанный действующий администратор"
		}
		personal = append(personal, tgChatRow{ID: c, Note: note})
	}
	reqs, err := s.Store.TelegramRequests(ctx)
	if err != nil {
		s.internalError(w, r, "заявки не прочитаны", err)
		return
	}
	bans, err := s.Store.TelegramBans(ctx)
	if err != nil {
		s.internalError(w, r, "блокировки не прочитаны", err)
		return
	}
	rr := []tgReqRow{}
	for _, q := range reqs {
		name := q.Name
		if q.Username != "" {
			name += " (@" + q.Username + ")"
		}
		rr = append(rr, tgReqRow{ID: q.ID, Name: name, Created: unixText(q.Created)})
	}
	bb := []tgBanRow{}
	for _, x := range bans {
		bb = append(bb, tgBanRow{x.ID, unixText(x.Created)})
	}
	data := map[string]any{"Groups": groups, "Personal": personal, "Requests": rr, "Bans": bb, "BotOn": s.botName() != ""}
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "telegram", data)
}

// telegramBackupGroups сохраняет, каким группам из backup_chats разрешено
// получать бэкап. Бэкап содержит ключи всех клиентов: группа без явного
// подтверждения его не получает.
func (s *Server) telegramBackupGroups(w http.ResponseWriter, r *http.Request) {
	var keep []int64
	for _, v := range r.PostForm["group"] {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil && n < 0 && slices.Contains(s.Telegram.BackupChats, n) && !slices.Contains(keep, n) {
			keep = append(keep, n) // только группы, названные в backup_chats
		}
	}
	slices.Sort(keep)
	before := "—"
	if v, found, err := s.Store.Meta(r.Context(), bot.BackupGroupsKey); err == nil && found && v != "" {
		before = v
	}
	if err := s.Store.SetMeta(r.Context(), bot.BackupGroupsKey, bot.FormatChatList(keep)); err != nil {
		s.internalError(w, r, "группы не сохранены", err)
		return
	}
	after := bot.FormatChatList(keep)
	if after == "" {
		after = "—"
	}
	s.audit(r, "tg_backup_groups", "backup_chats", before, after)
	s.redirectMsg(w, r, "/users/telegram", "tg_saved")
}

// telegramUnban снимает блокировку Telegram ID.
func (s *Server) telegramUnban(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if err != nil || id == 0 {
		s.telegramView(w, r, http.StatusBadRequest, "неверный Telegram ID")
		return
	}
	if err := s.Store.UnbanTelegram(r.Context(), id); err != nil {
		s.internalError(w, r, "блокировка не снята", err)
		return
	}
	s.audit(r, "tg_unban", strconv.FormatInt(id, 10), "заблокирован", "разблокирован")
	s.redirectMsg(w, r, "/users/telegram", "tg_saved")
}

// --- действия для бота ---

// BotBackend — действия панели, которые использует бот.
func (s *Server) BotBackend() bot.Backend { return botBackend{s} }

type botBackend struct{ s *Server }

func (b botBackend) Redeem(ctx context.Context, c nodeapi.Client, owner *int64, code string) (bot.Extend, error) {
	res, err := b.s.redeemForClient(ctx, c, owner, code)
	if errors.Is(err, errManualBlock) {
		return bot.Extend{}, bot.ErrBlocked
	}
	if err != nil {
		return bot.Extend{}, err
	}
	return bot.Extend{Before: res.Before, After: res.After, Days: res.Days, CertRenewed: res.CertRenewed, CertErr: res.CertErr}, nil
}

func (b botBackend) Block(ctx context.Context, c nodeapi.Client, blocked bool) (int, error) {
	res, err := b.s.Node.SetBlocked(ctx, c.Name, blocked)
	if err != nil {
		return 0, err
	}
	if blocked {
		b.s.makeManualBlock(ctx, c)
	} else {
		b.s.forgetAutoBlock(ctx, c)
	}
	return res.Killed, nil
}

func (b botBackend) Delete(ctx context.Context, c nodeapi.Client, kind string) error {
	if _, err := b.s.Node.DeleteClient(ctx, kind, c.Name); err != nil {
		return err
	}
	b.s.dropDeletedRecords(ctx, c, kind)
	return nil
}

func (b botBackend) Create(ctx context.Context, name, kind string, days int) error {
	existed, known := b.s.clientExists(ctx, name)
	if _, err := b.s.Node.CreateClient(ctx, nodeapi.CreateClient{Name: name, Kind: kind, Days: days}); err != nil {
		return err
	}
	if known && !existed {
		b.s.dropStaleHistory(ctx, name)
	}
	return nil
}

func (b botBackend) NewUser(ctx context.Context, login string) (store.User, error) {
	pw, err := generatePassword()
	if err != nil {
		return store.User{}, err
	}
	hash, err := HashPassword(pw) // пароль нигде не показывается: вход после сброса администратором
	if err != nil {
		return store.User{}, err
	}
	return b.s.Store.CreateUser(ctx, store.User{Login: login, Hash: hash, Role: store.RoleUser, MustChange: true, Created: b.s.now().Unix()})
}

func (b botBackend) QR(data []byte) ([]byte, bool) { return profileQRPNG(data) }

// Попытки ввода кода в боте — тот же счётчик, что у веба и портала: ключ по
// пользователю панели, пять неверных за час закрывают ввод на час.
func (b botBackend) OpenAttempt(ctx context.Context, userID int64) (bot.AttemptTicket, time.Duration, error) {
	t, retry, err := b.s.openAttempt(ctx, fmt.Sprintf("code:user:%d", userID), b.s.now())
	return bot.AttemptTicket{Key: t.key, TS: t.ts}, retry, err
}

func (b botBackend) RefundAttempt(ctx context.Context, t bot.AttemptTicket) {
	b.s.refundAttempt(ctx, attemptTicket{key: t.Key, ts: t.TS})
}

func (b botBackend) FailAttempt(ctx context.Context, t bot.AttemptTicket) int {
	return b.s.failAttempt(ctx, attemptTicket{key: t.Key, ts: t.TS}, b.s.now())
}

// telegramBaseURL — адрес Bot API; пусто — api.telegram.org. Подменяется в тестах.
var telegramBaseURL = ""

// botRetryBase — первая пауза перед повтором getMe при неудачном старте бота
// (дальше удваивается до botRetryMax).
var (
	botRetryBase = time.Minute
	botRetryMax  = 15 * time.Minute
)

// startBot запускает бота в фоне: getMe даёт имя для ссылок привязки. Ошибка
// getMe — предупреждение в журнале и повтор позже; панель работает без бота.
// Токен в журнал не попадает: клиент Bot API вырезает его из всех ошибок.
func (s *Server) startBot(ctx context.Context, wg *sync.WaitGroup, cfg config.Config, token string, node bot.Node, log *slog.Logger) {
	s.Telegram = cfg.Telegram
	b := &bot.Bot{
		TG: telegram.New(token, telegramBaseURL), Node: node, Store: s.Store, Back: s.BotBackend(),
		Cfg: cfg.Telegram, NodeID: s.NodeID, Log: log, BackupDir: paths.Backup(),
	}
	if s.Collector != nil {
		b.LastSystem = s.Collector.LastSystem
	}
	s.BotName = b.Username
	wg.Add(1)
	go func() {
		defer wg.Done()
		wait := botRetryBase
		for {
			ictx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := b.Init(ictx)
			cancel()
			if err == nil {
				break
			}
			log.Warn("бот не запущен: getMe не удался, панель работает без бота", "err", err, "повтор_через", wait.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(wait*2, botRetryMax)
		}
		log.Info("Telegram-бот запущен", "бот", b.Username())
		b.Run(ctx)
	}()
}
