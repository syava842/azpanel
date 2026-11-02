package panel

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/panel/bot"
	"github.com/syava842/azpanel/internal/store"
)

// botName — имя бота для ссылки привязки; пусто — бот не запущен.
func (s *Server) botName() string {
	if s.BotName == nil {
		return ""
	}
	return s.BotName()
}

// accountTelegram выпускает ссылку привязки Telegram: одноразовый код на 10
// минут, адрес показывается один раз.
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
	redirectMsg(w, r, "/account", "tg_unlinked")
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
	redirectMsg(w, r, userHref(u), "tg_unlinked")
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

// --- действия для бота ---

// BotBackend — действия панели, которые использует бот.
func (s *Server) BotBackend() bot.Backend { return botBackend{s} }

type botBackend struct{ s *Server }

func (b botBackend) Redeem(ctx context.Context, c nodeapi.Client, owner *int64, code string) (bot.Extend, error) {
	res, err := b.s.redeemForClient(ctx, c, owner, code)
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
