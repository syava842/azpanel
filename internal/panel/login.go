package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

const (
	defaultSessionTTL = 7 * 24 * time.Hour
	mfaPendingTTL     = 5 * time.Minute // сколько живёт сессия, ждущая код 2FA
	maxAgentLen       = 200             // байт User-Agent в базе

	pathLoginMFA        = "/login/2fa"
	pathAccountPassword = "/account/password"
	pathAccount2FA      = "/account/2fa"
)

type guardMode int

const (
	guardNormal guardMode = iota // полный доступ: сессия без ожидания кода
	guardMFA                     // только сессия, ждущая код 2FA
	guardAny                     // любая живая сессия (выход)
)

type ctxKey struct{}

// session — сессия запроса, положенная в контекст обработчиком protect.
// Через неё обработчики узнают текущего пользователя (User — логин,
// UserID) и роль (Role, IsAdmin).
func session(r *http.Request) (Session, bool) {
	sess, ok := r.Context().Value(ctxKey{}).(Session)
	return sess, ok
}

// createSession кладёт в базу новую сессию пользователя и возвращает
// идентификатор для cookie. Ждущая код 2FA живёт mfaPendingTTL.
func (s *Server) createSession(ctx context.Context, u store.User, ip, agent string, pending bool) (string, Session, error) {
	id, err := randomHex()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randomHex()
	if err != nil {
		return "", Session{}, err
	}
	now := s.now()
	ttl := s.SessionTTL
	if pending {
		ttl = mfaPendingTTL
	}
	if len(agent) > maxAgentLen {
		agent = agent[:maxAgentLen]
	}
	x := store.Session{
		IDHash: hashSessionID(id), UserID: u.ID, CSRF: csrf, IP: ip, Agent: agent,
		Created: now.Unix(), Seen: now.Unix(), Expires: now.Add(ttl).Unix(), MFAPending: pending,
	}
	if err := s.Store.CreateSession(ctx, x); err != nil {
		return "", Session{}, err
	}
	return id, toSession(x, u), nil
}

func toSession(x store.Session, u store.User) Session {
	return Session{
		IDHash: x.IDHash, CSRF: x.CSRF, UserID: u.ID, User: u.Login, Role: u.Role,
		MustChange: u.MustChange, Has2FA: len(u.TOTPSecret) > 0, MFAPending: x.MFAPending,
		Expires: time.Unix(x.Expires, 0),
	}
}

// sessionFromRequest читает сессию из базы по cookie. Истёкшая сессия,
// сессия удалённого или отключённого пользователя удаляются и не отдаются
// (ok=false, ошибки нет). Ошибка — только сбой базы.
func (s *Server) sessionFromRequest(r *http.Request) (Session, bool, error) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" || s.Store == nil {
		return Session{}, false, nil
	}
	ctx := r.Context()
	h := hashSessionID(c.Value)
	x, err := s.Store.SessionByIDHash(ctx, h)
	if errors.Is(err, store.ErrNotFound) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	now := s.now()
	if x.Expires <= now.Unix() {
		s.Store.DeleteSession(ctx, h)
		return Session{}, false, nil
	}
	u, err := s.Store.UserByID(ctx, x.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Disabled) {
		s.Store.DeleteSession(ctx, h)
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	if err := s.Store.TouchSession(ctx, h, now.Unix()); err != nil {
		s.Log.Warn("активность сессии не записана", "err", err)
	}
	return toSession(x, u), true, nil
}

// pathIs: путь равен p или лежит под ним.
func pathIs(r *http.Request, p string) bool {
	return r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/")
}

// gate решает, пускать ли сессию на маршрут. Пустой target — пускать;
// иначе GET уходит на target, а изменяющий запрос получает 403 с msg.
func (s *Server) gate(sess Session, r *http.Request, mode guardMode) (target, msg string) {
	switch mode {
	case guardAny:
		return "", ""
	case guardMFA:
		if !sess.MFAPending {
			return "/", "вход уже выполнен"
		}
		return "", ""
	}
	if sess.MFAPending {
		return pathLoginMFA, "введите код двухфакторной проверки"
	}
	if sess.MustChange {
		// Смена пароля идёт первой: 2FA администратор включит после неё,
		// иначе страница пароля и страница 2FA гоняли бы его по кругу.
		if !pathIs(r, pathAccountPassword) {
			return pathAccountPassword, "сначала смените пароль"
		}
		return "", ""
	}
	if s.RequireAdmin2FA && sess.IsAdmin() && !sess.Has2FA && !pathIs(r, pathAccount2FA) {
		return pathAccount2FA, "администратору нужно включить двухфакторную проверку"
	}
	return "", ""
}

// protect пускает только со входом, без ожидания кода 2FA, без обязательной
// смены пароля и (для администратора при require_admin_2fa) без включённой 2FA.
func (s *Server) protect(h http.HandlerFunc) http.Handler { return s.guard(h, guardNormal) }

// guard: POST — ещё и с верным CSRF. Без сессии GET уходит на /login, POST
// получает 403.
func (s *Server) guard(h http.HandlerFunc, mode guardMode) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok, err := s.sessionFromRequest(r)
		if err != nil {
			s.Log.Error("сессия не прочитана", "err", err)
			s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
			return
		}
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		if !ok {
			if safe {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			s.errorPage(w, r, http.StatusForbidden, "нужен вход")
			return
		}
		if target, msg := s.gate(sess, r, mode); target != "" {
			if safe {
				http.Redirect(w, r, target, http.StatusSeeOther)
				return
			}
			s.errorPage(w, r, http.StatusForbidden, msg)
			return
		}
		if !safe {
			limit := int64(maxFormBody)
			if strings.HasPrefix(r.URL.Path, "/routing/files/") {
				limit = maxRoutingForm // списки целиком — до 1 МБ текста
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			if err := r.ParseForm(); err != nil {
				s.errorPage(w, r, http.StatusBadRequest, "неверный запрос")
				return
			}
			if !SameCSRF(sess.CSRF, r.PostForm.Get("csrf")) {
				s.errorPage(w, r, http.StatusForbidden, "неверный токен формы, обновите страницу")
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, r, http.StatusOK, "", "")
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, user, errText string) {
	if s.Store == nil {
		errText = "база панели недоступна"
	} else if us, err := s.Store.Users(r.Context()); err == nil && len(us) == 0 {
		errText = "пароль не задан: azpanel panel passwd"
	}
	s.render(w, r, status, "login", map[string]any{"Error": errText, "FormUser": user})
}

// issueSession выдаёт cookie с новой сессией; прежняя сессия этого браузера
// не должна жить дальше.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, u store.User, pending bool) error {
	id, sess, err := s.createSession(r.Context(), u, remoteHost(r), r.UserAgent(), pending)
	if err != nil {
		return err
	}
	if c, err := r.Cookie(cookieName); err == nil {
		if err := s.Store.DeleteSession(r.Context(), hashSessionID(c.Value)); err != nil {
			s.Log.Warn("прежняя сессия не удалена", "err", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", Expires: sess.Expires,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r),
	})
	return nil
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "неверный запрос")
		return
	}
	if s.Store == nil {
		s.renderLogin(w, r, http.StatusServiceUnavailable, "", "")
		return
	}
	host := remoteHost(r)
	user, pw := r.PostForm.Get("user"), r.PostForm.Get("password")
	// Попытка засчитывается до bcrypt и атомарно с проверкой лимита.
	if !s.Limiter.Begin(host) {
		if s.shouldLogBlocked(host) {
			s.Log.Warn("вход заблокирован: слишком много попыток", "remote", host)
		}
		s.renderLogin(w, r, http.StatusTooManyRequests, user, "слишком много попыток, подождите 15 минут")
		return
	}
	login := strings.ToLower(strings.TrimSpace(user))
	u, err := s.Store.UserByLogin(r.Context(), login)
	found := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.Log.Error("пользователь не прочитан", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	// Нет такого или отключён — проверка идёт с пустым хешем (фиктивный
	// bcrypt): время ответа и текст ошибки те же, что при неверном пароле.
	wantUser, hash := "", ""
	if found && !u.Disabled {
		wantUser, hash = u.Login, u.Hash
	}
	s.loginSem <- struct{}{} // одновременно не больше maxParallelBcrypt проверок
	ok := s.CheckPassword(wantUser, hash, login, pw)
	<-s.loginSem
	if !ok {
		s.Sleep(loginDelay)
		s.Log.Warn("неверный вход", "user", truncateRunes(user, maxLoggedName), "remote", host)
		s.auditAs(r, "", "login_failed", truncateRunes(user, maxLoggedName), "", "")
		s.renderLogin(w, r, http.StatusUnauthorized, user, "неверное имя или пароль")
		return
	}
	pending := len(u.TOTPSecret) > 0
	if pending && s.Limiter.Blocked(mfaKey(u.ID)) {
		// Пароль верен, но коды этого пользователя уже перебирали: новая
		// ждущая сессия дала бы ещё попытки.
		s.Log.Warn("вход заблокирован: слишком много неверных кодов 2FA", "user", truncateRunes(u.Login, maxLoggedName), "remote", host)
		s.renderLogin(w, r, http.StatusTooManyRequests, user, "слишком много попыток, подождите 15 минут")
		return
	}
	if err := s.issueSession(w, r, u, pending); err != nil {
		s.Log.Error("сессия не создана", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	if pending {
		// Счётчики не сбрасываются: верный пароль не должен обнулять
		// перебор кода. Сброс — только верным кодом в mfaSubmit.
		http.Redirect(w, r, pathLoginMFA, http.StatusSeeOther)
		return
	}
	s.Limiter.Reset(host)
	s.Log.Info("вход", "user", truncateRunes(u.Login, maxLoggedName), "remote", host)
	s.auditAs(r, truncateRunes(u.Login, maxLoggedName), "login", "", "", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// mfaKey — ключ счётчика неверных кодов пользователя: общий для всех адресов
// и сессий, не снимается верным паролем.
func mfaKey(userID int64) string { return fmt.Sprintf("mfa:%d", userID) }

func (s *Server) mfaForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "mfa", nil)
}

// normalizeCode убирает пробелы и дефисы, приводит к нижнему регистру.
func normalizeCode(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	return strings.NewReplacer(" ", "", "-", "").Replace(c)
}

func isTOTPShape(c string) bool {
	if len(c) != totpDigits {
		return false
	}
	for _, ch := range c {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// checkSecondFactor сверяет код TOTP или резервный код. backup — принят
// резервный. Ошибка — сбой базы или ключа, а не неверный код.
func (s *Server) checkSecondFactor(r *http.Request, userID int64, code string) (ok, backup bool, err error) {
	ctx := r.Context()
	if isTOTPShape(code) {
		s.mfaMu.Lock() // два запроса с одним кодом не должны оба пройти
		defer s.mfaMu.Unlock()
		u, err := s.Store.UserByID(ctx, userID)
		if err != nil {
			return false, false, err
		}
		if len(u.TOTPSecret) == 0 {
			return false, false, nil
		}
		secret, err := Open(s.DataKey, u.TOTPSecret)
		if err != nil {
			return false, false, err
		}
		step, ok := CheckTOTP(secret, code, s.now(), u.TOTPLastStep)
		if !ok {
			return false, false, nil
		}
		advanced, err := s.Store.AdvanceTOTPStep(ctx, userID, step)
		if err != nil {
			return false, false, err
		}
		return advanced, false, nil
	}
	s.loginSem <- struct{}{} // сверка резервного кода — bcrypt
	ok, err = s.Store.UseBackupCode(ctx, userID, code)
	<-s.loginSem
	return ok, ok, err
}

func (s *Server) mfaSubmit(w http.ResponseWriter, r *http.Request) {
	sess, _ := session(r)
	host := remoteHost(r)
	mkey := mfaKey(sess.UserID)
	if !s.Limiter.Begin(host) || !s.Limiter.Begin(mkey) {
		if s.shouldLogBlocked(host) {
			s.Log.Warn("вход заблокирован: слишком много попыток", "remote", host)
		}
		s.render(w, r, http.StatusTooManyRequests, "mfa", map[string]any{"Error": "слишком много попыток, подождите 15 минут"})
		return
	}
	code := normalizeCode(r.PostForm.Get("code"))
	ok, backup, err := s.checkSecondFactor(r, sess.UserID, code)
	if err != nil {
		s.Log.Error("второй фактор не проверен", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	if !ok {
		s.Sleep(loginDelay)
		s.Log.Warn("неверный код 2FA", "user", truncateRunes(sess.User, maxLoggedName), "remote", host)
		s.auditAs(r, truncateRunes(sess.User, maxLoggedName), "login_2fa_failed", "", "", "")
		s.render(w, r, http.StatusUnauthorized, "mfa", map[string]any{"Error": "неверный код"})
		return
	}
	u, err := s.Store.UserByID(r.Context(), sess.UserID)
	if err == nil {
		err = s.issueSession(w, r, u, false) // новый идентификатор: старый был лишь пропуском на второй шаг
	}
	if err != nil {
		s.Log.Error("сессия не создана", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	s.Limiter.Reset(host)
	s.Limiter.Reset(mkey)
	name := truncateRunes(sess.User, maxLoggedName)
	s.Log.Info("вход", "user", name, "remote", host, "backup_code", backup)
	s.auditAs(r, name, "login", "", "", "")
	if backup {
		s.auditAs(r, name, "login_backup_code", "", "", "")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r),
	})
}

// logoutRoute: без живой сессии (истекла, вкладка осталась открытой) просто
// стирает cookie и ведёт на вход — менять нечего, CSRF не нужен. С живой
// сессией (в том числе ждущей код 2FA) CSRF обязателен, как у остальных
// изменяющих маршрутов.
func (s *Server) logoutRoute(w http.ResponseWriter, r *http.Request) {
	if _, ok, err := s.sessionFromRequest(r); ok || err != nil {
		s.guard(s.logout, guardAny).ServeHTTP(w, r)
		return
	}
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := session(r)
	if err := s.Store.DeleteSession(r.Context(), sess.IDHash); err != nil {
		s.Log.Warn("сессия не удалена", "err", err)
	}
	clearSessionCookie(w, r)
	s.Log.Info("выход", "user", truncateRunes(sess.User, maxLoggedName), "remote", remoteHost(r))
	s.auditAs(r, truncateRunes(sess.User, maxLoggedName), "logout", "", "", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
