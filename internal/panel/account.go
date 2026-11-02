package panel

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"github.com/syava842/azpanel/internal/store"
)

const (
	totpIssuer      = "azpanel"
	backupCodeCount = 10
	backupCodeLen   = 10
	backupCodeChars = "abcdefghijkmnpqrstuvwxyz23456789" // без похожих l, o, 0, 1
	backupCodeCost  = 10                                 // коды длинные и случайные: дешевле пароля
	genPasswordLen  = 16
	genLetters      = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
	genDigits       = "23456789"
)

var loginRe = regexp.MustCompile(`^[a-z0-9_.-]{3,32}$`)

// validPassword — правила пароля: от 10 символов, буквы и цифры, не логин.
func validPassword(login, pw string) error {
	if utf8.RuneCountInString(pw) < minPasswordLen {
		return errors.New("пароль короче 10 символов")
	}
	if len(pw) > maxPasswordLen {
		return errors.New("пароль длиннее 72 байт")
	}
	var letter, digit bool
	for _, r := range pw {
		letter = letter || unicode.IsLetter(r)
		digit = digit || unicode.IsDigit(r)
	}
	if !letter || !digit {
		return errors.New("в пароле нужны и буквы, и цифры")
	}
	if strings.EqualFold(pw, login) {
		return errors.New("пароль не должен совпадать с логином")
	}
	return nil
}

func randomChar(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

// generatePassword — 16 знаков: буквы и цифры, обязательно и те и другие.
func generatePassword() (string, error) {
	for {
		b := make([]byte, genPasswordLen)
		for i := range b {
			c, err := randomChar(genLetters + genDigits)
			if err != nil {
				return "", err
			}
			b[i] = c
		}
		if p := string(b); strings.ContainsAny(p, genLetters) && strings.ContainsAny(p, genDigits) {
			return p, nil
		}
	}
}

// newBackupCodes — десять резервных кодов и их bcrypt-хеши.
func newBackupCodes() (codes, hashes []string, err error) {
	for i := 0; i < backupCodeCount; i++ {
		b := make([]byte, backupCodeLen)
		for j := range b {
			if b[j], err = randomChar(backupCodeChars); err != nil {
				return nil, nil, err
			}
		}
		h, err := bcrypt.GenerateFromPassword(b, backupCodeCost)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, string(b))
		hashes = append(hashes, string(h))
	}
	return codes, hashes, nil
}

// hashNewPassword — bcrypt нового пароля под ограничением параллельных проверок.
func (s *Server) hashNewPassword(pw string) (string, error) {
	s.loginSem <- struct{}{}
	defer func() { <-s.loginSem }()
	return HashPassword(pw)
}

// verifyPassword сверяет пароль текущего пользователя с попыткой в счёт
// ограничения (5 за 15 минут на пользователя). throttled — лимит исчерпан.
func (s *Server) verifyPassword(u store.User, pw string) (ok, throttled bool) {
	key := fmt.Sprintf("acct:%d", u.ID)
	if !s.Limiter.Begin(key) {
		return false, true
	}
	s.loginSem <- struct{}{}
	ok = s.CheckPassword(u.Login, u.Hash, u.Login, pw)
	<-s.loginSem
	if ok {
		s.Limiter.Reset(key)
	} else {
		s.Sleep(loginDelay)
	}
	return ok, false
}

type acctSession struct {
	ID, IP, Agent, Created, Seen string
	Current                      bool
}

func unixText(ts int64) string {
	t := time.Unix(ts, 0)
	return formatTime(&t)
}

func (s *Server) sessionRows(r *http.Request, userID int64, currentHash string) ([]acctSession, error) {
	list, err := s.Store.UserSessions(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	now := s.now().Unix()
	rows := []acctSession{}
	for _, x := range list {
		if x.MFAPending || x.Expires <= now {
			continue
		}
		rows = append(rows, acctSession{ID: x.IDHash, IP: x.IP, Agent: x.Agent, Created: unixText(x.Created),
			Seen: unixText(x.Seen), Current: x.IDHash == currentHash})
	}
	return rows, nil
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.Log.Error(what, "err", err)
	s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
}

// currentUser читает пользователя сессии из базы.
func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) (store.User, Session, bool) {
	sess, _ := session(r)
	if s.Store == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна")
		return store.User{}, sess, false
	}
	u, err := s.Store.UserByID(r.Context(), sess.UserID)
	if err != nil {
		s.internalError(w, r, "пользователь не прочитан", err)
		return store.User{}, sess, false
	}
	return u, sess, true
}

// accountPage — страница «Аккаунт».
func (s *Server) accountPage(w http.ResponseWriter, r *http.Request) {
	s.accountView(w, r, http.StatusOK, "")
}

func (s *Server) accountView(w http.ResponseWriter, r *http.Request, status int, errText string) {
	u, sess, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	rows, err := s.sessionRows(r, u.ID, sess.IDHash)
	if err != nil {
		s.internalError(w, r, "сессии не прочитаны", err)
		return
	}
	data := map[string]any{"Login": u.Login, "RoleText": roleText(u.Role), "Has2FA": len(u.TOTPSecret) > 0,
		"MustChange": u.MustChange, "Sessions": rows, "Can2FA": len(s.DataKey) == 32}
	s.addTelegram(data, u)
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "account", data)
}

func roleText(role string) string {
	if role == store.RoleAdmin {
		return "администратор"
	}
	return "пользователь"
}

// accountPassword — смена пароля: старый и новый дважды; остальные сессии
// завершаются.
func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	u, sess, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	old, pw, pw2 := r.PostForm.Get("old"), r.PostForm.Get("new"), r.PostForm.Get("new2")
	if pw != pw2 {
		s.accountView(w, r, http.StatusBadRequest, "новый пароль и повтор не совпадают")
		return
	}
	if err := validPassword(u.Login, pw); err != nil {
		s.accountView(w, r, http.StatusBadRequest, err.Error())
		return
	}
	good, throttled := s.verifyPassword(u, old)
	if throttled {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return
	}
	if !good {
		s.auditAs(r, u.Login, "password_failed", u.Login, "", "неверный текущий пароль")
		s.accountView(w, r, http.StatusUnauthorized, "текущий пароль неверен")
		return
	}
	hash, err := s.hashNewPassword(pw)
	if err != nil {
		s.accountView(w, r, http.StatusBadRequest, err.Error())
		return
	}
	// Хеш заменяется, только если он всё ещё тот, что проверен выше: сброс,
	// сделанный администратором за это время, не затирается.
	if err := s.Store.ChangePassword(r.Context(), u.ID, u.Hash, hash); err != nil {
		if errors.Is(err, store.ErrPasswordChanged) {
			s.accountView(w, r, http.StatusConflict, err.Error())
			return
		}
		s.internalError(w, r, "пароль не сохранён", err)
		return
	}
	if err := s.Store.DeleteUserSessions(r.Context(), u.ID, sess.IDHash); err != nil {
		s.Log.Warn("прочие сессии не завершены", "err", err)
	}
	s.audit(r, "password_change", u.Login, "", "пароль изменён, прочие сессии завершены")
	redirectMsg(w, r, "/account", "password_changed")
}

// qrDataURI — PNG с QR-кодом как data-адрес для <img>.
func qrDataURI(text string) (template.URL, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, qrSize)
	if err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}

// setupTTL — сколько действует форма включения 2FA.
const setupTTL = 10 * time.Minute

// setupAAD привязывает запечатанный секрет формы к пользователю и сроку.
func setupAAD(userID, exp int64) []byte {
	return []byte(fmt.Sprintf("totp-setup:%d:%d", userID, exp))
}

// setup2FA показывает шаг «отсканируйте и подтвердите»: секрет приходит в
// скрытом поле запечатанным ключом данных, в базу попадает только после кода.
func (s *Server) setup2FA(w http.ResponseWriter, r *http.Request, u store.User, secret []byte, status int, errText string) {
	exp := s.now().Add(setupTTL).Unix()
	sealed, err := SealAAD(s.DataKey, secret, setupAAD(u.ID, exp))
	if err != nil {
		s.internalError(w, r, "секрет не запечатан", err)
		return
	}
	uri := TOTPURL(totpIssuer, u.Login, secret)
	qr, err := qrDataURI(uri)
	if err != nil {
		s.internalError(w, r, "QR не построен", err)
		return
	}
	data := map[string]any{"Sealed": base64.RawURLEncoding.EncodeToString(sealed), "Exp": exp, "QR": qr,
		"Secret": base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)}
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "account_2fa", data)
}

func (s *Server) account2FAForm(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	if len(s.DataKey) != 32 {
		s.errorPage(w, r, http.StatusServiceUnavailable, "2FA недоступна: нет ключа данных PANEL_DATA_KEY")
		return
	}
	if len(u.TOTPSecret) > 0 {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		s.internalError(w, r, "секрет не создан", err)
		return
	}
	s.setup2FA(w, r, u, secret, http.StatusOK, "")
}

func (s *Server) account2FAEnable(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	if len(s.DataKey) != 32 {
		s.errorPage(w, r, http.StatusServiceUnavailable, "2FA недоступна: нет ключа данных PANEL_DATA_KEY")
		return
	}
	if len(u.TOTPSecret) > 0 {
		s.accountView(w, r, http.StatusBadRequest, "двухфакторная проверка уже включена")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.PostForm.Get("sealed"))
	exp, expErr := strconv.ParseInt(r.PostForm.Get("exp"), 10, 64)
	now := s.now().Unix()
	var secret []byte
	if err == nil && expErr == nil && exp > now && exp-now <= int64(setupTTL/time.Second) {
		secret, err = OpenAAD(s.DataKey, raw, setupAAD(u.ID, exp))
	} else {
		err = errors.New("срок формы вышел")
	}
	if err != nil {
		s.accountView(w, r, http.StatusBadRequest, "форма устарела, начните включение заново")
		return
	}
	// Включить 2FA со свежей сессии одним кодом нельзя: нужен и пароль.
	if good, throttled := s.verifyPassword(u, r.PostForm.Get("password")); throttled {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return
	} else if !good {
		s.setup2FA(w, r, u, secret, http.StatusUnauthorized, "пароль неверен")
		return
	}
	key := fmt.Sprintf("acct:%d", u.ID)
	if !s.Limiter.Begin(key) {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return
	}
	step, good := CheckTOTP(secret, normalizeCode(r.PostForm.Get("code")), s.now(), 0)
	if !good {
		s.Sleep(loginDelay)
		s.setup2FA(w, r, u, secret, http.StatusBadRequest, "неверный код, попробуйте ещё раз")
		return
	}
	s.Limiter.Reset(key)
	sealed, err := Seal(s.DataKey, secret)
	if err != nil {
		s.internalError(w, r, "секрет не запечатан", err)
		return
	}
	codes, hashes, err := newBackupCodes()
	if err != nil {
		s.internalError(w, r, "резервные коды не созданы", err)
		return
	}
	if err := s.Store.EnableTOTP(r.Context(), u.ID, sealed, step); err != nil {
		if errors.Is(err, store.ErrTOTPAlreadyOn) {
			s.accountView(w, r, http.StatusBadRequest, err.Error())
			return
		}
		s.internalError(w, r, "2FA не сохранена", err)
		return
	}
	if err := s.Store.SetBackupCodes(r.Context(), u.ID, hashes); err != nil {
		s.internalError(w, r, "резервные коды не сохранены", err)
		return
	}
	s.audit(r, "2fa_on", u.Login, "выключена", "включена")
	s.showOnce(w, r, "Двухфакторная проверка включена",
		"Сохраните резервные коды: каждый подходит один раз, повторно они не показываются.", "/account", "К аккаунту", codes)
}

func (s *Server) account2FADisable(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	if len(u.TOTPSecret) == 0 {
		s.accountView(w, r, http.StatusBadRequest, "двухфакторная проверка не включена")
		return
	}
	good, throttled := s.verifyPassword(u, r.PostForm.Get("password"))
	if throttled {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return
	}
	if !good {
		s.accountView(w, r, http.StatusUnauthorized, "пароль неверен")
		return
	}
	// Неверные коды считаются на пользователя и не снимаются верным паролем.
	mkey := mfaKey(u.ID)
	if !s.Limiter.Begin(mkey) {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return
	}
	code, err := s.secondFactorOK(r, u.ID)
	if err != nil {
		s.internalError(w, r, "второй фактор не проверен", err)
		return
	}
	if !code {
		s.Sleep(loginDelay)
		s.accountView(w, r, http.StatusUnauthorized, "неверный код")
		return
	}
	s.Limiter.Reset(mkey)
	err = s.Store.SetTOTP(r.Context(), u.ID, nil, 0)
	if err == nil {
		err = s.Store.SetBackupCodes(r.Context(), u.ID, nil)
	}
	if err != nil {
		s.internalError(w, r, "2FA не выключена", err)
		return
	}
	s.audit(r, "2fa_off", u.Login, "включена", "выключена")
	redirectMsg(w, r, "/account", "2fa_off")
}

// secondFactorOK сверяет введённый код 2FA (или резервный) текущего пользователя.
func (s *Server) secondFactorOK(r *http.Request, userID int64) (bool, error) {
	ok, _, err := s.checkSecondFactor(r, userID, normalizeCode(r.PostForm.Get("code")))
	return ok, err
}

func (s *Server) accountNewCodes(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	if len(u.TOTPSecret) == 0 {
		s.accountView(w, r, http.StatusBadRequest, "двухфакторная проверка не включена")
		return
	}
	good, throttled := s.verifyPassword(u, r.PostForm.Get("password"))
	if throttled {
		s.accountView(w, r, http.StatusTooManyRequests, "слишком много попыток, подождите 15 минут")
		return
	}
	if !good {
		s.accountView(w, r, http.StatusUnauthorized, "пароль неверен")
		return
	}
	codes, hashes, err := newBackupCodes()
	if err == nil {
		err = s.Store.SetBackupCodes(r.Context(), u.ID, hashes)
	}
	if err != nil {
		s.internalError(w, r, "резервные коды не созданы", err)
		return
	}
	s.audit(r, "2fa_codes", u.Login, "", "выпущены новые резервные коды")
	s.showOnce(w, r, "Новые резервные коды",
		"Прежние коды больше не действуют. Новые показываются один раз.", "/account", "К аккаунту", codes)
}

// accountRevoke отзывает любую свою сессию, кроме текущей.
func (s *Server) accountRevoke(w http.ResponseWriter, r *http.Request) {
	u, sess, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	id := r.PostForm.Get("session")
	if id == sess.IDHash {
		s.accountView(w, r, http.StatusBadRequest, "текущую сессию отозвать нельзя: используйте «Выйти»")
		return
	}
	if !s.ownsSession(w, r, u.ID, id) {
		return
	}
	if err := s.Store.DeleteSession(r.Context(), id); err != nil {
		s.internalError(w, r, "сессия не отозвана", err)
		return
	}
	s.audit(r, "session_revoke", u.Login, "", "отозвана своя сессия")
	redirectMsg(w, r, "/account", "session_revoked")
}

// ownsSession: сессия id принадлежит пользователю; иначе ответ 404 уже дан.
func (s *Server) ownsSession(w http.ResponseWriter, r *http.Request, userID int64, id string) bool {
	list, err := s.Store.UserSessions(r.Context(), userID)
	if err != nil {
		s.internalError(w, r, "сессии не прочитаны", err)
		return false
	}
	for _, x := range list {
		if x.IDHash == id {
			return true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "сессия не найдена")
	return false
}

// accountLogoutAll завершает все сессии пользователя, включая текущую.
func (s *Server) accountLogoutAll(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteUserSessions(r.Context(), u.ID, ""); err != nil {
		s.internalError(w, r, "сессии не завершены", err)
		return
	}
	s.audit(r, "logout_all", u.Login, "", "завершены все сессии")
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
