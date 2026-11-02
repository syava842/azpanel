package panel

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

var errLastAdmin = errors.New("это последний активный администратор")

type userRow struct {
	ID        int64
	Login     string
	Role      string
	Has2FA    bool
	Disabled  bool
	Clients   int
	LastLogin string
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	s.usersView(w, r, http.StatusOK, "", "")
}

func (s *Server) usersView(w http.ResponseWriter, r *http.Request, status int, errText, formLogin string) {
	list, err := s.Store.Users(r.Context())
	if err != nil {
		s.internalError(w, r, "пользователи не прочитаны", err)
		return
	}
	rows := []userRow{}
	for _, u := range list {
		refs, err := s.Store.ClientsOf(r.Context(), u.ID)
		if err != nil {
			s.internalError(w, r, "клиенты пользователя не прочитаны", err)
			return
		}
		last := "—"
		if ss, err := s.Store.UserSessions(r.Context(), u.ID); err == nil {
			var newest int64
			for _, x := range ss {
				if !x.MFAPending && x.Created > newest {
					newest = x.Created
				}
			}
			if newest > 0 {
				last = unixText(newest)
			}
		}
		rows = append(rows, userRow{ID: u.ID, Login: u.Login, Role: roleText(u.Role), Has2FA: len(u.TOTPSecret) > 0,
			Disabled: u.Disabled, Clients: len(refs), LastLogin: last})
	}
	data := map[string]any{"Rows": rows, "FormLogin": formLogin}
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "users", data)
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	login := strings.TrimSpace(r.PostForm.Get("login"))
	role := r.PostForm.Get("role")
	fail := func(status int, text string) { s.usersView(w, r, status, text, login) }
	if !loginRe.MatchString(login) {
		fail(http.StatusBadRequest, "логин: 3-32 знака, строчные латинские буквы, цифры и _ . -")
		return
	}
	if role != store.RoleAdmin && role != store.RoleUser {
		fail(http.StatusBadRequest, "роль: администратор или пользователь")
		return
	}
	pw, generated := r.PostForm.Get("password"), r.PostForm.Get("generate") == "1"
	if generated || pw == "" {
		var err error
		if pw, err = generatePassword(); err != nil {
			s.internalError(w, r, "пароль не создан", err)
			return
		}
		generated = true
	} else if err := validPassword(login, pw); err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	hash, err := s.hashNewPassword(pw)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.Store.CreateUser(r.Context(), store.User{Login: login, Hash: hash, Role: role,
		MustChange: r.PostForm.Get("must_change") == "1", Created: s.now().Unix()})
	if errors.Is(err, store.ErrLoginTaken) {
		fail(http.StatusConflict, "такой логин уже занят")
		return
	}
	if err != nil {
		s.internalError(w, r, "пользователь не создан", err)
		return
	}
	s.audit(r, "user_create", u.Login, "", roleText(u.Role))
	if !generated {
		redirectMsg(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "user_created")
		return
	}
	s.showOnce(w, r, "Пользователь "+u.Login+" создан",
		"Пароль показан один раз: передайте его пользователю.", "/users/"+strconv.FormatInt(u.ID, 10), "К пользователю",
		[]string{pw})
}

// pathUser читает пользователя из {id}; нет такого — 404 и false.
func (s *Server) pathUser(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var u store.User
		if u, err = s.Store.UserByID(r.Context(), id); err == nil {
			return u, true
		}
		if !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, r, "пользователь не прочитан", err)
			return store.User{}, false
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "пользователь не найден")
	return store.User{}, false
}

func userHref(u store.User) string { return "/users/" + strconv.FormatInt(u.ID, 10) }

func (s *Server) userPage(w http.ResponseWriter, r *http.Request) {
	u, ok := s.pathUser(w, r)
	if !ok {
		return
	}
	s.userView(w, r, u, http.StatusOK, "")
}

func (s *Server) userView(w http.ResponseWriter, r *http.Request, u store.User, status int, errText string) {
	sess, _ := session(r)
	rows, err := s.sessionRows(r, u.ID, "")
	if err != nil {
		s.internalError(w, r, "сессии не прочитаны", err)
		return
	}
	refs, err := s.Store.ClientsOf(r.Context(), u.ID)
	if err != nil {
		s.internalError(w, r, "клиенты пользователя не прочитаны", err)
		return
	}
	type clientLink struct{ Name, Href string }
	clients := []clientLink{}
	for _, x := range refs {
		if x.Node == s.NodeID {
			clients = append(clients, clientLink{x.Name, clientHref(x.Name)})
		}
	}
	until := ""
	if u.AccessUntil != nil {
		until = untilText(u.AccessUntil)
	}
	data := map[string]any{"PublicURLSet": s.PublicURL != "", "Until": until, "UntilStamp": untilStamp(u.AccessUntil), "U": u, "Href": userHref(u), "RoleText": roleText(u.Role), "IsAdminRole": u.Role == store.RoleAdmin,
		"Has2FA": len(u.TOTPSecret) > 0, "Sessions": rows, "Clients": clients, "IsSelf": u.ID == sess.UserID}
	s.addTelegram(data, u)
	if created, has, err := s.Store.UserLinkCreated(r.Context(), u.ID); err != nil {
		s.Log.Warn("ссылка портала пользователя не прочитана", "user", u.Login, "err", err)
	} else if has {
		t := time.Unix(created, 0)
		data["PortalCreated"] = formatTime(&t)
	}
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "user", data)
}

// lastAdmin: пользователь — единственный активный администратор.
func (s *Server) lastAdmin(r *http.Request, u store.User) (bool, error) {
	if u.Role != store.RoleAdmin || u.Disabled {
		return false, nil
	}
	n, err := s.Store.AdminCount(r.Context())
	return n <= 1, err
}

// mutateUser выполняет действие над пользователем под замком: проверка
// «последнего администратора» и запись идут вместе. guard вернёт ошибку,
// если действие лишило бы панель последнего администратора.
func (s *Server) mutateUser(w http.ResponseWriter, r *http.Request, protectLast bool, f func(u store.User) (store.User, error)) (store.User, bool) {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	u, ok := s.pathUser(w, r)
	if !ok {
		return u, false
	}
	if protectLast {
		last, err := s.lastAdmin(r, u)
		if err != nil {
			s.internalError(w, r, "администраторы не посчитаны", err)
			return u, false
		}
		if last {
			s.userView(w, r, u, http.StatusConflict, "Нельзя: "+errLastAdmin.Error())
			return u, false
		}
	}
	next, err := f(u)
	if err != nil {
		s.userView(w, r, u, http.StatusBadRequest, err.Error())
		return u, false
	}
	return next, true
}

func (s *Server) userRole(w http.ResponseWriter, r *http.Request) {
	role := r.PostForm.Get("role")
	if role != store.RoleAdmin && role != store.RoleUser {
		if u, ok := s.pathUser(w, r); ok {
			s.userView(w, r, u, http.StatusBadRequest, "роль: администратор или пользователь")
		}
		return
	}
	old := ""
	u, ok := s.mutateUser(w, r, role == store.RoleUser, func(u store.User) (store.User, error) {
		old = u.Role
		u.Role = role
		return u, s.Store.SetRole(r.Context(), u.ID, role)
	})
	if ok {
		s.audit(r, "user_role", u.Login, roleText(old), roleText(role))
		redirectMsg(w, r, userHref(u), "role_set")
	}
}

func (s *Server) userDisabled(w http.ResponseWriter, r *http.Request) {
	disable := r.PostForm.Get("disabled") == "1"
	u, ok := s.mutateUser(w, r, disable, func(u store.User) (store.User, error) {
		u.Disabled = disable
		if err := s.Store.SetDisabled(r.Context(), u.ID, disable); err != nil {
			return u, err
		}
		if disable {
			return u, s.Store.DeleteUserSessions(r.Context(), u.ID, "")
		}
		return u, nil
	})
	if !ok {
		return
	}
	if disable {
		s.audit(r, "user_disable", u.Login, "включён", "отключён")
		redirectMsg(w, r, userHref(u), "user_disabled")
		return
	}
	s.audit(r, "user_enable", u.Login, "отключён", "включён")
	redirectMsg(w, r, userHref(u), "user_enabled")
}

// userResetPassword: новый случайный пароль показывается один раз,
// must_change=1, все сессии пользователя завершаются.
func (s *Server) userResetPassword(w http.ResponseWriter, r *http.Request) {
	pw, err := generatePassword()
	if err != nil {
		s.internalError(w, r, "пароль не создан", err)
		return
	}
	hash, err := s.hashNewPassword(pw)
	if err != nil {
		s.internalError(w, r, "пароль не хеширован", err)
		return
	}
	sess, _ := session(r)
	u, ok := s.mutateUser(w, r, false, func(u store.User) (store.User, error) {
		// Сброс себе завершил бы и текущую сессию, а новый пароль
		// показывается в ней — администратор остался бы без пароля.
		if u.ID == sess.UserID {
			return u, errors.New("свой пароль меняйте на странице «Аккаунт»")
		}
		u.Hash, u.MustChange = hash, true
		if err := s.Store.SetPassword(r.Context(), u.ID, hash, true); err != nil {
			return u, err
		}
		return u, s.Store.DeleteUserSessions(r.Context(), u.ID, "")
	})
	if !ok {
		return
	}
	s.audit(r, "user_password_reset", u.Login, "", "пароль сброшен, сессии завершены")
	s.showOnce(w, r, "Пароль пользователя "+u.Login+" сброшен",
		"Новый пароль показан один раз; при входе его придётся сменить. Все сессии пользователя завершены.",
		userHref(u), "К пользователю", []string{pw})
}

func (s *Server) userReset2FA(w http.ResponseWriter, r *http.Request) {
	sess, _ := session(r)
	u, ok := s.mutateUser(w, r, false, func(u store.User) (store.User, error) {
		u.TOTPSecret, u.TOTPLastStep = nil, 0
		if err := s.Store.SetTOTP(r.Context(), u.ID, nil, 0); err != nil {
			return u, err
		}
		if err := s.Store.SetBackupCodes(r.Context(), u.ID, nil); err != nil {
			return u, err
		}
		except := ""
		if u.ID == sess.UserID {
			except = sess.IDHash
		}
		return u, s.Store.DeleteUserSessions(r.Context(), u.ID, except)
	})
	if ok {
		s.audit(r, "user_2fa_reset", u.Login, "", "2FA сброшена, сессии завершены")
		redirectMsg(w, r, userHref(u), "2fa_reset")
	}
}

func (s *Server) userRevoke(w http.ResponseWriter, r *http.Request) {
	u, ok := s.pathUser(w, r)
	if !ok || !s.ownsSession(w, r, u.ID, r.PostForm.Get("session")) {
		return
	}
	if err := s.Store.DeleteSession(r.Context(), r.PostForm.Get("session")); err != nil {
		s.internalError(w, r, "сессия не отозвана", err)
		return
	}
	s.audit(r, "session_revoke", u.Login, "", "сессия отозвана администратором")
	redirectMsg(w, r, userHref(u), "session_revoked")
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	confirm := strings.TrimSpace(r.PostForm.Get("confirm"))
	u, ok := s.mutateUser(w, r, true, func(u store.User) (store.User, error) {
		if confirm != u.Login {
			return u, errors.New("для удаления впишите логин пользователя")
		}
		return u, s.Store.DeleteUser(r.Context(), u.ID)
	})
	if ok {
		s.audit(r, "user_delete", u.Login, roleText(u.Role), "удалён")
		redirectMsg(w, r, "/users", "user_deleted")
	}
}

// userAccess задаёт срок доступа пользователя (пусто — без срока): действует
// на все его клиенты, у клиента — меньший из его срока и этого.
func (s *Server) userAccess(w http.ResponseWriter, r *http.Request) {
	u, ok := s.pathUser(w, r)
	if !ok {
		return
	}
	until, err := parseUntil(strings.TrimSpace(r.PostForm.Get("until")))
	if err != nil {
		s.userView(w, r, u, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.SetUserAccessUntil(r.Context(), u.ID, until); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.errorPage(w, r, http.StatusNotFound, "пользователь не найден")
			return
		}
		s.internalError(w, r, "срок доступа не сохранён", err)
		return
	}
	s.audit(r, "user_access", u.Login, "доступ до: "+untilText(u.AccessUntil), "доступ до: "+untilText(until))
	redirectMsg(w, r, userHref(u), "user_access_saved")
}
