package panel

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	maxFormBody = 64 << 10
	loginDelay  = time.Second

	contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'"
)

// Node — то, что панель берёт у агента; *nodeapi.HTTPClient подходит.
type Node interface {
	Info(ctx context.Context) (nodeapi.Info, error)
	Clients(ctx context.Context) ([]nodeapi.Client, error)
	Sessions(ctx context.Context) ([]nodeapi.Session, error)
	System(ctx context.Context) (nodeapi.System, error)
	Profiles(ctx context.Context, name string) ([]nodeapi.Profile, error)
	Profile(ctx context.Context, name string, p nodeapi.Profile) ([]byte, error)
	CreateClient(ctx context.Context, req nodeapi.CreateClient) (nodeapi.Result, error)
	Renew(ctx context.Context, name string, days int) (nodeapi.Result, error)
	DeleteClient(ctx context.Context, kind, name string) (nodeapi.Result, error)
	SetLimit(ctx context.Context, name string, limit int) error
	SetBlocked(ctx context.Context, name string, blocked bool) (nodeapi.Result, error)
}

var _ Node = (*nodeapi.HTTPClient)(nil)

type Server struct {
	Node      Node
	AdminUser string
	AdminHash string // пусто — вход невозможен, страница входа говорит «пароль не задан: azpanel panel passwd»
	Version   string
	Sessions  *Sessions
	Limiter   *Limiter
	Log       *slog.Logger
	Sleep     func(time.Duration) // задержка неверного входа; в тестах — no-op

	pages map[string]*template.Template
}

type ctxKey struct{}

// Handler собирает маршруты и разбирает шаблоны (один раз). Маршруты
// страниц за входом добавляются через s.protect.
func (s *Server) Handler() http.Handler {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Sleep == nil {
		s.Sleep = time.Sleep
	}
	s.pages = parsePages()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.Handle("POST /logout", s.protect(s.logout))

	// Всё остальное — за входом; страницы клиентов и мониторинга
	// добавляются выше этих двух строк.
	mux.Handle("GET /{$}", s.protect(s.home))
	mux.Handle("/", s.protect(func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, http.StatusNotFound, "страница не найдена")
	}))
	return s.headers(mux)
}

// parsePages: каждая страница — свой набор layout.html + страница.
func parsePages() map[string]*template.Template {
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		panic(err)
	}
	pages := map[string]*template.Template{}
	for _, e := range entries {
		name := e.Name()
		if name == "layout.html" {
			continue
		}
		t := template.Must(template.ParseFS(templatesFS, "templates/layout.html", path.Join("templates", name)))
		pages[strings.TrimSuffix(name, ".html")] = t
	}
	return pages
}

// headers — защитные заголовки на каждом ответе.
func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// session — сессия запроса, положенная в контекст обработчиком protect.
func session(r *http.Request) (Session, bool) {
	sess, ok := r.Context().Value(ctxKey{}).(Session)
	return sess, ok
}

// protect пускает только со входом; POST — ещё и с верным CSRF. Без
// сессии GET уходит на /login, POST получает 403.
func (s *Server) protect(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sess Session
		ok := false
		if c, err := r.Cookie(cookieName); err == nil {
			sess, ok = s.Sessions.Get(c.Value)
		}
		if !ok {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			s.errorPage(w, r, http.StatusForbidden, "нужен вход")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
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

// render показывает страницу; в data добавляются CSRF, User, Version, Msg.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, data map[string]any) {
	t, ok := s.pages[page]
	if !ok {
		s.Log.Error("нет шаблона", "page", page)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	d := map[string]any{}
	for k, v := range data {
		d[k] = v
	}
	if sess, ok := session(r); ok {
		d["CSRF"], d["User"] = sess.CSRF, sess.User
	}
	d["Version"] = s.Version
	d["Msg"] = r.URL.Query().Get("msg")
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", d); err != nil {
		s.Log.Error("шаблон не выполнен", "page", page, "err", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, text string) {
	s.render(w, r, status, "error", map[string]any{"Error": text, "Status": status})
}

// nodeErr: 4xx агента — 400, 5xx — 502, сеть — «агент недоступен».
func (s *Server) nodeErr(err error) (status int, text string) {
	var ne *nodeapi.Error
	if errors.As(err, &ne) {
		if ne.Status >= 500 {
			return http.StatusBadGateway, ne.Message
		}
		return http.StatusBadRequest, ne.Message
	}
	return http.StatusBadGateway, "агент недоступен: " + err.Error()
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "home", nil) // заглушка до страницы клиентов
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, r, http.StatusOK, "", "")
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, user, errText string) {
	if s.AdminHash == "" {
		errText = "пароль не задан: azpanel panel passwd"
	}
	s.render(w, r, status, "login", map[string]any{"Error": errText, "FormUser": user})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "неверный запрос")
		return
	}
	host := remoteHost(r)
	user, pw := r.PostForm.Get("user"), r.PostForm.Get("password")
	if s.Limiter.Blocked(host) {
		s.Log.Warn("вход заблокирован: слишком много попыток", "remote", host)
		s.renderLogin(w, r, http.StatusTooManyRequests, user, "слишком много попыток, подождите 15 минут")
		return
	}
	if !CheckPassword(s.AdminUser, s.AdminHash, user, pw) {
		s.Sleep(loginDelay)
		s.Limiter.Fail(host)
		s.Log.Warn("неверный вход", "user", user, "remote", host)
		s.renderLogin(w, r, http.StatusUnauthorized, user, "неверное имя или пароль")
		return
	}
	sess, err := s.Sessions.Create(user)
	if err != nil {
		s.Log.Error("сессия не создана", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	s.Limiter.Reset(host)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: sess.ID, Path: "/", Expires: sess.Expires,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r),
	})
	s.Log.Info("вход", "user", user, "remote", host)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := session(r)
	s.Sessions.Delete(sess.ID)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r),
	})
	s.Log.Info("выход", "user", sess.User, "remote", remoteHost(r))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
