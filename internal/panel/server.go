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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	maxFormBody = 64 << 10
	loginDelay  = time.Second

	maxParallelBcrypt = 4           // одновременных проверок пароля
	maxLoggedName     = 64          // рун имени в журнале
	blockedLogEvery   = time.Minute // не чаще раза в минуту на адрес

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
	Denials(ctx context.Context, since time.Time) ([]nodeapi.Denial, error)
}

var _ Node = (*nodeapi.HTTPClient)(nil)

type Server struct {
	Node    Node
	Version string
	// SessionTTL — срок жизни сессии; ноль — семь суток.
	SessionTTL time.Duration
	// DataKey — 32 байта ключа AES-256-GCM для секретов TOTP; пусто — 2FA
	// недоступна (вход пользователей с включённой 2FA невозможен).
	DataKey []byte
	// RequireAdmin2FA — администратор без 2FA после входа обязан её включить.
	RequireAdmin2FA bool
	Limiter         *Limiter
	Log             *slog.Logger
	Sleep           func(time.Duration) // задержка неверного входа; в тестах — no-op
	Now             func() time.Time    // по умолчанию time.Now
	// CheckPassword — проверка входа; по умолчанию CheckPassword пакета,
	// в тестах подменяется счётчиком.
	CheckPassword func(wantUser, hash, user, pw string) bool
	// Store — база панели: пользователи, сессии, карточки, история, журнал;
	// без неё войти нельзя.
	Store  *store.Store
	NodeID int64
	// Collector нужен ради пометки частой смены адреса; nil — без пометок.
	Collector *Collector
	// Geo — город и провайдер по адресу; nil — без этих столбцов.
	Geo *Geo

	pages map[string]*template.Template

	loginSem      chan struct{} // ограничивает одновременные bcrypt
	mfaMu         sync.Mutex    // сверка кода 2FA и запись принятого шага — одним куском
	blockedMu     sync.Mutex
	blockedLogged map[string]time.Time // адрес -> когда последний раз писали 429
}

// Handler собирает маршруты и разбирает шаблоны (один раз). Маршруты
// страниц за входом добавляются через s.protect.
func (s *Server) Handler() http.Handler {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Sleep == nil {
		s.Sleep = time.Sleep
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.CheckPassword == nil {
		s.CheckPassword = CheckPassword
	}
	if s.SessionTTL <= 0 {
		s.SessionTTL = defaultSessionTTL
	}
	s.loginSem = make(chan struct{}, maxParallelBcrypt)
	s.blockedLogged = map[string]time.Time{}
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
	mux.Handle("GET /login/2fa", s.guard(s.mfaForm, guardMFA))
	mux.Handle("POST /login/2fa", s.guard(s.mfaSubmit, guardMFA))
	mux.HandleFunc("POST /logout", s.logoutRoute)

	// Всё остальное — за входом; новые страницы добавляются выше
	// этих двух строк.
	mux.Handle("GET /monitor", s.protect(s.monitor))
	mux.Handle("GET /audit", s.protect(s.auditPage))
	mux.Handle("GET /clients/new", s.protect(s.newForm))
	mux.Handle("POST /clients", s.protect(s.createClient))
	mux.Handle("GET /clients/{name}", s.protect(s.clientCard))
	mux.Handle("GET /clients/{name}/profiles/{kind}/{variant}/{file}", s.protect(s.profileFile))
	mux.Handle("GET /clients/{name}/qr/{kind}/{variant}/{file}", s.protect(s.profileQR))
	mux.Handle("POST /clients/{name}/renew", s.protect(s.renew))
	mux.Handle("POST /clients/{name}/limit", s.protect(s.setLimit))
	mux.Handle("POST /clients/{name}/card", s.protect(s.saveCard))
	mux.Handle("POST /clients/{name}/block", s.protect(s.block))
	mux.Handle("POST /clients/{name}/delete", s.protect(s.deleteClient))
	mux.Handle("GET /{$}", s.protect(s.clientsList))
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
		d["CSRF"], d["Role"], d["IsAdmin"] = sess.CSRF, sess.Role, sess.IsAdmin()
		if !sess.MFAPending { // до ввода кода меню и «Выйти» не показываются
			d["User"] = sess.User
		}
	}
	d["Version"] = s.Version
	d["Msg"] = flashText(r)
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

// shouldLogBlocked: 429 с одного адреса пишется в журнал не чаще раза в
// минуту, иначе поток запросов вытеснит из ротации всё остальное.
func (s *Server) shouldLogBlocked(host string) bool {
	now := s.Now()
	s.blockedMu.Lock()
	defer s.blockedMu.Unlock()
	for h, t := range s.blockedLogged {
		if now.Sub(t) >= blockedLogEvery {
			delete(s.blockedLogged, h)
		}
	}
	if _, ok := s.blockedLogged[host]; ok {
		return false
	}
	s.blockedLogged[host] = now
	return true
}

// truncateRunes обрезает строку для журнала по рунам.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
