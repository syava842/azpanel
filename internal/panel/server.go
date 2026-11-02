package panel

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/update"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	maxFormBody = 64 << 10
	// maxRoutingForm — предел тела форм редактора списков: вкладка «Целиком»
	// шлёт до 1 МБ текста, а в urlencoded кириллица раздувается в разы.
	maxRoutingForm = 4 << 20
	loginDelay     = time.Second

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

	// Маршрутизация, setup и фоновые задачи AntiZapret.
	RoutingFiles(ctx context.Context) ([]nodeapi.RoutingFile, error)
	RoutingLines(ctx context.Context, name string, o nodeapi.RoutingListOpts) (nodeapi.RoutingPage, error)
	PatchRouting(ctx context.Context, name string, p nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error)
	RoutingRaw(ctx context.Context, name string) (nodeapi.RoutingRaw, error)
	ReplaceRouting(ctx context.Context, name, content, baseSHA string) (nodeapi.RoutingPutResult, error)
	RoutingBackups(ctx context.Context, name string) ([]nodeapi.RoutingBackup, error)
	RestoreRouting(ctx context.Context, name, stamp string) (nodeapi.RoutingFile, error)
	Setup(ctx context.Context) ([]nodeapi.SetupEntry, error)
	SetSetup(ctx context.Context, values map[string]string) (nodeapi.SetupResult, error)
	Tasks(ctx context.Context) ([]nodeapi.Task, error)
	Task(ctx context.Context, id string) (nodeapi.TaskDetail, error)
	ApplyRouting(ctx context.Context) (nodeapi.Task, error)
	RestartAntiZapret(ctx context.Context) (nodeapi.Task, error)
	RebuildProfiles(ctx context.Context) (nodeapi.Task, error)
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
	// Allow — белый список адресов (пустой пускает всех); nil заводится при
	// сборке маршрутов.
	Allow *AllowList
	// Pending — опасные настройки с таймером возврата; по умолчанию на Store.
	Pending *PendingStore
	// ConfigFile — config.toml, куда пишется белый список; пусто — по умолчанию
	// из paths. NoConfigFile — не писать файл (тесты без файла).
	ConfigFile   string
	NoConfigFile bool
	// PublicURL — внешний адрес панели (panel.public_url) для ссылок портала
	// и одноразовых ссылок; пусто — ссылки относительные.
	PublicURL string
	// BasePath — префикс пути (panel.base_path): пусто или «/x/». Панель
	// снимает его с запроса сама; запрос без префикса — 404.
	BasePath string
	// TrustedProxies — прокси, чьим X-Forwarded-For и X-Forwarded-Proto
	// верим (panel.trusted_proxies); пусто — не верим никому.
	TrustedProxies []netip.Prefix
	// SecretsFile — secrets.env, который правит страница «Настройки»; пусто —
	// по умолчанию из paths.
	SecretsFile string
	// Exit завершает процесс панели: так она перезапускается из настроек
	// (поднимает systemd, Restart=always). nil — перезапуск не настроен.
	Exit func()
	// ExitDelay — пауза между страницей «перезапуск…» и вызовом Exit;
	// ноль — секунда.
	ExitDelay time.Duration
	// RestartNode просит агента узла перезапуститься (POST /v1/system/restart);
	// nil — не умеем, оператор перезапускает вручную.
	RestartNode func(ctx context.Context) error
	// SyncNginx переписывает фрагмент nginx под новые panel.base_path и
	// panel.listen. done=false — фрагмента нет, nginx не тронут. nil — панель
	// nginx не правит.
	SyncNginx func(basePath, listen string) (done bool, err error)
	// Telegram — настройки бота (backup_chats для страницы «Telegram-бот»);
	// заполняется при запуске бота.
	Telegram config.Telegram
	// Svc — узел с методами сервисов (обновление AntiZapret, telemt, WARP,
	// самообновление); nil — берётся из Node, если он их умеет.
	Svc ServiceNode
	// Updates — проверка обновлений azpanel (раз в 6 часов); nil — страница
	// «Обновление» без сведений о версии, пометки в шапке нет.
	Updates *update.Checker
	// FetchUpdate подменяет скачивание релиза (тесты); nil — GitHub.
	FetchUpdate func(ctx context.Context) (update.Fetched, error)
	// BotName — имя бота для ссылки привязки Telegram; nil или пустая
	// строка — бот не запущен, привязка в панели скрыта.
	BotName func() string

	pages      map[string]*template.Template
	registered []string   // шаблоны маршрутов Handler(): сверяются с таблицей прав
	usersMu    sync.Mutex // действия над пользователями — по одному (защита последнего администратора)
	attemptMu  keyedMutex // счёт попыток ввода кода: замок на ключ, а не общий на всех
	access     accessState
	hub        hubState // узлы, группы, выбор узла страницами
	settings   settingsState
	once       onceStore // секреты «показать один раз»
	az         azMemory  // что видели у обновления AntiZapret
	upd        fetchedRelease

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
	s.pages = s.parsePages()
	s.initAccess()

	mux := http.NewServeMux()
	s.registered = nil
	s.route(mux, "GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	s.route(mux, "GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)).ServeHTTP)
	s.route(mux, "GET /login", s.loginForm)
	s.route(mux, "POST /login", s.loginSubmit)
	s.route(mux, "GET /login/2fa", s.mfaForm)
	s.route(mux, "POST /login/2fa", s.mfaSubmit)
	s.route(mux, "POST /logout", s.logoutRoute)

	// Аккаунт и пользователи.
	s.route(mux, "GET /account", s.accountPage)
	s.route(mux, "GET /account/password", s.accountPage)
	s.route(mux, "POST /account/password", s.accountPassword)
	s.route(mux, "GET /account/2fa", s.account2FAForm)
	s.route(mux, "POST /account/2fa", s.account2FAEnable)
	s.route(mux, "POST /account/2fa/disable", s.account2FADisable)
	s.route(mux, "POST /account/2fa/codes", s.accountNewCodes)
	s.route(mux, "POST /account/sessions/revoke", s.accountRevoke)
	s.route(mux, "POST /account/sessions/all", s.accountLogoutAll)
	s.route(mux, "GET /account/once", s.oncePage)

	s.route(mux, "POST /account/telegram", s.accountTelegram)
	s.route(mux, "POST /account/telegram/unlink", s.accountTelegramUnlink)

	s.route(mux, "GET /users", s.usersPage)
	s.route(mux, "POST /users/{id}/telegram/unlink", s.userTelegramUnlink)
	s.route(mux, "GET /users/telegram", s.telegramPage)
	s.route(mux, "POST /users/telegram/backup-groups", s.telegramBackupGroups)
	s.route(mux, "POST /users/telegram/unban", s.telegramUnban)
	s.route(mux, "POST /users", s.userCreate)
	s.route(mux, "GET /users/{id}", s.userPage)
	s.route(mux, "POST /users/{id}/role", s.userRole)
	s.route(mux, "POST /users/{id}/disabled", s.userDisabled)
	s.route(mux, "POST /users/{id}/password", s.userResetPassword)
	s.route(mux, "POST /users/{id}/2fa/reset", s.userReset2FA)
	s.route(mux, "POST /users/{id}/sessions/revoke", s.userRevoke)
	s.route(mux, "POST /users/{id}/delete", s.userDelete)
	s.route(mux, "POST /users/{id}/access", s.userAccess)
	s.route(mux, "POST /users/{id}/portal", s.userPortalLink)

	// Коды продления: только администратор; ввод кода — в карточке клиента.
	s.route(mux, "GET /codes", s.codesPage)
	s.route(mux, "GET /codes/new", s.codesNewForm)
	s.route(mux, "POST /codes", s.codesIssue)
	s.route(mux, "POST /codes/download", s.codesDownload)
	s.route(mux, "POST /codes/{id}/revoke", s.codeRevoke)
	s.route(mux, "POST /codes/batch/{batch}/revoke", s.codeBatchRevoke)

	// Настройки: только администратор.
	s.route(mux, "GET /settings/access", s.accessPage)
	s.route(mux, "POST /settings/access", s.accessSave)
	s.route(mux, "POST /settings/access/confirm", s.accessConfirm)

	s.route(mux, "GET /settings", s.settingsPage)
	s.route(mux, "POST /settings", s.settingsSave)
	s.route(mux, "POST /settings/apply", s.settingsApply)
	s.route(mux, "POST /settings/confirm", s.settingsConfirm)
	s.route(mux, "POST /settings/secrets", s.settingsSecrets)
	s.route(mux, "GET /settings/export", s.exportPage)
	s.route(mux, "POST /settings/export", s.exportDownload)
	s.route(mux, "POST /settings/import", s.settingsImport)

	// Всё остальное — за входом; права каждого маршрута — в таблице routes.
	s.route(mux, "GET /monitor", s.monitor)
	s.route(mux, "GET /audit", s.auditPage)
	s.route(mux, "GET /clients/new", s.newForm)
	s.route(mux, "POST /clients", s.createClient)
	s.route(mux, "GET /clients/{name}", s.clientCard)
	s.route(mux, "GET /clients/{name}/profiles/{kind}/{variant}/{file}", s.profileFile)
	s.route(mux, "GET /clients/{name}/qr/{kind}/{variant}/{file}", s.profileQR)
	s.route(mux, "POST /clients/{name}/renew", s.renew)
	s.route(mux, "POST /clients/{name}/limit", s.setLimit)
	s.route(mux, "POST /clients/{name}/card", s.saveCard)
	s.route(mux, "POST /clients/{name}/block", s.block)
	s.route(mux, "POST /clients/{name}/delete", s.deleteClient)
	s.route(mux, "POST /clients/{name}/owner", s.setOwner)
	s.route(mux, "POST /clients/{name}/redeem", s.redeemCode)
	s.route(mux, "POST /clients/{name}/kinds", s.setKinds)
	s.route(mux, "POST /clients/{name}/portal", s.clientPortalLink)
	s.route(mux, "POST /clients/{name}/dl", s.clientDownloadLink)

	// Публичный портал клиента и одноразовые ссылки: без входа, доступ по
	// токену в адресе; белый список адресов панели на них не действует.
	s.route(mux, "GET /p/{token}", s.portalIndex)
	s.route(mux, "GET /p/{token}/help", s.portalHelp)
	s.route(mux, "GET /p/{token}/profile/{name}/{kind}/{variant}/{file}", s.portalProfile)
	s.route(mux, "GET /p/{token}/qr/{name}/{kind}/{variant}/{file}", s.portalQR)
	s.route(mux, "POST /p/{token}/unlock", s.portalUnlock)
	s.route(mux, "/p/", s.portalGone)
	s.route(mux, "GET /dl/{token}", s.dlPage)
	s.route(mux, "POST /dl/{token}", s.dlDownload)
	s.route(mux, "/dl/", s.dlGone)

	// Маршрутизация, настройки AntiZapret, задачи: только администратор.
	s.route(mux, "GET /routing", s.routingPage)
	s.route(mux, "GET /routing/files/{name}", s.routingFile)
	s.route(mux, "POST /routing/files/{name}/add", s.routingAdd)
	s.route(mux, "POST /routing/files/{name}/remove", s.routingRemove)
	s.route(mux, "POST /routing/files/{name}/replace", s.routingReplace)
	s.route(mux, "POST /routing/files/{name}/restore", s.routingRestore)
	s.route(mux, "GET /settings/antizapret", s.setupPage)
	s.route(mux, "POST /settings/antizapret", s.setupSave)
	s.route(mux, "GET /tasks", s.tasksPage)
	s.route(mux, "GET /tasks/{id}", s.taskPage)
	s.route(mux, "POST /tasks/start", s.taskStart)

	// Узлы: только администратор.
	s.route(mux, "GET /nodes", s.nodesPage)
	s.route(mux, "GET /nodes/new", s.nodeNewForm)
	s.route(mux, "POST /nodes", s.nodeCreate)
	s.route(mux, "GET /nodes/{id}", s.nodePage)
	s.route(mux, "POST /nodes/{id}/probe", s.nodeProbe)
	s.route(mux, "POST /nodes/{id}/connect", s.nodeConnect)
	s.route(mux, "POST /nodes/{id}/check", s.nodeCheck)
	s.route(mux, "POST /nodes/{id}/delete", s.nodeDelete)

	// Обновление AntiZapret: только администратор.
	s.route(mux, "GET /antizapret/update", s.azUpdatePage)
	s.route(mux, "POST /antizapret/update", s.azStart)
	s.route(mux, "POST /antizapret/update/restore", s.azRestore)

	// telemt (MTProxy): состояние, пользователи, ссылки, установка, обновление.
	s.route(mux, "GET /telemt", s.telemtPage)
	s.route(mux, "POST /telemt/users", s.telemtAddUser)
	s.route(mux, "POST /telemt/users/{name}/delete", s.telemtRemoveUser)
	s.route(mux, "POST /telemt/users/{name}/link", s.telemtShowLink)
	s.route(mux, "POST /telemt/restart", s.telemtRestart)
	s.route(mux, "POST /telemt/update", s.telemtUpdate)
	s.route(mux, "POST /telemt/install", s.telemtInstall)

	// WARP: встроенный и AZ-WARP.
	s.route(mux, "GET /warp", s.warpPage)
	s.route(mux, "POST /warp/domains", s.warpEdit("domains"))
	s.route(mux, "POST /warp/ips", s.warpEdit("ips"))
	s.route(mux, "POST /warp/sync", s.warpSync)
	s.route(mux, "POST /warp/update", s.warpUpdate)
	s.route(mux, "POST /warp/install", s.warpInstall)

	// Обновление azpanel: версия, изменения, запуск.
	s.route(mux, "GET /update", s.updatePage)
	s.route(mux, "POST /update", s.updateStart)
	s.route(mux, "POST /update/check", s.updateCheck)

	s.route(mux, "GET /{$}", s.clientsList)
	s.route(mux, "/", func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, http.StatusNotFound, "страница не найдена")
	})
	return s.stripBase(s.headers(s.allowGate(mux)))
}

// parsePages: каждая страница — свой набор layout.html + страница.
func (s *Server) parsePages() map[string]*template.Template {
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
		t := template.Must(template.New(name).Funcs(template.FuncMap{"url": s.url, "urlAt": urlAt}).ParseFS(templatesFS, "templates/layout.html", path.Join("templates", name)))
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
		// Портал: форма отправляет свой Origin только при same-origin, иначе
		// браузеры без Sec-Fetch-Site (Safari до 16.4, адрес без TLS) шлют
		// Origin: null. Наружу адрес с токеном всё равно не уходит.
		if isPortalPath(r.URL.Path) {
			h.Set("Referrer-Policy", "same-origin")
		} else {
			h.Set("Referrer-Policy", "no-referrer")
		}
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
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
		d["CSRF"], d["Role"], d["IsAdmin"] = sess.CSRF, sess.Role, sess.IsAdmin()
		if sess.IsAdmin() {
			d["UpdateAvail"] = s.updateAvailable()
		}
		if !sess.MFAPending { // до ввода кода меню и «Выйти» не показываются
			d["User"] = sess.User
		}
	}
	d["Version"] = s.Version
	s.switchData(r, d)
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
