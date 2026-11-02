# Этап 2а-2: минимальная панель — план

> **Исполнителям:** задачи идут по порядку, по одной. Проверка — одна
> итоговая на всю ветку (решение владельца 02.11.2026), поэтому каждая
> задача сама доводит свои тесты до зелёных и `go vet` до чистого.

**Цель:** веб-панель на том же хосте, что агент: вход администратора,
список клиентов с онлайном, создание, продление, удаление, профили и QR,
лимит и блокировка, страница «Сейчас» (ресурсы, службы, сессии).

**Архитектура:** режим `azpanel panel` — HTTP-сервер на `panel.listen`
(`127.0.0.1:8080`), ходит в агент через `nodeapi.HTTPClient` по
`panel.node_url` с `NODE_TOKEN` из `secrets.env`. Своего хранилища нет:
всё состояние берётся у агента при каждом запросе. Интерфейс — шаблоны
`html/template` и CSS, вшитые `embed`; JavaScript не нужен.

**Стек:** Go 1.24, стандартная библиотека; `golang.org/x/crypto/bcrypt`,
`golang.org/x/term`; `github.com/skip2/go-qrcode`.

**Спецификация:** `docs/specs/2026-11-01-azpanel-design.md`, разделы
«Панель», «Клиенты», «Мониторинг».

## Что сознательно отложено (не делать в этом плане)

- SQLite, история трафика и ресурсов, журнал действий в базе — журнал
  действий пока пишется строками в `panel.log`.
- Настройки через веб, несколько пользователей, роли, 2FA.
- nginx, HTTPS, мастер установки (2б), самообновление (2в).
- Доступ к панели — SSH-туннелем:
  `ssh -L 8080:127.0.0.1:8080 root@<сервер>`, затем `http://127.0.0.1:8080`.

## Общие ограничения

- Код — латиница; комментарии, тексты интерфейса, ошибок и журналов — по-русски.
- Панель слушает только петлевой адрес (`config.Validate` это уже требует).
- Пароль администратора — bcrypt cost 12 в `secrets.env`, ключ
  `PANEL_ADMIN_HASH`; имя администратора — `PANEL_ADMIN_USER`, по
  умолчанию `admin`. Ни пароль, ни хеш, ни `NODE_TOKEN`, ни cookie сессии
  не попадают в журналы, ошибки и HTML.
- Cookie сессии: имя `azpanel_session`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`, `Secure` — если запрос пришёл по TLS или с
  `X-Forwarded-Proto: https`. Срок — `panel.session_hours`.
- Каждый POST, кроме `/login`, проверяет CSRF-токен сессии (скрытое поле
  `csrf`) за постоянное время. GET ничего не меняет.
- Неверный вход — задержка 1 с перед ответом; не больше 5 неверных
  попыток с одного адреса за 15 минут, дальше — 429 до конца окна.
- Заголовки на каждом ответе: `Content-Security-Policy: default-src 'self';
  img-src 'self' data:; frame-ancestors 'none'; form-action 'self'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`.
- Ошибка агента показывается пользователю текстом `nodeapi.Error.Message`
  (агент уже отдаёт понятные причины: 409 о совпадении профилей и т. п.);
  ошибка сети — «агент недоступен: …».
- Блокировка клиента только с WireGuard показывается с пометкой
  «блокировка действует только на OpenVPN».
- Тесты — только против поддельного агента; на 94 — только клиенты
  `azpanel-test-*`, живых клиентов, StatusOpenVPN, telemt, 3proxy, AZ-WARP,
  nginx не трогать.
- Коммиты — от syava842@gmail.com, **без строк `Co-Authored-By` и подписей
  Claude**. Сообщения — по-русски.

## Файлы

| Файл | Ответственность |
| --- | --- |
| `internal/panel/auth.go` | сессии в памяти, CSRF, ограничитель попыток входа, проверка пароля |
| `internal/panel/server.go` | `Server`, маршруты, промежуточные обработчики, рендер шаблонов |
| `internal/panel/clients.go` | обработчики страниц клиентов |
| `internal/panel/monitor.go` | страница «Сейчас» |
| `internal/panel/run.go` | `Run(ctx, cfg, version)` — сборка из конфига и секретов, журнал, остановка |
| `internal/panel/templates/*.html`, `internal/panel/static/style.css` | интерфейс, `embed` |
| `cmd/azpanel/panelcmd.go` | `azpanel panel` и `azpanel panel passwd` |
| `internal/install/install.go` | юнит `azpanel-panel.service`, флаг `--panel` |

---

### Задача 1: аутентификация

**Файлы:** создать `internal/panel/auth.go`, `internal/panel/auth_test.go`;
`go.mod`/`go.sum` (`go get golang.org/x/crypto/bcrypt`).

**Интерфейсы (точно эти имена):**

```go
const (
	SecretAdminUser = "PANEL_ADMIN_USER"
	SecretAdminHash = "PANEL_ADMIN_HASH"
	cookieName      = "azpanel_session"
	bcryptCost      = 12
)

// HashPassword — bcrypt с bcryptCost; пароль короче 10 символов — ошибка
// «пароль короче 10 символов», длиннее 72 байт — ошибка.
func HashPassword(pw string) (string, error)

type Session struct {
	ID      string // 32 случайных байта, hex
	CSRF    string // 32 случайных байта, hex
	User    string
	Expires time.Time
}

// Sessions — сессии в памяти: перезапуск панели выводит всех.
type Sessions struct {
	TTL time.Duration
	Now func() time.Time
	// mu, m map[string]Session — приватные
}
func NewSessions(ttl time.Duration) *Sessions
func (s *Sessions) Create(user string) (Session, error)
func (s *Sessions) Get(id string) (Session, bool) // истёкшую удаляет и не отдаёт
func (s *Sessions) Delete(id string)

// Limiter — неверные попытки входа по адресу.
type Limiter struct {
	Max    int           // 5
	Window time.Duration // 15 мин
	Now    func() time.Time
}
func NewLimiter() *Limiter
func (l *Limiter) Blocked(addr string) bool
func (l *Limiter) Fail(addr string)
func (l *Limiter) Reset(addr string)

// CheckPassword: имя сверяется за постоянное время
// (subtle.ConstantTimeCompare), пароль — bcrypt; bcrypt выполняется
// всегда, даже при неверном имени или пустом hash (сравнение с
// фиксированным фиктивным хешем), чтобы время ответа не выдавало,
// существует ли имя. Пустой hash — всегда false.
func CheckPassword(wantUser, hash, user, pw string) bool

// SameCSRF — сравнение за постоянное время, пустые — false.
func SameCSRF(want, got string) bool
```

Адрес для `Limiter` — хост из `r.RemoteAddr` (без порта). Панель за nginx
появится в 2б; `X-Forwarded-For` сейчас **не** доверять. Старые записи
`Limiter` и истёкшие сессии вычищаются при обращении (без фоновых горутин).

**Тесты (`auth_test.go`):**
- `HashPassword("короткий")` — ошибка; 10+ символов — хеш, `CheckPassword`
  с ним и верным именем — true; неверный пароль, неверное имя, пустой hash
  — false.
- `Sessions`: `Create` даёт разные `ID` и `CSRF` длиной 64; `Get` до срока
  — есть; с подменённым `Now` после `TTL` — нет и запись удалена;
  `Delete` убирает.
- `Limiter`: 5 `Fail` — `Blocked` true; после `Window` (подменённое
  `Now`) — false; `Reset` — false; другой адрес не задет.
- `SameCSRF("", "")` — false; равные — true; разные — false.

Коммит: «Панель: пароль администратора, сессии, CSRF, ограничение попыток входа».

### Задача 2: сервер, вход и шаблоны

**Файлы:** создать `internal/panel/server.go`, `server_test.go`,
`templates/layout.html`, `templates/login.html`, `templates/error.html`,
`static/style.css`.

**Интерфейсы:**

```go
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

type Server struct {
	Node      Node
	AdminUser string
	AdminHash string // пусто — вход невозможен, страница входа говорит «пароль не задан: azpanel panel passwd»
	Version   string
	Sessions  *Sessions
	Limiter   *Limiter
	Log       *slog.Logger
	Sleep     func(time.Duration) // задержка неверного входа; в тестах — no-op
}

func (s *Server) Handler() http.Handler
```

**Маршруты (`http.ServeMux` с шаблонами Go 1.22):**

| Маршрут | Доступ | Что |
| --- | --- | --- |
| `GET /healthz` | без входа | `200 ok` текстом |
| `GET /static/` | без входа | `embed` из `static/` |
| `GET /login` | без входа | форма |
| `POST /login` | без входа, без CSRF | вход; успех — `Limiter.Reset`, новая сессия, `303 /`; неверно — `Sleep(1s)`, `Limiter.Fail`, форма с «неверное имя или пароль» и код 401; `Limiter.Blocked` — 429 «слишком много попыток, подождите 15 минут» без проверки пароля |
| `POST /logout` | сессия + CSRF | удалить сессию, стереть cookie, `303 /login` |
| всё остальное (задачи 3–4) | сессия; POST — ещё и CSRF | без сессии GET — `303 /login`, POST — 403 |

- Промежуточный обработчик заголовков из «Общих ограничений» — на всех ответах.
- Тело POST ограничено 64 КБ (`http.MaxBytesReader`).
- Шаблоны разбираются один раз в `Handler()` (`template.ParseFS`); каждая
  страница — свой набор `layout.html` + страница, `{{define "content"}}`.
  В layout: шапка с `Version`, ссылки «Клиенты» (`/`) и «Сейчас»
  (`/monitor`), кнопка «Выйти» (форма POST `/logout` с `csrf`), блок
  `.flash` для сообщения из параметра `?msg=` (экранируется шаблоном) и
  блок `.error` для текста ошибки.
- Хелпер `s.render(w, r, status, page string, data map[string]any)`
  добавляет в data `CSRF`, `User`, `Version`, `Msg`.
- Хелпер `s.nodeErr(err) (status int, text string)`: `*nodeapi.Error` с 4xx
  → 400 и `Message`; `*nodeapi.Error` с 5xx → 502 и `Message`; иначе 502 и
  «агент недоступен: <err>».
- Вход и выход пишутся в журнал: `Log.Info("вход", "user", u, "remote", host)`,
  неверный — `Warn("неверный вход", "user", u, "remote", host)`. Пароль не пишется.
- CSS — простой, читаемый, без внешних шрифтов: таблицы, формы, кнопка
  опасного действия красная, ширина до 1100px, работает на телефоне.

**Тесты (`server_test.go`, поддельный `Node` — структура с полями-функциями,
переиспользуется в задачах 3–4):**
- `/healthz` — 200 без cookie.
- `GET /` без cookie — 303 на `/login` (в этой задаче `/` может отдавать
  временную заглушку за входом; задача 3 её заменит).
- верный вход — 303, cookie `azpanel_session` с `HttpOnly` и
  `SameSite=Strict`, без `Secure`; с `X-Forwarded-Proto: https` — с `Secure`.
- неверный вход — 401, `Sleep` вызван с 1 с; шестая неверная попытка — 429.
- пустой `AdminHash` — вход невозможен даже с любым паролем, на форме
  текст про `azpanel panel passwd`.
- `POST /logout` без `csrf` — 403; с верным — 303, сессия больше не работает.
- заголовок `Content-Security-Policy` есть на `/login`.

Коммит: «Панель: сервер, вход и выход, шаблоны».

### Задача 3: клиенты

**Файлы:** создать `internal/panel/clients.go`, `clients_test.go`,
`templates/clients.html`, `templates/client.html`, `templates/new.html`;
`go get github.com/skip2/go-qrcode`.

**Маршруты:**

| Маршрут | Что |
| --- | --- |
| `GET /` | таблица: имя (ссылка на карточку), OpenVPN/WireGuard, срок сертификата (дата и «осталось N дн.», меньше 30 — выделено), онлайн (число сессий из `Sessions` по имени), лимит («—» если 0), «заблокирован»; фильтр `?q=` по подстроке имени без учёта регистра; кнопка «Новый клиент» |
| `GET /clients/new` | форма: имя, тип (`openvpn`/`wireguard`), дни (только OpenVPN, пусто — 3650) |
| `POST /clients` | `CreateClient`; успех — `303 /clients/{name}?msg=создан`; ошибка — форма с введёнными значениями и текстом ошибки, код из `nodeErr` |
| `GET /clients/{name}` | карточка: данные клиента, текущие сессии клиента (экземпляр, адрес, трафик ↓↑, с какого времени), список профилей со ссылками на скачивание и (для WireGuard) QR, формы ниже. Нет такого клиента — 404 |
| `GET /clients/{name}/profiles/{kind}/{variant}/{file}` | `Profile`; ответ `Content-Disposition` через `mime.FormatMediaType("attachment", map[string]string{"filename": file})`, `Content-Type: application/octet-stream` |
| `GET /clients/{name}/qr/{kind}/{variant}/{file}` | только `kind == wireguard`, иначе 404; PNG 512px из содержимого профиля (`qrcode.Encode(data, qrcode.Medium, 512)`); профиль больше 2900 байт — 422 «профиль слишком велик для QR» |
| `POST /clients/{name}/renew` | поле `days` 1..3650; `Renew` |
| `POST /clients/{name}/limit` | поле `limit` 0..1000 (0 — снять); `SetLimit` |
| `POST /clients/{name}/block` | поле `blocked` = `1`/`0`; `SetBlocked`; при блокировке сообщение «заблокирован, разорвано сессий: N» |
| `POST /clients/{name}/delete` | поле `kind` (`openvpn`/`wireguard`) и `confirm`, равное имени клиента (форма просит вписать имя); без совпадения — 400; `DeleteClient`; успех — `303 /?msg=удалён` |

- Все действия — POST с CSRF; после успеха — `303` на карточку с
  `?msg=…` (через `url.QueryEscape`); ошибка — карточка с текстом ошибки
  и кодом из `nodeErr`.
- Числовые поля — `strconv.Atoi`; вне диапазона — 400 с причиной, агент не
  вызывается.
- Журнал действий: `Log.Info("действие", "user", u, "op", "create|renew|limit|block|unblock|delete", "client", name, "detail", …)` после успеха; ошибка — `Warn` с `err`.
- Кнопки «Продлить», «Удалить OpenVPN», «Удалить WireGuard» — только для
  тех типов, что есть у клиента; у клиента только с WireGuard рядом с
  блокировкой — «блокировка действует только на OpenVPN».
- Путь `{name}` в карточке и действиях (кроме создания) сверяется с
  именами из `Clients`: неизвестное имя → 404, действие агента не вызывается.

**Тесты (`clients_test.go`, поддельный Node и вход через `Sessions.Create`):**
- список: онлайн 2 для клиента с двумя сессиями, «—» для лимита 0, фильтр
  `?q=TeSt` находит `azpanel-test-1`.
- создание: Node получил `{Name, Kind, Days}`; ошибка агента 409 — код 400
  и текст агента на странице.
- продление `days=0` и `days=abc` — 400, Node не вызван; `days=30` — вызван.
- лимит `1001` — 400; `0` — `SetLimit(name, 0)`.
- блокировка: `SetBlocked(name, true)`, сообщение с числом разорванных.
- удаление без верного `confirm` — 400, Node не вызван; с верным — вызван с `kind`.
- POST действия без `csrf` — 403, Node не вызван.
- QR для wireguard — `image/png`; для openvpn — 404; профиль 3000 байт — 422.
- профиль: `Content-Disposition` содержит имя файла.
- неизвестный клиент в любом действии — 404, действие не вызвано.
- имя клиента `<script>` в списке выводится экранированным.

Коммит: «Панель: клиенты — список, создание, продление, удаление, профили, QR, лимит, блокировка».

### Задача 4: страница «Сейчас»

**Файлы:** `internal/panel/monitor.go`, `monitor_test.go`, `templates/monitor.html`.

`GET /monitor`: `System` и `Sessions` параллельно (две горутины, общий
тайм-аут 10 с). Показывает:
- ресурсы: CPU %, нагрузка, память (занято/всего), диск `/` (свободно/всего),
  сеть (интерфейс, принято/отправлено всего), uptime — в человеческих
  единицах: `humanBytes` (Б, КБ, МБ, ГБ, ТБ, один знак после точки, кроме
  байтов) и `humanDuration` («3 д 4 ч», «5 ч 12 мин», «40 с»);
- службы: юнит и состояние; не `active` — класс `bad`;
- сессии: тип, экземпляр, имя (ссылка на карточку), адрес, ↓↑, с какого
  времени (OpenVPN) или последнее рукопожатие (WireGuard);
- `<meta http-equiv="refresh" content="15">` только на этой странице;
- сбой одной из двух частей — вторая показывается, на месте первой — текст ошибки.

Поля `sysinfo.Snapshot` смотреть в `internal/sysinfo/sampler.go` и `proc.go`.

**Тесты:** `humanBytes(0)` = «0 Б», `(1536)` = «1.5 КБ», `(5<<30)` =
«5.0 ГБ»; `humanDuration(40s)`, `(5h12m)`, `(76h)`; страница при сбое
`System` и рабочем `Sessions` — 200, есть имя сессии и текст ошибки;
служба `failed` с классом `bad`.

Коммит: «Панель: страница «Сейчас» — ресурсы, службы, сессии».

### Задача 5: запуск, команда и установка

**Файлы:** `internal/panel/run.go`, `run_test.go`, `cmd/azpanel/panelcmd.go`,
`cmd/azpanel/main.go`, `internal/install/install.go`, `install_test.go`,
файл, где разбираются флаги `install` в `cmd/azpanel/` (найти `runInstall`).

- `panel.Run(ctx, cfg config.Config, version string) error`:
  журнал `paths.Log()/panel.log` через `logx.Open`/`logx.New` (размеры из
  `cfg.Log`); секреты `secrets.Load(paths.SecretsFile())`; без
  `NODE_TOKEN` — ошибка «нет NODE_TOKEN в secrets.env: переустановите
  узел»; `AdminUser` — `PANEL_ADMIN_USER` или `admin`; пустой
  `PANEL_ADMIN_HASH` — предупреждение в журнал, панель всё равно
  стартует; `http.Server` на `cfg.Panel.Listen` с `ReadHeaderTimeout 10 с`,
  `ReadTimeout 30 с`, `WriteTimeout` = `2 × node.client_sh_timeout_seconds
  + 60 с`, `IdleTimeout 120 с`; остановка по `ctx` — `Shutdown` с 10 с,
  ошибку `Shutdown` вернуть. `Sessions` с TTL `cfg.Panel.SessionHours`.
  Слушатель создаётся до запуска сервера (`net.Listen`), ошибка занятого
  порта возвращается сразу.
- `azpanel panel` — запуск (как `runNode`: `config.Load`, `signal.NotifyContext`).
- `azpanel panel passwd [--user ИМЯ]` — пароль из терминала без эха
  (`golang.org/x/term`, `term.ReadPassword`) дважды, несовпадение —
  ошибка; если stdin не терминал — одна строка из stdin (для скриптов).
  `HashPassword` → `secrets.Set(PANEL_ADMIN_HASH)`; `PANEL_ADMIN_USER` —
  если задан `--user`. Печатает «пароль задан; перезапустите панель:
  systemctl restart azpanel-panel». Пароль и хеш не печатаются.
- `usage()` — строки `azpanel panel` и `azpanel panel passwd [--user ИМЯ]`,
  у `install` — `[--panel]`.
- Установка: `PanelUnit(bin string) string` — как `NodeUnit`, но
  `Description=azpanel: веб-панель`, `ExecStart=<bin> panel`,
  `After=network-online.target azpanel-node.service`,
  `ReadWritePaths=/opt/azpanel`, `ProtectSystem=strict`, `ProtectHome=true`,
  `PrivateTmp=true`, `NoNewPrivileges=true`, без `RuntimeDirectory`.
  `Options.Panel bool` (флаг `--panel`): ставит ещё и
  `azpanel-panel.service` (`enable`, `restart azpanel-panel` после
  агента), в тексте подтверждения — строка про панель на `127.0.0.1` из
  конфига; в конце печатает, как задать пароль (`azpanel panel passwd`) и
  как открыть туннелем. `Uninstall` останавливает и удаляет и юнит
  панели, если он есть (до хука, как агент).
- Тесты: `PanelUnit` содержит `ExecStart=/x panel` и `ProtectSystem=strict`;
  `InstallNode` с `Panel: true` пишет оба юнита и вызывает
  `restart azpanel-panel`; без `Panel` — юнита панели нет; `Uninstall`
  удаляет юнит панели; `Run` с `AZPANEL_ROOT` во временном каталоге без
  `NODE_TOKEN` — ошибка с этим текстом; `Run` с токеном и свободным
  портом (взять через `net.Listen("tcp","127.0.0.1:0")` и закрыть) —
  `/healthz` отвечает 200, отмена `ctx` — `Run` возвращает nil.

Коммит: «Панель: запуск azpanel panel, смена пароля, служба при установке».

### Задача 6: приёмка на 94

Выполняет контроллер, не исполнитель. Результат — в
`docs/notes/2026-11-02-priemka-etap-2a2.md`.

1. `GOOS=linux GOARCH=amd64 go build -o azpanel ./cmd/azpanel`, скопировать
   на 94, `./azpanel install --yes --panel`, `azpanel panel passwd`
   (пароль случайный, через stdin, не печатается), `systemctl restart azpanel-panel`.
2. `systemctl is-active azpanel-node azpanel-panel` — оба `active`;
   `ss -ltn` — `127.0.0.1:8080`.
3. Через туннель `ssh -L 18080:127.0.0.1:8080`: вход с неверным паролем
   — 401; верным — cookie; `/` — 200, в списке есть живые клиенты (только смотреть).
4. Создать `azpanel-test-p1` (OpenVPN, 30 дней) формой с CSRF — есть в
   `client.sh 3`; скачать профиль; лимит 1; блок — `limits.json` содержит
   его в `blocked`; разблок; продлить на 60; удалить с `confirm`.
5. Создать `azpanel-test-w1` (WireGuard), QR — `image/png`; удалить.
6. `/monitor` — 200, четыре OpenVPN-службы `active`.
7. Шесть неверных входов — шестой 429.
8. В `panel.log` нет пароля, хеша, `NODE_TOKEN`; на 94 не осталось
   клиентов `azpanel-test-*`.

---

## Итоговая проверка

После задачи 5 — одна проверка коммитов этого плана (от коммита с этим
планом до `HEAD`) самой сильной моделью: безопасность входа и CSRF,
утечки секретов, экранирование, соответствие плану; один круг
исправлений и короткая повторная проверка. Затем — задача 6.
