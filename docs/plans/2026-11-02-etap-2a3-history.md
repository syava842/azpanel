# Этап 2а-3: база, история, карточки клиентов, журнал — план

> **Исполнителям:** задачи по порядку, по одной; проверка — одна итоговая
> на всю ветку. Каждая задача сама доводит тесты и `go vet` до чистого.

**Цель:** то, что есть в StatusOpenVPN и чего нет в панели 2а-2: история
трафика по клиентам и ресурсов сервера за 1/7/30 дней с графиками,
карточка клиента (заметка, «доступ до», лимит трафика за период),
автоблокировка по сроку и по трафику, журнал действий с IP, отказы по
лимиту подключений, город и провайдер по адресу, предупреждение о
WireGuard-пире, меняющем адрес.

**Архитектура:** `internal/store` — SQLite (`modernc.org/sqlite`, без cgo)
с миграциями; `internal/panel/collector.go` — фоновый сборщик раз в
`panel.collect_seconds`: снимает сессии и ресурсы у агента, пишет
поминутные точки, сворачивает в часовые, удаляет старое, применяет
автоблокировки. Графики — SVG, который рисует сервер (без JS).
Узел пока один, но таблицы с первого дня несут `node_id` — этап 4 добавит
узлы без миграции данных.

**Стек:** Go 1.24; `modernc.org/sqlite`; `github.com/oschwald/maxminddb-golang`.

**Спецификация:** `docs/specs/2026-11-01-azpanel-design.md` — «Панель»
(SQLite), «Клиенты» (срок действия), «Мониторинг», «Пользователи и
доступ» (журнал действий).

## Общие ограничения

- Код — латиница; комментарии, интерфейс, ошибки, журнал — по-русски.
- `go.mod`: директива `go 1.24` не меняется; после `go get` вернуть её и
  закрепить совместимую версию зависимости.
- База — `paths.Data()/azpanel.db`, права `600`, `PRAGMA journal_mode=WAL`,
  `busy_timeout=5000`, `foreign_keys=ON`. Один `*sql.DB` на процесс.
- Время в базе — Unix-секунды UTC (INTEGER). Байты — INTEGER.
- Шаг хранения (спецификация): поминутные точки — за последние сутки,
  часовые — за `panel.history_days` (по умолчанию 30). Старше — удаляется.
- Автоблокировка панели помечает причину; панель снимает только ту
  блокировку, которую ставила сама, и только когда причина ушла. Ручную
  блокировку сборщик не трогает никогда.
- Все действия — в журнал: время, пользователь, IP, действие, объект,
  «было → стало». Секретов в журнале нет.
- Тесты — против поддельного агента и временной базы в `t.TempDir()`.
- На 94 можно всё, но живых клиентов не удалять и не блокировать;
  тестовые — `azpanel-test-*`.
- Коммиты — от syava842@gmail.com, **без `Co-Authored-By` и подписей
  Claude**, по-русски.

---

### Задача 1: хранилище

**Файлы:** `internal/store/store.go`, `migrate.go`, `traffic.go`,
`resources.go`, `cards.go`, `audit.go`, тесты к каждому.

```go
type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) // создаёт файл 600, применяет миграции
func (s *Store) Close() error
func (s *Store) SchemaVersion(ctx context.Context) (int, error)
```

Миграции — срез строк SQL, версия в таблице `meta` (`schema_version`);
каждая — в транзакции; база новее бинарника — ошибка «база версии N
новее, чем знает эта версия azpanel». Последующие планы добавляют
миграции в конец среза. Схема 1:

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL);
-- узел 1 = 'local' с url '' вставляется миграцией
CREATE TABLE client_cards (
  node_id INTEGER NOT NULL REFERENCES nodes(id),
  name TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  access_until INTEGER,                         -- NULL — без срока
  traffic_limit INTEGER NOT NULL DEFAULT 0,     -- байт за период, 0 — без лимита
  traffic_period TEXT NOT NULL DEFAULT 'month', -- day | week | month
  auto_block TEXT NOT NULL DEFAULT '',          -- '' | expired | traffic — блок, поставленный панелью
  PRIMARY KEY (node_id, name));
CREATE TABLE traffic_minute (node_id INTEGER, name TEXT, ts INTEGER, rx INTEGER, tx INTEGER, PRIMARY KEY (node_id, name, ts));
CREATE TABLE traffic_hour   (node_id INTEGER, name TEXT, ts INTEGER, rx INTEGER, tx INTEGER, PRIMARY KEY (node_id, name, ts));
CREATE TABLE resource_minute (node_id INTEGER, ts INTEGER, cpu REAL, load1 REAL,
  mem_used INTEGER, mem_total INTEGER, disk_free INTEGER, disk_total INTEGER,
  net_rx INTEGER, net_tx INTEGER, online INTEGER, PRIMARY KEY (node_id, ts));
CREATE TABLE resource_hour (те же столбцы, PRIMARY KEY (node_id, ts));
CREATE TABLE audit (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user TEXT NOT NULL, ip TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL, before TEXT NOT NULL DEFAULT '', after TEXT NOT NULL DEFAULT '');
CREATE INDEX audit_ts ON audit(ts);
```

Методы (все с `ctx context.Context` первым аргументом):

- `AddTraffic(ctx, node int64, ts int64, rows map[string]Bytes) error` —
  `Bytes{Rx, Tx int64}`; прибавляет к строке минуты (UPSERT).
- `TrafficSeries(ctx, node int64, name string, from, to int64, step Step) ([]Point, error)` —
  `Step` = `Minute` | `Hour`; `Point{TS, Rx, Tx int64}`. Для `Hour`
  последние, ещё не свёрнутые часы досчитываются из минут.
- `TrafficTotals(ctx, node int64, from, to int64) (map[string]Bytes, error)` —
  суммы по клиентам: часовые точки плюс минутные из ещё не свёрнутых
  часов, без двойного счёта.
- `AddResource(ctx, node int64, r ResourcePoint) error`,
  `ResourceSeries(ctx, node int64, from, to int64, step Step) ([]ResourcePoint, error)`.
- `Rollup(ctx, now int64, historyDays int) error` — сворачивает минуты
  законченных часов в часовые (трафик — сумма; ресурсы — среднее, счётчики
  сети и `online` — максимум), удаляет минутные старше суток и часовые
  старше `historyDays`. Повторный вызов результат не меняет (час
  перезаписывается целиком, а не прибавляется).
- `Card(ctx, node int64, name string) (Card, error)` — нет строки —
  карточка по умолчанию, не ошибка; `SaveCard(ctx, Card) error`;
  `Cards(ctx, node int64) (map[string]Card, error)`;
  `DeleteCard(ctx, node int64, name string) error`.
- `Audit(ctx, AuditEntry) error`;
  `AuditList(ctx, limit, offset int, q string) ([]AuditEntry, int, error)` —
  `q` — подстрока по user/action/target без учёта регистра; второе
  значение — всего подходящих строк; новые сверху.

Тесты: миграция пустой базы и повторное открытие; база версии 99 —
ошибка; права файла `600` (на Windows — пропуск); `AddTraffic` дважды в
одну минуту — сумма; `Rollup` — часовые суммы верны, повторный вызов ничего
не меняет, минуты старше суток и часы старше 30 дней удалены;
`TrafficTotals` за частично свёрнутый период — без двойного счёта;
карточка по умолчанию; журнал с поиском и счётчиком.

Коммит: «Хранилище SQLite: схема, миграции, трафик, ресурсы, карточки, журнал».

### Задача 2: отказы по лимиту у агента

**Файлы:** `internal/node/` (трекер или новый `denials.go`, `api.go`),
`internal/nodeapi/nodeapi.go`, тесты; `internal/panel` — метод в
интерфейсе `Node` и в поддельном узле тестов.

- Агент держит последние 1000 отказов хука в кольцевом буфере в памяти:
  `nodeapi.Denial{Time time.Time, Name, Instance, Addr, Reason string /* limit | blocked */, Count, Limit int}`.
  Запись — там же, где агент сейчас пишет отказ в `hook.log`.
- `GET /v1/denials?since=<unix>` → `[]nodeapi.Denial` новее `since`, по
  возрастанию времени. `HTTPClient.Denials(ctx, since time.Time) ([]Denial, error)`.
- Тесты: отказ по лимиту и по блокировке попадают в буфер; 1001-й
  вытесняет первый; `since` фильтрует; маршрут требует токен.

Коммит: «Агент: журнал отказов хука в API».

### Задача 3: сборщик

**Файлы:** `internal/panel/collector.go`, `collector_test.go`.

```go
type Collector struct {
	Node        Node
	Store       *store.Store
	NodeID      int64
	Every       time.Duration // panel.collect_seconds
	HistoryDays int
	Log         *slog.Logger
	Now         func() time.Time
	// приватное: прежние счётчики сессий, история адресов WG-пиров, час последнего Rollup
}
func (c *Collector) Run(ctx context.Context)        // проход сразу, затем раз в Every
func (c *Collector) Tick(ctx context.Context) error // один проход — для тестов
func (c *Collector) Flapping() map[string]bool      // имена WG-клиентов с частой сменой адреса
```

Один проход:

1. `Sessions`: ключ сессии — `kind|instance|name|since` для OpenVPN и
   `kind|instance|name` для WG. Дельта = текущие счётчики минус прежние;
   текущие меньше прежних (сброс) — дельта = текущие. Сессия, впервые
   увиденная: OpenVPN — полные счётчики, если `since` позже прошлого
   прохода, иначе 0 (панель только запустилась); WG — 0 (счётчики пира
   копятся с поднятия интерфейса). Суммы по имени → `AddTraffic` в
   минуту `now`, усечённую до минуты. Пропавшие сессии забываются.
2. `System` → `AddResource` (CPU, нагрузка, память, диск, накопительные
   счётчики сети как есть — скорость считает график; `online` — число
   сессий из шага 1).
3. WG: адрес пира сменился больше двух раз за последние 5 минут — имя в
   `Flapping()` (спецификация: «меняет адрес чаще раза в минуту»).
4. Первый проход после смены часа — `Rollup(now, HistoryDays)`.
5. Автоблокировки по `Cards` и списку `Clients`:
   - `access_until` прошёл, клиент не заблокирован — `SetBlocked(true)`,
     `auto_block='expired'`, журнал от пользователя «система»;
   - лимит трафика: сумма `TrafficTotals` с начала периода (сутки — с
     00:00 UTC, неделя — с понедельника 00:00 UTC, месяц — с 1-го числа)
     не меньше лимита, клиент не заблокирован — блок, `auto_block='traffic'`;
   - `auto_block` стоит, клиент заблокирован, а причины больше нет (срок
     продлён или снят, начался новый период, лимит снят или поднят) —
     `SetBlocked(false)`, `auto_block=''`, журнал;
   - `auto_block` стоит, а клиент уже разблокирован (администратор снял
     блок вручную, см. задачу 4) — только обнулить `auto_block`.
   Клиент заблокирован при `auto_block=''` — ручной блок, не трогать.
6. Ошибка одного шага — `Warn` в журнал, остальные шаги выполняются.

Тесты (поддельный Node, временная база, подменённое `Now`):
- две сессии одного клиента, три прохода — минута содержит верную сумму
  дельт; сброс счётчика — дельта равна новым счётчикам.
- `access_until` в прошлом — `SetBlocked(name, true)` один раз, повторный
  проход его не вызывает; продлили срок — `SetBlocked(false)`.
- ручной блок не снимается.
- лимит трафика превышен — блок; наступил новый период — разблок.
- смена часа вызывает свёртку (в базе появилась часовая точка).
- WG-пир с тремя разными адресами за 3 минуты — в `Flapping`.

Коммит: «Панель: сборщик истории и автоблокировка по сроку и трафику».

### Задача 4: интерфейс истории, карточек и журнала

**Файлы:** `internal/panel/charts.go`, `history.go`, `audit.go`,
`geo.go`, правки `clients.go`, `monitor.go`, `server.go`; шаблоны
`client.html`, `clients.html`, `monitor.html`, новый `audit.html`, ссылка
«Журнал» в layout; тесты.

- `Server` получает поля `Store *store.Store`, `NodeID int64`,
  `Collector *Collector` (для `Flapping`; nil — без пометок),
  `Geo *Geo` (nil — без города и провайдера).
- `charts.go`: `LineChart(series []Series, from, to time.Time, unit string) template.HTML`
  — SVG 720×200 с `viewBox` (тянется по ширине), оси и подписи по-русски,
  до 3 линий, цвета через CSS-переменные; пустые данные — «нет данных»;
  пропуск точек — разрыв линии. Подписи экранируются.
- Карточка клиента: блок «Трафик», переключатель `?range=1d|7d|30d` (1d
  — минутные точки, 7d и 30d — часовые), итог за период ↓↑. Форма
  «Карточка»: заметка (до 500 символов), «доступ до» (дата
  `YYYY-MM-DD`, конец дня по UTC; пусто — без срока), лимит трафика в ГБ
  (0 — без), период (сутки, неделя, месяц); POST с CSRF, журнал «было →
  стало». У автоблокированного — «заблокирован автоматически: истёк срок»
  или «… превышен трафик» и подсказка, что снимается продлением срока или
  лимита. Ручная разблокировка такого клиента разрешена и обнуляет
  `auto_block`.
- Список клиентов: столбцы «трафик 30 дн.» и «доступ до»; сортировка
  `?sort=name|traffic|until|online`, по умолчанию `name`.
- «Сейчас»: графики CPU, памяти, сети (скорость из разности соседних
  накопительных счётчиков; отрицательная разность — точка пропускается) и
  онлайна за `?range=1d|7d|30d`; у сессий — город и провайдер; у WG-клиента
  из `Flapping` — «адрес меняется часто — возможно, один ключ на двух
  устройствах»; последние 50 отказов хука за сутки таблицей.
- Удаление клиента удаляет и карточку.
- `/audit`: таблица (время, пользователь, IP, действие, объект, было →
  стало), поиск `?q=`, страницы по 100 (`?page=`).
- Все места, где сейчас пишется `Log.Info("действие" …)`, дополнительно
  пишут `Store.Audit` с IP; вход и выход — тоже (`action` login / logout /
  login_failed).
- `geo.go`: `OpenGeo(dir string) (*Geo, error)` — ищет
  `GeoLite2-City.mmdb` и `GeoLite2-ASN.mmdb` в `dir`; нет обоих — nil, nil;
  `Lookup(ip string) (city, isp string)` — пустые строки, если не найдено.

Тесты: `LineChart` на пустых данных и на двух точках — валидный XML
(`encoding/xml`); карточка сохраняет поля и пишет журнал; неверная дата —
400; лимит ГБ отрицательный — 400; список сортируется по трафику; `/audit`
с поиском и страницами; «Сейчас» показывает отказ и пометку частой смены
адреса; `Geo` nil — столбцы пустые без ошибки; удаление клиента удаляет
карточку.

Коммит: «Панель: графики трафика и ресурсов, карточки клиентов, журнал действий».

### Задача 5: запуск

**Файлы:** `internal/panel/run.go`, `run_test.go`.

- `Run` открывает `store.Open(filepath.Join(paths.Data(), "azpanel.db"))`
  и закрывает при выходе; `Geo` — `OpenGeo(paths.Data())` (ошибка — `Warn`,
  работа без геоданных); `Collector.Run` — в горутине на том же `ctx`;
  `Run` дожидается её остановки перед возвратом и закрытием базы.
- `ReadWritePaths=/opt/azpanel` юнита уже покрывает `data/`.
- Тест: `Run` создаёт базу, сборщик делает хотя бы один проход против
  поддельного агента (`httptest.Server`, проверяющий токен), отмена `ctx` —
  возврат nil, файл базы существует.

Коммит: «Панель: база и сборщик в службе».

### Задача 6: приёмка на 94 (контроллер)

Результат — `docs/notes/2026-11-02-priemka-etap-2a3.md`.

1. Сборка, установка `--panel`, обе службы `active`.
2. Через 3 минуты в базе есть `resource_minute` и `traffic_minute` по
   живым клиентам (их данные — только читать).
3. `azpanel-test-h1`: «доступ до» вчера → после прохода сборщика клиент
   заблокирован, `auto_block='expired'`, запись в журнале; срок продлён —
   разблокирован.
4. Лимит трафика 1 байт/сутки на `azpanel-test-h1` с подключённым
   тестовым клиентом — блок; лимит снят — разблок.
5. Графики на карточке и «Сейчас» — SVG; `/audit` показывает действия с IP.
6. Тестовый клиент и его карточка удалены.

---

## Итоговая проверка

После задачи 5 — одна проверка коммитов плана самой сильной моделью
(корректность учёта трафика и свёртки, автоблокировки, SQL-инъекции,
экранирование SVG, соответствие плану), один круг исправлений, короткая
повторная проверка. Затем задача 6.
