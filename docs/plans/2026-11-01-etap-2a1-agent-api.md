# Этап 2а-1: API агента — клиенты, блокировка, сессии, ресурсы — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** агент на 94 отвечает по HTTP на `127.0.0.1:9100` с токеном: список клиентов OpenVPN и WireGuard со сроком сертификата, лимитом и блокировкой; создание, продление и удаление клиента родным `client.sh`; выдача файлов профилей; блокировка клиента OpenVPN (хук отказывает, текущие сессии рвутся); текущие сессии OpenVPN и WireGuard; ресурсы сервера и состояние служб.

**Architecture:** к агенту этапа 1 добавляется HTTP API (`internal/node/api.go`) — через него панель этапа 2а-2 будет делать всё. Состояние читается напрямую (каталог `issued/` EasyRSA, `/etc/wireguard/*.conf`, `/root/antizapret/client/`, снимки сокетов, `wg show`, `/proc`), изменения AntiZapret — только `client.sh` (опции 1, 2, 4, 5). Блокировка — список `blocked` в `limits.json`: хук отказывает заблокированному так же, как сверх лимита. Типы запросов и HTTP-клиент для панели — пакет `internal/nodeapi`.

**Tech Stack:** Go 1.24+, стандартная библиотека (`net/http` с шаблонами маршрутов Go 1.22, `crypto/x509`, `crypto/subtle`), `github.com/BurntSushi/toml` v1.4.0. Сборка `CGO_ENABLED=0`, linux/amd64 и linux/arm64.

**Spec:** [docs/specs/2026-11-01-azpanel-design.md](../specs/2026-11-01-azpanel-design.md) — разделы «Агент», «Клиенты», «Мониторинг», «Раскладка на сервере», «Этапы» (п. 2).

**Место в этапе 2.** Этап 2 спецификации разбит на четыре плана, каждый даёт рабочий результат:
2а-1 — этот план; 2а-2 — панель: вход, клиенты, мониторинг с историей, настройки через веб, один сервер; 2б — полный мастер установки (nginx, HTTPS, опасные настройки с таймером возврата); 2в — самообновление с миграцией конфига.

## Global Constraints

- Модуль `github.com/syava842/azpanel`; `go 1.24` в `go.mod`; новых зависимостей в этом плане нет.
- Имена файлов, пакетов, функций, типов, переменных — латиницей. Комментарии, тексты ошибок, сообщения журнала и CLI — по-русски.
- Раскладка `/opt/azpanel/{bin,etc,log,data,backup}`; права корня и `bin/` — `755`, `etc/`, `data/`, `backup/`, `log/` — `700`, файлы журналов и `limits.json` — `600`, `secrets.env` — `600`.
- API агента в этом этапе слушает только loopback (`127.0.0.1:порт` или `[::1]:порт`); TLS и внешние адреса — этап 4.
- Доступ к API — заголовок `Authorization: Bearer <токен>`, токен — `NODE_TOKEN` из `/opt/azpanel/etc/secrets.env`, 64 hex-символа; сравнение `subtle.ConstantTimeCompare`. Нет токена — API не запускается, хук работает как раньше.
- Протокол API — номер 1, каждый ответ несёт заголовок `X-Azpanel-Proto: 1`.
- AntiZapret меняется только через `client.sh` (опции 1, 2, 4, 5), один вызов за раз. Имя (`^[A-Za-z0-9_-]{1,32}$`) и срок (1–3650 дней) проверяются до запуска, stdin пуст, тайм-аут из конфига (по умолчанию 120 с): на неверном аргументе `client.sh` уходит в бесконечный цикл `read`.
- Закрытые и общие ключи WireGuard (`PrivateKey`, `PresharedKey`) и открытые ключи пиров не попадают ни в ответы API, ни в журналы.
- В управляющий сокет OpenVPN пишется только проверенное имя клиента: перевод строки в имени дал бы чужую команду.
- На 94 только тестовые клиенты `azpanel-test-*`; живых клиентов, StatusOpenVPN, telemt, 3proxy, AZ-WARP, nginx не трогать. Перезагрузка 94 и обновление AntiZapret запрещены.
- Коммиты — с `user.email = syava842@gmail.com` (задан в репозитории), сообщения по-русски, в конце строка `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Работа — в ветке `etap-2a`.
- Тесты запускаются на Windows-машине разработчика (`go test ./...`); всё, что требует linux (`statfs`, `SO_PEERCRED`), — под build-тегами с заглушкой.

## Факты с 94, на которых стоит план (01.11.2026, только чтение)

- `client.sh [1-9] [имя] [дней]`; без верных аргументов спрашивает через `read -rp` в цикле `until`.
- Опция 1 для существующего клиента продлевает сертификат (`sign client` на новый срок) — создание и продление одна опция.
- Опция 2: `easyrsa revoke`, `gen-crl`, удаление шести `.ovpn` и `kill <имя>` в четырёх сокетах через `socat`. Опции 4/5: блок `# Client = <имя>` / `# PrivateKey` / `[Peer]` / `PublicKey` / `PresharedKey` / `AllowedIPs` в `/etc/wireguard/antizapret.conf` и `vpn.conf`, затем `wg syncconf`.
- Список OpenVPN — `ls /etc/openvpn/easyrsa3/pki/issued` без `antizapret-server`; список WG — строки `# Client =` в двух конфигах.
- Файл профиля: `<antizapret|vpn>-<база>-(<адрес>)[-udp|-tcp|-wg|-am].<ovpn|conf>`, база — имя без приставок `antizapret-` и `vpn-`; адрес — `OPENVPN_HOST`/`WIREGUARD_HOST` из `setup`, пусто — внешний IP. Каталоги `client/openvpn/{antizapret,antizapret-udp,antizapret-tcp,vpn,vpn-udp,vpn-tcp}`, `client/{wireguard,amneziawg}/{antizapret,vpn}`.
- Файла `banned_clients` в нынешнем AntiZapret нет, ни один скрипт его не упоминает.
- На 94 `WIREGUARD_ENABLE=n`: интерфейсов `antizapret` и `vpn` нет, поднят только `warp-antizapret` (AZ-WARP) — его агент не трогает и не показывает.
- Службы: `openvpn-server@{antizapret-udp,antizapret-tcp,vpn-udp,vpn-tcp}`, `kresd@1..3`, `azpanel-node`. Порты 9100 и 8080 свободны. Ubuntu 24.04.5, 1 ядро.

## Карта файлов

| Файл | Отвечает за |
| --- | --- |
| `internal/config/config.go` | `config_version = 2`: ключи API агента, путей AntiZapret, раздел `[panel]` |
| `internal/secrets/secrets.go` | `secrets.env`: чтение, запись ключа, новый токен |
| `internal/paths/paths.go` | `SecretsFile()` |
| `internal/limits/limits.go` | `limits.json` версии 2: лимиты и `blocked` |
| `internal/agentproto/proto.go` | поле `Blocked` в ответе хуку |
| `internal/node/server.go` | отказ заблокированному |
| `internal/hook/hook.go` | сообщение об отказе по блокировке |
| `internal/antizapret/setup.go` | чтение `/root/antizapret/setup` |
| `internal/antizapret/inventory.go` | клиенты OpenVPN и WG, срок сертификата, имена пиров WG |
| `internal/antizapret/profiles.go` | поиск файлов профилей клиента |
| `internal/antizapret/clientsh.go` | запуск `client.sh` |
| `internal/antizapret/kill.go` | `kill <имя>` в управляющем сокете |
| `internal/antizapret/wg.go` | разбор `wg show <iface> dump` |
| `internal/node/tracker.go` | хранение подробностей сессий из снимка |
| `internal/sysinfo/*.go` | CPU, память, диск, сеть, uptime, службы |
| `internal/nodeapi/nodeapi.go` | типы API и HTTP-клиент для панели |
| `internal/node/api.go` | обработчики HTTP API агента |
| `internal/node/node.go` | запуск API в службе агента |
| `internal/install/install.go` | токен при установке, ограничения юнита |
| `cmd/azpanel/main.go`, `limitcmd.go` | версия в `node.Run`, новый формат лимитов |
| `docs/specs/2026-11-01-azpanel-design.md` | блокировка через хук, разбиение этапа 2, API |
| `docs/notes/2026-11-01-priemka-etap-2a1.md` | итоги приёмки на 94 |

---

### Task 1: config.toml версии 2 и secrets.env

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/paths/paths.go`
- Create: `internal/secrets/secrets.go`
- Test: `internal/secrets/secrets_test.go`

**Interfaces:**
- Consumes: `fsutil.WriteFileAtomic(path string, data []byte, perm os.FileMode) error`.
- Produces:
  - `config.CurrentVersion = 2`; `config.Node` получает `APIListen, AntiZapretDir, EasyRSAPKI, WireGuardDir string`, `ClientShTimeoutS int`; новый `config.Panel{Listen, NodeURL string; CollectSeconds, HistoryDays, SessionHours int}` в поле `Config.Panel`.
  - `paths.SecretsFile() string`.
  - `secrets.Load(path string) (map[string]string, error)`, `secrets.Set(path, key, value string) error`, `secrets.NewToken() (string, error)`, константа `secrets.NodeToken = "NODE_TOKEN"`.

- [ ] **Step 1: Написать падающие тесты конфига**

Добавить в `internal/config/config_test.go`:

```go
func TestLoadV1FileGetsV2Defaults(t *testing.T) {
	c, err := Load(write(t, "config_version = 1\n[node]\npoll_seconds = 7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ConfigVersion != CurrentVersion || CurrentVersion != 2 {
		t.Fatalf("config_version = %d, CurrentVersion = %d", c.ConfigVersion, CurrentVersion)
	}
	if c.Node.PollSeconds != 7 {
		t.Fatalf("poll_seconds = %d", c.Node.PollSeconds)
	}
	if c.Node.APIListen != "127.0.0.1:9100" || c.Node.ClientShTimeoutS != 120 {
		t.Fatalf("умолчания узла: %+v", c.Node)
	}
	if c.Panel.Listen != "127.0.0.1:8080" || c.Panel.HistoryDays != 30 {
		t.Fatalf("умолчания панели: %+v", c.Panel)
	}
}

func TestValidateListenAddresses(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
		ok   bool
	}{
		{"api пусто — API выключен", func(c *Config) { c.Node.APIListen = "" }, true},
		{"api ipv6 loopback", func(c *Config) { c.Node.APIListen = "[::1]:9100" }, true},
		{"api наружу", func(c *Config) { c.Node.APIListen = "0.0.0.0:9100" }, false},
		{"api без порта", func(c *Config) { c.Node.APIListen = "127.0.0.1" }, false},
		{"панель наружу", func(c *Config) { c.Panel.Listen = "10.0.0.1:8080" }, false},
		{"адрес агента не http", func(c *Config) { c.Panel.NodeURL = "127.0.0.1:9100" }, false},
		{"тайм-аут client.sh мал", func(c *Config) { c.Node.ClientShTimeoutS = 5 }, false},
		{"история 0 дней", func(c *Config) { c.Panel.HistoryDays = 0 }, false},
	}
	for _, tc := range cases {
		c := Default()
		tc.edit(&c)
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/config/`
Expected: FAIL — `c.Node.APIListen undefined`.

- [ ] **Step 3: Реализовать**

В `internal/config/config.go` заменить объявления от `const CurrentVersion` до конца `Default()` и функцию `Validate` на:

```go
// CurrentVersion — версия структуры конфига, которую знает этот бинарник.
// 2 — API агента, пути AntiZapret, раздел [panel].
const CurrentVersion = 2

type Config struct {
	ConfigVersion int   `toml:"config_version"`
	Node          Node  `toml:"node"`
	Panel         Panel `toml:"panel"`
	Log           Log   `toml:"log"`
}

type Node struct {
	OpenVPNSocketDir  string `toml:"openvpn_socket_dir"`
	OpenVPNScriptsDir string `toml:"openvpn_scripts_dir"`
	PollSeconds       int    `toml:"poll_seconds"`
	QueryTimeoutMs    int    `toml:"query_timeout_ms"`
	APIListen         string `toml:"api_listen"` // пусто — API выключен
	AntiZapretDir     string `toml:"antizapret_dir"`
	EasyRSAPKI        string `toml:"easyrsa_pki"`
	WireGuardDir      string `toml:"wireguard_dir"`
	ClientShTimeoutS  int    `toml:"client_sh_timeout_seconds"`
}

type Panel struct {
	Listen         string `toml:"listen"`
	NodeURL        string `toml:"node_url"`
	CollectSeconds int    `toml:"collect_seconds"`
	HistoryDays    int    `toml:"history_days"`
	SessionHours   int    `toml:"session_hours"`
}

type Log struct {
	MaxSizeMB int `toml:"max_size_mb"`
	Keep      int `toml:"keep"`
}

func Default() Config {
	return Config{
		ConfigVersion: CurrentVersion,
		Node: Node{
			OpenVPNSocketDir:  "/run/openvpn-server",
			OpenVPNScriptsDir: "/etc/openvpn/server/scripts",
			PollSeconds:       5,
			QueryTimeoutMs:    1000,
			APIListen:         "127.0.0.1:9100",
			AntiZapretDir:     "/root/antizapret",
			EasyRSAPKI:        "/etc/openvpn/easyrsa3/pki",
			WireGuardDir:      "/etc/wireguard",
			ClientShTimeoutS:  120,
		},
		Panel: Panel{
			Listen:         "127.0.0.1:8080",
			NodeURL:        "http://127.0.0.1:9100",
			CollectSeconds: 60,
			HistoryDays:    30,
			SessionHours:   168,
		},
		Log: Log{MaxSizeMB: 10, Keep: 5},
	}
}
```

В `Load` заменить

```go
	if c.ConfigVersion < 1 {
		c.ConfigVersion = CurrentVersion
	}
```

на

```go
	// Версия 2 только добавила ключи, умолчания для них уже подставлены
	// разбором поверх Default. Миграции с переименованием ключей появятся
	// вместе с самообновлением (план 2в).
	if c.ConfigVersion < CurrentVersion {
		c.ConfigVersion = CurrentVersion
	}
```

Новая `Validate` и помощник:

```go
func (c Config) Validate() error {
	n, p := c.Node, c.Panel
	switch {
	case n.OpenVPNSocketDir == "":
		return errors.New("node.openvpn_socket_dir пуст")
	case n.OpenVPNScriptsDir == "":
		return errors.New("node.openvpn_scripts_dir пуст")
	case n.PollSeconds < 1 || n.PollSeconds > 60:
		return fmt.Errorf("node.poll_seconds = %d, нужно 1..60", n.PollSeconds)
	case n.QueryTimeoutMs < 100 || n.QueryTimeoutMs > 5000:
		return fmt.Errorf("node.query_timeout_ms = %d, нужно 100..5000", n.QueryTimeoutMs)
	case n.APIListen != "" && !loopbackAddr(n.APIListen):
		return fmt.Errorf("node.api_listen = %q: нужен 127.0.0.1:порт, [::1]:порт или пусто", n.APIListen)
	case n.AntiZapretDir == "" || n.EasyRSAPKI == "" || n.WireGuardDir == "":
		return errors.New("node.antizapret_dir, node.easyrsa_pki и node.wireguard_dir не могут быть пустыми")
	case n.ClientShTimeoutS < 10 || n.ClientShTimeoutS > 600:
		return fmt.Errorf("node.client_sh_timeout_seconds = %d, нужно 10..600", n.ClientShTimeoutS)
	case !loopbackAddr(p.Listen):
		return fmt.Errorf("panel.listen = %q: нужен 127.0.0.1:порт или [::1]:порт", p.Listen)
	case !strings.HasPrefix(p.NodeURL, "http://") && !strings.HasPrefix(p.NodeURL, "https://"):
		return fmt.Errorf("panel.node_url = %q: нужен адрес http:// или https://", p.NodeURL)
	case p.CollectSeconds < 10 || p.CollectSeconds > 600:
		return fmt.Errorf("panel.collect_seconds = %d, нужно 10..600", p.CollectSeconds)
	case p.HistoryDays < 1 || p.HistoryDays > 365:
		return fmt.Errorf("panel.history_days = %d, нужно 1..365", p.HistoryDays)
	case p.SessionHours < 1 || p.SessionHours > 720:
		return fmt.Errorf("panel.session_hours = %d, нужно 1..720", p.SessionHours)
	case c.Log.MaxSizeMB < 1 || c.Log.MaxSizeMB > 1000:
		return fmt.Errorf("log.max_size_mb = %d, нужно 1..1000", c.Log.MaxSizeMB)
	case c.Log.Keep < 1 || c.Log.Keep > 100:
		return fmt.Errorf("log.keep = %d, нужно 1..100", c.Log.Keep)
	}
	return nil
}

// loopbackAddr — «адрес:порт» на петлевом интерфейсе. В этом этапе ни API
// агента, ни панель наружу не слушают: наружу — nginx и TLS (этапы 2б и 4).
func loopbackAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.Addr().IsLoopback() && ap.Port() != 0
}
```

В импорт добавить `"net/netip"` и `"strings"`.

В `internal/paths/paths.go` после `ConfigFile`:

```go
func SecretsFile() string { return filepath.Join(Etc(), "secrets.env") }
```

- [ ] **Step 4: Тесты конфига проходят**

Run: `go test ./internal/config/`
Expected: PASS (прежний `TestLoadRejectsNewerVersion` пишет 99 и остаётся верным).

- [ ] **Step 5: Написать падающие тесты secrets**

`internal/secrets/secrets_test.go`:

```go
package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadMissingIsEmpty(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "secrets.env"))
	if err != nil || len(m) != 0 {
		t.Fatalf("m = %v, err = %v", m, err)
	}
}

func TestSetKeepsOtherKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := Set(p, "B_KEY", "2"); err != nil {
		t.Fatal(err)
	}
	if err := Set(p, NodeToken, "abc=def"); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if m["B_KEY"] != "2" || m[NodeToken] != "abc=def" {
		t.Fatalf("m = %v", m)
	}
	data, _ := os.ReadFile(p)
	if string(data) != "B_KEY=2\nNODE_TOKEN=abc=def\n" {
		t.Fatalf("файл:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("права %v", st.Mode().Perm())
		}
	}
}

func TestSetRejectsBadInput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := Set(p, "bad key", "x"); err == nil {
		t.Fatal("имя с пробелом принято")
	}
	if err := Set(p, "KEY", "a\nB=c"); err == nil {
		t.Fatal("значение с переводом строки принято")
	}
}

func TestLoadBadLineHidesValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	os.WriteFile(p, []byte("# комментарий\n\nGOOD=1\nsupersecretvalue\n"), 0o600)
	_, err := Load(p)
	if err == nil || strings.Contains(err.Error(), "supersecretvalue") || !strings.Contains(err.Error(), ":4:") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewToken(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if len(a) != 64 || a == b {
		t.Fatalf("a = %q, b = %q", a, b)
	}
}
```

- [ ] **Step 6: Убедиться, что тесты падают**

Run: `go test ./internal/secrets/`
Expected: FAIL — пакет без исходников / `undefined: Load`.

- [ ] **Step 7: Реализовать `internal/secrets/secrets.go`**

```go
// Package secrets — /opt/azpanel/etc/secrets.env: строки KEY=VALUE, права 600.
// Значения не попадают ни в ошибки, ни в журналы.
package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/syava842/azpanel/internal/fsutil"
)

// NodeToken — токен, которым панель подписывает запросы к агенту.
const NodeToken = "NODE_TOKEN"

var keyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Load читает файл; нет файла — пустая карта. Пустые строки и строки с #
// пропускаются.
func Load(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !keyRe.MatchString(k) {
			// Саму строку не печатать: в ней может быть секрет.
			return nil, fmt.Errorf("%s:%d: ожидается KEY=VALUE", path, i+1)
		}
		out[k] = v
	}
	return out, nil
}

// Set меняет или добавляет один ключ, остальные сохраняет. Комментарии
// файла при этом не сохраняются: файл пишет только azpanel.
func Set(path, key, value string) error {
	if !keyRe.MatchString(key) {
		return fmt.Errorf("недопустимое имя ключа %q", key)
	}
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("значение секрета не может содержать перевод строки")
	}
	m, err := Load(path)
	if err != nil {
		return err
	}
	m[key] = value
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, m[k])
	}
	return fsutil.WriteFileAtomic(path, []byte(b.String()), 0o600)
}

// NewToken — 32 случайных байта в hex.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
```

- [ ] **Step 8: Все тесты проходят**

Run: `go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/config internal/paths internal/secrets
git commit -m "Конфиг версии 2 (API агента, пути AntiZapret, [panel]) и secrets.env

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Блокировка клиента в limits.json и отказ хука

**Files:**
- Modify: `internal/limits/limits.go`, `internal/limits/limits_test.go`
- Modify: `internal/agentproto/proto.go`
- Modify: `internal/node/server.go`, `internal/node/server_test.go`
- Modify: `internal/hook/hook.go`, `internal/hook/hook_test.go`
- Modify: `cmd/azpanel/limitcmd.go`, `cmd/azpanel/main.go`

**Interfaces:**
- Consumes: `limits.ValidName(string) bool`, `fsutil.WriteFileAtomic`.
- Produces:
  - `limits.Data{Limits map[string]int; Blocked map[string]bool}`, `limits.Empty() Data`;
  - `limits.Load(path) (Data, error)` — читает версии 1 и 2; `limits.Save(path, Data) error` — пишет версию 2;
  - `limits.Entry{Limit int; Blocked bool}`, `(*limits.Store).Get(name) (Entry, error)`;
  - `agentproto.Response.Blocked bool` (`json:"blocked,omitempty"`).

- [ ] **Step 1: Написать падающие тесты limits**

Заменить в `internal/limits/limits_test.go` тесты `TestLoadMissingIsEmpty` и `TestSaveLoad` и добавить новые:

```go
func TestLoadMissingIsEmpty(t *testing.T) {
	d, err := Load(filepath.Join(t.TempDir(), "limits.json"))
	if err != nil || len(d.Limits) != 0 || len(d.Blocked) != 0 || d.Limits == nil || d.Blocked == nil {
		t.Fatalf("d = %+v, err = %v", d, err)
	}
}

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	in := Data{Limits: map[string]int{"alice": 3}, Blocked: map[string]bool{"bob": true, "carol": true, "dave": false}}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	want := "{\n  \"version\": 2,\n  \"limits\": {\n    \"alice\": 3\n  },\n  \"blocked\": [\n    \"bob\",\n    \"carol\"\n  ]\n}\n"
	if string(data) != want {
		t.Fatalf("файл:\n%s", data)
	}
	d, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Limits["alice"] != 3 || !d.Blocked["bob"] || !d.Blocked["carol"] || d.Blocked["dave"] || len(d.Blocked) != 2 {
		t.Fatalf("d = %+v", d)
	}
}

func TestLoadVersion1(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(p, []byte(`{"version":1,"limits":{"alice":2}}`), 0o600)
	d, err := Load(p)
	if err != nil || d.Limits["alice"] != 2 || len(d.Blocked) != 0 {
		t.Fatalf("d = %+v, err = %v", d, err)
	}
}

func TestLoadRejectsBadBlockedName(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	os.WriteFile(p, []byte(`{"version":2,"limits":{},"blocked":["bad name"]}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("недопустимое имя в blocked принято")
	}
}

func TestStoreReportsBlocked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	Save(p, Data{Limits: map[string]int{"alice": 1}, Blocked: map[string]bool{"bob": true}})
	s := NewStore(p)
	if e, err := s.Get("bob"); err != nil || !e.Blocked || e.Limit != 0 {
		t.Fatalf("bob: %+v, %v", e, err)
	}
	if e, _ := s.Get("alice"); e.Blocked || e.Limit != 1 {
		t.Fatalf("alice: %+v", e)
	}
}
```

В оставшихся тестах этого файла (`TestLoadRejectsBadValues`, `TestStoreRereadsOnChange`, `TestStoreBrokenFromStartIsUnlimited`) заменить вызовы `Save(p, map[string]int{…})` на `Save(p, Data{Limits: map[string]int{…}})`, а проверки вида `n, err := s.Get(x)` / `n != 2` — на `e, err := s.Get(x)` / `e.Limit != 2`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/limits/`
Expected: FAIL — `undefined: Data`.

- [ ] **Step 3: Реализовать limits версии 2**

В `internal/limits/limits.go` заменить всё от `type file struct` до конца файла на:

```go
// Data — содержимое limits.json: лимит по клиенту (нет записи — без
// ограничения) и заблокированные клиенты.
type Data struct {
	Limits  map[string]int
	Blocked map[string]bool
}

func Empty() Data { return Data{Limits: map[string]int{}, Blocked: map[string]bool{}} }

// file — формат на диске. Версия 1 — только limits; версия 2 добавила
// blocked. Читаются обе, пишется 2.
type file struct {
	Version int            `json:"version"`
	Limits  map[string]int `json:"limits"`
	Blocked []string       `json:"blocked,omitempty"`
}

// Load читает лимиты; нет файла — пустые.
func Load(path string) (Data, error) {
	d := Empty()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return d, fmt.Errorf("%s: %w", path, err)
	}
	if f.Version != 1 && f.Version != 2 {
		return d, fmt.Errorf("%s: неизвестная версия %d", path, f.Version)
	}
	for name, n := range f.Limits {
		if !ValidName(name) {
			return Empty(), fmt.Errorf("%s: недопустимое имя клиента %q", path, name)
		}
		if n < 1 {
			return Empty(), fmt.Errorf("%s: лимит %s = %d, нужен 1 или больше", path, name, n)
		}
		d.Limits[name] = n
	}
	for _, name := range f.Blocked {
		if !ValidName(name) {
			return Empty(), fmt.Errorf("%s: недопустимое имя заблокированного клиента %q", path, name)
		}
		d.Blocked[name] = true
	}
	return d, nil
}

func Save(path string, d Data) error {
	f := file{Version: 2, Limits: d.Limits}
	if f.Limits == nil {
		f.Limits = map[string]int{}
	}
	for name, b := range d.Blocked {
		if b {
			f.Blocked = append(f.Blocked, name)
		}
	}
	sort.Strings(f.Blocked)
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Entry — что действует для одного клиента.
type Entry struct {
	Limit   int // 0 — без ограничения
	Blocked bool
}

// Store отдаёт лимиты и перечитывает файл, когда меняются его время или размер.
type Store struct {
	path string
	mu   sync.Mutex
	seen bool
	mod  time.Time
	size int64
	d    Data
}

func NewStore(path string) *Store { return &Store{path: path, d: Empty()} }

// Get — лимит и блокировка клиента. Если файл испорчен, вместе с ошибкой
// возвращается запись из последней прочитанной версии: одна кривая правка
// не должна снимать лимиты и блокировки у всех.
func (s *Store) Get(name string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.d, s.seen = Empty(), false
	case err != nil:
		return s.entry(name), err
	case !s.seen || !st.ModTime().Equal(s.mod) || st.Size() != s.size:
		d, err := Load(s.path)
		if err != nil {
			return s.entry(name), err
		}
		s.d, s.mod, s.size, s.seen = d, st.ModTime(), st.Size(), true
	}
	return s.entry(name), nil
}

func (s *Store) entry(name string) Entry {
	return Entry{Limit: s.d.Limits[name], Blocked: s.d.Blocked[name]}
}
```

В импорт добавить `"sort"`.

- [ ] **Step 4: Тесты limits проходят**

Run: `go test ./internal/limits/`
Expected: PASS.

- [ ] **Step 5: Написать падающие тесты сервера и хука**

В `internal/node/server_test.go` в `newServer` заменить `limits.Save(p, lim)` на `limits.Save(p, limits.Data{Limits: lim})` и добавить:

```go
func TestHandleBlockedDenied(t *testing.T) {
	s, hookLog := newServer(t, nil)
	p := filepath.Join(t.TempDir(), "limits.json")
	if err := limits.Save(p, limits.Data{Blocked: map[string]bool{"bob": true}}); err != nil {
		t.Fatal(err)
	}
	s.Limits = limits.NewStore(p)
	r := s.Handle(agentproto.Request{Op: agentproto.OpConnect, Instance: "antizapret-udp", CN: "bob", Addr: "1.2.3.4:5"})
	if r.Allow || !r.Blocked {
		t.Fatalf("ответ %+v", r)
	}
	if n := s.Tracker.Count("bob"); n != 0 {
		t.Fatalf("заблокированное подключение засчитано: %d", n)
	}
	if !strings.Contains(hookLog.String(), "клиент заблокирован") {
		t.Fatalf("журнал:\n%s", hookLog)
	}
}
```

(если `strings` ещё не импортирован в этом файле — добавить).

В `internal/hook/hook_test.go` добавить:

```go
func TestRunBlockedDenies(t *testing.T) {
	var stderr bytes.Buffer
	call := func(agentproto.Request) (agentproto.Response, error) {
		return agentproto.Response{Allow: false, Blocked: true}, nil
	}
	code := Run("connect", env(map[string]string{"common_name": "bob", "config": "antizapret-udp.conf"}), call, &stderr)
	if code != ExitDeny || !strings.Contains(stderr.String(), "заблокирован") {
		t.Fatalf("код %d, stderr %q", code, stderr.String())
	}
}
```

`env` — существующий помощник `hook_test.go`: строит `func(string) string` из карты.

- [ ] **Step 6: Убедиться, что тесты падают**

Run: `go test ./internal/node/ ./internal/hook/`
Expected: FAIL — `r.Blocked undefined` / ошибки компиляции из-за смены `Store.Get`.

- [ ] **Step 7: Реализовать отказ заблокированному**

`internal/agentproto/proto.go`, в `Response` после `Limit`:

```go
	Blocked bool           `json:"blocked,omitempty"`
```

`internal/node/server.go`, ветку `case agentproto.OpConnect:` заменить на:

```go
	case agentproto.OpConnect:
		e, err := s.Limits.Get(req.CN)
		if err != nil {
			// e — из последней прочитанной версии; не было её — без ограничений.
			s.HookLog.Error("limits.json не прочитан, действуют последние прочитанные лимиты", "cn", req.CN, "limit", e.Limit, "blocked", e.Blocked, "err", err)
		}
		if e.Blocked {
			s.HookLog.Warn("отказ: клиент заблокирован", "cn", req.CN, "instance", req.Instance, "addr", req.Addr)
			return agentproto.Response{Allow: false, Blocked: true}
		}
		ok, n := s.Tracker.Admit(k, s.Now(), e.Limit)
		if !ok {
			s.HookLog.Warn("отказ: лимит подключений", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", e.Limit)
			return agentproto.Response{Allow: false, Count: n, Limit: e.Limit}
		}
		s.HookLog.Info("подключение", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", e.Limit)
		return agentproto.Response{Allow: true, Count: n, Limit: e.Limit}
```

`internal/hook/hook.go`, блок отказа заменить на:

```go
	if req.Op == agentproto.OpConnect && !resp.Allow {
		if resp.Blocked {
			fmt.Fprintf(stderr, "azpanel hook: отказ %q — клиент заблокирован\n", cn)
		} else {
			fmt.Fprintf(stderr, "azpanel hook: отказ %q — подключений %d из %d\n", cn, resp.Count, resp.Limit)
		}
		return ExitDeny
	}
```

`cmd/azpanel/limitcmd.go`, в `cmdLimit`: `m, err := limits.Load(path)` → `d, err := limits.Load(path)`, далее все `m` → `d.Limits` (`sortedKeys(d.Limits)`, `d.Limits[args[1]]`, `delete(d.Limits, args[1])`), в конце `return limits.Save(path, d)`. Блокировки команда `limit` не трогает и сохраняет как есть.

`cmd/azpanel/main.go`, в `runSessions`: `formatSessions(resp.Counts, lim, os.Stdout)` → `formatSessions(resp.Counts, lim.Limits, os.Stdout)`.

- [ ] **Step 8: Все тесты проходят**

Run: `go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/limits internal/agentproto internal/node internal/hook cmd/azpanel
git commit -m "Блокировка клиента: blocked в limits.json версии 2, хук отказывает

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Состав клиентов, setup и файлы профилей

**Files:**
- Create: `internal/antizapret/setup.go`, `internal/antizapret/inventory.go`, `internal/antizapret/profiles.go`
- Test: `internal/antizapret/setup_test.go`, `internal/antizapret/inventory_test.go`, `internal/antizapret/profiles_test.go`

**Interfaces:**
- Consumes: `limits.ValidName`.
- Produces:
  - `antizapret.ReadSetup(path string) (map[string]string, error)`;
  - `antizapret.ClientInfo{Name string; OpenVPN, WireGuard bool; CertExpires time.Time}`;
  - `antizapret.Inventory{PKI, WireGuardDir string}` с методами `Clients() ([]ClientInfo, error)` и `WireGuardPeers() (map[string]map[string]string, error)` (интерфейс → открытый ключ → имя);
  - `antizapret.WGInterfaces = []string{"antizapret", "vpn"}`;
  - `antizapret.Profile{Kind, Variant, File string}`, `antizapret.Profiles(antizapretDir, name string) ([]Profile, error)`, `antizapret.ProfilePath(antizapretDir, name, kind, variant, file string) (string, error)`, `antizapret.ErrNotFound`.

- [ ] **Step 1: Написать падающие тесты**

`internal/antizapret/setup_test.go`:

```go
package antizapret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSetup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "setup")
	os.WriteFile(p, []byte("# комментарий\nWIREGUARD_ENABLE=n\nOPENVPN_HOST=\nDOMAIN='vpn.example.com'\nX=\"a b\"\r\n\nbroken line\n"), 0o644)
	m, err := ReadSetup(p)
	if err != nil {
		t.Fatal(err)
	}
	if m["WIREGUARD_ENABLE"] != "n" || m["OPENVPN_HOST"] != "" || m["DOMAIN"] != "vpn.example.com" || m["X"] != "a b" {
		t.Fatalf("m = %v", m)
	}
	if _, ok := m["broken line"]; ok {
		t.Fatal("строка без = попала в карту")
	}
}
```

`internal/antizapret/inventory_test.go`:

```go
package antizapret

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert пишет сертификат так, как его кладёт EasyRSA: текстовая
// расшифровка, затем PEM.
func writeCert(t *testing.T, path, cn string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := "Certificate:\n    Data:\n        Subject: CN=" + cn + "\n" +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const wgConf = `[Interface]
PrivateKey = SERVERPRIVATE
Address = 10.29.8.1/24

# Client = alice
# PrivateKey = ALICEPRIVATE
[Peer]
PublicKey = ALICEPUB
PresharedKey = ALICEPSK
AllowedIPs = 10.29.8.2/32

# Client = bob
# PrivateKey = BOBPRIVATE
[Peer]
PublicKey = BOBPUB
PresharedKey = BOBPSK
AllowedIPs = 10.29.8.3/32
`

func newInventory(t *testing.T) Inventory {
	t.Helper()
	root := t.TempDir()
	inv := Inventory{PKI: filepath.Join(root, "pki"), WireGuardDir: filepath.Join(root, "wireguard")}
	issued := filepath.Join(inv.PKI, "issued")
	os.MkdirAll(issued, 0o755)
	os.MkdirAll(inv.WireGuardDir, 0o755)
	exp := time.Date(2030, 5, 30, 11, 54, 53, 0, time.UTC)
	writeCert(t, filepath.Join(issued, "alice.crt"), "alice", exp)
	writeCert(t, filepath.Join(issued, "antizapret-server.crt"), "antizapret-server", exp)
	os.WriteFile(filepath.Join(issued, "carol.crt"), []byte("не сертификат"), 0o644)
	os.WriteFile(filepath.Join(issued, "readme.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(inv.WireGuardDir, "antizapret.conf"), []byte(wgConf), 0o600)
	os.WriteFile(filepath.Join(inv.WireGuardDir, "vpn.conf"), []byte(strings.ReplaceAll(wgConf, "bob", "dave")), 0o600)
	return inv
}

func TestInventoryClients(t *testing.T) {
	got, err := newInventory(t).Clients()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "alice,bob,carol,dave" {
		t.Fatalf("имена %v", names)
	}
	alice, bob, carol := got[0], got[1], got[2]
	if !alice.OpenVPN || !alice.WireGuard || !alice.CertExpires.Equal(time.Date(2030, 5, 30, 11, 54, 53, 0, time.UTC)) {
		t.Fatalf("alice %+v", alice)
	}
	if !carol.OpenVPN || carol.WireGuard || !carol.CertExpires.IsZero() {
		t.Fatalf("carol (сертификат не читается) %+v", carol)
	}
	if bob.OpenVPN || !bob.WireGuard {
		t.Fatalf("bob %+v", bob)
	}
}

func TestInventoryEmptyDirs(t *testing.T) {
	root := t.TempDir()
	got, err := Inventory{PKI: filepath.Join(root, "нет"), WireGuardDir: filepath.Join(root, "нет")}.Clients()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, err %v", got, err)
	}
}

func TestWireGuardPeers(t *testing.T) {
	m, err := newInventory(t).WireGuardPeers()
	if err != nil {
		t.Fatal(err)
	}
	if m["antizapret"]["ALICEPUB"] != "alice" || m["antizapret"]["BOBPUB"] != "bob" || m["vpn"]["BOBPUB"] != "dave" {
		t.Fatalf("m = %v", m)
	}
	if len(m["antizapret"]) != 2 {
		t.Fatalf("лишние ключи: %v", m["antizapret"])
	}
}
```

`internal/antizapret/profiles_test.go`:

```go
package antizapret

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func touch(t *testing.T, path string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte("профиль"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProfiles(t *testing.T) {
	dir := t.TempDir()
	c := filepath.Join(dir, "client")
	touch(t, filepath.Join(c, "openvpn/antizapret-udp/antizapret-client-(1.2.3.4)-udp.ovpn"))
	touch(t, filepath.Join(c, "openvpn/vpn/vpn-client-(1.2.3.4).ovpn"))
	touch(t, filepath.Join(c, "amneziawg/antizapret/antizapret-client-(1.2.3.4)-am.conf"))
	touch(t, filepath.Join(c, "openvpn/antizapret-udp/antizapret-clientx-(1.2.3.4)-udp.ovpn")) // чужой
	touch(t, filepath.Join(c, "openvpn/vpn/vpn-client-(1.2.3.4).ovpn.bak"))                   // не профиль

	got, err := Profiles(dir, "antizapret-client") // база имени — «client»
	if err != nil {
		t.Fatal(err)
	}
	want := []Profile{
		{Kind: "openvpn", Variant: "antizapret-udp", File: "antizapret-client-(1.2.3.4)-udp.ovpn"},
		{Kind: "openvpn", Variant: "vpn", File: "vpn-client-(1.2.3.4).ovpn"},
		{Kind: "amneziawg", Variant: "antizapret", File: "antizapret-client-(1.2.3.4)-am.conf"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	p, err := ProfilePath(dir, "client", "openvpn", "vpn", "vpn-client-(1.2.3.4).ovpn")
	if err != nil || p != filepath.Join(c, "openvpn", "vpn", "vpn-client-(1.2.3.4).ovpn") {
		t.Fatalf("p = %q, err = %v", p, err)
	}
	for _, bad := range [][3]string{
		{"openvpn", "vpn", "../../../setup"},
		{"openvpn", "..", "vpn-client-(1.2.3.4).ovpn"},
		{"openvpn", "antizapret-udp", "antizapret-clientx-(1.2.3.4)-udp.ovpn"},
	} {
		if _, err := ProfilePath(dir, "client", bad[0], bad[1], bad[2]); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%v: err = %v", bad, err)
		}
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/antizapret/`
Expected: FAIL — `undefined: ReadSetup`, `Inventory`, `Profiles`.

- [ ] **Step 3: Реализовать `setup.go`**

```go
package antizapret

import (
	"os"
	"strings"
)

// ReadSetup читает /root/antizapret/setup — строки KEY=VALUE, как их пишет
// setup.sh AntiZapret. Кавычки вокруг значения снимаются. Файл только
// читается: меняет его родной setup.sh.
func ReadSetup(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(k, " \t") {
			continue
		}
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, nil
}
```

- [ ] **Step 4: Реализовать `inventory.go`**

```go
package antizapret

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/limits"
)

// WGInterfaces — интерфейсы WireGuard AntiZapret. Прочие (warp-* от AZ-WARP)
// агент не трогает и не показывает.
var WGInterfaces = []string{"antizapret", "vpn"}

// serverCert — сертификат самого сервера в issued/, не клиент.
const serverCert = "antizapret-server"

type ClientInfo struct {
	Name        string
	OpenVPN     bool
	WireGuard   bool
	CertExpires time.Time // нулевое — сертификата нет или он не читается
}

// Inventory читает состав клиентов теми же источниками, что client.sh.
type Inventory struct {
	PKI          string // /etc/openvpn/easyrsa3/pki
	WireGuardDir string // /etc/wireguard
}

// Clients — все клиенты по алфавиту: OpenVPN — файлы issued/*.crt без
// antizapret-server (как listOpenVPN), WireGuard — строки «# Client = имя»
// в antizapret.conf и vpn.conf (как listWireGuard). Нет каталога или
// файла — нет клиентов этого вида.
func (inv Inventory) Clients() ([]ClientInfo, error) {
	byName := map[string]*ClientInfo{}
	get := func(name string) *ClientInfo {
		if c, ok := byName[name]; ok {
			return c
		}
		c := &ClientInfo{Name: name}
		byName[name] = c
		return c
	}
	entries, err := os.ReadDir(filepath.Join(inv.PKI, "issued"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".crt")
		if !ok || name == serverCert || !limits.ValidName(name) || !e.Type().IsRegular() {
			continue
		}
		c := get(name)
		c.OpenVPN = true
		c.CertExpires = certNotAfter(filepath.Join(inv.PKI, "issued", e.Name()))
	}
	for _, iface := range WGInterfaces {
		blocks, err := inv.wgBlocks(iface)
		if err != nil {
			return nil, err
		}
		for _, b := range blocks {
			get(b.name).WireGuard = true
		}
	}
	out := make([]ClientInfo, 0, len(byName))
	for _, c := range byName {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// certNotAfter — срок сертификата; EasyRSA пишет перед PEM текстовую
// расшифровку, pem.Decode её пропускает.
func certNotAfter(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return time.Time{}
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return time.Time{}
		}
		return c.NotAfter.UTC()
	}
}

// WireGuardPeers — имя клиента по открытому ключу пира, для каждого
// интерфейса. Ключи нужны только для сопоставления с выводом wg show и
// наружу не отдаются.
func (inv Inventory) WireGuardPeers() (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, iface := range WGInterfaces {
		blocks, err := inv.wgBlocks(iface)
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		for _, b := range blocks {
			if b.publicKey != "" {
				m[b.publicKey] = b.name
			}
		}
		out[iface] = m
	}
	return out, nil
}

type wgBlock struct{ name, publicKey string }

// wgBlocks разбирает блоки клиентов, которые пишет addWireGuard:
// «# Client = имя», «# PrivateKey = …», «[Peer]», «PublicKey = …», ….
// Закрытые ключи не сохраняются.
func (inv Inventory) wgBlocks(iface string) ([]wgBlock, error) {
	f, err := os.Open(filepath.Join(inv.WireGuardDir, iface+".conf"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []wgBlock
	cur := -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "# Client ="); ok {
			name := strings.ReplaceAll(rest, " ", "")
			if limits.ValidName(name) {
				out = append(out, wgBlock{name: name})
				cur = len(out) - 1
			} else {
				cur = -1
			}
			continue
		}
		if rest, ok := strings.CutPrefix(line, "PublicKey"); ok && cur >= 0 {
			if v, ok := strings.CutPrefix(strings.TrimSpace(rest), "="); ok {
				out[cur].publicKey = strings.TrimSpace(v)
				cur = -1
			}
		}
	}
	return out, sc.Err()
}
```

- [ ] **Step 5: Реализовать `profiles.go`**

```go
package antizapret

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrNotFound = errors.New("не найдено")

type Profile struct {
	Kind    string // openvpn, wireguard, amneziawg
	Variant string // antizapret, antizapret-udp, vpn-tcp, …
	File    string
}

// profileDirs — каталоги /root/antizapret/client в порядке показа.
var profileDirs = []struct{ kind, variant string }{
	{"openvpn", "antizapret"}, {"openvpn", "antizapret-udp"}, {"openvpn", "antizapret-tcp"},
	{"openvpn", "vpn"}, {"openvpn", "vpn-udp"}, {"openvpn", "vpn-tcp"},
	{"wireguard", "antizapret"}, {"wireguard", "vpn"},
	{"amneziawg", "antizapret"}, {"amneziawg", "vpn"},
}

// profileBase — часть имени файла, которую client.sh берёт из имени
// клиента (setServerHost_FileName): без приставок antizapret- и vpn-.
func profileBase(name string) string {
	return strings.TrimPrefix(strings.TrimPrefix(name, "antizapret-"), "vpn-")
}

// Profiles — файлы профилей клиента. Имя файла client.sh строит как
// <antizapret|vpn>-<база>-(<адрес>)[-udp|-tcp|-wg|-am].<ovpn|conf>.
// У клиентов «antizapret-x» и «x» база одна, и AntiZapret кладёт их файлы
// под одним именем — различить их нельзя.
func Profiles(antizapretDir, name string) ([]Profile, error) {
	re := regexp.MustCompile(`^(antizapret|vpn)-` + regexp.QuoteMeta(profileBase(name)) +
		`-\([^()/]*\)(-udp|-tcp|-wg|-am)?\.(ovpn|conf)$`)
	var out []Profile
	for _, d := range profileDirs {
		entries, err := os.ReadDir(filepath.Join(antizapretDir, "client", d.kind, d.variant))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type().IsRegular() && re.MatchString(e.Name()) {
				out = append(out, Profile{Kind: d.kind, Variant: d.variant, File: e.Name()})
			}
		}
	}
	return out, nil
}

// ProfilePath — путь к файлу, только если он есть среди Profiles клиента:
// путь из запроса на диск не попадает.
func ProfilePath(antizapretDir, name, kind, variant, file string) (string, error) {
	ps, err := Profiles(antizapretDir, name)
	if err != nil {
		return "", err
	}
	for _, p := range ps {
		if p.Kind == kind && p.Variant == variant && p.File == file {
			return filepath.Join(antizapretDir, "client", p.Kind, p.Variant, p.File), nil
		}
	}
	return "", ErrNotFound
}
```

- [ ] **Step 6: Тесты проходят**

Run: `go vet ./... && go test ./internal/antizapret/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/antizapret
git commit -m "Состав клиентов OpenVPN и WireGuard, setup и поиск файлов профилей

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Запуск client.sh и отключение сессий клиента

**Files:**
- Create: `internal/antizapret/clientsh.go`, `internal/antizapret/kill.go`
- Test: `internal/antizapret/clientsh_test.go`, `internal/antizapret/kill_test.go`

**Interfaces:**
- Consumes: `limits.ValidName`.
- Produces:
  - `antizapret.ClientSh{Dir string; Timeout time.Duration; Run func(ctx context.Context, dir string, args ...string) ([]byte, error)}` с методами `AddOpenVPN(ctx, name string, days int) (string, error)`, `DeleteOpenVPN(ctx, name string) (string, error)`, `AddWireGuard(ctx, name string) (string, error)`, `DeleteWireGuard(ctx, name string) (string, error)`; константа `antizapret.MaxCertDays = 3650`.
  - `antizapret.KillClient(sockPath, name string, timeout time.Duration) (int, error)`.

- [ ] **Step 1: Написать падающие тесты**

`internal/antizapret/clientsh_test.go`:

```go
package antizapret

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeRun struct {
	calls [][]string
	out   string
	err   error
	sleep time.Duration
}

func (f *fakeRun) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{dir}, args...))
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return []byte(f.out), ctx.Err()
		}
	}
	return []byte(f.out), f.err
}

func TestClientShArgs(t *testing.T) {
	f := &fakeRun{out: "ok\n"}
	c := &ClientSh{Dir: "/root/antizapret", Timeout: time.Second, Run: f.run}
	ctx := context.Background()
	c.AddOpenVPN(ctx, "azpanel-test-a1", 30)
	c.DeleteOpenVPN(ctx, "azpanel-test-a1")
	c.AddWireGuard(ctx, "azpanel-test-a1")
	c.DeleteWireGuard(ctx, "azpanel-test-a1")
	want := []string{
		"/root/antizapret 1 azpanel-test-a1 30",
		"/root/antizapret 2 azpanel-test-a1",
		"/root/antizapret 4 azpanel-test-a1",
		"/root/antizapret 5 azpanel-test-a1",
	}
	for i, w := range want {
		if got := strings.Join(f.calls[i], " "); got != w {
			t.Fatalf("[%d] %q, want %q", i, got, w)
		}
	}
}

func TestClientShRejectsBeforeRun(t *testing.T) {
	f := &fakeRun{}
	c := &ClientSh{Dir: "/x", Timeout: time.Second, Run: f.run}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		days int
	}{{"bad name", 30}, {"", 30}, {"a\nkill all", 30}, {"ok", 0}, {"ok", 3651}} {
		if _, err := c.AddOpenVPN(ctx, tc.name, tc.days); err == nil {
			t.Fatalf("%q/%d принято", tc.name, tc.days)
		}
	}
	if _, err := c.DeleteWireGuard(ctx, "x y"); err == nil {
		t.Fatal("имя с пробелом принято")
	}
	if len(f.calls) != 0 {
		t.Fatalf("client.sh запускался: %v", f.calls)
	}
}

func TestClientShErrorCarriesOutputTail(t *testing.T) {
	f := &fakeRun{out: "строка 1\nError at line 140: easyrsa revoke\n", err: errors.New("exit status 1")}
	c := &ClientSh{Dir: "/x", Timeout: time.Second, Run: f.run}
	_, err := c.DeleteOpenVPN(context.Background(), "nobody-here")
	if err == nil || !strings.Contains(err.Error(), "easyrsa revoke") || !strings.Contains(err.Error(), "client.sh 2 nobody-here") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientShTimeout(t *testing.T) {
	f := &fakeRun{sleep: time.Second}
	c := &ClientSh{Dir: "/x", Timeout: 20 * time.Millisecond, Run: f.run}
	_, err := c.AddWireGuard(context.Background(), "slow")
	if err == nil || !strings.Contains(err.Error(), "не уложился") {
		t.Fatalf("err = %v", err)
	}
}
```

`internal/antizapret/kill_test.go`:

```go
package antizapret

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeMgmt отвечает на одну команду так, как управляющий интерфейс OpenVPN.
func fakeMgmt(t *testing.T, reply string) (sock string, got chan string) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "x.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n"))
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- strings.TrimSpace(line)
		c.Write([]byte(reply))
	}()
	return sock, got
}

func TestKillClientSuccess(t *testing.T) {
	sock, got := fakeMgmt(t, "SUCCESS: common name 'alice' found, 2 client(s) killed\r\n")
	n, err := KillClient(sock, "alice", time.Second)
	if err != nil || n != 2 {
		t.Fatalf("n = %d, err = %v", n, err)
	}
	if cmd := <-got; cmd != "kill alice" {
		t.Fatalf("команда %q", cmd)
	}
}

func TestKillClientNotFoundIsZero(t *testing.T) {
	sock, _ := fakeMgmt(t, "ERROR: common name 'alice' not found\r\n")
	n, err := KillClient(sock, "alice", time.Second)
	if err != nil || n != 0 {
		t.Fatalf("n = %d, err = %v", n, err)
	}
}

func TestKillClientOtherError(t *testing.T) {
	sock, _ := fakeMgmt(t, "ERROR: unknown command\r\n")
	if _, err := KillClient(sock, "alice", time.Second); err == nil {
		t.Fatal("ошибка интерфейса не передана")
	}
}

func TestKillClientRejectsBadName(t *testing.T) {
	if _, err := KillClient(filepath.Join(t.TempDir(), "нет.sock"), "a\nsignal SIGTERM", time.Second); err == nil || !strings.Contains(err.Error(), "имя") {
		t.Fatalf("err = %v", err)
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/antizapret/`
Expected: FAIL — `undefined: ClientSh`, `KillClient`.

- [ ] **Step 3: Реализовать `clientsh.go`**

```go
package antizapret

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/limits"
)

// MaxCertDays — верхняя граница срока сертификата в client.sh.
const MaxCertDays = 3650

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ClientSh запускает /root/antizapret/client.sh — единственный способ, которым
// azpanel меняет клиентов AntiZapret. Вызовы идут по одному: client.sh
// правит общие файлы (PKI, конфиги WireGuard) без блокировок.
type ClientSh struct {
	Dir     string        // каталог AntiZapret, в нём client.sh и setup
	Timeout time.Duration // на один вызов
	// Run — запуск процесса; nil — настоящий client.sh. Подменяется в тестах.
	Run func(ctx context.Context, dir string, args ...string) ([]byte, error)
	mu  sync.Mutex
}

// AddOpenVPN — опция 1. Для существующего клиента client.sh не создаёт
// нового, а продлевает сертификат на days дней, поэтому создание и
// продление различает вызывающий.
func (c *ClientSh) AddOpenVPN(ctx context.Context, name string, days int) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	if days < 1 || days > MaxCertDays {
		return "", fmt.Errorf("срок сертификата %d дней, нужно 1..%d", days, MaxCertDays)
	}
	return c.run(ctx, "1", name, strconv.Itoa(days))
}

// DeleteOpenVPN — опция 2: отзыв сертификата, CRL, удаление профилей, kill сессий.
func (c *ClientSh) DeleteOpenVPN(ctx context.Context, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return c.run(ctx, "2", name)
}

// AddWireGuard — опция 4: пир в antizapret.conf и vpn.conf, профили WG и AmneziaWG.
func (c *ClientSh) AddWireGuard(ctx context.Context, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return c.run(ctx, "4", name)
}

// DeleteWireGuard — опция 5.
func (c *ClientSh) DeleteWireGuard(ctx context.Context, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return c.run(ctx, "5", name)
}

func checkName(name string) error {
	if !limits.ValidName(name) {
		return fmt.Errorf("недопустимое имя клиента %q: 1–32 символа a-z, A-Z, 0-9, _ и -", name)
	}
	return nil
}

// run: на неверном аргументе client.sh спрашивает через read в цикле и с
// пустым вводом не выходит никогда — поэтому аргументы проверены выше, а
// тайм-аут обрывает вызов в любом случае.
func (c *ClientSh) run(ctx context.Context, args ...string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	run := c.Run
	if run == nil {
		run = execClientSh
	}
	out, err := run(ctx, c.Dir, args...)
	text := tail(string(out), 20)
	what := "client.sh " + strings.Join(args, " ")
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return text, fmt.Errorf("%s не уложился в %s: %s", what, c.Timeout, text)
	case err != nil:
		return text, fmt.Errorf("%s: %w: %s", what, err, text)
	}
	return text, nil
}

func execClientSh(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "client.sh"), args...)
	cmd.Dir = dir
	cmd.Stdin = nil // /dev/null: read в client.sh сразу получит EOF
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// tail — последние n строк без цветовых кодов терминала.
func tail(s string, n int) string {
	s = ansiRe.ReplaceAllString(s, "")
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 4: Реализовать `kill.go`**

```go
package antizapret

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/limits"
)

var killedRe = regexp.MustCompile(`(\d+) client\(s\) killed`)

// KillClient отключает все сессии клиента в одном экземпляре OpenVPN
// командой управляющего интерфейса «kill <имя>» и возвращает их число.
// Клиента в экземпляре нет — 0 без ошибки.
func KillClient(sockPath, name string, timeout time.Duration) (int, error) {
	// Имя уходит в командную строку интерфейса: перевод строки в нём дал
	// бы вторую, чужую команду.
	if !limits.ValidName(name) {
		return 0, fmt.Errorf("недопустимое имя клиента %q", name)
	}
	deadline := time.Now().Add(timeout)
	conn, err := (&net.Dialer{Deadline: deadline}).Dial("unix", sockPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(conn, "kill "+name+"\n"); err != nil {
		return 0, err
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SUCCESS:"):
			io.WriteString(conn, "quit\n")
			if m := killedRe.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				return n, nil
			}
			return 1, nil
		case strings.HasPrefix(line, "ERROR:"):
			io.WriteString(conn, "quit\n")
			if strings.Contains(line, "not found") {
				return 0, nil
			}
			return 0, fmt.Errorf("%s: %s", sockPath, line)
		}
		if err != nil {
			return 0, fmt.Errorf("%s: нет ответа на kill: %w", sockPath, err)
		}
	}
}
```

- [ ] **Step 5: Тесты проходят**

Run: `go vet ./... && go test ./internal/antizapret/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/antizapret
git commit -m "Запуск client.sh с проверкой аргументов и kill клиента в сокете OpenVPN

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Подробности сессий OpenVPN и пиры WireGuard

**Files:**
- Modify: `internal/node/tracker.go`, `internal/node/tracker_test.go`
- Create: `internal/antizapret/wg.go`
- Test: `internal/antizapret/wg_test.go`

**Interfaces:**
- Consumes: `antizapret.Session`, `antizapret.NormalizeAddr`.
- Produces:
  - `(*node.Tracker).Sessions() []antizapret.Session` — сессии из последних снимков, по экземпляру, имени, адресу;
  - `antizapret.WGPeer{Interface, PublicKey, Endpoint string; LatestHandshake time.Time; RxBytes, TxBytes int64}`;
  - `antizapret.ParseWGDump(iface string, r io.Reader) ([]WGPeer, error)`;
  - `antizapret.WGShow(ctx context.Context, iface string) ([]WGPeer, error)`.

- [ ] **Step 1: Написать падающие тесты**

В `internal/node/tracker_test.go`:

```go
func TestTrackerSessions(t *testing.T) {
	tr := NewTracker()
	at := time.Unix(1000, 0)
	tr.ApplySnapshot("vpn-udp", at, []antizapret.Session{
		{Instance: "vpn-udp", CommonName: "bob", RealAddr: "5.6.7.8:1", BytesRx: 10},
	})
	tr.ApplySnapshot("antizapret-udp", at, []antizapret.Session{
		{Instance: "antizapret-udp", CommonName: "bob", RealAddr: "1.1.1.1:2"},
		{Instance: "antizapret-udp", CommonName: "alice", RealAddr: "1.1.1.1:1"},
	})
	got := tr.Sessions()
	var keys []string
	for _, s := range got {
		keys = append(keys, s.Instance+"/"+s.CommonName)
	}
	if strings.Join(keys, ",") != "antizapret-udp/alice,antizapret-udp/bob,vpn-udp/bob" {
		t.Fatalf("порядок %v", keys)
	}
	if got[2].BytesRx != 10 {
		t.Fatalf("подробности потеряны: %+v", got[2])
	}
	tr.Forget("vpn-udp")
	if n := len(tr.Sessions()); n != 2 {
		t.Fatalf("после Forget осталось %d", n)
	}
}
```

(добавить импорт `strings`, если его нет).

`internal/antizapret/wg_test.go`:

```go
package antizapret

import (
	"strings"
	"testing"
	"time"
)

const wgDump = "SERVERPRIVATE\tSERVERPUB\t51820\toff\n" +
	"ALICEPUB\tALICEPSK\t1.2.3.4:5555\t10.29.8.2/32\t1793564373\t48024\t227676\t0\n" +
	"BOBPUB\tBOBPSK\t(none)\t10.29.8.3/32\t0\t0\t0\t0\n" +
	"CAROLPUB\t(none)\t[2001:db8::1]:51820\t10.29.8.4/32\t1793564000\t1\t2\t25\n"

func TestParseWGDump(t *testing.T) {
	got, err := ParseWGDump("antizapret", strings.NewReader(wgDump))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("пиров %d", len(got))
	}
	a := got[0]
	if a.Interface != "antizapret" || a.PublicKey != "ALICEPUB" || a.Endpoint != "1.2.3.4:5555" ||
		!a.LatestHandshake.Equal(time.Unix(1793564373, 0)) || a.RxBytes != 48024 || a.TxBytes != 227676 {
		t.Fatalf("alice %+v", a)
	}
	if b := got[1]; b.Endpoint != "" || !b.LatestHandshake.IsZero() {
		t.Fatalf("bob %+v", b)
	}
	if c := got[2]; c.Endpoint != "[2001:db8::1]:51820" {
		t.Fatalf("carol %+v", c)
	}
}

func TestParseWGDumpBadLineHidesKeys(t *testing.T) {
	_, err := ParseWGDump("vpn", strings.NewReader("SERVERPRIVATE\tSERVERPUB\t51820\toff\nALICEPUB\tALICEPSK\n"))
	if err == nil || strings.Contains(err.Error(), "ALICEPSK") || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("err = %v", err)
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/node/ ./internal/antizapret/`
Expected: FAIL — `tr.Sessions undefined`, `undefined: ParseWGDump`.

- [ ] **Step 3: Реализовать хранение сессий в трекере**

В `internal/node/tracker.go`: в `type snapshot` добавить поле

```go
	sessions []antizapret.Session // для показа; лимит считается по keys
```

в `ApplySnapshot` строку `t.snaps[instance] = snapshot{taken: taken, keys: keys}` заменить на

```go
	t.snaps[instance] = snapshot{taken: taken, keys: keys, sessions: append([]antizapret.Session(nil), sessions...)}
```

и добавить метод:

```go
// Sessions — сессии из последних снимков всех экземпляров, для показа.
// События хуков между снимками сюда не входят: список отстаёт от учёта
// лимита не больше чем на один опрос.
func (t *Tracker) Sessions() []antizapret.Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []antizapret.Session
	for _, s := range t.snaps {
		out = append(out, s.sessions...)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		if a.CommonName != b.CommonName {
			return a.CommonName < b.CommonName
		}
		return a.RealAddr < b.RealAddr
	})
	return out
}
```

- [ ] **Step 4: Реализовать `wg.go`**

```go
package antizapret

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// WGPeer — пир из «wg show <iface> dump». PublicKey нужен только для
// сопоставления с именем клиента и наружу не отдаётся.
type WGPeer struct {
	Interface       string
	PublicKey       string
	Endpoint        string // пусто — пир ни разу не подключался
	LatestHandshake time.Time
	RxBytes         int64 // принято сервером от пира
	TxBytes         int64
}

// ParseWGDump разбирает «wg show <iface> dump»: первая строка — сам
// интерфейс (4 поля, среди них закрытый ключ), дальше пиры по 8 полей.
// Ключи в ошибки не попадают.
func ParseWGDump(iface string, r io.Reader) ([]WGPeer, error) {
	sc := bufio.NewScanner(r)
	var out []WGPeer
	for n := 1; sc.Scan(); n++ {
		f := strings.Split(strings.TrimRight(sc.Text(), "\r"), "\t")
		if n == 1 {
			if len(f) != 4 {
				return nil, fmt.Errorf("wg show %s dump: в строке интерфейса %d полей, ожидалось 4", iface, len(f))
			}
			continue
		}
		if len(f) != 8 {
			return nil, fmt.Errorf("wg show %s dump: в строке %d — %d полей, ожидалось 8", iface, n, len(f))
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		p := WGPeer{Interface: iface, PublicKey: f[0], RxBytes: rx, TxBytes: tx}
		if f[2] != "(none)" {
			p.Endpoint = NormalizeAddr(f[2])
		}
		if hs > 0 {
			p.LatestHandshake = time.Unix(hs, 0)
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// WGShow — пиры интерфейса. Интерфейса нет (WireGuard выключен в setup) —
// пусто без ошибки.
func WGShow(ctx context.Context, iface string) ([]WGPeer, error) {
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return nil, nil
	}
	out, err := exec.CommandContext(ctx, "wg", "show", iface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show %s dump: %w", iface, err)
	}
	return ParseWGDump(iface, bytes.NewReader(out))
}
```

- [ ] **Step 5: Тесты проходят**

Run: `go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/node internal/antizapret
git commit -m "Подробности сессий OpenVPN из снимка и разбор wg show dump

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Ресурсы сервера и состояние служб

**Files:**
- Create: `internal/sysinfo/proc.go`, `internal/sysinfo/sampler.go`, `internal/sysinfo/disk_linux.go`, `internal/sysinfo/disk_other.go`, `internal/sysinfo/services.go`
- Test: `internal/sysinfo/proc_test.go`, `internal/sysinfo/sampler_test.go`, `internal/sysinfo/services_test.go`

**Interfaces:**
- Produces:
  - `sysinfo.CPUTimes{Idle, Total uint64}`, `ParseCPU(io.Reader) (CPUTimes, error)`, `CPUPercent(prev, cur CPUTimes) float64`;
  - `sysinfo.Memory{TotalBytes, AvailableBytes uint64}`, `ParseMeminfo(io.Reader) (Memory, error)`;
  - `sysinfo.NetCounters{RxBytes, TxBytes uint64}`, `ParseNetDev(io.Reader, iface string) (NetCounters, error)`, `DefaultRouteIface(io.Reader) (string, error)`;
  - `ParseUptime(io.Reader) (time.Duration, error)`, `ParseLoadavg(io.Reader) ([3]float64, error)`;
  - `sysinfo.Disk{TotalBytes, FreeBytes uint64}`, `DiskUsage(path string) (Disk, error)`;
  - `sysinfo.Snapshot{Taken time.Time; CPUPercent float64; Load [3]float64; Memory Memory; Disk Disk; NetIface string; Net NetCounters; UptimeSec int64}` (JSON-теги snake_case);
  - `sysinfo.Sampler{Proc, DiskPath string}`, `(*Sampler).Sample(now time.Time) (Snapshot, error)`;
  - `sysinfo.Service{Unit, State string}`, `ServiceUnits(kresd []string, wireguard bool) []string`, `ParseListUnits(string) []string`, `ParseIsActive(units []string, out string) []Service`, `Services(ctx, units) ([]Service, error)`, `KresdUnits(ctx) ([]string, error)`.

- [ ] **Step 1: Написать падающие тесты**

`internal/sysinfo/proc_test.go`:

```go
package sysinfo

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestParseCPU(t *testing.T) {
	c, err := ParseCPU(strings.NewReader("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 100 0 50 800 50 0 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Idle != 850 || c.Total != 1000 {
		t.Fatalf("%+v", c)
	}
	if _, err := ParseCPU(strings.NewReader("intr 1 2 3\n")); err == nil {
		t.Fatal("нет строки cpu — нет ошибки")
	}
}

func TestCPUPercent(t *testing.T) {
	prev := CPUTimes{Idle: 850, Total: 1000}
	cur := CPUTimes{Idle: 925, Total: 1100}
	if p := CPUPercent(prev, cur); math.Abs(p-25) > 0.001 {
		t.Fatalf("p = %v", p)
	}
	if p := CPUPercent(cur, cur); p != 0 {
		t.Fatalf("без прироста p = %v", p)
	}
}

func TestParseMeminfo(t *testing.T) {
	m, err := ParseMeminfo(strings.NewReader("MemTotal:        2014056 kB\nMemFree:  100 kB\nMemAvailable:    1000000 kB\n"))
	if err != nil || m.TotalBytes != 2014056*1024 || m.AvailableBytes != 1000000*1024 {
		t.Fatalf("%+v, %v", m, err)
	}
	if _, err := ParseMeminfo(strings.NewReader("MemTotal: 1 kB\n")); err == nil {
		t.Fatal("без MemAvailable — нет ошибки")
	}
}

const netDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     100       1    0    0    0     0          0         0      100       1    0    0    0     0       0          0
  eth0: 123456     100    0    0    0     0          0         0   654321     200    0    0    0     0       0          0
`

func TestParseNetDev(t *testing.T) {
	n, err := ParseNetDev(strings.NewReader(netDev), "eth0")
	if err != nil || n.RxBytes != 123456 || n.TxBytes != 654321 {
		t.Fatalf("%+v, %v", n, err)
	}
	if _, err := ParseNetDev(strings.NewReader(netDev), "eth9"); err == nil {
		t.Fatal("нет интерфейса — нет ошибки")
	}
}

func TestDefaultRouteIface(t *testing.T) {
	route := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"vpn-udp\t0018A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	i, err := DefaultRouteIface(strings.NewReader(route))
	if err != nil || i != "eth0" {
		t.Fatalf("%q, %v", i, err)
	}
}

func TestParseUptimeLoadavg(t *testing.T) {
	u, err := ParseUptime(strings.NewReader("3600.52 100.00\n"))
	if err != nil || u != 3600*time.Second+520*time.Millisecond {
		t.Fatalf("%v, %v", u, err)
	}
	l, err := ParseLoadavg(strings.NewReader("0.15 0.10 0.05 1/123 4567\n"))
	if err != nil || l != [3]float64{0.15, 0.10, 0.05} {
		t.Fatalf("%v, %v", l, err)
	}
}
```

`internal/sysinfo/sampler_test.go`:

```go
package sysinfo

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeProc(t *testing.T, dir, stat string) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
	os.WriteFile(filepath.Join(dir, "meminfo"), []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "loadavg"), []byte("0.50 0.40 0.30 1/1 1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "uptime"), []byte("120.00 50.00\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "route"), []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "dev"), []byte(netDev), 0o644)
}

func TestSampler(t *testing.T) {
	dir := t.TempDir()
	writeProc(t, dir, "cpu  100 0 50 800 50 0 0 0\n")
	s := &Sampler{Proc: dir, DiskPath: dir}
	first, err := s.Sample(time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(first.CPUPercent-15) > 0.001 { // с загрузки: 150 из 1000
		t.Fatalf("первый замер CPU %v", first.CPUPercent)
	}
	if first.Memory.TotalBytes != 1000*1024 || first.UptimeSec != 120 || first.Load[0] != 0.5 {
		t.Fatalf("%+v", first)
	}
	if first.NetIface != "eth0" || first.Net.RxBytes != 123456 {
		t.Fatalf("сеть: %+v", first)
	}
	writeProc(t, dir, "cpu  175 0 50 825 50 0 0 0\n") // +100 всего, +25 простоя
	second, _ := s.Sample(time.Unix(20, 0))
	if math.Abs(second.CPUPercent-75) > 0.001 {
		t.Fatalf("второй замер CPU %v", second.CPUPercent)
	}
}

func TestSamplerNeedsCPUAndMemory(t *testing.T) {
	s := &Sampler{Proc: t.TempDir(), DiskPath: "/"}
	if _, err := s.Sample(time.Now()); err == nil {
		t.Fatal("без /proc/stat — нет ошибки")
	}
}
```

`internal/sysinfo/services_test.go`:

```go
package sysinfo

import (
	"strings"
	"testing"
)

func TestServiceUnits(t *testing.T) {
	got := strings.Join(ServiceUnits([]string{"kresd@1", "kresd@2"}, false), ",")
	want := "openvpn-server@antizapret-udp,openvpn-server@antizapret-tcp,openvpn-server@vpn-udp,openvpn-server@vpn-tcp,kresd@1,kresd@2,azpanel-node"
	if got != want {
		t.Fatalf("%s", got)
	}
	if got := ServiceUnits(nil, true); !strings.Contains(strings.Join(got, ","), "wg-quick@antizapret,wg-quick@vpn") {
		t.Fatalf("%v", got)
	}
}

func TestParseListUnits(t *testing.T) {
	out := "kresd@2.service loaded active running Knot Resolver daemon\nkresd@1.service loaded active running Knot Resolver daemon\n"
	if got := strings.Join(ParseListUnits(out), ","); got != "kresd@1,kresd@2" {
		t.Fatalf("%s", got)
	}
}

func TestParseIsActive(t *testing.T) {
	got := ParseIsActive([]string{"a", "b", "c"}, "active\nfailed\n")
	if len(got) != 3 || got[0].State != "active" || got[1].State != "failed" || got[2].State != "unknown" {
		t.Fatalf("%+v", got)
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/sysinfo/`
Expected: FAIL — пакет без исходников.

- [ ] **Step 3: Реализовать `proc.go`**

```go
// Package sysinfo — ресурсы сервера из /proc и состояние служб systemd.
package sysinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type CPUTimes struct{ Idle, Total uint64 }

// ParseCPU — строка «cpu» /proc/stat: user nice system idle iowait irq
// softirq steal. Простой — idle + iowait; guest уже входит в user.
func ParseCPU(r io.Reader) (CPUTimes, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 9 || f[0] != "cpu" {
			continue
		}
		var v [8]uint64
		var total uint64
		for i := range v {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return CPUTimes{}, fmt.Errorf("/proc/stat: %w", err)
			}
			v[i] = n
			total += n
		}
		return CPUTimes{Idle: v[3] + v[4], Total: total}, nil
	}
	return CPUTimes{}, errors.New("/proc/stat: нет строки cpu")
}

// CPUPercent — доля занятого времени между двумя замерами.
func CPUPercent(prev, cur CPUTimes) float64 {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return 0
	}
	dt := cur.Total - prev.Total
	di := cur.Idle - prev.Idle
	if di > dt {
		return 0
	}
	return 100 * float64(dt-di) / float64(dt)
}

type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

func ParseMeminfo(r io.Reader) (Memory, error) {
	var m Memory
	var haveTotal, haveAvail bool
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			m.TotalBytes, haveTotal = n*1024, true
		case "MemAvailable:":
			m.AvailableBytes, haveAvail = n*1024, true
		}
	}
	if !haveTotal || !haveAvail {
		return Memory{}, errors.New("/proc/meminfo: нет MemTotal или MemAvailable")
	}
	return m, sc.Err()
}

type NetCounters struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// ParseNetDev — счётчики интерфейса из /proc/net/dev: после «имя:» восемь
// полей приёма, затем передача.
func ParseNetDev(r io.Reader, iface string) (NetCounters, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			return NetCounters{}, fmt.Errorf("/proc/net/dev: мало полей у %s", iface)
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			return NetCounters{}, fmt.Errorf("/proc/net/dev: счётчики %s не разобраны", iface)
		}
		return NetCounters{RxBytes: rx, TxBytes: tx}, nil
	}
	return NetCounters{}, fmt.Errorf("/proc/net/dev: нет интерфейса %s", iface)
}

// DefaultRouteIface — интерфейс маршрута по умолчанию из /proc/net/route.
func DefaultRouteIface(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0], nil
		}
	}
	return "", errors.New("/proc/net/route: нет маршрута по умолчанию")
}

func ParseUptime(r io.Reader) (time.Duration, error) {
	var s float64
	if _, err := fmt.Fscan(r, &s); err != nil {
		return 0, fmt.Errorf("/proc/uptime: %w", err)
	}
	return time.Duration(s * float64(time.Second)).Round(time.Millisecond), nil
}

func ParseLoadavg(r io.Reader) ([3]float64, error) {
	var l [3]float64
	if _, err := fmt.Fscan(r, &l[0], &l[1], &l[2]); err != nil {
		return l, fmt.Errorf("/proc/loadavg: %w", err)
	}
	return l, nil
}
```

- [ ] **Step 4: Реализовать диск и сэмплер**

`internal/sysinfo/disk_linux.go`:

```go
//go:build linux

package sysinfo

import "syscall"

func DiskUsage(path string) (Disk, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Disk{}, err
	}
	bs := uint64(st.Bsize)
	return Disk{TotalBytes: st.Blocks * bs, FreeBytes: st.Bavail * bs}, nil
}
```

`internal/sysinfo/disk_other.go`:

```go
//go:build !linux

package sysinfo

import "errors"

func DiskUsage(string) (Disk, error) {
	return Disk{}, errors.New("место на диске считается только на linux")
}
```

`internal/sysinfo/sampler.go`:

```go
package sysinfo

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Disk struct {
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

type Snapshot struct {
	Taken      time.Time   `json:"taken"`
	CPUPercent float64     `json:"cpu_percent"`
	Load       [3]float64  `json:"load"`
	Memory     Memory      `json:"memory"`
	Disk       Disk        `json:"disk"`
	NetIface   string      `json:"net_iface"`
	Net        NetCounters `json:"net"`
	UptimeSec  int64       `json:"uptime_seconds"`
}

// Sampler снимает ресурсы по запросу. CPU — доля занятого времени с
// прошлого вызова (у первого — с загрузки системы), поэтому фонового
// опроса не нужно: панель спрашивает раз в collect_seconds.
type Sampler struct {
	Proc     string // /proc
	DiskPath string // /
	mu       sync.Mutex
	prev     CPUTimes
}

// Sample: без CPU и памяти — ошибка; нагрузка, uptime, сеть и диск
// необязательны, их сбой оставляет нули.
func (s *Sampler) Sample(now time.Time) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{Taken: now.UTC()}
	cpu, err := parseFile(filepath.Join(s.Proc, "stat"), ParseCPU)
	if err != nil {
		return snap, err
	}
	snap.CPUPercent, s.prev = CPUPercent(s.prev, cpu), cpu
	if snap.Memory, err = parseFile(filepath.Join(s.Proc, "meminfo"), ParseMeminfo); err != nil {
		return snap, err
	}
	if l, err := parseFile(filepath.Join(s.Proc, "loadavg"), ParseLoadavg); err == nil {
		snap.Load = l
	}
	if u, err := parseFile(filepath.Join(s.Proc, "uptime"), ParseUptime); err == nil {
		snap.UptimeSec = int64(u / time.Second)
	}
	if iface, err := parseFile(filepath.Join(s.Proc, "net", "route"), DefaultRouteIface); err == nil {
		snap.NetIface = iface
		parse := func(r io.Reader) (NetCounters, error) { return ParseNetDev(r, iface) }
		if n, err := parseFile(filepath.Join(s.Proc, "net", "dev"), parse); err == nil {
			snap.Net = n
		}
	}
	if d, err := DiskUsage(s.DiskPath); err == nil {
		snap.Disk = d
	}
	return snap, nil
}

func parseFile[T any](path string, parse func(io.Reader) (T, error)) (T, error) {
	f, err := os.Open(path)
	if err != nil {
		var zero T
		return zero, err
	}
	defer f.Close()
	return parse(f)
}
```

- [ ] **Step 5: Реализовать `services.go`**

```go
package sysinfo

import (
	"context"
	"errors"
	"os/exec"
	"sort"
	"strings"
)

type Service struct {
	Unit  string `json:"unit"`
	State string `json:"state"` // active, inactive, failed, …; unknown — systemd не ответил
}

var openvpnUnits = []string{
	"openvpn-server@antizapret-udp", "openvpn-server@antizapret-tcp",
	"openvpn-server@vpn-udp", "openvpn-server@vpn-tcp",
}

// ServiceUnits — что показывать: четыре экземпляра OpenVPN, найденные
// kresd@*, wg-quick@antizapret и @vpn — если WireGuard включён, агент.
func ServiceUnits(kresd []string, wireguard bool) []string {
	out := append([]string{}, openvpnUnits...)
	out = append(out, kresd...)
	if wireguard {
		out = append(out, "wg-quick@antizapret", "wg-quick@vpn")
	}
	return append(out, "azpanel-node")
}

// ParseListUnits — первый столбец «systemctl list-units --plain --no-legend»
// без «.service», по алфавиту.
func ParseListUnits(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			units = append(units, strings.TrimSuffix(f[0], ".service"))
		}
	}
	sort.Strings(units)
	return units
}

// ParseIsActive — вывод «systemctl is-active u1 u2 …»: строка на юнит в
// том же порядке.
func ParseIsActive(units []string, out string) []Service {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	svcs := make([]Service, len(units))
	for i, u := range units {
		svcs[i] = Service{Unit: u, State: "unknown"}
		if i < len(lines) && strings.TrimSpace(lines[i]) != "" {
			svcs[i].State = strings.TrimSpace(lines[i])
		}
	}
	return svcs
}

// Services опрашивает systemd. is-active выходит с ненулевым кодом, если
// хоть один юнит не active, — это не ошибка: состояние в выводе.
func Services(ctx context.Context, units []string) ([]Service, error) {
	out, err := exec.CommandContext(ctx, "systemctl", append([]string{"is-active"}, units...)...).Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return nil, err
	}
	return ParseIsActive(units, string(out)), nil
}

// KresdUnits — экземпляры kresd@*, сколько их запустил AntiZapret.
func KresdUnits(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--plain", "--no-legend", "--all", "kresd@*").Output()
	if err != nil {
		return nil, err
	}
	return ParseListUnits(string(out)), nil
}
```

- [ ] **Step 6: Тесты проходят, сборка под linux цела**

Run: `go vet ./... && go test ./internal/sysinfo/ && GOOS=linux go vet ./internal/sysinfo/`
Expected: PASS, `vet` под linux без замечаний.

- [ ] **Step 7: Commit**

```bash
git add internal/sysinfo
git commit -m "Ресурсы сервера из /proc и состояние служб systemd

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Типы API и HTTP-клиент для панели

**Files:**
- Create: `internal/nodeapi/nodeapi.go`
- Test: `internal/nodeapi/nodeapi_test.go`

**Interfaces:**
- Consumes: `sysinfo.Snapshot`, `sysinfo.Service`.
- Produces (всё в пакете `nodeapi`):
  - константы `Proto = 1`, `ProtoHeader = "X-Azpanel-Proto"`, `KindOpenVPN = "openvpn"`, `KindWireGuard = "wireguard"`;
  - типы `Info`, `Client`, `Session`, `System`, `Profile`, `CreateClient`, `Renew`, `SetLimit`, `SetBlocked`, `Result`, `ErrorBody`, `*Error{Status int; Message string}`;
  - `New(baseURL, token string) *HTTPClient` и методы `Info`, `Clients`, `Sessions`, `System`, `Profiles(ctx, name)`, `Profile(ctx, name string, p Profile) ([]byte, error)`, `CreateClient(ctx, CreateClient) (Result, error)`, `Renew(ctx, name string, days int) (Result, error)`, `DeleteClient(ctx, kind, name string) (Result, error)`, `SetLimit(ctx, name string, limit int) error`, `SetBlocked(ctx, name string, blocked bool) (Result, error)`.
  - Маршруты (их же регистрирует агент в задаче 8):

| Метод и путь | Тело запроса | Ответ |
| --- | --- | --- |
| `GET /v1/info` | — | `Info` |
| `GET /v1/clients` | — | `[]Client` |
| `POST /v1/clients` | `CreateClient` | 201 `Result` |
| `POST /v1/clients/openvpn/{name}/renew` | `Renew` | `Result` |
| `DELETE /v1/clients/{kind}/{name}` | — | `Result` |
| `GET /v1/clients/{name}/profiles` | — | `[]Profile` |
| `GET /v1/clients/{name}/profiles/{kind}/{variant}/{file}` | — | файл |
| `PUT /v1/clients/{name}/limit` | `SetLimit` | 204 |
| `PUT /v1/clients/{name}/blocked` | `SetBlocked` | `Result` |
| `GET /v1/sessions` | — | `[]Session` |
| `GET /v1/system` | — | `System` |

- [ ] **Step 1: Написать падающий тест**

`internal/nodeapi/nodeapi_test.go`:

```go
package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientSendsTokenAndEscapesPath(t *testing.T) {
	mux := http.NewServeMux()
	var gotAuth, gotFile string
	mux.HandleFunc("GET /v1/clients/{name}/profiles/{kind}/{variant}/{file}", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotFile = r.PathValue("file")
		w.Write([]byte("PROFILE"))
	})
	mux.HandleFunc("POST /v1/clients", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorBody{Error: "клиент OpenVPN с таким именем уже есть"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL+"/", "TOKEN")
	data, err := c.Profile(context.Background(), "alice", Profile{Kind: "openvpn", Variant: "antizapret-udp", File: "antizapret-alice-(1.2.3.4)-udp.ovpn"})
	if err != nil || string(data) != "PROFILE" {
		t.Fatalf("data %q, err %v", data, err)
	}
	if gotAuth != "Bearer TOKEN" || gotFile != "antizapret-alice-(1.2.3.4)-udp.ovpn" {
		t.Fatalf("auth %q, file %q", gotAuth, gotFile)
	}

	_, err = c.CreateClient(context.Background(), CreateClient{Name: "alice", Kind: KindOpenVPN})
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict || e.Message != "клиент OpenVPN с таким именем уже есть" {
		t.Fatalf("err = %v", err)
	}
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `go test ./internal/nodeapi/`
Expected: FAIL — пакет без исходников.

- [ ] **Step 3: Реализовать `nodeapi.go`**

```go
// Package nodeapi — HTTP API агента узла: типы запросов и ответов и клиент,
// которым пользуется панель. Proto растёт при несовместимых изменениях;
// панель работает с агентами своей и предыдущей версии протокола.
package nodeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/sysinfo"
)

const (
	Proto       = 1
	ProtoHeader = "X-Azpanel-Proto"

	KindOpenVPN   = "openvpn"
	KindWireGuard = "wireguard"

	maxResponse = 16 << 20
)

type Info struct {
	Proto     int    `json:"proto"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname"`
	WireGuard bool   `json:"wireguard"` // WIREGUARD_ENABLE=y в setup
}

type Client struct {
	Name        string     `json:"name"`
	OpenVPN     bool       `json:"openvpn"`
	WireGuard   bool       `json:"wireguard"`
	CertExpires *time.Time `json:"cert_expires,omitempty"`
	Limit       int        `json:"limit"` // 0 — без ограничения
	Blocked     bool       `json:"blocked"`
}

type Session struct {
	Kind          string     `json:"kind"`     // openvpn, wireguard
	Instance      string     `json:"instance"` // экземпляр OpenVPN или интерфейс WG
	Name          string     `json:"name"`
	Addr          string     `json:"addr"`
	RxBytes       int64      `json:"rx_bytes"` // принято сервером от клиента
	TxBytes       int64      `json:"tx_bytes"`
	Since         *time.Time `json:"since,omitempty"`          // OpenVPN
	LastHandshake *time.Time `json:"last_handshake,omitempty"` // WireGuard
}

type System struct {
	Resources sysinfo.Snapshot  `json:"resources"`
	Services  []sysinfo.Service `json:"services"`
}

type Profile struct {
	Kind    string `json:"kind"`
	Variant string `json:"variant"`
	File    string `json:"file"`
}

type CreateClient struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Days int    `json:"days,omitempty"` // только OpenVPN; 0 — 3650
}

type Renew struct {
	Days int `json:"days"`
}

type SetLimit struct {
	Limit int `json:"limit"` // 0 — снять лимит
}

type SetBlocked struct {
	Blocked bool `json:"blocked"`
}

type Result struct {
	Output string `json:"output,omitempty"` // хвост вывода client.sh
	Killed int    `json:"killed,omitempty"` // разорвано сессий при блокировке
}

type ErrorBody struct {
	Error string `json:"error"`
}

// Error — ответ агента с кодом 4xx или 5xx.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("агент ответил %d: %s", e.Status, e.Message) }

type HTTPClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New: тайм-аут с запасом на самый долгий client.sh (до 10 минут по
// настройке узла).
func New(baseURL, token string) *HTTPClient {
	return &HTTPClient{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 11 * time.Minute}}
}

func (c *HTTPClient) Info(ctx context.Context) (Info, error) {
	var v Info
	return v, c.do(ctx, http.MethodGet, "/v1/info", nil, &v)
}

func (c *HTTPClient) Clients(ctx context.Context) ([]Client, error) {
	var v []Client
	return v, c.do(ctx, http.MethodGet, "/v1/clients", nil, &v)
}

func (c *HTTPClient) Sessions(ctx context.Context) ([]Session, error) {
	var v []Session
	return v, c.do(ctx, http.MethodGet, "/v1/sessions", nil, &v)
}

func (c *HTTPClient) System(ctx context.Context) (System, error) {
	var v System
	return v, c.do(ctx, http.MethodGet, "/v1/system", nil, &v)
}

func (c *HTTPClient) Profiles(ctx context.Context, name string) ([]Profile, error) {
	var v []Profile
	return v, c.do(ctx, http.MethodGet, "/v1/clients/"+url.PathEscape(name)+"/profiles", nil, &v)
}

func (c *HTTPClient) Profile(ctx context.Context, name string, p Profile) ([]byte, error) {
	path := "/v1/clients/" + url.PathEscape(name) + "/profiles/" +
		url.PathEscape(p.Kind) + "/" + url.PathEscape(p.Variant) + "/" + url.PathEscape(p.File)
	return c.raw(ctx, http.MethodGet, path, nil)
}

func (c *HTTPClient) CreateClient(ctx context.Context, req CreateClient) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodPost, "/v1/clients", req, &v)
}

func (c *HTTPClient) Renew(ctx context.Context, name string, days int) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodPost, "/v1/clients/openvpn/"+url.PathEscape(name)+"/renew", Renew{Days: days}, &v)
}

func (c *HTTPClient) DeleteClient(ctx context.Context, kind, name string) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodDelete, "/v1/clients/"+url.PathEscape(kind)+"/"+url.PathEscape(name), nil, &v)
}

func (c *HTTPClient) SetLimit(ctx context.Context, name string, limit int) error {
	return c.do(ctx, http.MethodPut, "/v1/clients/"+url.PathEscape(name)+"/limit", SetLimit{Limit: limit}, nil)
}

func (c *HTTPClient) SetBlocked(ctx context.Context, name string, blocked bool) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodPut, "/v1/clients/"+url.PathEscape(name)+"/blocked", SetBlocked{Blocked: blocked}, &v)
}

func (c *HTTPClient) do(ctx context.Context, method, path string, in, out any) error {
	body, err := c.raw(ctx, method, path, in)
	if err != nil || out == nil || len(body) == 0 {
		return err
	}
	return json.Unmarshal(body, out)
}

func (c *HTTPClient) raw(ctx context.Context, method, path string, in any) ([]byte, error) {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode >= 400 {
		var e ErrorBody
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return nil, &Error{Status: resp.StatusCode, Message: e.Error}
	}
	return body, err
}
```

- [ ] **Step 4: Тест проходит**

Run: `go vet ./... && go test ./internal/nodeapi/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/nodeapi
git commit -m "Типы API агента и HTTP-клиент для панели

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Обработчики HTTP API агента

**Files:**
- Create: `internal/node/api.go`
- Test: `internal/node/api_test.go`

**Interfaces:**
- Consumes: всё из задач 2–7: `limits.Load/Save/Data/ValidName`, `antizapret.Inventory`, `antizapret.ClientSh`, `antizapret.Profiles/ProfilePath/ErrNotFound`, `antizapret.ListSockets`, `antizapret.ReadSetup`, `antizapret.WGInterfaces`, `antizapret.WGPeer`, `(*Tracker).Sessions`, `sysinfo.Sampler`, `sysinfo.Service`, типы `nodeapi`.
- Produces: `node.API{Token, Version string; Tracker *Tracker; LimitsPath string; Inventory antizapret.Inventory; ClientSh *antizapret.ClientSh; AntiZapretDir, SocketDir string; Sampler *sysinfo.Sampler; Services func(context.Context) ([]sysinfo.Service, error); WGShow func(context.Context, string) ([]antizapret.WGPeer, error); Kill func(sock, name string, timeout time.Duration) (int, error); Log *slog.Logger; Now func() time.Time}`, `(*API).Handler() http.Handler`, `(*API).WireGuardEnabled() bool`.

- [ ] **Step 1: Написать падающие тесты**

`internal/node/api_test.go`:

```go
package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type apiEnv struct {
	api    *API
	client *nodeapi.HTTPClient
	srv    *httptest.Server
	calls  *[]string
	kills  *[]string
}

func newAPI(t *testing.T) apiEnv {
	t.Helper()
	root := t.TempDir()
	pki := filepath.Join(root, "pki")
	wg := filepath.Join(root, "wireguard")
	az := filepath.Join(root, "antizapret")
	socks := filepath.Join(root, "run")
	proc := filepath.Join(root, "proc")
	for _, d := range []string{filepath.Join(pki, "issued"), wg, az, socks, proc} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(pki, "issued", "alice.crt"), []byte("не PEM"), 0o644)
	os.WriteFile(filepath.Join(wg, "antizapret.conf"), []byte("# Client = alice\n# PrivateKey = ALICEPRIVATE\n[Peer]\nPublicKey = ALICEPUB\nPresharedKey = ALICEPSK\nAllowedIPs = 10.29.8.2/32\n"), 0o600)
	os.WriteFile(filepath.Join(az, "setup"), []byte("WIREGUARD_ENABLE=y\n"), 0o644)
	prof := filepath.Join(az, "client", "openvpn", "antizapret-udp")
	os.MkdirAll(prof, 0o755)
	os.WriteFile(filepath.Join(prof, "antizapret-alice-(1.2.3.4)-udp.ovpn"), []byte("OVPN-ALICE"), 0o644)
	for _, s := range []string{"antizapret-udp.sock", "vpn-udp.sock"} {
		os.WriteFile(filepath.Join(socks, s), nil, 0o600)
	}
	os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu  100 0 50 800 50 0 0 0\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), 0o644)

	now := time.Unix(2_000_000_000, 0)
	tr := NewTracker()
	tr.ApplySnapshot("antizapret-udp", now, []antizapret.Session{{
		Instance: "antizapret-udp", CommonName: "alice", RealAddr: "5.6.7.8:1000", BytesRx: 1, BytesTx: 2, ConnectedSince: now.Add(-time.Hour),
	}})

	var calls, kills []string
	// Имитация client.sh: опция 2 удаляет сертификат, 5 — пиров WG.
	run := func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "2":
			os.Remove(filepath.Join(pki, "issued", args[1]+".crt"))
		case "5":
			os.WriteFile(filepath.Join(wg, "antizapret.conf"), nil, 0o600)
		}
		return []byte("готово\n"), nil
	}
	api := &API{
		Token: testToken, Version: "v-test", Tracker: tr,
		LimitsPath:    filepath.Join(root, "limits.json"),
		Inventory:     antizapret.Inventory{PKI: pki, WireGuardDir: wg},
		ClientSh:      &antizapret.ClientSh{Dir: az, Timeout: time.Second, Run: run},
		AntiZapretDir: az,
		SocketDir:     socks,
		Sampler:       &sysinfo.Sampler{Proc: proc, DiskPath: root},
		Services: func(context.Context) ([]sysinfo.Service, error) {
			return []sysinfo.Service{{Unit: "openvpn-server@antizapret-udp", State: "active"}}, nil
		},
		WGShow: func(_ context.Context, iface string) ([]antizapret.WGPeer, error) {
			if iface != "antizapret" {
				return nil, nil
			}
			return []antizapret.WGPeer{
				{Interface: iface, PublicKey: "ALICEPUB", Endpoint: "9.9.9.9:51820", LatestHandshake: now.Add(-time.Minute), RxBytes: 5, TxBytes: 6},
				{Interface: iface, PublicKey: "STALEPUB", Endpoint: "8.8.8.8:1", LatestHandshake: now.Add(-time.Minute)},
			}, nil
		},
		Kill: func(sock, name string, _ time.Duration) (int, error) {
			kills = append(kills, filepath.Base(sock)+" "+name)
			return 1, nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now },
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return apiEnv{api: api, client: nodeapi.New(srv.URL, testToken), srv: srv, calls: &calls, kills: &kills}
}

func status(err error) int {
	var e *nodeapi.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func TestAPIRequiresToken(t *testing.T) {
	e := newAPI(t)
	for _, auth := range []string{"", "Bearer wrong", "Bearer " + testToken + "x", testToken} {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/info", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(nodeapi.ProtoHeader) != "1" {
			t.Fatalf("%q: %d, proto %q", auth, resp.StatusCode, resp.Header.Get(nodeapi.ProtoHeader))
		}
	}
	info, err := e.client.Info(context.Background())
	if err != nil || info.Proto != 1 || info.Version != "v-test" || !info.WireGuard {
		t.Fatalf("%+v, %v", info, err)
	}
}

func TestAPIEmptyTokenRejectsAll(t *testing.T) {
	e := newAPI(t)
	e.api.Token = ""
	if _, err := nodeapi.New(e.srv.URL, "").Info(context.Background()); status(err) != http.StatusUnauthorized {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIClients(t *testing.T) {
	e := newAPI(t)
	limits.Save(e.api.LimitsPath, limits.Data{Limits: map[string]int{"alice": 2}, Blocked: map[string]bool{"alice": true}})
	cs, err := e.client.Clients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Name != "alice" || !cs[0].OpenVPN || !cs[0].WireGuard || cs[0].Limit != 2 || !cs[0].Blocked || cs[0].CertExpires != nil {
		t.Fatalf("%+v", cs)
	}
}

func TestAPICreateClient(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindOpenVPN, Days: 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "carol", Kind: nodeapi.KindOpenVPN}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindWireGuard}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		req  nodeapi.CreateClient
		code int
	}{
		{nodeapi.CreateClient{Name: "alice", Kind: nodeapi.KindOpenVPN}, http.StatusConflict},
		{nodeapi.CreateClient{Name: "alice", Kind: nodeapi.KindWireGuard}, http.StatusConflict},
		{nodeapi.CreateClient{Name: "bad name", Kind: nodeapi.KindOpenVPN}, http.StatusBadRequest},
		{nodeapi.CreateClient{Name: "dan", Kind: "ipsec"}, http.StatusBadRequest},
		{nodeapi.CreateClient{Name: "dan", Kind: nodeapi.KindOpenVPN, Days: 5000}, http.StatusBadRequest},
	} {
		if _, err := e.client.CreateClient(ctx, bad.req); status(err) != bad.code {
			t.Fatalf("%+v: err = %v", bad.req, err)
		}
	}
	if got := strings.Join(*e.calls, "|"); got != "1 bob 30|1 carol 3650|4 bob" {
		t.Fatalf("вызовы client.sh: %s", got)
	}
}

func TestAPIRenewAndDelete(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	limits.Save(e.api.LimitsPath, limits.Data{Limits: map[string]int{"alice": 2}, Blocked: map[string]bool{"alice": true}})
	if _, err := e.client.Renew(ctx, "alice", 90); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Renew(ctx, "ghost", 90); status(err) != http.StatusNotFound {
		t.Fatalf("ghost: %v", err)
	}
	if _, err := e.client.Renew(ctx, "alice", 0); status(err) != http.StatusBadRequest {
		t.Fatalf("0 дней: %v", err)
	}
	if _, err := e.client.DeleteClient(ctx, nodeapi.KindOpenVPN, "alice"); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); d.Limits["alice"] != 2 {
		t.Fatal("лимит снят, хотя у клиента остался WireGuard")
	}
	if _, err := e.client.DeleteClient(ctx, nodeapi.KindOpenVPN, "alice"); status(err) != http.StatusNotFound {
		t.Fatalf("повторное удаление: %v", err)
	}
	if _, err := e.client.DeleteClient(ctx, nodeapi.KindWireGuard, "alice"); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); len(d.Limits) != 0 || len(d.Blocked) != 0 {
		t.Fatalf("лимит и блокировка удалённого клиента остались: %+v", d)
	}
	if got := strings.Join(*e.calls, "|"); got != "1 alice 90|2 alice|5 alice" {
		t.Fatalf("вызовы client.sh: %s", got)
	}
}

func TestAPIProfiles(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	ps, err := e.client.Profiles(ctx, "alice")
	if err != nil || len(ps) != 1 || ps[0].File != "antizapret-alice-(1.2.3.4)-udp.ovpn" {
		t.Fatalf("%+v, %v", ps, err)
	}
	data, err := e.client.Profile(ctx, "alice", ps[0])
	if err != nil || string(data) != "OVPN-ALICE" {
		t.Fatalf("%q, %v", data, err)
	}
	if _, err := e.client.Profile(ctx, "alice", nodeapi.Profile{Kind: "openvpn", Variant: "antizapret-udp", File: "../../setup"}); status(err) != http.StatusNotFound {
		t.Fatalf("выход из каталога: %v", err)
	}
}

func TestAPILimitAndBlock(t *testing.T) {
	e := newAPI(t)
	ctx := context.Background()
	if err := e.client.SetLimit(ctx, "alice", 3); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); d.Limits["alice"] != 3 {
		t.Fatalf("%+v", d)
	}
	if err := e.client.SetLimit(ctx, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); len(d.Limits) != 0 {
		t.Fatalf("лимит не снят: %+v", d)
	}
	if err := e.client.SetLimit(ctx, "alice", -1); status(err) != http.StatusBadRequest {
		t.Fatalf("-1: %v", err)
	}
	res, err := e.client.SetBlocked(ctx, "alice", true)
	if err != nil || res.Killed != 2 {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := strings.Join(*e.kills, "|"); got != "antizapret-udp.sock alice|vpn-udp.sock alice" {
		t.Fatalf("kill: %s", got)
	}
	if d, _ := limits.Load(e.api.LimitsPath); !d.Blocked["alice"] {
		t.Fatalf("блокировка не записана: %+v", d)
	}
	if _, err := e.client.SetBlocked(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if d, _ := limits.Load(e.api.LimitsPath); d.Blocked["alice"] || len(*e.kills) != 2 {
		t.Fatalf("разблокировка: %+v, kill %v", d, *e.kills)
	}
}

func TestAPIBrokenLimitsNotOverwritten(t *testing.T) {
	e := newAPI(t)
	os.WriteFile(e.api.LimitsPath, []byte("{"), 0o600)
	if err := e.client.SetLimit(context.Background(), "alice", 3); status(err) != http.StatusInternalServerError {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(e.api.LimitsPath); string(b) != "{" {
		t.Fatalf("испорченный файл перезаписан: %q", b)
	}
}

func TestAPISessionsHidesKeys(t *testing.T) {
	e := newAPI(t)
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, secret := range []string{"ALICEPUB", "ALICEPSK", "ALICEPRIVATE", "STALEPUB"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("в ответе %s:\n%s", secret, body)
		}
	}
	ss, err := e.client.Sessions(context.Background())
	if err != nil || len(ss) != 2 {
		t.Fatalf("%+v, %v", ss, err)
	}
	if ss[0].Kind != nodeapi.KindOpenVPN || ss[0].Name != "alice" || ss[0].Addr != "5.6.7.8:1000" || ss[0].Since == nil {
		t.Fatalf("OpenVPN: %+v", ss[0])
	}
	if ss[1].Kind != nodeapi.KindWireGuard || ss[1].Name != "alice" || ss[1].Instance != "antizapret" || ss[1].RxBytes != 5 || ss[1].LastHandshake == nil {
		t.Fatalf("WireGuard: %+v", ss[1])
	}
}

func TestAPISystem(t *testing.T) {
	e := newAPI(t)
	s, err := e.client.System(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Resources.Memory.TotalBytes != 1000*1024 || len(s.Services) != 1 || s.Services[0].State != "active" {
		t.Fatalf("%+v", s)
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/node/`
Expected: FAIL — `undefined: API`.

- [ ] **Step 3: Реализовать `internal/node/api.go`**

```go
package node

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const (
	maxAPIBody    = 64 << 10
	wgOnlineAfter = 3 * time.Minute // рукопожатие свежее — пир на связи
	killTimeout   = 2 * time.Second
	maxLimit      = 1000
)

// API — HTTP API агента для панели. Клиенты AntiZapret меняются только
// через client.sh; лимиты и блокировки — в limits.json, который читает хук.
type API struct {
	Token         string
	Version       string
	Tracker       *Tracker
	LimitsPath    string
	Inventory     antizapret.Inventory
	ClientSh      *antizapret.ClientSh
	AntiZapretDir string
	SocketDir     string
	Sampler       *sysinfo.Sampler
	Services      func(ctx context.Context) ([]sysinfo.Service, error)
	WGShow        func(ctx context.Context, iface string) ([]antizapret.WGPeer, error)
	Kill          func(sock, name string, timeout time.Duration) (int, error)
	Log           *slog.Logger
	Now           func() time.Time

	mu sync.Mutex // чтение-изменение-запись limits.json
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", a.info)
	mux.HandleFunc("GET /v1/clients", a.clients)
	mux.HandleFunc("POST /v1/clients", a.createClient)
	mux.HandleFunc("POST /v1/clients/openvpn/{name}/renew", a.renew)
	mux.HandleFunc("DELETE /v1/clients/{kind}/{name}", a.deleteClient)
	mux.HandleFunc("GET /v1/clients/{name}/profiles", a.profiles)
	mux.HandleFunc("GET /v1/clients/{name}/profiles/{kind}/{variant}/{file}", a.profile)
	mux.HandleFunc("PUT /v1/clients/{name}/limit", a.setLimit)
	mux.HandleFunc("PUT /v1/clients/{name}/blocked", a.setBlocked)
	mux.HandleFunc("GET /v1/sessions", a.sessions)
	mux.HandleFunc("GET /v1/system", a.system)
	return a.auth(mux)
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(nodeapi.ProtoHeader, strconv.Itoa(nodeapi.Proto))
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || a.Token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.Token)) != 1 {
			a.Log.Warn("API: запрос без верного токена", "remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
			writeErr(w, http.StatusUnauthorized, "нужен токен узла")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAPIBody)
		next.ServeHTTP(w, r)
	})
}

// WireGuardEnabled — WIREGUARD_ENABLE=y в setup AntiZapret.
func (a *API) WireGuardEnabled() bool {
	m, err := antizapret.ReadSetup(filepath.Join(a.AntiZapretDir, "setup"))
	return err == nil && m["WIREGUARD_ENABLE"] == "y"
}

func (a *API) info(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, nodeapi.Info{Proto: nodeapi.Proto, Version: a.Version, Hostname: host, WireGuard: a.WireGuardEnabled()})
}

func (a *API) clients(w http.ResponseWriter, r *http.Request) {
	list, err := a.Inventory.Clients()
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	lim, err := limits.Load(a.LimitsPath)
	if err != nil {
		a.fail(w, "limits.json не прочитан", err)
		return
	}
	out := make([]nodeapi.Client, 0, len(list))
	for _, c := range list {
		nc := nodeapi.Client{Name: c.Name, OpenVPN: c.OpenVPN, WireGuard: c.WireGuard, Limit: lim.Limits[c.Name], Blocked: lim.Blocked[c.Name]}
		if !c.CertExpires.IsZero() {
			t := c.CertExpires
			nc.CertExpires = &t
		}
		out = append(out, nc)
	}
	writeJSON(w, http.StatusOK, out)
}

// find — клиент по имени; нет — found == false.
func (a *API) find(name string) (antizapret.ClientInfo, bool, error) {
	list, err := a.Inventory.Clients()
	if err != nil {
		return antizapret.ClientInfo{}, false, err
	}
	for _, c := range list {
		if c.Name == name {
			return c, true, nil
		}
	}
	return antizapret.ClientInfo{}, false, nil
}

// noCancel: обрыв соединения панелью не должен прерывать client.sh на
// середине — недоделанный клиент хуже долгого ответа. Тайм-аут у ClientSh свой.
func noCancel(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }

func (a *API) createClient(w http.ResponseWriter, r *http.Request) {
	var req nodeapi.CreateClient
	if !decode(w, r, &req) {
		return
	}
	if !limits.ValidName(req.Name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента: 1–32 символа a-z, A-Z, 0-9, _ и -")
		return
	}
	c, _, err := a.find(req.Name)
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	var out string
	switch req.Kind {
	case nodeapi.KindOpenVPN:
		if c.OpenVPN {
			// client.sh 1 для существующего клиента продлил бы сертификат.
			writeErr(w, http.StatusConflict, "клиент OpenVPN с таким именем уже есть")
			return
		}
		days := req.Days
		if days == 0 {
			days = antizapret.MaxCertDays
		}
		if days < 1 || days > antizapret.MaxCertDays {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("срок сертификата — 1..%d дней", antizapret.MaxCertDays))
			return
		}
		out, err = a.ClientSh.AddOpenVPN(noCancel(r), req.Name, days)
	case nodeapi.KindWireGuard:
		if c.WireGuard {
			writeErr(w, http.StatusConflict, "клиент WireGuard с таким именем уже есть")
			return
		}
		out, err = a.ClientSh.AddWireGuard(noCancel(r), req.Name)
	default:
		writeErr(w, http.StatusBadRequest, "kind — openvpn или wireguard")
		return
	}
	if err != nil {
		a.fail(w, "клиент не создан", err)
		return
	}
	a.Log.Info("клиент создан", "name", req.Name, "kind", req.Kind)
	writeJSON(w, http.StatusCreated, nodeapi.Result{Output: out})
}

func (a *API) renew(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req nodeapi.Renew
	if !decode(w, r, &req) {
		return
	}
	c, found, err := a.find(name)
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	if !found || !c.OpenVPN {
		writeErr(w, http.StatusNotFound, "клиента OpenVPN с таким именем нет")
		return
	}
	if req.Days < 1 || req.Days > antizapret.MaxCertDays {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("срок сертификата — 1..%d дней", antizapret.MaxCertDays))
		return
	}
	out, err := a.ClientSh.AddOpenVPN(noCancel(r), name, req.Days)
	if err != nil {
		a.fail(w, "сертификат не продлён", err)
		return
	}
	a.Log.Info("сертификат продлён", "name", name, "days", req.Days)
	writeJSON(w, http.StatusOK, nodeapi.Result{Output: out})
}

func (a *API) deleteClient(w http.ResponseWriter, r *http.Request) {
	kind, name := r.PathValue("kind"), r.PathValue("name")
	c, _, err := a.find(name)
	if err != nil {
		a.fail(w, "состав клиентов не прочитан", err)
		return
	}
	var out string
	switch kind {
	case nodeapi.KindOpenVPN:
		if !c.OpenVPN {
			writeErr(w, http.StatusNotFound, "клиента OpenVPN с таким именем нет")
			return
		}
		out, err = a.ClientSh.DeleteOpenVPN(noCancel(r), name)
	case nodeapi.KindWireGuard:
		if !c.WireGuard {
			writeErr(w, http.StatusNotFound, "клиента WireGuard с таким именем нет")
			return
		}
		out, err = a.ClientSh.DeleteWireGuard(noCancel(r), name)
	default:
		writeErr(w, http.StatusBadRequest, "kind — openvpn или wireguard")
		return
	}
	if err != nil {
		a.fail(w, "клиент не удалён", err)
		return
	}
	a.Log.Info("клиент удалён", "name", name, "kind", kind)
	// Клиента не осталось ни в одном виде — его лимит и блокировка больше
	// ничего не значат, а с тем же именем может появиться новый клиент.
	if _, still, err := a.find(name); err == nil && !still {
		if err := a.updateLimits(func(d *limits.Data) { delete(d.Limits, name); delete(d.Blocked, name) }); err != nil {
			a.Log.Error("лимит удалённого клиента не снят", "name", name, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, nodeapi.Result{Output: out})
}

func (a *API) profiles(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	ps, err := antizapret.Profiles(a.AntiZapretDir, name)
	if err != nil {
		a.fail(w, "профили не прочитаны", err)
		return
	}
	out := make([]nodeapi.Profile, 0, len(ps))
	for _, p := range ps {
		out = append(out, nodeapi.Profile{Kind: p.Kind, Variant: p.Variant, File: p.File})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) profile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	p, err := antizapret.ProfilePath(a.AntiZapretDir, name, r.PathValue("kind"), r.PathValue("variant"), r.PathValue("file"))
	if errors.Is(err, antizapret.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "профиль не найден")
		return
	}
	if err != nil {
		a.fail(w, "профили не прочитаны", err)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		a.fail(w, "профиль не прочитан", err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(p)}))
	w.Write(data)
	a.Log.Info("профиль выдан", "name", name, "file", filepath.Base(p))
}

func (a *API) setLimit(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	var req nodeapi.SetLimit
	if !decode(w, r, &req) {
		return
	}
	if req.Limit < 0 || req.Limit > maxLimit {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("лимит — 0 (без ограничения) или 1..%d", maxLimit))
		return
	}
	err := a.updateLimits(func(d *limits.Data) {
		if req.Limit == 0 {
			delete(d.Limits, name)
		} else {
			d.Limits[name] = req.Limit
		}
	})
	if err != nil {
		a.fail(w, "лимит не записан", err)
		return
	}
	a.Log.Info("лимит изменён", "name", name, "limit", req.Limit)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setBlocked(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !limits.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "недопустимое имя клиента")
		return
	}
	var req nodeapi.SetBlocked
	if !decode(w, r, &req) {
		return
	}
	err := a.updateLimits(func(d *limits.Data) {
		if req.Blocked {
			d.Blocked[name] = true
		} else {
			delete(d.Blocked, name)
		}
	})
	if err != nil {
		a.fail(w, "блокировка не записана", err)
		return
	}
	var res nodeapi.Result
	if req.Blocked {
		// Файл уже записан: переподключение после kill хук не пустит.
		socks, err := antizapret.ListSockets(a.SocketDir)
		if err != nil {
			a.Log.Warn("сокеты OpenVPN не найдены, сессии не разорваны", "name", name, "err", err)
		}
		for _, s := range socks {
			n, err := a.Kill(s, name, killTimeout)
			if err != nil {
				a.Log.Warn("сессии клиента не разорваны", "socket", s, "name", name, "err", err)
				continue
			}
			res.Killed += n
		}
	}
	a.Log.Info("блокировка изменена", "name", name, "blocked", req.Blocked, "killed", res.Killed)
	writeJSON(w, http.StatusOK, res)
}

// updateLimits — чтение, правка, атомарная запись. Испорченный файл не
// перезаписывается: ошибка уходит вызывающему, хук продолжает работать
// по последней прочитанной версии.
func (a *API) updateLimits(edit func(*limits.Data)) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := limits.Load(a.LimitsPath)
	if err != nil {
		return err
	}
	edit(&d)
	return limits.Save(a.LimitsPath, d)
}

func (a *API) sessions(w http.ResponseWriter, r *http.Request) {
	out := []nodeapi.Session{}
	for _, s := range a.Tracker.Sessions() {
		since := s.ConnectedSince.UTC()
		out = append(out, nodeapi.Session{
			Kind: nodeapi.KindOpenVPN, Instance: s.Instance, Name: s.CommonName, Addr: s.RealAddr,
			RxBytes: s.BytesRx, TxBytes: s.BytesTx, Since: &since,
		})
	}
	peers, err := a.Inventory.WireGuardPeers()
	if err != nil {
		a.Log.Warn("конфиги WireGuard не прочитаны", "err", err)
		writeJSON(w, http.StatusOK, out)
		return
	}
	now := a.Now()
	for _, iface := range antizapret.WGInterfaces {
		list, err := a.WGShow(r.Context(), iface)
		if err != nil {
			a.Log.Warn("wg show не ответил", "iface", iface, "err", err)
			continue
		}
		for _, p := range list {
			name, ok := peers[iface][p.PublicKey]
			if !ok || p.LatestHandshake.IsZero() || now.Sub(p.LatestHandshake) > wgOnlineAfter {
				continue
			}
			hs := p.LatestHandshake.UTC()
			out = append(out, nodeapi.Session{
				Kind: nodeapi.KindWireGuard, Instance: iface, Name: name, Addr: p.Endpoint,
				RxBytes: p.RxBytes, TxBytes: p.TxBytes, LastHandshake: &hs,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) system(w http.ResponseWriter, r *http.Request) {
	snap, err := a.Sampler.Sample(a.Now())
	if err != nil {
		a.fail(w, "ресурсы не прочитаны", err)
		return
	}
	svcs, err := a.Services(r.Context())
	if err != nil {
		a.Log.Warn("состояние служб не получено", "err", err)
		svcs = []sysinfo.Service{}
	}
	writeJSON(w, http.StatusOK, nodeapi.System{Resources: snap, Services: svcs})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "неверный запрос: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, nodeapi.ErrorBody{Error: msg})
}

func (a *API) fail(w http.ResponseWriter, what string, err error) {
	a.Log.Error(what, "err", err)
	writeErr(w, http.StatusInternalServerError, what+": "+err.Error())
}
```

- [ ] **Step 4: Тесты проходят**

Run: `go vet ./... && go test ./internal/node/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/node/api.go internal/node/api_test.go
git commit -m "HTTP API агента: клиенты, профили, лимит, блокировка, сессии, ресурсы

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: API в службе агента, токен при установке, ограничения юнита, спецификация

**Files:**
- Modify: `internal/node/node.go`
- Modify: `cmd/azpanel/main.go`
- Modify: `internal/install/install.go`, `internal/install/install_test.go`
- Modify: `docs/specs/2026-11-01-azpanel-design.md`

**Interfaces:**
- Consumes: `node.API`, `secrets.Load/Set/NewToken/NodeToken`, `paths.SecretsFile`, `antizapret.WGShow`, `antizapret.KillClient`, `sysinfo.KresdUnits/Services/ServiceUnits`.
- Produces: `node.Run(ctx context.Context, cfg config.Config, version string, ensureHook func() (bool, error)) error`; `install.NodeUnit(bin string) string` с ограничениями systemd.

- [ ] **Step 1: Написать падающие тесты установщика**

В `internal/install/install_test.go`, в конец `TestInstallNode` (перед закрывающей скобкой):

```go
	sec, err := secrets.Load(paths.SecretsFile())
	if err != nil || len(sec[secrets.NodeToken]) != 64 {
		t.Fatalf("токен узла: %v", err)
	}
	for _, line := range []string{"ProtectSystem=strict", "ReadWritePaths=/opt/azpanel -/etc/openvpn -/etc/wireguard -/root/antizapret", "PrivateTmp=true", "NoNewPrivileges=true"} {
		if !strings.Contains(string(unit), line) {
			t.Fatalf("в юните нет %q:\n%s", line, unit)
		}
	}
```

И новый тест:

```go
func TestInstallNodeKeepsToken(t *testing.T) {
	o, _ := setup(t)
	os.MkdirAll(paths.Etc(), 0o700)
	if err := secrets.Set(paths.SecretsFile(), secrets.NodeToken, "OLDTOKEN"); err != nil {
		t.Fatal(err)
	}
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if sec, _ := secrets.Load(paths.SecretsFile()); sec[secrets.NodeToken] != "OLDTOKEN" {
		t.Fatal("токен заменён")
	}
}
```

В импорт теста добавить `"github.com/syava842/azpanel/internal/secrets"`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/install/`
Expected: FAIL — `токен узла` / `в юните нет "ProtectSystem=strict"`.

- [ ] **Step 3: Токен и юнит в установщике**

`internal/install/install.go`, `NodeUnit` заменить на:

```go
// NodeUnit — юнит агента. Сам агент пишет только в /opt/azpanel; остальные
// пути на запись нужны client.sh (PKI EasyRSA, профили, конфиги WireGuard)
// и установке хука (скрипты OpenVPN). «-» — каталога может не быть.
func NodeUnit(bin string) string {
	return `[Unit]
Description=azpanel: агент узла AntiZapret
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + bin + ` node
Restart=on-failure
RestartSec=3
RuntimeDirectory=azpanel
RuntimeDirectoryMode=0755
ProtectSystem=strict
ReadWritePaths=/opt/azpanel -/etc/openvpn -/etc/wireguard -/root/antizapret
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`
}
```

В `InstallNode` в текст сводки после строки `  %s — служба azpanel-node (включится и перезапустится)` вставить строку

```
  %s — токен API агента (если его ещё нет); API — только с этого сервера
```

и аргумент `paths.SecretsFile()` в вызов `Fprintf` между `unit` и `o.ScriptsDir`. После блока записи `config.toml` добавить:

```go
	if err := ensureNodeToken(paths.SecretsFile()); err != nil {
		return fmt.Errorf("токен узла: %w", err)
	}
```

и функцию:

```go
// ensureNodeToken создаёт NODE_TOKEN, если его нет. Существующий не
// меняется: панель уже знает его.
func ensureNodeToken(path string) error {
	m, err := secrets.Load(path)
	if err != nil {
		return err
	}
	if m[secrets.NodeToken] != "" {
		return nil
	}
	t, err := secrets.NewToken()
	if err != nil {
		return err
	}
	return secrets.Set(path, secrets.NodeToken, t)
}
```

В импорт добавить `"github.com/syava842/azpanel/internal/secrets"`.

- [ ] **Step 4: Тесты установщика проходят**

Run: `go test ./internal/install/`
Expected: PASS.

- [ ] **Step 5: Запуск API в службе агента**

`internal/node/node.go`: сигнатуру `Run` заменить на

```go
func Run(ctx context.Context, cfg config.Config, version string, ensureHook func() (bool, error)) error {
```

после строки `go p.Run(ctx, time.Duration(cfg.Node.PollSeconds)*time.Second)` вставить:

```go
	if cfg.Node.APIListen != "" {
		stop, err := startAPI(cfg, version, tr, log)
		if err != nil {
			log.Error("API агента не запущен — панель узел не увидит, хук работает", "err", err)
		} else {
			defer stop()
		}
	}
```

и добавить функцию:

```go
// startAPI запускает HTTP API для панели. Его сбой не трогает хук: лимиты
// и блокировки работают и без API. При остановке службы systemd гасит и
// дочерние процессы — client.sh, запущенный в эту секунду, оборвётся.
func startAPI(cfg config.Config, version string, tr *Tracker, log *slog.Logger) (func(), error) {
	sec, err := secrets.Load(paths.SecretsFile())
	if err != nil {
		return nil, err
	}
	token := sec[secrets.NodeToken]
	if len(token) < 32 {
		return nil, errors.New("в secrets.env нет NODE_TOKEN — его создаёт azpanel install")
	}
	n := cfg.Node
	api := &API{
		Token: token, Version: version, Tracker: tr, LimitsPath: paths.LimitsFile(),
		Inventory:     antizapret.Inventory{PKI: n.EasyRSAPKI, WireGuardDir: n.WireGuardDir},
		ClientSh:      &antizapret.ClientSh{Dir: n.AntiZapretDir, Timeout: time.Duration(n.ClientShTimeoutS) * time.Second},
		AntiZapretDir: n.AntiZapretDir,
		SocketDir:     n.OpenVPNSocketDir,
		Sampler:       &sysinfo.Sampler{Proc: "/proc", DiskPath: "/"},
		WGShow:        antizapret.WGShow,
		Kill:          antizapret.KillClient,
		Log:           log,
		Now:           time.Now,
	}
	api.Services = func(ctx context.Context) ([]sysinfo.Service, error) {
		kresd, err := sysinfo.KresdUnits(ctx)
		if err != nil {
			return nil, err
		}
		return sysinfo.Services(ctx, sysinfo.ServiceUnits(kresd, api.WireGuardEnabled()))
	}
	ln, err := net.Listen("tcp", n.APIListen)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      time.Duration(n.ClientShTimeoutS)*time.Second + time.Minute,
		IdleTimeout:       time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("API агента остановлен с ошибкой", "err", err)
		}
	}()
	log.Info("API агента запущен", "listen", n.APIListen)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}, nil
}
```

В импорт `node.go` добавить `"errors"`, `"log/slog"`, `"net/http"`, `"github.com/syava842/azpanel/internal/secrets"`, `"github.com/syava842/azpanel/internal/sysinfo"`.

`cmd/azpanel/main.go`, в `runNode`: `node.Run(ctx, cfg, hookFiles(cfg).Ensure)` → `node.Run(ctx, cfg, version, hookFiles(cfg).Ensure)`.

- [ ] **Step 6: Все тесты и сборка под linux**

Run: `go vet ./... && go test ./... && GOOS=linux GOARCH=amd64 go vet ./...`
Expected: PASS, `vet` под linux без замечаний.

- [ ] **Step 7: Спецификация**

В `docs/specs/2026-11-01-azpanel-design.md`:

1. Раздел «Клиенты», пункт «Заблокировать — …» заменить на:

```markdown
- Заблокировать — имя в списке `blocked` файла `limits.json` на узле: хук
  отказывает такому клиенту так же, как сверх лимита, а текущие сессии
  агент рвёт командой `kill <имя>` во всех сокетах OpenVPN. Файла
  `banned_clients` в нынешнем AntiZapret нет (проверено на 94 01.11.2026).
  Блокировка WireGuard — снятием пира — в этапе 7 вместе с подписками:
  `client.sh` при добавлении любого клиента пересобирает пиры из конфига
  и вернул бы снятого.
```

2. Раздел «Агент»: к пункту «Слушает `127.0.0.1`, если панель на том же хосте; …» дописать предложение «API — протокол 1, маршруты `/v1/…` (план 2а-1, таблица в задаче 7); каждый ответ несёт `X-Azpanel-Proto`.»; пункт «Опрашивает сокеты и `wg show` раз в 10 с, копит трафик в своей SQLite до отправки в панель …» заменить на «Сокеты OpenVPN опрашиваются раз в 5 с, `wg show` и ресурсы — по запросу панели. Буфер трафика на узле на время недоступности панели — этап 4, вместе с несколькими серверами: пока панель на том же хосте, недоступны они вместе.»

3. Раздел «Агент», новый пункт: «Юнит `azpanel-node` ограничен: `ProtectSystem=strict`, запись — только `/opt/azpanel`, `/etc/openvpn`, `/etc/wireguard`, `/root/antizapret` (их пишут `client.sh` и установка хука), `PrivateTmp`, `NoNewPrivileges`.»

4. Раздел «Этапы», п. 2 дополнить: «Разбит на планы: 2а-1 — API агента (клиенты, профили, лимит, блокировка, сессии, ресурсы); 2а-2 — панель: вход, клиенты, мониторинг с историей, настройки через веб; 2б — полный мастер установки, nginx, HTTPS, опасные настройки с таймером возврата; 2в — самообновление с миграцией конфига.»

- [ ] **Step 8: Commit**

```bash
git add internal/node/node.go cmd/azpanel/main.go internal/install docs/specs/2026-11-01-azpanel-design.md
git commit -m "API в службе агента, токен узла при установке, ограничения юнита; спецификация

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Приёмка на 94

Код не пишется. Перед началом — сообщить владельцу: на 94 обновляется агент (служба `azpanel-node` перезапускается на секунды, хук на это время пропускает всех), создаются и удаляются клиенты `azpanel-test-a1` (OpenVPN) и `azpanel-test-w1` (WireGuard; при выключенном `WIREGUARD_ENABLE` подключиться им нельзя — проверяются только файлы).

**Files:**
- Create: `docs/notes/2026-11-01-priemka-etap-2a1.md`

Все команды на 94 — пачками в одной SSH-сессии (защита AntiZapret ограничивает новые подключения SSH). Токен в вывод не печатается: он читается в переменную на самом 94. Клиентов OpenVPN останавливать только по pid-файлам, не `pkill -f`.

- [ ] **Step 1: Сборка и установка**

```bash
scripts/build.sh
scp dist/azpanel-linux-amd64 root@192.0.2.94:/root/azpanel-new
ssh root@192.0.2.94 'chmod +x /root/azpanel-new && /root/azpanel-new install --yes && rm /root/azpanel-new &&
  systemctl is-active azpanel-node && /opt/azpanel/bin/azpanel hook status &&
  stat -c "%a %n" /opt/azpanel/etc/secrets.env && grep -c "^NODE_TOKEN=" /opt/azpanel/etc/secrets.env &&
  grep -E "API агента|ERROR" /opt/azpanel/log/node.log | tail -3'
```

Expected: `active`, `хук установлен`, `600 …/secrets.env`, `1`, строка `API агента запущен listen=127.0.0.1:9100`, без `ERROR`.

- [ ] **Step 2: Доступ и чтение**

```bash
ssh root@192.0.2.94 'T=$(sed -n "s/^NODE_TOKEN=//p" /opt/azpanel/etc/secrets.env); A="http://127.0.0.1:9100"
  curl -s -o /dev/null -w "без токена: %{http_code}\n" $A/v1/info
  curl -s -o /dev/null -w "чужой токен: %{http_code}\n" -H "Authorization: Bearer x" $A/v1/info
  curl -s -H "Authorization: Bearer $T" $A/v1/info; echo
  echo "OpenVPN по API: $(curl -s -H "Authorization: Bearer $T" $A/v1/clients | grep -o "\"openvpn\":true" | wc -l), по issued: $(ls /etc/openvpn/easyrsa3/pki/issued | grep -vc "^antizapret-server.crt$")"
  echo "сессий OpenVPN по API: $(curl -s -H "Authorization: Bearer $T" $A/v1/sessions | grep -o "\"kind\":\"openvpn\"" | wc -l)"
  /opt/azpanel/bin/azpanel sessions | tail -n +2 | awk "{s+=\$2} END {print \"сессий у агента:\", s}"
  curl -s -H "Authorization: Bearer $T" $A/v1/system | head -c 700; echo
  ss -ltnH "sport = :9100"'
```

Expected: `401`, `401`; `info` с `"proto":1` и `"wireguard":false`; числа клиентов равны; число сессий по API равно сумме у агента; в `system` ненулевые `memory.total_bytes` и `disk.total_bytes`, `"net_iface":"eth0"`, службы `active`; слушает только `127.0.0.1:9100`.

- [ ] **Step 3: Создание, профиль, сессия**

```bash
ssh root@192.0.2.94 'T=$(sed -n "s/^NODE_TOKEN=//p" /opt/azpanel/etc/secrets.env); A="http://127.0.0.1:9100"; H="Authorization: Bearer $T"
  curl -s -w " %{http_code}\n" -H "$H" -d "{\"name\":\"azpanel-test-a1\",\"kind\":\"openvpn\",\"days\":30}" $A/v1/clients | tail -c 200
  curl -s -w " %{http_code}\n" -H "$H" -d "{\"name\":\"azpanel-test-a1\",\"kind\":\"openvpn\"}" $A/v1/clients
  curl -s -H "$H" $A/v1/clients | grep -o "{\"name\":\"azpanel-test-a1\"[^}]*}"
  curl -s -H "$H" $A/v1/clients/azpanel-test-a1/profiles; echo
  F=$(ls /root/antizapret/client/openvpn/antizapret-udp/ | grep "azpanel-test-a1")
  curl -s -H "$H" "$A/v1/clients/azpanel-test-a1/profiles/openvpn/antizapret-udp/$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$F")" | sha256sum
  sha256sum < "/root/antizapret/client/openvpn/antizapret-udp/$F"
  mkdir -p /root/azpanel-probe && cp "/root/antizapret/client/openvpn/antizapret-udp/$F" /root/azpanel-probe/a1-udp.ovpn && cd /root/azpanel-probe
  openvpn --config a1-udp.ovpn --route-nopull --ifconfig-noexec --route-noexec --disable-dco --log a.log --writepid a.pid --daemon azt-a
  sleep 12; grep -c "Initialization Sequence Completed" a.log
  curl -s -H "$H" $A/v1/sessions | grep -o "{\"kind\":\"openvpn\"[^}]*azpanel-test-a1[^}]*}"'
```

Expected: первый запрос `201`; повтор — `409`; клиент с `cert_expires` ≈ сегодня + 30 дней, `"limit":0`, `"blocked":false`; шесть профилей `.ovpn`; суммы sha256 совпадают; `1`; сессия `azpanel-test-a1` с адресом 94.

- [ ] **Step 4: Блокировка и разблокировка**

```bash
ssh root@192.0.2.94 'T=$(sed -n "s/^NODE_TOKEN=//p" /opt/azpanel/etc/secrets.env); A="http://127.0.0.1:9100"; H="Authorization: Bearer $T"; cd /root/azpanel-probe
  curl -s -X PUT -H "$H" -d "{\"blocked\":true}" $A/v1/clients/azpanel-test-a1/blocked; echo
  tr -d "\n " < /opt/azpanel/data/limits.json; echo
  sleep 45; grep -c "AUTH_FAILED" a.log; grep "azpanel-test-a1" /opt/azpanel/log/hook.log | grep -c "клиент заблокирован"
  kill $(cat a.pid); sleep 2
  curl -s -X PUT -H "$H" -d "{\"blocked\":false}" $A/v1/clients/azpanel-test-a1/blocked; echo
  : > a.log; openvpn --config a1-udp.ovpn --route-nopull --ifconfig-noexec --route-noexec --disable-dco --log a.log --writepid a.pid --daemon azt-a
  sleep 12; grep -c "Initialization Sequence Completed" a.log'
```

Expected (UDP-клиент переподключается только после ping-restart, около 45 с, поэтому `sleep 45`): `{"killed":1}`; в `limits.json` — `"blocked":["azpanel-test-a1"]`; клиент после разрыва переподключается и получает `AUTH_FAILED` (≥1), в `hook.log` — `отказ: клиент заблокирован` (≥1); после разблокировки — `{}` и снова `1`.

- [ ] **Step 5: Лимит через API**

```bash
ssh root@192.0.2.94 'T=$(sed -n "s/^NODE_TOKEN=//p" /opt/azpanel/etc/secrets.env); A="http://127.0.0.1:9100"; H="Authorization: Bearer $T"; cd /root/azpanel-probe
  curl -s -o /dev/null -w "%{http_code}\n" -X PUT -H "$H" -d "{\"limit\":1}" $A/v1/clients/azpanel-test-a1/limit
  openvpn --config a1-udp.ovpn --route-nopull --ifconfig-noexec --route-noexec --disable-dco --log b.log --writepid b.pid --daemon azt-b
  sleep 12; grep -c "AUTH_FAILED" b.log; kill $(cat b.pid) $(cat a.pid); sleep 2
  curl -s -o /dev/null -w "%{http_code}\n" -X PUT -H "$H" -d "{\"limit\":0}" $A/v1/clients/azpanel-test-a1/limit'
```

Expected: `204`; второе подключение — `AUTH_FAILED` (≥1); `204`.

- [ ] **Step 6: WireGuard-клиент — только файлы**

```bash
ssh root@192.0.2.94 'T=$(sed -n "s/^NODE_TOKEN=//p" /opt/azpanel/etc/secrets.env); A="http://127.0.0.1:9100"; H="Authorization: Bearer $T"
  before=$(grep -c "^# Client =" /etc/wireguard/antizapret.conf)
  curl -s -o /dev/null -w "%{http_code}\n" -H "$H" -d "{\"name\":\"azpanel-test-w1\",\"kind\":\"wireguard\"}" $A/v1/clients
  curl -s -H "$H" $A/v1/clients/azpanel-test-w1/profiles; echo
  curl -s -H "$H" $A/v1/clients $A/v1/sessions | grep -c "PrivateKey\|PresharedKey\|PublicKey"
  curl -s -o /dev/null -w "%{http_code}\n" -X DELETE -H "$H" $A/v1/clients/wireguard/azpanel-test-w1
  echo "пиров до: $before, после: $(grep -c "^# Client =" /etc/wireguard/antizapret.conf)"'
```

Expected: `201`; четыре профиля (`wireguard` и `amneziawg` × `antizapret`, `vpn`); `0` — ключей в ответах нет; `200`; числа пиров до и после равны.

- [ ] **Step 7: Удаление и уборка**

```bash
ssh root@192.0.2.94 'T=$(sed -n "s/^NODE_TOKEN=//p" /opt/azpanel/etc/secrets.env); A="http://127.0.0.1:9100"; H="Authorization: Bearer $T"
  curl -s -o /dev/null -w "%{http_code}\n" -X PUT -H "$H" -d "{\"limit\":2}" $A/v1/clients/azpanel-test-a1/limit
  curl -s -o /dev/null -w "%{http_code}\n" -X DELETE -H "$H" $A/v1/clients/openvpn/azpanel-test-a1
  curl -s -H "$H" $A/v1/clients | grep -c "azpanel-test"
  ls /root/antizapret/client/*/*/ | grep -c "azpanel-test"
  cat /opt/azpanel/data/limits.json
  rm -rf /root/azpanel-probe
  systemctl is-active openvpn-server@antizapret-udp openvpn-server@antizapret-tcp openvpn-server@vpn-udp openvpn-server@vpn-tcp azpanel-node
  grep -c "ERROR" /opt/azpanel/log/node.log; grep "отказ" /opt/azpanel/log/hook.log | grep -vc "azpanel-test"'
```

Expected: `204`, `200`; `0` клиентов `azpanel-test`; `0` файлов; `limits.json` — `"version": 2`, `limits` пуст, `blocked` нет; пять `active`; `ERROR` — 0 (или только записи, объяснённые в заметке); отказов не по тестовым клиентам — `0`.

- [ ] **Step 8: Записать итоги и закоммитить**

Создать `docs/notes/2026-11-01-priemka-etap-2a1.md` по образцу `docs/notes/2026-11-01-priemka-etap-1.md`: дата, сборка (`git describe`), таблица «Шаг | Проверка | Итог» по шагам 1–7 с фактическим выводом, раздел «Наблюдения» (в том числе — хватило ли `ReadWritePaths` юнита; если `client.sh` упал с `Read-only file system`, добавить нужный путь в `NodeUnit` и в тест `TestInstallNode`, переустановить, повторить шаг и записать, какой путь и почему), раздел «Что осталось на 94».

```bash
git add docs/notes/2026-11-01-priemka-etap-2a1.md
git commit -m "Приёмка этапа 2а-1 на 94

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Проверка плана по спецификации

| Требование спецификации | Задача |
| --- | --- |
| Клиенты: список OpenVPN и WG, статус, срок сертификата, лимит | 3, 5, 8 |
| Создать, продлить, удалить — `client.sh 1/2/4/5` | 4, 8 |
| Скачать профиль | 3, 8 (QR-код — в панели, план 2а-2) |
| Заблокировать с отключением текущих сессий | 2, 4, 8 (WireGuard — этап 7, правка спецификации в задаче 9) |
| Клиенты, созданные руками через `client.sh`, появляются при следующем опросе | 3 — состав читается при каждом запросе |
| Мониторинг «сейчас»: сессии, ресурсы, службы | 5, 6, 8 (история — план 2а-2) |
| Агент: loopback, токен, сравнение за постоянное время | 1, 8, 9 |
| Хук проверяется при старте и раз в минуту | без изменений с этапа 1 |
| Настройки — в `config.toml` с проверкой; правка через веб — план 2а-2 | 1 |
| Раскладка и права `/opt/azpanel`, `secrets.env` 600 | 1, 9 |
| Ограничение юнита агента (перенесено с этапа 1) | 9 |
