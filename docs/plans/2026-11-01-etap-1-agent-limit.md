# Этап 1: агент узла и лимит подключений — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** на 192.0.2.94 работает `azpanel node`, а хук OpenVPN отказывает клиенту сверх его лимита одновременных подключений и пропускает всех остальных как раньше.

**Architecture:** один бинарник Go. Агент (`azpanel node`, служба systemd) раз в 5 с снимает `status 3` со всех управляющих сокетов OpenVPN и ведёт учёт сессий вместе с событиями хуков. Хук (`azpanel hook connect|disconnect`) запускается OpenVPN от `nobody`, спрашивает агента через unix-сокет и выходит с кодом 3 только при явном отказе. Лимиты — `/opt/azpanel/data/limits.json`, правятся командой `azpanel limit`.

**Tech Stack:** Go 1.24+, стандартная библиотека, `github.com/BurntSushi/toml` v1.4.0. Сборка `CGO_ENABLED=0`, linux/amd64 и linux/arm64.

**Spec:** [docs/specs/2026-11-01-azpanel-design.md](../specs/2026-11-01-azpanel-design.md) — разделы «Архитектура», «Раскладка на сервере», «Лимит подключений», «Этапы» (п. 1).

## Global Constraints

- Модуль `github.com/syava842/azpanel`; `go 1.24` в `go.mod`; зависимости — только стандартная библиотека и `github.com/BurntSushi/toml v1.4.0`.
- Имена файлов, пакетов, функций, типов, переменных — латиницей. Комментарии, тексты ошибок, сообщения журнала и CLI — по-русски.
- Раскладка: `/opt/azpanel/{bin,etc,log,data,backup}`; права `/opt/azpanel` и `bin/` — `755`, `etc/`, `data/`, `backup/` — `700`, `log/` — `750`.
- Корень переопределяется переменной `AZPANEL_ROOT` (только для тестов).
- Хук: код выхода 3 — отказ; любой другой исход — подключение проходит. Хук файлов не пишет.
- Сокет агента `/run/azpanel/node.sock`, права `666`, собеседник проверяется по `SO_PEERCRED`: только root и `nobody`.
- Клиент без своего лимита — без ограничения. Имя клиента — `^[A-Za-z0-9_-]{1,32}$`.
- На 94 только тестовые клиенты `azpanel-test-*`; живых клиентов, StatusOpenVPN, telemt, 3proxy, AZ-WARP, nginx не трогать. Перезагрузка 94 и обновление AntiZapret в этом этапе не нужны и запрещены.
- Коммиты — с `user.email = syava842@gmail.com` (задан в репозитории), сообщения по-русски, в конце строка `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Тесты запускаются на Windows-машине разработчика (`go test ./...`): unix-сокеты в Go на Windows 10+ работают; проверка `SO_PEERCRED` — только под `linux`, на других ОС заглушка.

## Карта файлов

| Файл | Отвечает за |
| --- | --- |
| `go.mod` | модуль и зависимость toml |
| `cmd/azpanel/main.go` | разбор подкоманд, запуск режимов |
| `cmd/azpanel/limitcmd.go` | `azpanel limit …`, `azpanel sessions` |
| `internal/paths/paths.go` | пути `/opt/azpanel/...`, сокет агента |
| `internal/fsutil/atomic.go` | атомарная запись файла |
| `internal/config/config.go` | `config.toml`: умолчания, загрузка, проверка, запись |
| `internal/logx/rotator.go` | журнал с ротацией по размеру, `slog` поверх |
| `internal/antizapret/mgmt.go` | разбор `status 3`, опрос сокета OpenVPN |
| `internal/antizapret/hookfile.go` | вставка и снятие блока хука в `custom-client-*.sh` |
| `internal/limits/limits.go` | `limits.json`: чтение, запись, перечитывание по изменению |
| `internal/agentproto/proto.go` | запрос/ответ хук ↔ агент, `Call` |
| `internal/node/tracker.go` | учёт сессий: снимки + события |
| `internal/node/server.go` | обработка запросов на сокете агента |
| `internal/node/peercred_linux.go`, `peercred_other.go` | проверка собеседника |
| `internal/node/poller.go` | опрос экземпляров OpenVPN |
| `internal/node/node.go` | `Run` — служба агента целиком |
| `internal/hook/hook.go` | логика `azpanel hook connect` и `disconnect` |
| `internal/install/install.go` | `azpanel install`, `azpanel uninstall` для узла |
| `scripts/build.sh` | сборка под linux |
| `docs/notes/2026-11-01-proba-94.md` | результаты пробы на 94 (задача 1) |

---

### Task 1: Проба на 94 — что видит скрипт client-connect

Код не пишется. Проверяются три предположения, на которых стоит этап: (а) экземпляр OpenVPN не отвечает на свой управляющий сокет, пока выполняется `client-connect`; (б) в окружении скрипта есть `common_name`, `config`, `trusted_ip`, `trusted_port`, и `config` имеет вид `<экземпляр>.conf`; (в) скрипт выполняется от `nobody`. Плюс выясняется, как создать тестового клиента и подключить его с самого 94.

Перед началом — сообщить владельцу, что на время пробы меняется `custom-client-connect.sh` на 94, и изменение срабатывает только для имён `azpanel-test-*`.

**Files:**
- Create: `docs/notes/2026-11-01-proba-94.md`

- [ ] **Step 1: Убедиться, что добавление клиента не перезапускает OpenVPN**

```bash
ssh root@192.0.2.94 'sed -n "/^addOpenVPN()/,/^}/p" /root/antizapret/client.sh | grep -nE "systemctl|restart|kill" || echo "перезапусков нет"'
```

Expected: `перезапусков нет`. Если есть `systemctl restart openvpn…` — остановиться и сообщить владельцу: добавление клиента рвёт живые сессии.

- [ ] **Step 2: Создать тестового клиента на 1 день и найти его профиль**

```bash
ssh root@192.0.2.94 '/root/antizapret/client.sh 1 azpanel-test-1 1 >/dev/null && find /root/antizapret/client -name "*azpanel-test-1*" -name "*.ovpn"'
```

Expected: один или несколько путей `.ovpn` (AntiZapret кладёт профили по видам: `antizapret-…`, `vpn-…`). Записать в заметку путь профиля `antizapret` UDP — он нужен дальше.

- [ ] **Step 3: Поставить пробу в custom-client-connect.sh**

```bash
ssh root@192.0.2.94 'set -e
mkdir -p /root/azpanel-probe
cp -p /etc/openvpn/server/scripts/custom-client-connect.sh /root/azpanel-probe/custom-client-connect.sh.orig
install -d -m 0777 /run/azpanel-probe
cat > /etc/openvpn/server/scripts/custom-client-connect.sh <<'"'"'EOF'"'"'
#!/bin/bash
if [[ "$common_name" == azpanel-test-* ]]; then
	d=/run/azpanel-probe
	{ env | sort; id; } > "$d/env-$$.txt"
	inst=$(basename "$config" .conf)
	{ echo "status 3"; sleep 2; } | timeout 3 socat - "UNIX-CONNECT:/run/openvpn-server/$inst.sock" > "$d/own-$$.txt" 2>&1
	echo "rc=$?" >> "$d/own-$$.txt"
	for s in /run/openvpn-server/*.sock; do
		[[ "$s" == */"$inst".sock ]] && continue
		{ echo "status 3"; sleep 1; } | timeout 3 socat - "UNIX-CONNECT:$s" > "$d/other-$$.txt" 2>&1
		echo "rc=$? sock=$s" >> "$d/other-$$.txt"
		break
	done
fi
exit 0
EOF
chmod 755 /etc/openvpn/server/scripts/custom-client-connect.sh
bash -n /etc/openvpn/server/scripts/custom-client-connect.sh && echo синтаксис-ок'
```

Expected: `синтаксис-ок`. Для любых других клиентов скрипт делает то же, что прежний (`exit 0`).

- [ ] **Step 4: Подключить тестового клиента с самого 94, без маршрутов и адресов**

`/root/azpanel-probe/test-udp.ovpn` — путь из шага 2.

```bash
ssh root@192.0.2.94 'cd /root/azpanel-probe
openvpn --config /root/azpanel-probe/test-udp.ovpn --route-nopull --ifconfig-noexec --route-noexec --disable-dco \
  --log a.log --writepid a.pid --daemon azt-probe
for i in $(seq 1 30); do grep -qE "Initialization Sequence Completed|AUTH_FAILED|Exiting" a.log && break; sleep 1; done
tail -5 a.log; kill "$(cat a.pid)"; sleep 1
ls -la /run/azpanel-probe; cat /run/azpanel-probe/own-*.txt; echo ===; head -c 400 /run/azpanel-probe/other-*.txt; tail -1 /run/azpanel-probe/other-*.txt; echo ===
grep -E "^(common_name|config|trusted_ip|trusted_port|untrusted_ip|untrusted_port|dev|uid)=|^uid" /run/azpanel-probe/env-*.txt'
```

Expected:
- в `a.log` — `Initialization Sequence Completed`;
- `own-*.txt` — нет строк `CLIENT_LIST` и `END`, `rc=124` (экземпляр молчит);
- `other-*.txt` — есть `END`, `rc=0`;
- `env-*.txt` — `common_name=azpanel-test-1`, `config=<экземпляр>.conf`, `trusted_ip`, `trusted_port`, строка `uid=65534(nobody)`.

Если клиент не подключился (`Exiting`, тайм-аут) — посмотреть `a.log`; частая причина — защита от сканирования AntiZapret: тогда добавить свой внешний IP в `allow-ips.txt` НЕЛЬЗЯ без владельца, остановиться и спросить.

- [ ] **Step 5: Вернуть исходный скрипт и проверить, что он тот же**

```bash
ssh root@192.0.2.94 'cp -p /root/azpanel-probe/custom-client-connect.sh.orig /etc/openvpn/server/scripts/custom-client-connect.sh
cmp /root/azpanel-probe/custom-client-connect.sh.orig /etc/openvpn/server/scripts/custom-client-connect.sh && echo возвращён
rm -rf /run/azpanel-probe'
```

Expected: `возвращён`. Тестовый клиент `azpanel-test-1` и каталог `/root/azpanel-probe` (с профилем) остаются для задачи 14.

- [ ] **Step 6: Записать результаты**

Создать `docs/notes/2026-11-01-proba-94.md`: дата, версия OpenVPN, путь профиля, фактические значения четырёх переменных окружения, uid, вывод `own` и `other` (без адресов живых клиентов — в `other` их вырезать), вывод. Если любое из предположений (а)–(в) не подтвердилось — остановиться и сообщить владельцу до задачи 2: от этого зависят задачи 7, 9, 10.

- [ ] **Step 7: Commit**

```bash
git add docs/notes/2026-11-01-proba-94.md
git commit -m "Проба на 94: окружение client-connect, молчание своего сокета, uid скрипта"
```

---

### Task 2: Каркас — модуль, пути, атомарная запись, сборка

**Files:**
- Create: `go.mod`, `cmd/azpanel/main.go`, `internal/paths/paths.go`, `internal/paths/paths_test.go`, `internal/fsutil/atomic.go`, `internal/fsutil/atomic_test.go`, `scripts/build.sh`, `.gitignore`

**Interfaces:**
- Produces: `paths.Root() string`, `paths.Bin()`, `paths.Etc()`, `paths.Log()`, `paths.Data()`, `paths.Backup()`, `paths.Binary()`, `paths.ConfigFile()`, `paths.LimitsFile()`, `paths.NodeSocket()`; `fsutil.WriteFileAtomic(path string, data []byte, perm os.FileMode) error`; в `main.go` — `var version`, `run(args []string) int`.

- [ ] **Step 1: Создать модуль**

```bash
cd C:/Users/faza8/Desktop/project/azpanel
go mod init github.com/syava842/azpanel
go mod edit -go=1.24
printf 'dist/\n' > .gitignore
```

- [ ] **Step 2: Написать падающие тесты путей и атомарной записи**

`internal/paths/paths_test.go`:

```go
package paths

import (
	"path/filepath"
	"testing"
)

func TestRootDefault(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", "")
	if got := Root(); got != "/opt/azpanel" {
		t.Fatalf("Root() = %q", got)
	}
	if got := NodeSocket(); got != "/run/azpanel/node.sock" {
		t.Fatalf("NodeSocket() = %q", got)
	}
}

func TestRootOverride(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AZPANEL_ROOT", root)
	if got, want := LimitsFile(), filepath.Join(root, "data", "limits.json"); got != want {
		t.Fatalf("LimitsFile() = %q, want %q", got, want)
	}
	if got, want := NodeSocket(), filepath.Join(root, "run", "node.sock"); got != want {
		t.Fatalf("NodeSocket() = %q, want %q", got, want)
	}
}
```

`internal/fsutil/atomic_test.go`:

```go
package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicReplacesContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Fatalf("содержимое %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("остались временные файлы: %v", entries)
	}
}
```

- [ ] **Step 3: Запустить — должны упасть**

Run: `go test ./internal/...`
Expected: FAIL — `undefined: Root`, `undefined: WriteFileAtomic`.

- [ ] **Step 4: Реализовать**

`internal/paths/paths.go`:

```go
// Package paths — раскладка azpanel на сервере.
package paths

import (
	"os"
	"path/filepath"
)

// Root — корень установки. AZPANEL_ROOT переопределяет его (для тестов).
func Root() string {
	if r := os.Getenv("AZPANEL_ROOT"); r != "" {
		return r
	}
	return "/opt/azpanel"
}

func Bin() string    { return filepath.Join(Root(), "bin") }
func Etc() string    { return filepath.Join(Root(), "etc") }
func Log() string    { return filepath.Join(Root(), "log") }
func Data() string   { return filepath.Join(Root(), "data") }
func Backup() string { return filepath.Join(Root(), "backup") }

func Binary() string     { return filepath.Join(Bin(), "azpanel") }
func ConfigFile() string { return filepath.Join(Etc(), "config.toml") }
func LimitsFile() string { return filepath.Join(Data(), "limits.json") }

// NodeSocket — сокет агента. Путь не настраивается: хук работает от nobody,
// config.toml ему не прочитать.
func NodeSocket() string {
	if os.Getenv("AZPANEL_ROOT") != "" {
		return filepath.Join(Root(), "run", "node.sock")
	}
	return "/run/azpanel/node.sock"
}
```

`internal/fsutil/atomic.go`:

```go
// Package fsutil — работа с файлами, общая для всех режимов.
package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic пишет файл через временный рядом и rename: читатель видит
// либо прежнее содержимое, либо новое целиком.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // после rename файла под этим именем уже нет
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // на Windows каталог не синхронизируется — ошибка не важна
		d.Close()
	}
	return nil
}
```

`cmd/azpanel/main.go`:

```go
// azpanel — панель и агент для AntiZapret-VPN. Режим задаёт первый аргумент.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Использование:
  azpanel version
`)
}
```

`scripts/build.sh`:

```bash
#!/usr/bin/env bash
# Сборка azpanel под linux: dist/azpanel-linux-<arch>.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
mkdir -p dist
for arch in amd64 arm64; do
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$version" \
		-o "dist/azpanel-linux-$arch" ./cmd/azpanel
done
ls -l dist
```

- [ ] **Step 5: Запустить тесты и сборку**

Run: `go test ./... && bash scripts/build.sh`
Expected: `ok` для `paths` и `fsutil`; в `dist/` два файла.

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore cmd internal scripts
git commit -m "Каркас: модуль, пути /opt/azpanel, атомарная запись, сборка под linux"
```

---

### Task 3: config.toml

**Files:**
- Create: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: `fsutil.WriteFileAtomic`.
- Produces: `config.CurrentVersion = 1`; `type Config{ConfigVersion int; Node Node; Log Log}`; `type Node{OpenVPNSocketDir, OpenVPNScriptsDir string; PollSeconds, QueryTimeoutMs int}`; `type Log{MaxSizeMB, Keep int}`; `config.Default() Config`; `config.Load(path string) (Config, error)` — при ошибке возвращает умолчания вместе с ошибкой; `config.Save(path string, c Config) error`; `(Config) Validate() error`.

- [ ] **Step 1: Подключить toml**

Run: `go get github.com/BurntSushi/toml@v1.4.0`

- [ ] **Step 2: Написать падающие тесты**

`internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMissingGivesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "нет.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if c != Default() {
		t.Fatalf("получено %+v", c)
	}
}

func TestLoadPartialKeepsOtherDefaults(t *testing.T) {
	c, err := Load(write(t, "config_version = 1\n[node]\npoll_seconds = 7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Node.PollSeconds != 7 {
		t.Fatalf("poll_seconds = %d", c.Node.PollSeconds)
	}
	if c.Node.OpenVPNSocketDir != "/run/openvpn-server" || c.Log.Keep != 5 {
		t.Fatalf("умолчания потеряны: %+v", c)
	}
}

func TestLoadRejectsNewerVersion(t *testing.T) {
	_, err := Load(write(t, "config_version = 99\n"))
	if err == nil || !strings.Contains(err.Error(), "новее") {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestLoadRejectsBadPoll(t *testing.T) {
	_, err := Load(write(t, "config_version = 1\n[node]\npoll_seconds = 0\n"))
	if err == nil || !strings.Contains(err.Error(), "poll_seconds") {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	c := Default()
	c.Log.Keep = 9
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Fatalf("получено %+v, ждали %+v", got, c)
	}
}
```

- [ ] **Step 3: Запустить — должны упасть**

Run: `go test ./internal/config/`
Expected: FAIL — `undefined: Load`.

- [ ] **Step 4: Реализовать**

`internal/config/config.go`:

```go
// Package config — /opt/azpanel/etc/config.toml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/syava842/azpanel/internal/fsutil"
)

// CurrentVersion — версия структуры конфига, которую знает этот бинарник.
const CurrentVersion = 1

type Config struct {
	ConfigVersion int  `toml:"config_version"`
	Node          Node `toml:"node"`
	Log           Log  `toml:"log"`
}

type Node struct {
	OpenVPNSocketDir  string `toml:"openvpn_socket_dir"`
	OpenVPNScriptsDir string `toml:"openvpn_scripts_dir"`
	PollSeconds       int    `toml:"poll_seconds"`
	QueryTimeoutMs    int    `toml:"query_timeout_ms"`
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
		},
		Log: Log{MaxSizeMB: 10, Keep: 5},
	}
}

// Load читает конфиг поверх умолчаний; нет файла — умолчания. При ошибке
// вместе с ней возвращаются умолчания.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return Default(), err
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	if c.ConfigVersion > CurrentVersion {
		return Default(), fmt.Errorf("%s: config_version %d новее, чем знает эта версия azpanel (%d)", path, c.ConfigVersion, CurrentVersion)
	}
	if c.ConfigVersion < 1 {
		c.ConfigVersion = CurrentVersion
	}
	if err := c.Validate(); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c Config) Validate() error {
	switch {
	case c.Node.OpenVPNSocketDir == "":
		return errors.New("node.openvpn_socket_dir пуст")
	case c.Node.OpenVPNScriptsDir == "":
		return errors.New("node.openvpn_scripts_dir пуст")
	case c.Node.PollSeconds < 1 || c.Node.PollSeconds > 60:
		return fmt.Errorf("node.poll_seconds = %d, нужно 1..60", c.Node.PollSeconds)
	case c.Node.QueryTimeoutMs < 100 || c.Node.QueryTimeoutMs > 5000:
		return fmt.Errorf("node.query_timeout_ms = %d, нужно 100..5000", c.Node.QueryTimeoutMs)
	case c.Log.MaxSizeMB < 1 || c.Log.MaxSizeMB > 1000:
		return fmt.Errorf("log.max_size_mb = %d, нужно 1..1000", c.Log.MaxSizeMB)
	case c.Log.Keep < 1 || c.Log.Keep > 100:
		return fmt.Errorf("log.keep = %d, нужно 1..100", c.Log.Keep)
	}
	return nil
}

func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, buf.Bytes(), 0o600)
}
```

- [ ] **Step 5: Запустить тесты**

Run: `go test ./internal/config/`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/config
git commit -m "config.toml: умолчания, загрузка поверх умолчаний, проверка, запись"
```

---

### Task 4: Журнал с ротацией

**Files:**
- Create: `internal/logx/rotator.go`, `internal/logx/rotator_test.go`

**Interfaces:**
- Produces: `logx.Open(path string, maxBytes int64, keep int) (*Rotator, error)`; `(*Rotator) Write([]byte) (int, error)`; `(*Rotator) Close() error`; `logx.New(w io.Writer) *slog.Logger`.

- [ ] **Step 1: Написать падающий тест**

`internal/logx/rotator_test.go`:

```go
package logx

import (
	"os"
	"path/filepath"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<нет>"
	}
	return string(b)
}

func TestRotatorShiftsAndDropsOldest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node.log")
	r, err := Open(p, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"first\n", "second\n", "third\n", "fourth\n"} {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	if got := read(t, p); got != "fourth\n" {
		t.Fatalf("node.log = %q", got)
	}
	if got := read(t, p+".1"); got != "third\n" {
		t.Fatalf("node.log.1 = %q", got)
	}
	if got := read(t, p+".2"); got != "second\n" {
		t.Fatalf("node.log.2 = %q", got)
	}
	if got := read(t, p+".3"); got != "<нет>" {
		t.Fatalf("лишний node.log.3 = %q", got)
	}
}

func TestRotatorAppendsToExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node.log")
	os.WriteFile(p, []byte("old\n"), 0o640)
	r, err := Open(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	r.Write([]byte("new\n"))
	r.Close()
	if got := read(t, p); got != "old\nnew\n" {
		t.Fatalf("node.log = %q", got)
	}
}
```

- [ ] **Step 2: Запустить — должен упасть**

Run: `go test ./internal/logx/`
Expected: FAIL — `undefined: Open`.

- [ ] **Step 3: Реализовать**

`internal/logx/rotator.go`:

```go
// Package logx — журналы azpanel в /opt/azpanel/log с ротацией по размеру.
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// Rotator пишет в файл и при превышении размера сдвигает его:
// file → file.1 → … → file.<keep>, самый старый удаляется.
type Rotator struct {
	mu   sync.Mutex
	path string
	max  int64
	keep int
	f    *os.File
	size int64
}

func Open(path string, maxBytes int64, keep int) (*Rotator, error) {
	r := &Rotator{path: path, max: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotator) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *Rotator) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	os.Rename(r.path, r.path+".1")
	return r.open()
}

func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// New — текстовый slog поверх любого писателя.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}
```

- [ ] **Step 4: Запустить тесты**

Run: `go test ./internal/logx/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/logx
git commit -m "Журнал с ротацией по размеру"
```

---

### Task 5: Опрос управляющего сокета OpenVPN

**Files:**
- Create: `internal/antizapret/mgmt.go`, `internal/antizapret/mgmt_test.go`

**Interfaces:**
- Produces: `type Session{Instance, CommonName, RealAddr string; BytesRx, BytesTx int64; ConnectedSince time.Time}`; `antizapret.ErrIncomplete`; `antizapret.NormalizeAddr(a string) string`; `antizapret.ParseStatus3(instance string, r io.Reader) ([]Session, error)`; `antizapret.QueryStatus(sockPath string, timeout time.Duration) ([]Session, error)`; `antizapret.InstanceFromSocket(p string) string`; `antizapret.ListSockets(dir string) ([]string, error)`.

- [ ] **Step 1: Написать падающие тесты**

`internal/antizapret/mgmt_test.go`:

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

const status3 = ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n" +
	"TITLE\tOpenVPN 2.7.8\n" +
	"TIME\t2026-11-01 19:15:12\t1793560512\n" +
	"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n" +
	"CLIENT_LIST\talice\t203.0.113.5:40001\t10.29.0.2\t\t1000\t2000\t2026-11-01 19:00:00\t1793559600\tUNDEF\t1\t0\tAES-256-GCM\n" +
	"CLIENT_LIST\talice\t::ffff:198.51.100.7:40002\t10.29.0.3\t\t10\t20\t2026-11-01 19:01:00\t1793559660\tUNDEF\t2\t1\tAES-256-GCM\n" +
	"CLIENT_LIST\tUNDEF\t192.0.2.9:40003\t\t\t0\t0\t2026-11-01 19:02:00\t1793559720\tUNDEF\t3\t2\tnone\n" +
	"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\n" +
	"GLOBAL_STATS\tdco_enabled\t1\n" +
	"END\n"

func TestParseStatus3(t *testing.T) {
	s, err := ParseStatus3("antizapret-udp", strings.NewReader(status3))
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 {
		t.Fatalf("сессий %d, ждали 2 (UNDEF пропускается): %+v", len(s), s)
	}
	if s[0].Instance != "antizapret-udp" || s[0].CommonName != "alice" || s[0].RealAddr != "203.0.113.5:40001" {
		t.Fatalf("первая сессия %+v", s[0])
	}
	if s[0].BytesRx != 1000 || s[0].BytesTx != 2000 || s[0].ConnectedSince.Unix() != 1793559600 {
		t.Fatalf("счётчики %+v", s[0])
	}
	if s[1].RealAddr != "198.51.100.7:40002" {
		t.Fatalf("префикс ::ffff: не снят: %q", s[1].RealAddr)
	}
}

func TestParseStatus3Incomplete(t *testing.T) {
	_, err := ParseStatus3("x", strings.NewReader("CLIENT_LIST\talice\t1.2.3.4:1\n"))
	if err != ErrIncomplete {
		t.Fatalf("ошибка = %v", err)
	}
}

func TestNormalizeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4:5":                  "1.2.3.4:5",
		"::ffff:1.2.3.4:5":           "1.2.3.4:5",
		"[AF_INET]1.2.3.4:5":         "1.2.3.4:5",
		"[AF_INET6]::ffff:1.2.3.4:5": "1.2.3.4:5",
	} {
		if got := NormalizeAddr(in); got != want {
			t.Errorf("NormalizeAddr(%q) = %q, ждали %q", in, got, want)
		}
	}
}

// fakeMgmt поднимает сокет, который отвечает как OpenVPN; silent — молчит.
func fakeMgmt(t *testing.T, name string, silent bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name+".sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if silent {
					time.Sleep(3 * time.Second)
					return
				}
				c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\n"))
				line, _ := bufio.NewReader(c).ReadString('\n')
				if strings.TrimSpace(line) == "status 3" {
					c.Write([]byte(status3[strings.Index(status3, "TITLE"):]))
				}
			}(c)
		}
	}()
	return p
}

func TestQueryStatus(t *testing.T) {
	p := fakeMgmt(t, "vpn-udp", false)
	s, err := QueryStatus(p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 || s[0].Instance != "vpn-udp" {
		t.Fatalf("получено %+v", s)
	}
}

func TestQueryStatusTimeout(t *testing.T) {
	p := fakeMgmt(t, "vpn-tcp", true)
	start := time.Now()
	if _, err := QueryStatus(p, 300*time.Millisecond); err == nil {
		t.Fatal("ждали ошибку тайм-аута")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("ждали %v — тайм-аут не сработал", d)
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./internal/antizapret/`
Expected: FAIL — `undefined: ParseStatus3`.

- [ ] **Step 3: Реализовать**

`internal/antizapret/mgmt.go`:

```go
// Package antizapret — работа с файлами, скриптами и службами AntiZapret.
package antizapret

import (
	"bufio"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Session — одна строка CLIENT_LIST ответа на «status 3».
type Session struct {
	Instance       string
	CommonName     string
	RealAddr       string
	BytesRx        int64
	BytesTx        int64
	ConnectedSince time.Time
}

var ErrIncomplete = errors.New("ответ status оборван до END")

// NormalizeAddr приводит адрес клиента к виду ip:port: OpenVPN может писать
// метку семейства и IPv4 в виде ::ffff:a.b.c.d.
func NormalizeAddr(a string) string {
	a = strings.TrimPrefix(a, "[AF_INET6]")
	a = strings.TrimPrefix(a, "[AF_INET]")
	return strings.TrimPrefix(a, "::ffff:")
}

// ParseStatus3 разбирает ответ управляющего интерфейса на «status 3»
// (поля через табуляцию) до строки END.
func ParseStatus3(instance string, r io.Reader) ([]Session, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []Session
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "END" {
			return out, nil
		}
		if strings.HasPrefix(line, ">") {
			continue // приветствие и асинхронные уведомления
		}
		f := strings.Split(line, "\t")
		if len(f) < 9 || f[0] != "CLIENT_LIST" || f[1] == "UNDEF" {
			continue // UNDEF — рукопожатие ещё не закончено
		}
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		since, _ := strconv.ParseInt(f[8], 10, 64)
		out = append(out, Session{
			Instance:       instance,
			CommonName:     f[1],
			RealAddr:       NormalizeAddr(f[2]),
			BytesRx:        rx,
			BytesTx:        tx,
			ConnectedSince: time.Unix(since, 0),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, ErrIncomplete
}

// QueryStatus спрашивает «status 3» у одного экземпляра. Управляющий
// интерфейс обслуживает одного собеседника за раз, поэтому соединение
// держится не дольше timeout.
func QueryStatus(sockPath string, timeout time.Duration) ([]Session, error) {
	conn, err := net.DialTimeout("unix", sockPath, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, "status 3\n"); err != nil {
		return nil, err
	}
	s, err := ParseStatus3(InstanceFromSocket(sockPath), conn)
	io.WriteString(conn, "quit\n")
	return s, err
}

// InstanceFromSocket: /run/openvpn-server/antizapret-udp.sock → antizapret-udp.
func InstanceFromSocket(p string) string {
	return strings.TrimSuffix(filepath.Base(p), ".sock")
}

func ListSockets(dir string) ([]string, error) {
	return filepath.Glob(filepath.Join(dir, "*.sock"))
}
```

- [ ] **Step 4: Запустить тесты**

Run: `go test ./internal/antizapret/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/antizapret
git commit -m "Разбор status 3 и опрос управляющего сокета OpenVPN с тайм-аутом"
```

---

### Task 6: limits.json

**Files:**
- Create: `internal/limits/limits.go`, `internal/limits/limits_test.go`

**Interfaces:**
- Consumes: `fsutil.WriteFileAtomic`.
- Produces: `limits.ValidName(string) bool`; `limits.Load(path string) (map[string]int, error)` — нет файла → пустая карта; `limits.Save(path string, m map[string]int) error`; `limits.NewStore(path string) *Store`; `(*Store) Get(name string) (int, error)` — 0 значит без ограничения.

- [ ] **Step 1: Написать падающие тесты**

`internal/limits/limits_test.go`:

```go
package limits

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"alice": true, "a-b_C9": true, "": false, "имя": false,
		"a b": false, "abcdefghijabcdefghijabcdefghijabc": false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v", name, got)
		}
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "limits.json"))
	if err != nil || len(m) != 0 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	if err := Save(p, map[string]int{"alice": 3}); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil || m["alice"] != 3 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"битый JSON":   `{`,
		"версия":       `{"version":2,"limits":{}}`,
		"ноль":         `{"version":1,"limits":{"alice":0}}`,
		"кривое имя":   `{"version":1,"limits":{"a b":1}}`,
	} {
		p := filepath.Join(dir, "l.json")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: ждали ошибку", name)
		}
	}
}

func TestStoreRereadsOnChange(t *testing.T) {
	p := filepath.Join(t.TempDir(), "limits.json")
	s := NewStore(p)
	if n, err := s.Get("alice"); n != 0 || err != nil {
		t.Fatalf("без файла: n=%d err=%v", n, err)
	}
	Save(p, map[string]int{"alice": 2})
	if n, _ := s.Get("alice"); n != 2 {
		t.Fatalf("после записи n=%d", n)
	}
	Save(p, map[string]int{"alice": 2, "bob": 10})
	if n, _ := s.Get("bob"); n != 10 {
		t.Fatalf("после второй записи n=%d", n)
	}
	os.WriteFile(p, []byte("{"), 0o600)
	if _, err := s.Get("alice"); err == nil {
		t.Fatal("битый файл: ждали ошибку")
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./internal/limits/`
Expected: FAIL — `undefined: ValidName`.

- [ ] **Step 3: Реализовать**

`internal/limits/limits.go`:

```go
// Package limits — лимиты одновременных подключений, /opt/azpanel/data/limits.json.
package limits

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/fsutil"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ValidName — то же правило имени, что у client.sh AntiZapret.
func ValidName(name string) bool { return nameRe.MatchString(name) }

type file struct {
	Version int            `json:"version"`
	Limits  map[string]int `json:"limits"`
}

// Load читает лимиты; нет файла — пустая карта.
func Load(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: неизвестная версия %d", path, f.Version)
	}
	for name, n := range f.Limits {
		if !ValidName(name) {
			return nil, fmt.Errorf("%s: недопустимое имя клиента %q", path, name)
		}
		if n < 1 {
			return nil, fmt.Errorf("%s: лимит %s = %d, нужен 1 или больше", path, name, n)
		}
	}
	if f.Limits == nil {
		f.Limits = map[string]int{}
	}
	return f.Limits, nil
}

func Save(path string, m map[string]int) error {
	data, err := json.MarshalIndent(file{Version: 1, Limits: m}, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Store отдаёт лимиты и перечитывает файл, когда меняются его время или размер.
type Store struct {
	path string
	mu   sync.Mutex
	seen bool
	mod  time.Time
	size int64
	m    map[string]int
}

func NewStore(path string) *Store { return &Store{path: path, m: map[string]int{}} }

// Get — лимит клиента; 0 — без ограничения.
func (s *Store) Get(name string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.m, s.seen = map[string]int{}, false
	case err != nil:
		return 0, err
	case !s.seen || !st.ModTime().Equal(s.mod) || st.Size() != s.size:
		m, err := Load(s.path)
		if err != nil {
			return 0, err
		}
		s.m, s.mod, s.size, s.seen = m, st.ModTime(), st.Size(), true
	}
	return s.m[name], nil
}
```

- [ ] **Step 4: Запустить тесты**

Run: `go test ./internal/limits/`
Expected: `ok`. Если `TestStoreRereadsOnChange` падает на второй записи (одинаковые время и размер) — проверить, что во второй записи размер другой: он другой (добавлен `bob`).

- [ ] **Step 5: Commit**

```bash
git add internal/limits
git commit -m "limits.json: проверка имён и значений, перечитывание при изменении"
```

---

### Task 7: Учёт сессий

**Files:**
- Create: `internal/node/tracker.go`, `internal/node/tracker_test.go`

**Interfaces:**
- Consumes: `antizapret.Session`.
- Produces: `type Key{Instance, CN, Addr string}`; `node.NewTracker() *Tracker`; `(*Tracker) ApplySnapshot(instance string, taken time.Time, sessions []antizapret.Session)`; `(*Tracker) Admit(k Key, at time.Time, limit int) (allowed bool, count int)`; `(*Tracker) Disconnect(k Key, at time.Time)`; `(*Tracker) Count(cn string) int`; `(*Tracker) Counts() map[string]int`.

Правило учёта: сессия есть, если её событие хука новее снимка экземпляра (из двух событий — более позднее), иначе — если она есть в снимке. Новый снимок удаляет события своего экземпляра, которые не новее его.

- [ ] **Step 1: Написать падающие тесты**

`internal/node/tracker_test.go`:

```go
package node

import (
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func sess(cn, addr string) antizapret.Session { return antizapret.Session{CommonName: cn, RealAddr: addr} }

func TestCountAcrossInstances(t *testing.T) {
	tr := NewTracker()
	tr.ApplySnapshot("antizapret-udp", at(0), []antizapret.Session{sess("alice", "1.1.1.1:1"), sess("alice", "1.1.1.1:2"), sess("bob", "2.2.2.2:1")})
	tr.ApplySnapshot("vpn-tcp", at(0), []antizapret.Session{sess("alice", "3.3.3.3:1")})
	if n := tr.Count("alice"); n != 3 {
		t.Fatalf("alice = %d", n)
	}
	if got := tr.Counts(); got["alice"] != 3 || got["bob"] != 1 || len(got) != 2 {
		t.Fatalf("Counts = %v", got)
	}
}

func TestAdmitLimit(t *testing.T) {
	tr := NewTracker()
	tr.ApplySnapshot("antizapret-udp", at(0), []antizapret.Session{sess("alice", "1.1.1.1:1")})
	ok, n := tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:2"}, at(1), 2)
	if !ok || n != 2 {
		t.Fatalf("второе подключение: ok=%v n=%d", ok, n)
	}
	ok, n = tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:3"}, at(2), 2)
	if ok || n != 2 {
		t.Fatalf("третье при лимите 2: ok=%v n=%d", ok, n)
	}
}

func TestAdmitUnlimited(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 10; i++ {
		if ok, _ := tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:" + string(rune('a'+i))}, at(i), 0); !ok {
			t.Fatalf("подключение %d без лимита отклонено", i)
		}
	}
}

func TestRepeatOfSameKeyIsNotSecond(t *testing.T) {
	tr := NewTracker()
	k := Key{"vpn-udp", "alice", "1.1.1.1:1"}
	tr.Admit(k, at(1), 1)
	if ok, n := tr.Admit(k, at(2), 1); !ok || n != 1 {
		t.Fatalf("повтор: ok=%v n=%d", ok, n)
	}
}

func TestFailedConnectDisappearsWithNextSnapshot(t *testing.T) {
	tr := NewTracker()
	tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:1"}, at(1), 0)
	tr.ApplySnapshot("vpn-udp", at(5), nil) // подключение так и не состоялось
	if n := tr.Count("alice"); n != 0 {
		t.Fatalf("alice = %d", n)
	}
}

func TestOlderSnapshotKeepsNewerConnect(t *testing.T) {
	tr := NewTracker()
	tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:1"}, at(3), 0)
	tr.ApplySnapshot("vpn-udp", at(2), nil) // снимок начат до подключения
	if n := tr.Count("alice"); n != 1 {
		t.Fatalf("alice = %d", n)
	}
}

func TestDisconnectBeatsOlderSnapshot(t *testing.T) {
	tr := NewTracker()
	tr.ApplySnapshot("vpn-udp", at(0), []antizapret.Session{sess("alice", "1.1.1.1:1")})
	tr.Disconnect(Key{"vpn-udp", "alice", "1.1.1.1:1"}, at(1))
	if n := tr.Count("alice"); n != 0 {
		t.Fatalf("после отключения alice = %d", n)
	}
	ok, _ := tr.Admit(Key{"vpn-udp", "alice", "1.1.1.1:2"}, at(2), 1)
	if !ok {
		t.Fatal("после отключения место освободилось, но подключение отклонено")
	}
}

func TestConnectAfterDisconnectOfSameKey(t *testing.T) {
	tr := NewTracker()
	k := Key{"vpn-udp", "alice", "1.1.1.1:1"}
	tr.Admit(k, at(1), 0)
	tr.Disconnect(k, at(2))
	tr.Admit(k, at(3), 0)
	if n := tr.Count("alice"); n != 1 {
		t.Fatalf("alice = %d", n)
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./internal/node/`
Expected: FAIL — `undefined: NewTracker`.

- [ ] **Step 3: Реализовать**

`internal/node/tracker.go`:

```go
// Package node — агент узла: учёт сессий OpenVPN и ответы хуку лимита.
package node

import (
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

// Key — одна сессия: экземпляр OpenVPN, имя клиента, адрес ip:port.
type Key struct {
	Instance string
	CN       string
	Addr     string
}

type snapshot struct {
	taken time.Time
	keys  map[Key]struct{}
}

// Tracker считает сессии по снимкам управляющих сокетов и событиям хуков
// между снимками. Экземпляр, к которому идёт подключение, во время
// client-connect не отвечает, поэтому одних снимков мало.
type Tracker struct {
	mu    sync.Mutex
	snaps map[string]snapshot
	conns map[Key]time.Time
	discs map[Key]time.Time
}

func NewTracker() *Tracker {
	return &Tracker{snaps: map[string]snapshot{}, conns: map[Key]time.Time{}, discs: map[Key]time.Time{}}
}

// ApplySnapshot заменяет снимок экземпляра. taken — время начала опроса:
// события позже него снимок мог не увидеть, поэтому они сохраняются.
func (t *Tracker) ApplySnapshot(instance string, taken time.Time, sessions []antizapret.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	keys := make(map[Key]struct{}, len(sessions))
	for _, s := range sessions {
		keys[Key{Instance: instance, CN: s.CommonName, Addr: s.RealAddr}] = struct{}{}
	}
	t.snaps[instance] = snapshot{taken: taken, keys: keys}
	for k, ev := range t.conns {
		if k.Instance == instance && !ev.After(taken) {
			delete(t.conns, k)
		}
	}
	for k, ev := range t.discs {
		if k.Instance == instance && !ev.After(taken) {
			delete(t.discs, k)
		}
	}
}

// present: событие новее снимка побеждает снимок; из двух событий — позднее.
func (t *Tracker) present(k Key) bool {
	snap := t.snaps[k.Instance]
	_, inSnap := snap.keys[k]
	c, hasC := t.conns[k]
	d, hasD := t.discs[k]
	cAfter := hasC && c.After(snap.taken)
	dAfter := hasD && d.After(snap.taken)
	switch {
	case cAfter && (!dAfter || c.After(d)):
		return true
	case dAfter:
		return false
	default:
		return inSnap
	}
}

func (t *Tracker) keysOf(cn string) map[Key]struct{} {
	out := map[Key]struct{}{}
	for _, s := range t.snaps {
		for k := range s.keys {
			if k.CN == cn && t.present(k) {
				out[k] = struct{}{}
			}
		}
	}
	for k := range t.conns {
		if k.CN == cn && t.present(k) {
			out[k] = struct{}{}
		}
	}
	return out
}

func (t *Tracker) Count(cn string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keysOf(cn))
}

// Admit засчитывает подключение, если у клиента меньше limit сессий.
// limit 0 — без ограничения. count — сколько сессий будет с этой (или есть
// сейчас, если отказ).
func (t *Tracker) Admit(k Key, at time.Time, limit int) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	keys := t.keysOf(k.CN)
	delete(keys, k) // повтор того же подключения не считается вторым
	if limit > 0 && len(keys) >= limit {
		return false, len(keys)
	}
	t.conns[k] = at
	return true, len(keys) + 1
}

func (t *Tracker) Disconnect(k Key, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.discs[k] = at
}

// Counts — число сессий по каждому клиенту, у которого они есть.
func (t *Tracker) Counts() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cns := map[string]struct{}{}
	for _, s := range t.snaps {
		for k := range s.keys {
			cns[k.CN] = struct{}{}
		}
	}
	for k := range t.conns {
		cns[k.CN] = struct{}{}
	}
	out := map[string]int{}
	for cn := range cns {
		if n := len(t.keysOf(cn)); n > 0 {
			out[cn] = n
		}
	}
	return out
}
```

- [ ] **Step 4: Запустить тесты**

Run: `go test ./internal/node/ -run Tracker -v` затем `go test ./internal/node/`
Expected: `ok`, все восемь тестов `PASS`.

- [ ] **Step 5: Commit**

```bash
git add internal/node/tracker.go internal/node/tracker_test.go
git commit -m "Учёт сессий: снимки сокетов плюс события хуков между снимками"
```

---

### Task 8: Протокол хук ↔ агент и сервер агента

**Files:**
- Create: `internal/agentproto/proto.go`, `internal/node/server.go`, `internal/node/server_test.go`, `internal/node/peercred_linux.go`, `internal/node/peercred_other.go`

**Interfaces:**
- Consumes: `node.Tracker`, `node.Key`, `limits.Store`.
- Produces: `agentproto.OpConnect = "connect"`, `OpDisconnect = "disconnect"`, `OpList = "list"`; `type agentproto.Request{Op, Instance, CN, Addr string}`; `type agentproto.Response{Allow bool; Count, Limit int; Counts map[string]int; Error string}`; `agentproto.Call(sock string, req Request, timeout time.Duration) (Response, error)`; `type node.Server{Tracker *Tracker; Limits *limits.Store; HookLog, Log *slog.Logger; Now func() time.Time; Peer func(net.Conn) error}`; `(*Server) Handle(agentproto.Request) agentproto.Response`; `(*Server) Serve(net.Listener) error`; `node.PeerChecker() func(net.Conn) error`.

- [ ] **Step 1: Протокол**

`internal/agentproto/proto.go`:

```go
// Package agentproto — запрос и ответ между хуком и агентом через unix-сокет:
// одна строка JSON в каждую сторону.
package agentproto

import (
	"encoding/json"
	"net"
	"time"
)

const (
	OpConnect    = "connect"
	OpDisconnect = "disconnect"
	OpList       = "list"
)

type Request struct {
	Op       string `json:"op"`
	Instance string `json:"instance,omitempty"`
	CN       string `json:"cn,omitempty"`
	Addr     string `json:"addr,omitempty"`
}

type Response struct {
	Allow  bool           `json:"allow"`
	Count  int            `json:"count,omitempty"`
	Limit  int            `json:"limit,omitempty"`
	Counts map[string]int `json:"counts,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// Call отправляет один запрос и ждёт ответ не дольше timeout.
func Call(sock string, req Request, timeout time.Duration) (Response, error) {
	var resp Response
	conn, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		return resp, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return resp, err
	}
	err = json.NewDecoder(conn).Decode(&resp)
	return resp, err
}
```

- [ ] **Step 2: Написать падающие тесты сервера**

`internal/node/server_test.go`:

```go
package node

import (
	"bytes"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/logx"
)

func newServer(t *testing.T, lim map[string]int) (*Server, *bytes.Buffer) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "limits.json")
	if lim != nil {
		if err := limits.Save(p, lim); err != nil {
			t.Fatal(err)
		}
	}
	var hookLog bytes.Buffer
	return &Server{
		Tracker: NewTracker(),
		Limits:  limits.NewStore(p),
		HookLog: logx.New(&hookLog),
		Log:     logx.New(io.Discard),
		Now:     func() time.Time { return t0 },
	}, &hookLog
}

func connect(cn, addr string) agentproto.Request {
	return agentproto.Request{Op: agentproto.OpConnect, Instance: "antizapret-udp", CN: cn, Addr: addr}
}

func TestHandleConnectWithinAndOverLimit(t *testing.T) {
	s, hookLog := newServer(t, map[string]int{"alice": 1})
	if r := s.Handle(connect("alice", "1.1.1.1:1")); !r.Allow || r.Count != 1 || r.Limit != 1 {
		t.Fatalf("первое: %+v", r)
	}
	r := s.Handle(connect("alice", "1.1.1.1:2"))
	if r.Allow || r.Count != 1 || r.Limit != 1 || r.Error != "" {
		t.Fatalf("второе: %+v", r)
	}
	if !strings.Contains(hookLog.String(), "отказ") {
		t.Fatalf("в hook.log нет отказа:\n%s", hookLog.String())
	}
}

func TestHandleNoLimitAllows(t *testing.T) {
	s, _ := newServer(t, nil)
	for i := 0; i < 5; i++ {
		if r := s.Handle(connect("bob", "2.2.2.2:"+string(rune('1'+i)))); !r.Allow {
			t.Fatalf("подключение %d: %+v", i, r)
		}
	}
}

func TestHandleBrokenLimitsFailsOpen(t *testing.T) {
	s, hookLog := newServer(t, nil)
	s.Limits = limits.NewStore(writeFile(t, "limits.json", "{"))
	r := s.Handle(connect("alice", "1.1.1.1:1"))
	if !r.Allow || r.Error == "" {
		t.Fatalf("ответ %+v", r)
	}
	if !strings.Contains(hookLog.String(), "без проверки") {
		t.Fatalf("hook.log:\n%s", hookLog.String())
	}
}

func TestHandleDisconnectFreesSlot(t *testing.T) {
	s, _ := newServer(t, map[string]int{"alice": 1})
	s.Handle(connect("alice", "1.1.1.1:1"))
	s.Now = func() time.Time { return t0.Add(time.Second) }
	s.Handle(agentproto.Request{Op: agentproto.OpDisconnect, Instance: "antizapret-udp", CN: "alice", Addr: "1.1.1.1:1"})
	s.Now = func() time.Time { return t0.Add(2 * time.Second) }
	if r := s.Handle(connect("alice", "1.1.1.1:2")); !r.Allow {
		t.Fatalf("после отключения: %+v", r)
	}
}

func TestHandleUnknownOpAllows(t *testing.T) {
	s, _ := newServer(t, nil)
	if r := s.Handle(agentproto.Request{Op: "что-то"}); !r.Allow || r.Error == "" {
		t.Fatalf("ответ %+v", r)
	}
}

func TestServeOverSocket(t *testing.T) {
	s, _ := newServer(t, map[string]int{"alice": 1})
	sock := filepath.Join(t.TempDir(), "node.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.Serve(ln)
	r, err := agentproto.Call(sock, connect("alice", "1.1.1.1:1"), time.Second)
	if err != nil || !r.Allow {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	r, err = agentproto.Call(sock, agentproto.Request{Op: agentproto.OpList}, time.Second)
	if err != nil || r.Counts["alice"] != 1 {
		t.Fatalf("list: r=%+v err=%v", r, err)
	}
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
```

В импорты этого файла добавить `"os"`.

- [ ] **Step 3: Запустить — должны упасть**

Run: `go test ./internal/node/`
Expected: FAIL — `undefined: Server`.

- [ ] **Step 4: Реализовать сервер и проверку собеседника**

`internal/node/server.go`:

```go
package node

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/limits"
)

// Server отвечает хуку. Любая своя ошибка — «пускать»: из-за сбоя azpanel
// VPN отключаться не должен.
type Server struct {
	Tracker *Tracker
	Limits  *limits.Store
	HookLog *slog.Logger // hook.log: решения по подключениям
	Log     *slog.Logger // node.log: работа агента
	Now     func() time.Time
	Peer    func(net.Conn) error // nil — без проверки собеседника
}

func (s *Server) Handle(req agentproto.Request) agentproto.Response {
	k := Key{Instance: req.Instance, CN: req.CN, Addr: req.Addr}
	switch req.Op {
	case agentproto.OpConnect:
		limit, err := s.Limits.Get(req.CN)
		if err != nil {
			s.HookLog.Error("лимиты не прочитаны, подключение пропущено без проверки", "cn", req.CN, "err", err)
			return agentproto.Response{Allow: true, Error: err.Error()}
		}
		ok, n := s.Tracker.Admit(k, s.Now(), limit)
		if !ok {
			s.HookLog.Warn("отказ: лимит подключений", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", limit)
			return agentproto.Response{Allow: false, Count: n, Limit: limit}
		}
		s.HookLog.Info("подключение", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", limit)
		return agentproto.Response{Allow: true, Count: n, Limit: limit}
	case agentproto.OpDisconnect:
		s.Tracker.Disconnect(k, s.Now())
		s.HookLog.Info("отключение", "cn", req.CN, "instance", req.Instance, "addr", req.Addr)
		return agentproto.Response{Allow: true}
	case agentproto.OpList:
		return agentproto.Response{Allow: true, Counts: s.Tracker.Counts()}
	default:
		return agentproto.Response{Allow: true, Error: "неизвестная операция " + req.Op}
	}
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveConn(c)
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if s.Peer != nil {
		if err := s.Peer(c); err != nil {
			s.Log.Warn("чужой процесс на сокете агента, отклонён", "err", err)
			return
		}
	}
	var req agentproto.Request
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		return
	}
	json.NewEncoder(c).Encode(s.Handle(req))
}
```

`internal/node/peercred_linux.go`:

```go
//go:build linux

package node

import (
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"syscall"
)

// PeerChecker пускает к сокету агента только root и nobody — под nobody
// OpenVPN AntiZapret выполняет скрипты.
func PeerChecker() func(net.Conn) error {
	allowed := map[uint32]bool{0: true}
	if u, err := user.Lookup("nobody"); err == nil {
		if id, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			allowed[uint32(id)] = true
		}
	}
	return func(c net.Conn) error {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return errors.New("не unix-сокет")
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return err
		}
		var cred *syscall.Ucred
		var cerr error
		if err := raw.Control(func(fd uintptr) {
			cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		}); err != nil {
			return err
		}
		if cerr != nil {
			return cerr
		}
		if !allowed[cred.Uid] {
			return fmt.Errorf("uid %d, pid %d", cred.Uid, cred.Pid)
		}
		return nil
	}
}
```

`internal/node/peercred_other.go`:

```go
//go:build !linux

package node

import "net"

// PeerChecker вне linux не проверяет: агент работает только на linux,
// здесь — для тестов на машине разработчика.
func PeerChecker() func(net.Conn) error { return nil }
```

- [ ] **Step 5: Запустить тесты и проверить сборку под linux**

Run: `go test ./internal/... && GOOS=linux go vet ./...`
Expected: `ok` для всех пакетов; `vet` без замечаний (проверяет и `peercred_linux.go`).

- [ ] **Step 6: Commit**

```bash
git add internal/agentproto internal/node
git commit -m "Протокол хук–агент, сервер агента, проверка собеседника по SO_PEERCRED"
```

---

### Task 9: Опрос экземпляров и служба агента

**Files:**
- Create: `internal/node/poller.go`, `internal/node/poller_test.go`, `internal/node/node.go`, `internal/node/node_test.go`

**Interfaces:**
- Consumes: `antizapret.ListSockets`, `antizapret.InstanceFromSocket`, `antizapret.QueryStatus`, `antizapret.HookFiles` (задача 11 — в этой задаче `node.go` вызывает `ensureHook`, см. шаг 3), `config.Config`, `paths.*`, `logx`.
- Produces: `type node.Poller{Dir string; Timeout time.Duration; Tracker *Tracker; Log *slog.Logger; Now func() time.Time; Query func(string, time.Duration) ([]antizapret.Session, error)}`; `(*Poller) PollOnce()`; `(*Poller) Run(ctx context.Context, every time.Duration)`; `node.Run(ctx context.Context, cfg config.Config, ensureHook func() (bool, error)) error`.

`node.Run` получает установку хука функцией: так задача 9 не зависит от задачи 11, а `main.go` (задача 12) передаёт туда `HookFiles.Ensure`.

- [ ] **Step 1: Написать падающие тесты**

`internal/node/poller_test.go`:

```go
package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/logx"
)

func TestPollOnceKeepsSnapshotOfSilentInstance(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"antizapret-udp.sock", "vpn-udp.sock"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	silent := false
	var logBuf bytes.Buffer
	tr := NewTracker()
	p := &Poller{
		Dir: dir, Timeout: time.Second, Tracker: tr, Log: logx.New(&logBuf),
		Now: func() time.Time { return t0 },
		Query: func(sock string, _ time.Duration) ([]antizapret.Session, error) {
			if antizapret.InstanceFromSocket(sock) == "vpn-udp" && silent {
				return nil, errors.New("i/o timeout")
			}
			return []antizapret.Session{{CommonName: "alice", RealAddr: antizapret.InstanceFromSocket(sock)}}, nil
		},
	}
	p.PollOnce()
	if n := tr.Count("alice"); n != 2 {
		t.Fatalf("после первого опроса alice = %d", n)
	}
	silent = true
	for i := 0; i < 3; i++ {
		p.PollOnce()
	}
	if n := tr.Count("alice"); n != 2 {
		t.Fatalf("молчащий экземпляр потерял снимок: alice = %d", n)
	}
	if c := strings.Count(logBuf.String(), "не отвечает"); c != 1 {
		t.Fatalf("предупреждений %d, ждали одно:\n%s", c, logBuf.String())
	}
}
```

`internal/node/node_test.go`:

```go
package node

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/paths"
)

func TestRunAnswersHook(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AZPANEL_ROOT", root)
	for _, d := range []string{paths.Log(), paths.Data(), filepath.Dir(paths.NodeSocket())} {
		os.MkdirAll(d, 0o755)
	}
	limits.Save(paths.LimitsFile(), map[string]int{"alice": 1})

	mgmtDir := filepath.Join(root, "ovpn")
	os.MkdirAll(mgmtDir, 0o755)
	ln, err := net.Listen("unix", filepath.Join(mgmtDir, "antizapret-udp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadString('\n')
			c.Write([]byte("CLIENT_LIST\talice\t1.1.1.1:1\t10.0.0.2\t\t1\t1\tx\t1\tUNDEF\t1\t0\tnone\nEND\n"))
			c.Close()
		}
	}()

	cfg := config.Default()
	cfg.Node.OpenVPNSocketDir = mgmtDir
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hooked := false
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, func() (bool, error) { hooked = true; return true, nil }) }()

	var r agentproto.Response
	for i := 0; i < 50; i++ {
		r, err = agentproto.Call(paths.NodeSocket(), agentproto.Request{Op: agentproto.OpConnect, Instance: "vpn-udp", CN: "alice", Addr: "2.2.2.2:1"}, time.Second)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if r.Allow {
		t.Fatalf("alice уже подключена (снимок), лимит 1 — ждали отказ: %+v", r)
	}
	if !hooked {
		t.Fatal("Run не вызвал установку хука")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(paths.Log(), "hook.log"))
	if !strings.Contains(string(b), "отказ") {
		t.Fatalf("hook.log:\n%s", b)
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./internal/node/`
Expected: FAIL — `undefined: Poller`, `undefined: Run`.

- [ ] **Step 3: Реализовать**

`internal/node/poller.go`:

```go
package node

import (
	"context"
	"log/slog"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

// silentWarnAfter — после стольких молчаливых опросов подряд экземпляр
// попадает в журнал. Одно-два молчания — штатно: экземпляр занят
// client-connect.
const silentWarnAfter = 3

type Poller struct {
	Dir     string
	Timeout time.Duration
	Tracker *Tracker
	Log     *slog.Logger
	Now     func() time.Time
	Query   func(sock string, timeout time.Duration) ([]antizapret.Session, error)
	fails   map[string]int
}

// PollOnce снимает состояние всех экземпляров. Не ответивший сохраняет
// прежний снимок.
func (p *Poller) PollOnce() {
	socks, err := antizapret.ListSockets(p.Dir)
	if err != nil {
		p.Log.Error("список сокетов OpenVPN не получен", "dir", p.Dir, "err", err)
		return
	}
	if p.fails == nil {
		p.fails = map[string]int{}
	}
	for _, sock := range socks {
		inst := antizapret.InstanceFromSocket(sock)
		taken := p.Now()
		sessions, err := p.Query(sock, p.Timeout)
		if err != nil {
			p.fails[inst]++
			if p.fails[inst] == silentWarnAfter {
				p.Log.Warn("экземпляр OpenVPN не отвечает", "instance", inst, "polls", p.fails[inst], "err", err)
			}
			continue
		}
		if p.fails[inst] >= silentWarnAfter {
			p.Log.Info("экземпляр OpenVPN снова отвечает", "instance", inst)
		}
		p.fails[inst] = 0
		p.Tracker.ApplySnapshot(inst, taken, sessions)
	}
}

func (p *Poller) Run(ctx context.Context, every time.Duration) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			p.PollOnce()
		}
	}
}
```

`internal/node/node.go`:

```go
package node

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/logx"
	"github.com/syava842/azpanel/internal/paths"
)

// hookCheckEvery — как часто проверять, что хук на месте: повторный
// setup.sh AntiZapret стирает /etc/openvpn/server целиком.
const hookCheckEvery = time.Minute

// Run — режим «azpanel node». ensureHook ставит хук в скрипты OpenVPN и
// сообщает, было ли изменение.
func Run(ctx context.Context, cfg config.Config, ensureHook func() (bool, error)) error {
	maxBytes := int64(cfg.Log.MaxSizeMB) << 20
	nodeW, err := logx.Open(filepath.Join(paths.Log(), "node.log"), maxBytes, cfg.Log.Keep)
	if err != nil {
		return err
	}
	defer nodeW.Close()
	hookW, err := logx.Open(filepath.Join(paths.Log(), "hook.log"), maxBytes, cfg.Log.Keep)
	if err != nil {
		return err
	}
	defer hookW.Close()
	log := logx.New(nodeW)

	checkHook := func() {
		changed, err := ensureHook()
		switch {
		case err != nil:
			log.Error("хук лимита не установлен", "err", err)
		case changed:
			log.Info("хук лимита установлен в скрипты OpenVPN", "dir", cfg.Node.OpenVPNScriptsDir)
		}
	}
	checkHook()

	tr := NewTracker()
	p := &Poller{
		Dir:     cfg.Node.OpenVPNSocketDir,
		Timeout: time.Duration(cfg.Node.QueryTimeoutMs) * time.Millisecond,
		Tracker: tr,
		Log:     log,
		Now:     time.Now,
		Query:   antizapret.QueryStatus,
	}
	p.PollOnce() // до первого ответа хуку счётчики должны быть заполнены

	sock := paths.NodeSocket()
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return err
	}
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	// Хук работает от nobody; кого пускать, решает PeerChecker.
	if err := os.Chmod(sock, 0o666); err != nil {
		log.Warn("права на сокет агента не выставлены — хук может не достучаться", "err", err)
	}
	srv := &Server{
		Tracker: tr,
		Limits:  limits.NewStore(paths.LimitsFile()),
		HookLog: logx.New(hookW),
		Log:     log,
		Now:     time.Now,
		Peer:    PeerChecker(),
	}
	go p.Run(ctx, time.Duration(cfg.Node.PollSeconds)*time.Second)
	go func() {
		tk := time.NewTicker(hookCheckEvery)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				ln.Close()
				return
			case <-tk.C:
				checkHook()
			}
		}
	}()
	log.Info("агент запущен", "socket", sock, "openvpn", cfg.Node.OpenVPNSocketDir)
	err = srv.Serve(ln)
	log.Info("агент остановлен")
	return err
}
```

Если `antizapret.HookFiles` ещё нет (задача 11 не сделана), на этом шаге ничего из неё не импортируется — `node.go` использует только `ensureHook`.

- [ ] **Step 4: Запустить тесты**

Run: `go test ./internal/node/`
Expected: `ok`. Если на Windows `bind: invalid argument` — путь к сокету длиннее 108 символов: в `TestRunAnswersHook` заменить `t.TempDir()` на `os.MkdirTemp("", "az")` с `t.Cleanup(func() { os.RemoveAll(root) })`.

- [ ] **Step 5: Commit**

```bash
git add internal/node
git commit -m "Агент: опрос экземпляров OpenVPN, сокет для хука, проверка хука раз в минуту"
```

---

### Task 10: Хук OpenVPN

**Files:**
- Create: `internal/hook/hook.go`, `internal/hook/hook_test.go`

**Interfaces:**
- Consumes: `agentproto.Request`, `agentproto.Response`, `antizapret.NormalizeAddr`.
- Produces: `hook.ExitDeny = 3`; `type hook.Caller func(agentproto.Request) (agentproto.Response, error)`; `hook.Run(op string, env func(string) string, call Caller, stderr io.Writer) int`.

- [ ] **Step 1: Написать падающие тесты**

`internal/hook/hook_test.go`:

```go
package hook

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/agentproto"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var aliceEnv = env(map[string]string{
	"common_name": "alice", "config": "antizapret-udp.conf",
	"trusted_ip": "203.0.113.5", "trusted_port": "40001",
})

func TestConnectSendsSessionAndAllows(t *testing.T) {
	var got agentproto.Request
	call := func(r agentproto.Request) (agentproto.Response, error) {
		got = r
		return agentproto.Response{Allow: true}, nil
	}
	if code := Run("connect", aliceEnv, call, &bytes.Buffer{}); code != 0 {
		t.Fatalf("код %d", code)
	}
	want := agentproto.Request{Op: agentproto.OpConnect, Instance: "antizapret-udp", CN: "alice", Addr: "203.0.113.5:40001"}
	if got != want {
		t.Fatalf("запрос %+v, ждали %+v", got, want)
	}
}

func TestConnectDenied(t *testing.T) {
	var stderr bytes.Buffer
	call := func(agentproto.Request) (agentproto.Response, error) {
		return agentproto.Response{Allow: false, Count: 3, Limit: 3}, nil
	}
	if code := Run("connect", aliceEnv, call, &stderr); code != ExitDeny {
		t.Fatalf("код %d", code)
	}
	if !strings.Contains(stderr.String(), "3 из 3") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestAgentDownFailsOpen(t *testing.T) {
	var stderr bytes.Buffer
	call := func(agentproto.Request) (agentproto.Response, error) {
		return agentproto.Response{}, errors.New("connect: no such file or directory")
	}
	if code := Run("connect", aliceEnv, call, &stderr); code != 0 {
		t.Fatalf("код %d", code)
	}
	if !strings.Contains(stderr.String(), "агент недоступен") {
		t.Fatalf("stderr: %q", stderr.String())
	}
}

func TestDisconnectNeverDenies(t *testing.T) {
	call := func(r agentproto.Request) (agentproto.Response, error) {
		if r.Op != agentproto.OpDisconnect {
			t.Fatalf("op %q", r.Op)
		}
		return agentproto.Response{Allow: false}, nil
	}
	if code := Run("disconnect", aliceEnv, call, &bytes.Buffer{}); code != 0 {
		t.Fatalf("код %d", code)
	}
}

func TestEmptyCommonNameSkipsAgent(t *testing.T) {
	call := func(agentproto.Request) (agentproto.Response, error) {
		t.Fatal("агент не должен вызываться")
		return agentproto.Response{}, nil
	}
	if code := Run("connect", env(nil), call, &bytes.Buffer{}); code != 0 {
		t.Fatalf("код %d", code)
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./internal/hook/`
Expected: FAIL — `undefined: Run`.

- [ ] **Step 3: Реализовать**

`internal/hook/hook.go`:

```go
// Package hook — «azpanel hook connect|disconnect», вызывается из скриптов
// OpenVPN от nobody. Файлов не пишет: решения записывает агент.
package hook

import (
	"fmt"
	"io"
	"net"
	"path"
	"strings"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/antizapret"
)

// ExitDeny — единственный код, по которому скрипт отказывает в подключении.
const ExitDeny = 3

type Caller func(agentproto.Request) (agentproto.Response, error)

// Run возвращает код выхода процесса. Отказ — только по явному ответу
// агента; любая ошибка — 0.
func Run(op string, env func(string) string, call Caller, stderr io.Writer) int {
	cn := env("common_name")
	if cn == "" {
		return 0
	}
	req := agentproto.Request{
		CN:       cn,
		Instance: strings.TrimSuffix(path.Base(env("config")), ".conf"),
		Addr:     antizapret.NormalizeAddr(net.JoinHostPort(env("trusted_ip"), env("trusted_port"))),
	}
	switch op {
	case "connect":
		req.Op = agentproto.OpConnect
	case "disconnect":
		req.Op = agentproto.OpDisconnect
	default:
		fmt.Fprintf(stderr, "azpanel hook: неизвестная операция %q\n", op)
		return 0
	}
	resp, err := call(req)
	if err != nil {
		fmt.Fprintf(stderr, "azpanel hook: агент недоступен (%v), лимит для %s не проверен\n", err, cn)
		return 0
	}
	if req.Op == agentproto.OpConnect && !resp.Allow {
		fmt.Fprintf(stderr, "azpanel hook: отказ %s — подключений %d из %d\n", cn, resp.Count, resp.Limit)
		return ExitDeny
	}
	return 0
}
```

- [ ] **Step 4: Запустить тесты**

Run: `go test ./internal/hook/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/hook
git commit -m "Хук OpenVPN: отказ кодом 3 только по ответу агента, иначе пропуск"
```

---

### Task 11: Установка хука в скрипты OpenVPN

**Files:**
- Create: `internal/antizapret/hookfile.go`, `internal/antizapret/hookfile_test.go`

**Interfaces:**
- Consumes: `fsutil.WriteFileAtomic`.
- Produces: `antizapret.ConnectBlock(bin string) string`; `antizapret.DisconnectBlock(bin string) string`; `antizapret.Insert(content, block string) string`; `antizapret.Strip(content string) string`; `type antizapret.HookFiles{ScriptsDir, Binary string}`; `(HookFiles) Ensure() (bool, error)`; `(HookFiles) Remove() error`; `(HookFiles) Installed() (bool, error)`.

- [ ] **Step 1: Написать падающие тесты**

`internal/antizapret/hookfile_test.go`:

```go
package antizapret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stock — custom-client-connect.sh из поставки AntiZapret (19 байт).
const stock = "#!/bin/bash\n\nexit 0"

const bin = "/opt/azpanel/bin/azpanel"

func TestInsertIntoStock(t *testing.T) {
	got := Insert(stock, ConnectBlock(bin))
	want := "#!/bin/bash\n# azpanel begin\n/opt/azpanel/bin/azpanel hook connect; [ $? -ne 3 ] || exit 1\n# azpanel end\n\nexit 0"
	if got != want {
		t.Fatalf("получено:\n%s", got)
	}
}

func TestInsertIsIdempotentAndReplacesOld(t *testing.T) {
	once := Insert(stock, ConnectBlock(bin))
	if twice := Insert(once, ConnectBlock(bin)); twice != once {
		t.Fatalf("повторная вставка изменила файл:\n%s", twice)
	}
	moved := Insert(once, ConnectBlock("/new/azpanel"))
	if strings.Contains(moved, bin) || strings.Count(moved, "# azpanel begin") != 1 {
		t.Fatalf("старый блок не заменён:\n%s", moved)
	}
}

func TestStripRestoresOriginal(t *testing.T) {
	custom := "#!/bin/bash\necho своё\nexit 0\n"
	if got := Strip(Insert(custom, ConnectBlock(bin))); got != custom {
		t.Fatalf("получено:\n%q", got)
	}
}

func TestInsertWithoutShebangAndEmpty(t *testing.T) {
	if got := Insert("echo x\n", DisconnectBlock(bin)); !strings.HasPrefix(got, "# azpanel begin\n") {
		t.Fatalf("без shebang:\n%s", got)
	}
	if got := Insert("", DisconnectBlock(bin)); !strings.HasPrefix(got, "#!/bin/bash\n# azpanel begin\n") || !strings.HasSuffix(got, "exit 0\n") {
		t.Fatalf("пустой:\n%s", got)
	}
}

func TestHookFilesEnsureRemove(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"custom-client-connect.sh", "custom-client-disconnect.sh"} {
		os.WriteFile(filepath.Join(dir, n), []byte(stock), 0o755)
	}
	h := HookFiles{ScriptsDir: dir, Binary: bin}
	if ok, _ := h.Installed(); ok {
		t.Fatal("до установки Installed = true")
	}
	changed, err := h.Ensure()
	if err != nil || !changed {
		t.Fatalf("Ensure: changed=%v err=%v", changed, err)
	}
	if changed, _ := h.Ensure(); changed {
		t.Fatal("второй Ensure что-то изменил")
	}
	if ok, _ := h.Installed(); !ok {
		t.Fatal("после установки Installed = false")
	}
	bak, err := os.ReadFile(filepath.Join(dir, "custom-client-connect.sh.bak-azpanel"))
	if err != nil || string(bak) != stock {
		t.Fatalf("копия: %q err=%v", bak, err)
	}
	if err := h.Remove(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"custom-client-connect.sh", "custom-client-disconnect.sh"} {
		b, _ := os.ReadFile(filepath.Join(dir, n))
		if string(b) != stock {
			t.Fatalf("%s после Remove:\n%q", n, b)
		}
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./internal/antizapret/`
Expected: FAIL — `undefined: Insert`.

- [ ] **Step 3: Реализовать**

`internal/antizapret/hookfile.go`:

```go
package antizapret

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/syava842/azpanel/internal/fsutil"
)

const (
	hookBegin        = "# azpanel begin"
	hookEnd          = "# azpanel end"
	connectScript    = "custom-client-connect.sh"
	disconnectScript = "custom-client-disconnect.sh"
	backupSuffix     = ".bak-azpanel"
)

// ConnectBlock: код 3 — отказ по лимиту; любой другой код (нет бинарника —
// 127, падение — 2) подключение не останавливает.
func ConnectBlock(bin string) string {
	return hookBegin + "\n" + bin + " hook connect; [ $? -ne 3 ] || exit 1\n" + hookEnd + "\n"
}

func DisconnectBlock(bin string) string {
	return hookBegin + "\n" + bin + " hook disconnect\n" + hookEnd + "\n"
}

// Strip убирает блок azpanel, остальное оставляет как было.
func Strip(content string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.SplitAfter(content, "\n") {
		t := strings.TrimRight(line, "\r\n")
		switch {
		case t == hookBegin:
			in = true
		case in && t == hookEnd:
			in = false
		case !in:
			b.WriteString(line)
		}
	}
	return b.String()
}

// Insert ставит блок сразу после shebang, заменяя прежний блок azpanel.
func Insert(content, block string) string {
	c := Strip(content)
	switch {
	case c == "":
		return "#!/bin/bash\n" + block + "\nexit 0\n"
	case strings.HasPrefix(c, "#!"):
		i := strings.IndexByte(c, '\n')
		if i < 0 {
			return c + "\n" + block
		}
		return c[:i+1] + block + c[i+1:]
	default:
		return block + c
	}
}

// HookFiles — хук в custom-client-connect.sh и custom-client-disconnect.sh.
// Эти файлы AntiZapret оставляет для своих правок и вызывает из
// client-connect.sh и client-disconnect.sh.
type HookFiles struct {
	ScriptsDir string
	Binary     string
}

type hookFile struct{ path, block string }

func (h HookFiles) files() []hookFile {
	return []hookFile{
		{filepath.Join(h.ScriptsDir, connectScript), ConnectBlock(h.Binary)},
		{filepath.Join(h.ScriptsDir, disconnectScript), DisconnectBlock(h.Binary)},
	}
}

// Ensure ставит блоки, если их нет или они устарели. Перед первой правкой
// файла сохраняет копию .bak-azpanel.
func (h HookFiles) Ensure() (bool, error) {
	if _, err := os.Stat(h.ScriptsDir); err != nil {
		return false, err
	}
	changed := false
	for _, f := range h.files() {
		old, err := os.ReadFile(f.path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return changed, err
		}
		updated := Insert(string(old), f.block)
		if updated == string(old) {
			continue
		}
		if err == nil {
			bak := f.path + backupSuffix
			if _, e := os.Stat(bak); errors.Is(e, fs.ErrNotExist) {
				if e := fsutil.WriteFileAtomic(bak, old, 0o755); e != nil {
					return changed, e
				}
			}
		}
		if err := fsutil.WriteFileAtomic(f.path, []byte(updated), 0o755); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// Installed — оба блока стоят в актуальном виде.
func (h HookFiles) Installed() (bool, error) {
	for _, f := range h.files() {
		b, err := os.ReadFile(f.path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if Insert(string(b), f.block) != string(b) {
			return false, nil
		}
	}
	return true, nil
}

// Remove убирает блоки; копии .bak-azpanel остаются.
func (h HookFiles) Remove() error {
	for _, f := range h.files() {
		b, err := os.ReadFile(f.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if s := Strip(string(b)); s != string(b) {
			if err := fsutil.WriteFileAtomic(f.path, []byte(s), 0o755); err != nil {
				return err
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Запустить тесты**

Run: `go test ./internal/antizapret/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/antizapret/hookfile.go internal/antizapret/hookfile_test.go
git commit -m "Установка и снятие хука в custom-client-*.sh с копией перед первой правкой"
```

---

### Task 12: Команды CLI — node, hook, limit, sessions

**Files:**
- Modify: `cmd/azpanel/main.go`
- Create: `cmd/azpanel/limitcmd.go`, `cmd/azpanel/limitcmd_test.go`

**Interfaces:**
- Consumes: `config.Load`, `node.Run`, `hook.Run`, `hook.ExitDeny`, `agentproto.Call`, `antizapret.HookFiles`, `limits.*`, `paths.*`.
- Produces: `errUsage`; `cmdLimit(args []string, out io.Writer) error`; `formatSessions(counts, lim map[string]int, out io.Writer)`.

- [ ] **Step 1: Написать падающие тесты**

`cmd/azpanel/limitcmd_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCmdLimit(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	var out bytes.Buffer
	if err := cmdLimit([]string{"set", "alice", "3"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdLimit([]string{"set", "bob", "1"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	cmdLimit([]string{"get", "alice"}, &out)
	if out.String() != "3\n" {
		t.Fatalf("get alice: %q", out.String())
	}
	out.Reset()
	cmdLimit([]string{"list"}, &out)
	if out.String() != "alice\t3\nbob\t1\n" {
		t.Fatalf("list: %q", out.String())
	}
	cmdLimit([]string{"unset", "alice"}, &out)
	out.Reset()
	cmdLimit([]string{"get", "alice"}, &out)
	if !strings.Contains(out.String(), "без ограничения") {
		t.Fatalf("после unset: %q", out.String())
	}
}

func TestCmdLimitRejects(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	for _, args := range [][]string{
		{"set", "a b", "1"}, {"set", "alice", "0"}, {"set", "alice", "x"}, {"set", "alice"}, {"что"},
	} {
		if err := cmdLimit(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v: ждали ошибку", args)
		}
	}
}

func TestFormatSessions(t *testing.T) {
	var out bytes.Buffer
	formatSessions(map[string]int{"alice": 2, "carol": 1}, map[string]int{"alice": 3, "bob": 1}, &out)
	got := out.String()
	for _, want := range []string{"alice", "2", "3", "bob", "0", "carol", "-"} {
		if !strings.Contains(got, want) {
			t.Fatalf("нет %q в:\n%s", want, got)
		}
	}
	if strings.Index(got, "alice") > strings.Index(got, "bob") || strings.Index(got, "bob") > strings.Index(got, "carol") {
		t.Fatalf("не по алфавиту:\n%s", got)
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./cmd/azpanel/`
Expected: FAIL — `undefined: cmdLimit`.

- [ ] **Step 3: Реализовать команды лимита**

`cmd/azpanel/limitcmd.go`:

```go
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/paths"
)

var errUsage = errors.New("неверные аргументы")

// cmdLimit — azpanel limit set|unset|get|list. Агент подхватывает файл сам.
func cmdLimit(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	path := paths.LimitsFile()
	m, err := limits.Load(path)
	if err != nil {
		return err
	}
	switch {
	case args[0] == "list" && len(args) == 1:
		for _, n := range sortedKeys(m) {
			fmt.Fprintf(out, "%s\t%d\n", n, m[n])
		}
		return nil
	case args[0] == "get" && len(args) == 2:
		if n, ok := m[args[1]]; ok {
			fmt.Fprintf(out, "%d\n", n)
		} else {
			fmt.Fprintln(out, "без ограничения")
		}
		return nil
	case args[0] == "set" && len(args) == 3:
		if !limits.ValidName(args[1]) {
			return fmt.Errorf("недопустимое имя клиента %q: 1–32 символа a-z, A-Z, 0-9, _ и -", args[1])
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 1 {
			return fmt.Errorf("лимит — целое число от 1, получено %q", args[2])
		}
		m[args[1]] = n
	case args[0] == "unset" && len(args) == 2:
		delete(m, args[1])
	default:
		return errUsage
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return limits.Save(path, m)
}

// formatSessions печатает клиентов с сессиями или лимитом; «-» — без ограничения.
func formatSessions(counts, lim map[string]int, out io.Writer) {
	all := map[string]int{}
	for n := range counts {
		all[n] = 0
	}
	for n := range lim {
		all[n] = 0
	}
	fmt.Fprintf(out, "%-32s %7s %7s\n", "клиент", "сессий", "лимит")
	for _, n := range sortedKeys(all) {
		l := "-"
		if v, ok := lim[n]; ok {
			l = strconv.Itoa(v)
		}
		fmt.Fprintf(out, "%-32s %7d %7s\n", n, counts[n], l)
	}
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 4: Подключить все режимы в main.go**

`cmd/azpanel/main.go` целиком:

```go
// azpanel — панель и агент для AntiZapret-VPN. Режим задаёт первый аргумент.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/hook"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/node"
	"github.com/syava842/azpanel/internal/paths"
)

var version = "dev"

// hookTimeout — сколько хук ждёт агента; дольше держать подключение нельзя.
const hookTimeout = time.Second

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return 0
	case "node":
		return runNode()
	case "hook":
		return runHook(args[1:])
	case "limit":
		return report(cmdLimit(args[1:], os.Stdout))
	case "sessions":
		return report(runSessions())
	case "install":
		return report(runInstall(args[1:]))
	case "uninstall":
		return report(runUninstall(args[1:]))
	default:
		usage()
		return 2
	}
}

func report(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		usage()
		return 2
	default:
		fmt.Fprintln(os.Stderr, "azpanel:", err)
		return 1
	}
}

func hookFiles(cfg config.Config) antizapret.HookFiles {
	return antizapret.HookFiles{ScriptsDir: cfg.Node.OpenVPNScriptsDir, Binary: paths.Binary()}
}

func runNode() int {
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		fmt.Fprintln(os.Stderr, "azpanel node:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := node.Run(ctx, cfg, hookFiles(cfg).Ensure); err != nil {
		fmt.Fprintln(os.Stderr, "azpanel node:", err)
		return 1
	}
	return 0
}

func runHook(args []string) int {
	if len(args) != 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "connect", "disconnect":
		call := func(r agentproto.Request) (agentproto.Response, error) {
			return agentproto.Call(paths.NodeSocket(), r, hookTimeout)
		}
		return hook.Run(args[0], os.Getenv, call, os.Stderr)
	}
	// Остальные подкоманды — для администратора, от root.
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return report(err)
	}
	h := hookFiles(cfg)
	switch args[0] {
	case "install":
		_, err := h.Ensure()
		return report(err)
	case "uninstall":
		return report(h.Remove())
	case "status":
		ok, err := h.Installed()
		if err != nil {
			return report(err)
		}
		if ok {
			fmt.Println("хук установлен")
			return 0
		}
		fmt.Println("хук не установлен")
		return 1
	default:
		usage()
		return 2
	}
}

func runSessions() error {
	resp, err := agentproto.Call(paths.NodeSocket(), agentproto.Request{Op: agentproto.OpList}, 2*time.Second)
	if err != nil {
		return fmt.Errorf("агент не отвечает: %w", err)
	}
	lim, err := limits.Load(paths.LimitsFile())
	if err != nil {
		return err
	}
	formatSessions(resp.Counts, lim, os.Stdout)
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `Использование:
  azpanel version
  azpanel install [--yes]              установить агент узла
  azpanel uninstall [--yes] [--purge]  удалить (--purge — вместе с /opt/azpanel)
  azpanel node                         агент узла (запускает systemd)
  azpanel limit set <клиент> <число>   лимит одновременных подключений OpenVPN
  azpanel limit unset <клиент>         снять лимит
  azpanel limit get <клиент>
  azpanel limit list
  azpanel sessions                     сессии и лимиты по клиентам
  azpanel hook install|uninstall|status
  azpanel hook connect|disconnect      вызывается OpenVPN
`)
}
```

Временно, до задачи 13, добавить в `cmd/azpanel/limitcmd.go` заглушки, чтобы собиралось:

```go
func runInstall(args []string) error   { return errors.New("установщик — задача 13") }
func runUninstall(args []string) error { return errors.New("установщик — задача 13") }
```

- [ ] **Step 5: Запустить тесты и сборку**

Run: `go test ./... && GOOS=linux go vet ./... && bash scripts/build.sh`
Expected: всё `ok`, сборка без ошибок.

- [ ] **Step 6: Commit**

```bash
git add cmd
git commit -m "CLI: node, hook, limit, sessions"
```

---

### Task 13: Установщик узла

**Files:**
- Create: `internal/install/install.go`, `internal/install/install_test.go`
- Modify: `cmd/azpanel/limitcmd.go` (убрать заглушки `runInstall`, `runUninstall`), `cmd/azpanel/main.go` (добавить `installcmd`)
- Create: `cmd/azpanel/installcmd.go`

**Interfaces:**
- Consumes: `paths.*`, `config.Save`, `config.Default`, `antizapret.HookFiles`, `agentproto.Call`, `fsutil.WriteFileAtomic`.
- Produces: `type install.Options{Yes, Purge bool; In io.Reader; Out io.Writer; Run func(name string, args ...string) error; Wait func() error; UnitDir, AntiZapretDir, ScriptsDir, Self string}`; `install.Defaults() Options`; `install.NodeUnit(bin string) string`; `install.InstallNode(o Options) error`; `install.Uninstall(o Options) error`.

- [ ] **Step 1: Написать падающие тесты**

`internal/install/install_test.go`:

```go
package install

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/paths"
)

const stock = "#!/bin/bash\n\nexit 0"

func setup(t *testing.T) (Options, *[]string) {
	t.Helper()
	base := t.TempDir()
	t.Setenv("AZPANEL_ROOT", filepath.Join(base, "opt", "azpanel"))
	az := filepath.Join(base, "antizapret")
	scripts := filepath.Join(base, "scripts")
	units := filepath.Join(base, "units")
	for _, d := range []string{az, scripts, units} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(az, "client.sh"), []byte("#!/bin/bash\n"), 0o755)
	for _, n := range []string{"custom-client-connect.sh", "custom-client-disconnect.sh"} {
		os.WriteFile(filepath.Join(scripts, n), []byte(stock), 0o755)
	}
	self := filepath.Join(base, "azpanel-new")
	os.WriteFile(self, []byte("BINARY"), 0o755)
	var calls []string
	return Options{
		Yes: true, In: strings.NewReader(""), Out: &bytes.Buffer{},
		Run:  func(name string, args ...string) error { calls = append(calls, name+" "+strings.Join(args, " ")); return nil },
		Wait: func() error { return nil },
		UnitDir: units, AntiZapretDir: az, ScriptsDir: scripts, Self: self,
	}, &calls
}

func TestInstallNode(t *testing.T) {
	o, calls := setup(t)
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(paths.Binary()); string(b) != "BINARY" {
		t.Fatalf("бинарник: %q", b)
	}
	if _, err := os.Stat(paths.ConfigFile()); err != nil {
		t.Fatalf("config.toml: %v", err)
	}
	unit, _ := os.ReadFile(filepath.Join(o.UnitDir, "azpanel-node.service"))
	if !strings.Contains(string(unit), "ExecStart="+paths.Binary()+" node") || !strings.Contains(string(unit), "RuntimeDirectory=azpanel") {
		t.Fatalf("юнит:\n%s", unit)
	}
	want := []string{"systemctl daemon-reload", "systemctl enable azpanel-node", "systemctl restart azpanel-node"}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("вызовы: %v", *calls)
	}
	b, _ := os.ReadFile(filepath.Join(o.ScriptsDir, "custom-client-connect.sh"))
	if !strings.Contains(string(b), "hook connect") {
		t.Fatalf("хук не поставлен:\n%s", b)
	}
	if runtime.GOOS == "linux" {
		for dir, mode := range map[string]os.FileMode{paths.Root(): 0o755, paths.Bin(): 0o755, paths.Etc(): 0o700, paths.Log(): 0o750, paths.Data(): 0o700, paths.Backup(): 0o700} {
			st, _ := os.Stat(dir)
			if st.Mode().Perm() != mode {
				t.Errorf("%s: %v, ждали %v", dir, st.Mode().Perm(), mode)
			}
		}
	}
}

func TestInstallNodeKeepsExistingConfig(t *testing.T) {
	o, _ := setup(t)
	os.MkdirAll(paths.Etc(), 0o700)
	os.WriteFile(paths.ConfigFile(), []byte("config_version = 1\n[node]\npoll_seconds = 9\n"), 0o600)
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(paths.ConfigFile()); !strings.Contains(string(b), "poll_seconds = 9") {
		t.Fatalf("конфиг перезаписан:\n%s", b)
	}
}

func TestInstallNodeRequiresAntiZapret(t *testing.T) {
	o, calls := setup(t)
	os.Remove(filepath.Join(o.AntiZapretDir, "client.sh"))
	if err := InstallNode(o); err == nil || !strings.Contains(err.Error(), "AntiZapret") {
		t.Fatalf("ошибка = %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("при отказе вызван systemctl: %v", *calls)
	}
}

func TestInstallNodeAsksWithoutYes(t *testing.T) {
	o, calls := setup(t)
	o.Yes = false
	o.In = strings.NewReader("n\n")
	if err := InstallNode(o); err == nil {
		t.Fatal("ответ «n» — ждали отказ")
	}
	if len(*calls) != 0 {
		t.Fatalf("после отказа вызван systemctl: %v", *calls)
	}
}

func TestUninstall(t *testing.T) {
	o, calls := setup(t)
	if err := InstallNode(o); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	o.Purge = true
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if (*calls)[0] != "systemctl disable --now azpanel-node" {
		t.Fatalf("сначала должна останавливаться служба: %v", *calls)
	}
	b, _ := os.ReadFile(filepath.Join(o.ScriptsDir, "custom-client-connect.sh"))
	if string(b) != stock {
		t.Fatalf("хук не снят:\n%q", b)
	}
	if _, err := os.Stat(filepath.Join(o.UnitDir, "azpanel-node.service")); !os.IsNotExist(err) {
		t.Fatal("юнит остался")
	}
	if _, err := os.Stat(paths.Root()); !os.IsNotExist(err) {
		t.Fatal("--purge не удалил корень")
	}
}
```

- [ ] **Step 2: Запустить — должны упасть**

Run: `go test ./internal/install/`
Expected: FAIL — `undefined: InstallNode`.

- [ ] **Step 3: Реализовать**

`internal/install/install.go`:

```go
// Package install — azpanel install / uninstall. Этап 1: только узел.
package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/paths"
)

const nodeUnitName = "azpanel-node.service"

type Options struct {
	Yes           bool
	Purge         bool
	In            io.Reader
	Out           io.Writer
	Run           func(name string, args ...string) error
	Wait          func() error // ждать, пока агент ответит
	UnitDir       string
	AntiZapretDir string
	ScriptsDir    string
	Self          string // путь к запущенному бинарнику
}

func Defaults() Options {
	self, _ := os.Executable()
	return Options{
		In:  os.Stdin,
		Out: os.Stdout,
		Run: func(name string, args ...string) error {
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		Wait:          waitAgent,
		UnitDir:       "/etc/systemd/system",
		AntiZapretDir: "/root/antizapret",
		ScriptsDir:    config.Default().Node.OpenVPNScriptsDir,
		Self:          self,
	}
}

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

[Install]
WantedBy=multi-user.target
`
}

type dirMode struct {
	path string
	mode os.FileMode
}

func layout() []dirMode {
	return []dirMode{
		{paths.Root(), 0o755}, {paths.Bin(), 0o755}, {paths.Etc(), 0o700},
		{paths.Log(), 0o750}, {paths.Data(), 0o700}, {paths.Backup(), 0o700},
	}
}

func InstallNode(o Options) error {
	if _, err := os.Stat(filepath.Join(o.AntiZapretDir, "client.sh")); err != nil {
		return fmt.Errorf("AntiZapret не найден: нет %s", filepath.Join(o.AntiZapretDir, "client.sh"))
	}
	if _, err := os.Stat(o.ScriptsDir); err != nil {
		return fmt.Errorf("нет каталога скриптов OpenVPN %s", o.ScriptsDir)
	}
	unit := filepath.Join(o.UnitDir, nodeUnitName)
	fmt.Fprintf(o.Out, `Будет установлено:
  %s — каталоги bin, etc, log, data, backup
  %s — служба azpanel-node (включится и перезапустится)
  хук лимита в %s: custom-client-connect.sh, custom-client-disconnect.sh
    (перед первой правкой — копии .bak-azpanel)
Лимитов после установки нет: все клиенты подключаются как раньше.
`, paths.Root(), unit, o.ScriptsDir)
	if !o.Yes && !confirm(o.In, o.Out, "Продолжить? [y/N]: ") {
		return errors.New("установка отменена")
	}
	for _, d := range layout() {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil { // MkdirAll не меняет права существующего
			return err
		}
	}
	if err := copyBinary(o.Self, paths.Binary()); err != nil {
		return fmt.Errorf("копирование бинарника: %w", err)
	}
	if _, err := os.Stat(paths.ConfigFile()); errors.Is(err, fs.ErrNotExist) {
		if err := config.Save(paths.ConfigFile(), config.Default()); err != nil {
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(unit, []byte(NodeUnit(paths.Binary())), 0o644); err != nil {
		return err
	}
	if _, err := (antizapret.HookFiles{ScriptsDir: o.ScriptsDir, Binary: paths.Binary()}).Ensure(); err != nil {
		return fmt.Errorf("хук: %w", err)
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "azpanel-node"}, {"restart", "azpanel-node"}} {
		if err := o.Run("systemctl", args...); err != nil {
			return err
		}
	}
	if err := o.Wait(); err != nil {
		return fmt.Errorf("агент не ответил: %w; журнал — %s", err, filepath.Join(paths.Log(), "node.log"))
	}
	fmt.Fprintln(o.Out, "Готово. Лимит: azpanel limit set <клиент> <число>; состояние: azpanel sessions")
	return nil
}

// Uninstall: сначала служба (иначе агент вернёт хук), потом хук и юнит.
func Uninstall(o Options) error {
	unit := filepath.Join(o.UnitDir, nodeUnitName)
	what := "служба azpanel-node, хук лимита, " + unit
	if o.Purge {
		what += ", " + paths.Root() + " целиком"
	}
	fmt.Fprintf(o.Out, "Будет удалено: %s\n", what)
	if !o.Yes && !confirm(o.In, o.Out, "Продолжить? [y/N]: ") {
		return errors.New("удаление отменено")
	}
	if err := o.Run("systemctl", "disable", "--now", "azpanel-node"); err != nil {
		fmt.Fprintln(o.Out, "служба не остановлена (возможно, её нет):", err)
	}
	if err := (antizapret.HookFiles{ScriptsDir: o.ScriptsDir, Binary: paths.Binary()}).Remove(); err != nil {
		return fmt.Errorf("хук: %w", err)
	}
	if err := os.Remove(unit); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := o.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if o.Purge {
		return os.RemoveAll(paths.Root())
	}
	fmt.Fprintf(o.Out, "Настройки, лимиты и журналы оставлены в %s\n", paths.Root())
	return nil
}

func copyBinary(src, dst string) error {
	if a, err := filepath.EvalSymlinks(src); err == nil {
		if b, err := filepath.EvalSymlinks(dst); err == nil && a == b {
			return nil // запущен уже установленный бинарник
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(dst, data, 0o755)
}

func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "д", "да":
		return true
	}
	return false
}

func waitAgent() error {
	var err error
	for i := 0; i < 50; i++ {
		if _, err = agentproto.Call(paths.NodeSocket(), agentproto.Request{Op: agentproto.OpList}, time.Second); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}
```

`cmd/azpanel/installcmd.go` (а заглушки из `limitcmd.go` удалить):

```go
package main

import (
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/paths"
)

func installOptions(args []string) (install.Options, error) {
	o := install.Defaults()
	if cfg, err := config.Load(paths.ConfigFile()); err == nil {
		o.ScriptsDir = cfg.Node.OpenVPNScriptsDir
	}
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			o.Yes = true
		case "--purge":
			o.Purge = true
		default:
			return o, errUsage
		}
	}
	return o, nil
}

func runInstall(args []string) error {
	o, err := installOptions(args)
	if err != nil {
		return err
	}
	return install.InstallNode(o)
}

func runUninstall(args []string) error {
	o, err := installOptions(args)
	if err != nil {
		return err
	}
	return install.Uninstall(o)
}
```

- [ ] **Step 4: Запустить тесты и сборку**

Run: `go test ./... && GOOS=linux go vet ./... && bash scripts/build.sh`
Expected: всё `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/install cmd
git commit -m "Установщик и удаление агента узла"
```

---

### Task 14: Приёмка на 94

Перед началом — сообщить владельцу, что ставится служба `azpanel-node` и хук в скрипты OpenVPN на 94. Все команды — одним `ssh` на шаг: защита AntiZapret режет частые новые SSH-подключения.

**Files:**
- Create: `docs/notes/2026-11-01-priemka-etap-1.md`

- [ ] **Step 1: Собрать и установить**

```bash
cd C:/Users/faza8/Desktop/project/azpanel && bash scripts/build.sh
scp dist/azpanel-linux-amd64 root@192.0.2.94:/tmp/azpanel
ssh root@192.0.2.94 'chmod +x /tmp/azpanel && /tmp/azpanel install --yes && rm /tmp/azpanel
systemctl is-active azpanel-node; /opt/azpanel/bin/azpanel hook status
stat -c "%a %n" /opt/azpanel /opt/azpanel/* /run/azpanel/node.sock
head -5 /etc/openvpn/server/scripts/custom-client-connect.sh'
```

Expected: `Готово.`, `active`, `хук установлен`, права `755 /opt/azpanel`, `755 …/bin`, `700 …/etc`, `750 …/log`, `700 …/data`, `700 …/backup`, `666 /run/azpanel/node.sock`; в скрипте блок `# azpanel begin`.

- [ ] **Step 2: Сверить счётчики агента с управляющими сокетами**

```bash
ssh root@192.0.2.94 '/opt/azpanel/bin/azpanel sessions
for s in /run/openvpn-server/*.sock; do { echo "status 3"; sleep 1; } | timeout 3 socat - UNIX-CONNECT:$s; done | awk -F"\t" "\$1==\"CLIENT_LIST\" && \$2!=\"UNDEF\" {print \$2}" | sort | uniq -c'
```

Expected: число сессий по каждому клиенту совпадает (расхождение в одну сессию допустимо, если кто-то подключился между командами; повторить).

- [ ] **Step 3: Отказ сверх лимита**

`/root/azpanel-probe/test-udp.ovpn` — путь из задачи 1, шаг 2.

```bash
ssh root@192.0.2.94 'cd /root/azpanel-probe && rm -f a.log b.log
/opt/azpanel/bin/azpanel limit set azpanel-test-1 1
ovpn() { openvpn --config /root/azpanel-probe/test-udp.ovpn --route-nopull --ifconfig-noexec --route-noexec --disable-dco --log "$1.log" --writepid "$1.pid" --daemon "azt-$1"; }
wait_log() { for i in $(seq 1 30); do grep -qE "Initialization Sequence Completed|AUTH_FAILED|Exiting" "$1.log" && break; sleep 1; done; }
ovpn a; wait_log a; grep -cE "Initialization Sequence Completed" a.log
ovpn b; wait_log b; grep -E "AUTH_FAILED|Initialization Sequence Completed" b.log | head -2
/opt/azpanel/bin/azpanel sessions | grep azpanel-test
grep azpanel-test-1 /opt/azpanel/log/hook.log | tail -3'
```

Expected: `a` — `1` (подключился); `b` — `AUTH_FAILED`; в `sessions` у `azpanel-test-1` — 1 сессия, лимит 1; в `hook.log` — `подключение … sessions=1 limit=1`, затем `отказ: лимит подключений … sessions=1 limit=1`. Если в `b.log` нет `AUTH_FAILED`, а клиент переподключается по кругу — отказ всё равно состоялся, если в журнале сервера есть `client-connect command failed` и `azpanel hook: отказ`: `journalctl -u "openvpn-server@*" --since "-2min" | grep -E "client-connect|azpanel hook"`; клиента `b` тогда остановить `pkill -f azt-b`.

- [ ] **Step 4: Место освобождается после отключения**

```bash
ssh root@192.0.2.94 'cd /root/azpanel-probe
kill "$(cat a.pid)"; pkill -f "azt-b" ; sleep 2; rm -f b.log
openvpn --config /root/azpanel-probe/test-udp.ovpn --route-nopull --ifconfig-noexec --route-noexec --disable-dco --log b.log --writepid b.pid --daemon azt-b
for i in $(seq 1 30); do grep -qE "Initialization Sequence Completed|AUTH_FAILED|Exiting" b.log && break; sleep 1; done
grep -cE "Initialization Sequence Completed" b.log; kill "$(cat b.pid)"
grep azpanel-test-1 /opt/azpanel/log/hook.log | tail -3'
```

Expected: `1`; в `hook.log` — `отключение` для `a`, затем `подключение` для `b`.

- [ ] **Step 5: Без агента подключения проходят**

```bash
ssh root@192.0.2.94 'cd /root/azpanel-probe; systemctl stop azpanel-node; rm -f a.log
openvpn --config /root/azpanel-probe/test-udp.ovpn --route-nopull --ifconfig-noexec --route-noexec --disable-dco --log a.log --writepid a.pid --daemon azt-a
for i in $(seq 1 30); do grep -qE "Initialization Sequence Completed|AUTH_FAILED|Exiting" a.log && break; sleep 1; done
grep -cE "Initialization Sequence Completed" a.log; kill "$(cat a.pid)"
journalctl -u "openvpn-server@*" --since "-2min" | grep -m2 "azpanel hook"
systemctl start azpanel-node; sleep 1; systemctl is-active azpanel-node'
```

Expected: `1` (подключился при остановленном агенте); в журнале OpenVPN — `azpanel hook: агент недоступен …, лимит для azpanel-test-1 не проверен`; агент снова `active`.

- [ ] **Step 6: Живые клиенты не задеты**

```bash
ssh root@192.0.2.94 'grep -c "подключение" /opt/azpanel/log/hook.log
grep "отказ" /opt/azpanel/log/hook.log | grep -vc azpanel-test || true
grep -E "level=(WARN|ERROR)" /opt/azpanel/log/node.log | tail -5'
```

Expected: отказов не по `azpanel-test-*` — `0`; в `node.log` нет `ERROR`. Если были подключения живых клиентов за время приёмки — они в `hook.log` как `подключение`.

- [ ] **Step 7: Убрать тестовое**

```bash
ssh root@192.0.2.94 '/opt/azpanel/bin/azpanel limit unset azpanel-test-1
/root/antizapret/client.sh 2 azpanel-test-1 >/dev/null; rm -rf /root/azpanel-probe
/opt/azpanel/bin/azpanel limit list; /root/antizapret/client.sh 3 | grep -c azpanel-test || true'
```

Expected: список лимитов пуст; `azpanel-test` в списке клиентов — `0`. Агент и хук остаются установленными — это результат этапа. Удалить их по просьбе владельца: `/opt/azpanel/bin/azpanel uninstall --yes`.

- [ ] **Step 8: Записать результаты и отправить**

Создать `docs/notes/2026-11-01-priemka-etap-1.md`: что проверено (шаги 1–6), фактический вывод (без имён и адресов живых клиентов), что осталось на 94. Затем:

```bash
git add docs/notes/2026-11-01-priemka-etap-1.md
git commit -m "Приёмка этапа 1 на 94: отказ сверх лимита, освобождение места, работа без агента"
git push
```

---

## Покрытие спецификации этапом 1

| Требование спецификации | Задача |
| --- | --- |
| Учёт сессий агентом, снимки раз в 5 с, тайм-аут 1 с, события хуков | 5, 7, 9 |
| Хук через `/run/azpanel/node.sock`, отказ кодом 3, ошибка — пропуск | 8, 10, 11 |
| Хук от `nobody`, файлов не пишет, решения — в `hook.log` агентом | 8, 9, 10 |
| Сокет `666` + `SO_PEERCRED` (root, nobody) | 8, 9 |
| Блок в `custom-client-*.sh` после shebang, копия `.bak-azpanel` | 11 |
| Проверка хука при старте и после обновления AntiZapret | 9 (при старте и раз в минуту) |
| Клиент без лимита — без ограничения; лимит на сервер отдельно | 6, 7 |
| `limits.json` в `data/`, команды `azpanel limit` | 6, 12 |
| Раскладка `/opt/azpanel/{bin,etc,log,data,backup}` и права | 2, 13 |
| `config.toml` с `config_version` | 3 |
| Журналы с ротацией 10 МБ × 5 | 4, 9 |
| `azpanel install` для узла без nginx и HTTPS, `uninstall` | 13 |
| Проверки до правки: экземпляр молчит во время `client-connect`, переменные окружения | 1 |
| Критерий готовности этапа: отказ на втором подключении при лимите 1, остальные как раньше | 14 |
