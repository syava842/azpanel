package antizapret

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/syava842/azpanel/internal/fsutil"
)

// Способы применения изменённого ключа setup. Сами задачи правка не запускает.
const (
	ApplyDoall     = "doall"     // ./doall.sh: update.sh и parse.sh читают ключ
	ApplyRestart   = "restart"   // systemctl restart antizapret: ключ читает up.sh
	ApplyProfiles  = "profiles"  // client.sh 7: ключ попадает в профили клиентов
	ApplyReinstall = "reinstall" // только повторный setup.sh; через панель — показ
)

// applyOrder — порядок способов в ответе.
var applyOrder = []string{ApplyDoall, ApplyRestart, ApplyProfiles}

// Виды значения ключа.
const (
	SetupYN   = "yn"   // y или n
	SetupEnum = "enum" // одно из Options
	SetupInt  = "int"  // целое Min..Max
	SetupHost = "host" // домен, IP-адрес или пусто
)

// SetupKey — описание ключа файла setup.
type SetupKey struct {
	Kind     string
	Options  []string // для enum
	Min, Max int      // для int
	Apply    []string
	Title    string
	Hint     string
	Editable bool // false — только показ
}

var (
	both    = []string{ApplyDoall, ApplyRestart}
	onlyDo  = []string{ApplyDoall}
	onlyRes = []string{ApplyRestart}
	onlyPro = []string{ApplyProfiles}
	reinst  = []string{ApplyReinstall}
)

func yn(title string, apply []string) SetupKey {
	return SetupKey{Kind: SetupYN, Apply: apply, Title: title, Editable: true}
}

func fixed(title string) SetupKey { return SetupKey{Apply: reinst, Title: title} }

// setupKeys — таблица ключей. Значения и способы применения сверены по
// скриптам AntiZapret с сервера 94 (internal/antizapret/testdata/scripts):
// какой скрипт какой ключ читает, указано у каждой группы. Ключа нет в
// таблице (и не подходит под суффиксные правила) — только чтение.
var setupKeys = map[string]SetupKey{
	// up.sh:55 — '2', '3', '4' поднимают warp-antizapret ('3', '4' — выход по
	// меткам fwmark, '2' — весь выход через WARP); parse.sh:327 — '3' кладёт
	// proxy.rpz в warp.rpz. Остальное ('n', '1') — без WARP.
	"ANTIZAPRET_WARP": {Kind: SetupEnum, Options: []string{"n", "1", "2", "3", "4"}, Apply: both, Editable: true,
		Title: "WARP для режима AntiZapret", Hint: "n, 1 — без WARP; 2 — весь выход через WARP; 3, 4 — по меткам"},
	// up.sh:114 — только '2' и '3' (значения '4' для VPN-режима скрипт не знает);
	// parse.sh:353 — '3' строит warp2.rpz.
	"VPN_WARP": {Kind: SetupEnum, Options: []string{"n", "1", "2", "3"}, Apply: both, Editable: true,
		Title: "WARP для полного VPN", Hint: "n, 1 — без WARP; 2 — весь выход через WARP; 3 — по меткам"},
	// up.sh:173 — сравнение только с 'y'.
	"DNS_WARP": yn("WARP для DNS-резолвера", onlyRes),
	// up.sh:49 — WARP_MTU по умолчанию 1280, пишется в warp-*.conf.
	"WARP_MTU": {Kind: SetupInt, Min: 1280, Max: 1500, Apply: onlyRes, Editable: true, Title: "MTU интерфейсов WARP"},
	// parse.sh:409 — переподключение warp-* после обновления списков.
	"RECONNECT_WARP": yn("Переподключать WARP после обновления списков", onlyDo),

	// update.sh:140-153 и parse.sh:82-99 — списки и правила блокировки рекламы.
	"ANTIZAPRET_ADBLOCK": yn("Блокировка рекламы в режиме AntiZapret", onlyDo),
	"VPN_ADBLOCK":        yn("Блокировка рекламы в полном VPN", onlyDo),
	// update.sh:140, parse.sh:176 — «все домены через AntiZapret».
	"ROUTE_ALL": yn("Все домены через AntiZapret", onlyDo),
	// parse.sh:166 — удаление доменов казино и букмекеров.
	"CLEAR_HOSTS": yn("Убирать домены казино и букмекеров", onlyDo),
	// update.sh:160-200 — подключаемые списки IP сервисов.
	"DISCORD_INCLUDE":      yn("Списки IP: Discord", onlyDo),
	"CLOUDFLARE_INCLUDE":   yn("Списки IP: Cloudflare", onlyDo),
	"AMAZON_INCLUDE":       yn("Списки IP: Amazon", onlyDo),
	"HETZNER_INCLUDE":      yn("Списки IP: Hetzner", onlyDo),
	"DIGITALOCEAN_INCLUDE": yn("Списки IP: DigitalOcean", onlyDo),
	"OVH_INCLUDE":          yn("Списки IP: OVH", onlyDo),
	"TELEGRAM_INCLUDE":     yn("Списки IP: Telegram", onlyDo),
	"GOOGLE_INCLUDE":       yn("Списки IP: Google", onlyDo),
	"AKAMAI_INCLUDE":       yn("Списки IP: Akamai", onlyDo),
	"WHATSAPP_INCLUDE":     yn("Списки IP: WhatsApp", onlyDo),
	"ROBLOX_INCLUDE":       yn("Списки IP: Roblox", onlyDo),

	// up.sh:292 строит правила защиты, parse.sh:202 наполняет ipset allow-ips.
	"ATTACK_PROTECTION": yn("Защита от атак (разрешённые IP)", both),

	// up.sh: каждый ключ — блок правил iptables, сравнение только с 'y'.
	"SSH_PROTECTION":     yn("Защита SSH от перебора", onlyRes),                    // up.sh:286
	"SCAN_PROTECTION":    yn("Защита от сканирования", onlyRes),                    // up.sh:320
	"TORRENT_GUARD":      yn("Блокировка торрентов", onlyRes),                      // up.sh:244
	"RESTRICT_FORWARD":   yn("Ограничить пересылку списками", onlyRes),             // up.sh:253, 403
	"CLIENT_ISOLATION":   yn("Изоляция клиентов друг от друга", onlyRes),           // up.sh:279
	"OPENVPN_BACKUP_UDP": yn("Резервный порт OpenVPN (UDP)", onlyRes),              // up.sh:366
	"OPENVPN_BACKUP_TCP": yn("Резервный порт OpenVPN (TCP)", onlyRes),              // up.sh:358
	"WIREGUARD_BACKUP":   yn("Резервный порт WireGuard", onlyRes),                  // up.sh:374
	"WARP_PROTECTION":    yn("Блокировать трафик, если WARP не поднялся", onlyRes), // up.sh:98, 157
	// up.sh:388 различает только '1' (DNS клиентов VPN через Knot Resolver) и
	// остальное; полный перечень значений задаёт setup.sh, которого среди
	// скриптов нет, поэтому допускается одна цифра.
	"VPN_DNS": {Kind: SetupInt, Min: 1, Max: 9, Apply: onlyRes, Editable: true,
		Title: "DNS клиентов полного VPN", Hint: "1 — через Knot Resolver AntiZapret"},
	// up.sh:461 — по умолчанию 10000, ip link set txqueuelen.
	"TXQUEUELEN": {Kind: SetupInt, Min: 0, Max: 100000, Apply: onlyRes, Editable: true, Title: "Длина очереди интерфейсов (txqueuelen)"},

	// client.sh:59-68, 104, 146, 190, 277 — адрес сервера в именах и конфигах профилей.
	"OPENVPN_HOST":   {Kind: SetupHost, Apply: onlyPro, Editable: true, Title: "Адрес сервера в профилях OpenVPN", Hint: "домен или IP; пусто — IP сервера"},
	"WIREGUARD_HOST": {Kind: SetupHost, Apply: onlyPro, Editable: true, Title: "Адрес сервера в профилях WireGuard", Hint: "домен или IP; пусто — IP сервера"},

	// Адресация читается всеми скриптами (up.sh:46, parse.sh:154, down.sh:39):
	// смена ломает уже выданные профили и правила — повторный setup.sh.
	"ALTERNATIVE_CLIENT_IP": fixed("Другая адресация клиентов (172.x вместо 10.x)"),
	"ALTERNATIVE_FAKE_IP":   fixed("Другие поддельные адреса (198.18.x)"),
	"CLIENT_IP":             fixed("Первый октет адресов клиентов"),
	"FAKE_IP":               fixed("Префикс поддельных адресов"),
	// MTU записан в конфиги OpenVPN, ANTIZAPRET_DNS — в настройку kresd.
	"MTU":               fixed("MTU OpenVPN"),
	"ANTIZAPRET_DNS":    fixed("DNS-серверы режима AntiZapret"),
	"OPENVPN_PATCH":     fixed("Патч OpenVPN"),
	"OPENVPN_DCO":       fixed("OpenVPN DCO"),
	"OPENVPN_DUPLICATE": fixed("Одинаковые сертификаты у нескольких устройств"),
	"OPENVPN_LOG":       fixed("Журнал OpenVPN"),
	"SETUP_DATE":        fixed("Дата установки"),
}

// Суффиксные правила для ключей, которых не перечислить: показ без правки.
var setupSuffixes = []struct{ suffix, title string }{
	{"_ENABLE", "Служба включена при установке"},
	{"_WARP_PUBLIC_KEY", "Публичный ключ WARP"},
	{"_ENDPOINT", "Адрес сервера WARP"},
	{"_ADDRESS", "Адрес интерфейса WARP"},
}

// secretSuffix — ключи с секретами: в API не отдаются и не принимаются.
const secretSuffix = "_PRIVATE_KEY"

// LookupSetupKey находит описание ключа. ok=false — ключ неизвестен: только чтение.
func LookupSetupKey(name string) (SetupKey, bool) {
	if k, ok := setupKeys[name]; ok {
		return k, true
	}
	for _, s := range setupSuffixes {
		if strings.HasSuffix(name, s.suffix) {
			return fixed(s.title), true
		}
	}
	return SetupKey{}, false
}

// IsSecretSetupKey — ключ с секретом (…_PRIVATE_KEY).
func IsSecretSetupKey(name string) bool { return strings.HasSuffix(name, secretSuffix) }

// SetupEntry — ключ файла setup для показа.
type SetupEntry struct {
	Key      string
	Value    string
	Kind     string // yn, enum, int, host; пусто — неизвестный ключ
	Apply    []string
	Title    string
	Hint     string
	Options  []string
	Min, Max int
	Editable bool
	Present  bool // false — ключа нет в файле, он известен только таблице
}

// KeyError — причина отказа по ключу.
type KeyError struct {
	Key    string
	Reason string
}

// SetupError — значения не приняты; файл не менялся.
type SetupError struct{ Errors []KeyError }

func (e *SetupError) Error() string {
	parts := make([]string, 0, len(e.Errors))
	for _, k := range e.Errors {
		parts = append(parts, k.Key+": "+k.Reason)
	}
	return strings.Join(parts, "; ")
}

// SetupResult — что изменено и какие способы применения нужны.
type SetupResult struct {
	Changed []string
	Apply   []string
}

var setupKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// SetupFile правит файл setup AntiZapret: проверка по таблице ключей, копия
// перед записью, атомарная замена с прежними правами и владельцем.
type SetupFile struct {
	Path    string
	Backups *Backups
	// Busy вызывается под замком перед записью; ошибка (обычно *BusyError)
	// отклоняет запись. nil — писать можно всегда.
	Busy func() error

	mu sync.Mutex
}

// setupName — имя копий файла setup.
const setupName = "setup"

type setupLine struct {
	key, val string
	quote    byte
}

// parseSetupLine разбирает строку KEY=VALUE так же, как ReadSetup.
func parseSetupLine(line string) (setupLine, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return setupLine{}, false
	}
	k, v, ok := strings.Cut(t, "=")
	if !ok || !setupKeyRe.MatchString(k) {
		return setupLine{}, false
	}
	l := setupLine{key: k, val: v}
	if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
		l.quote, l.val = v[0], v[1:len(v)-1]
	}
	return l, true
}

// List — ключи файла в порядке появления, без секретов. Повторный ключ
// показывается один раз с последним значением, как его прочтёт bash.
// Следом, по алфавиту, идут ключи таблицы, которых в файле нет (Present=false,
// значение пусто): их можно задать, Set допишет строку в конец.
func (s *SetupFile) List() ([]SetupEntry, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var order []string
	vals := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		l, ok := parseSetupLine(line)
		if !ok {
			continue
		}
		if _, seen := vals[l.key]; !seen {
			order = append(order, l.key)
		}
		vals[l.key] = l.val
	}
	out := make([]SetupEntry, 0, len(order))
	for _, k := range order {
		if IsSecretSetupKey(k) {
			continue
		}
		out = append(out, makeSetupEntry(k, vals[k], true))
	}
	var missing []string
	for k := range setupKeys {
		if _, in := vals[k]; !in && !IsSecretSetupKey(k) {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		out = append(out, makeSetupEntry(k, "", false))
	}
	return out, nil
}

func makeSetupEntry(k, val string, present bool) SetupEntry {
	e := SetupEntry{Key: k, Value: val, Present: present}
	if def, ok := LookupSetupKey(k); ok {
		e.Kind, e.Apply, e.Title, e.Hint = def.Kind, def.Apply, def.Title, def.Hint
		e.Options, e.Min, e.Max, e.Editable = def.Options, def.Min, def.Max, def.Editable
	}
	return e
}

// Set проверяет все значения и записывает изменившиеся. Есть хоть одна ошибка —
// ничего не записано (*SetupError). Строки KEY=... заменяются на месте, прочие
// строки сохраняются байт в байт; нового ключа в файле нет — дописывается в конец.
func (s *SetupFile) Set(values map[string]string) (SetupResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	canon := map[string]string{}
	var errs []KeyError
	for _, k := range keys {
		v, err := checkSetupValue(k, values[k])
		if err != nil {
			errs = append(errs, KeyError{Key: k, Reason: err.Error()})
			continue
		}
		canon[k] = v
	}
	if len(errs) > 0 {
		return SetupResult{}, &SetupError{Errors: errs}
	}

	data, err := os.ReadFile(s.Path)
	if err != nil {
		return SetupResult{}, err
	}
	lines := strings.Split(string(data), "\n")
	// Последний элемент после финального \n пуст — к нему дописывать нельзя.
	trailingNL := len(lines) > 0 && lines[len(lines)-1] == ""
	if trailingNL {
		lines = lines[:len(lines)-1]
	}
	found := map[string]bool{}
	changed := map[string]bool{}
	for i, line := range lines {
		l, ok := parseSetupLine(line)
		if !ok {
			continue
		}
		want, ok := canon[l.key]
		if !ok {
			continue
		}
		found[l.key] = true
		if l.val == want {
			continue
		}
		cr := ""
		if strings.HasSuffix(line, "\r") {
			cr = "\r"
		}
		q := ""
		if l.quote != 0 {
			q = string(l.quote)
		}
		lines[i] = l.key + "=" + q + want + q + cr
		changed[l.key] = true
	}
	appended := false
	for _, k := range keys {
		if !found[k] && canon[k] != "" {
			lines = append(lines, k+"="+canon[k])
			changed[k] = true
			appended = true
		}
	}
	if len(changed) == 0 {
		return SetupResult{Changed: []string{}, Apply: []string{}}, nil
	}
	if s.Busy != nil {
		if err := s.Busy(); err != nil {
			return SetupResult{}, err
		}
	}
	out := strings.Join(lines, "\n")
	if trailingNL || appended {
		out += "\n"
	}
	if _, err := s.Backups.Save(setupName, data); err != nil {
		return SetupResult{}, fmt.Errorf("копия setup не сохранена: %w", err)
	}
	if err := fsutil.WriteFileKeepMeta(s.Path, []byte(out)); err != nil {
		return SetupResult{}, err
	}
	res := SetupResult{Changed: []string{}, Apply: []string{}}
	need := map[string]bool{}
	for _, k := range keys {
		if !changed[k] {
			continue
		}
		res.Changed = append(res.Changed, k)
		def, _ := LookupSetupKey(k)
		for _, a := range def.Apply {
			need[a] = true
		}
	}
	for _, a := range applyOrder {
		if need[a] {
			res.Apply = append(res.Apply, a)
		}
	}
	return res, nil
}

// BackupList — копии файла setup, новые сверху.
func (s *SetupFile) BackupList() ([]BackupInfo, error) { return s.Backups.List(setupName) }

// checkSetupValue проверяет значение по таблице и возвращает его каноническую запись.
func checkSetupValue(key, v string) (string, error) {
	if IsSecretSetupKey(key) {
		return "", errors.New("ключ с секретом не меняется через API")
	}
	def, ok := LookupSetupKey(key)
	if !ok {
		return "", errors.New("неизвестный ключ — только чтение")
	}
	if !def.Editable {
		return "", errors.New("меняется переустановкой AntiZapret (setup.sh)")
	}
	return checkKindValue(def, v)
}

// checkKindValue проверяет значение только по виду ключа (y/n, перечень, целое,
// адрес) — без оглядки на Editable. По ней же PlanSetupSh проверяет окружение
// setup.sh: правила для API и для установки не расходятся.
func checkKindValue(def SetupKey, v string) (string, error) {
	switch def.Kind {
	case SetupYN:
		if v != "y" && v != "n" {
			return "", errors.New("допустимо y или n")
		}
		return v, nil
	case SetupEnum:
		for _, o := range def.Options {
			if v == o {
				return v, nil
			}
		}
		return "", fmt.Errorf("допустимо одно из: %s", strings.Join(def.Options, ", "))
	case SetupInt:
		n, err := strconv.Atoi(v)
		if err != nil || strconv.Itoa(n) != v || n < def.Min || n > def.Max {
			return "", fmt.Errorf("нужно целое число от %d до %d", def.Min, def.Max)
		}
		return v, nil
	case SetupHost:
		return checkHost(v)
	}
	return "", errors.New("неизвестный вид значения")
}

// checkHost: пусто, IP-адрес или домен. Значение попадает в имена файлов и
// конфиги профилей, поэтому допускается только безопасный набор символов.
func checkHost(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		if !a.Is4() {
			return "", errors.New("нужен IPv4-адрес: AntiZapret работает только по IPv4")
		}
		return a.String(), nil
	}
	d := strings.ToLower(v)
	if err := validateDomain(d); err != nil {
		return "", fmt.Errorf("нужен домен, IP-адрес или пустое значение: %w", err)
	}
	return d, nil
}
