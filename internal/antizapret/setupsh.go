package antizapret

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Как работает setup.sh (testdata/setup.sh — main от 02.11.2026) и что из
// этого берёт агент:
//
//   - Первый вопрос — MTU OpenVPN/WireGuard: «read … MTU» стоит БЕЗ проверки
//     переменной окружения, спрашивается всегда, значение берётся из
//     стандартного ввода. Так же всегда спрашиваются адреса серверов
//     OPENVPN_HOST и WIREGUARD_HOST (по строке на каждый, пустая строка —
//     «пропустить»). Поэтому на стандартный ввод идут три строки: MTU,
//     OPENVPN_HOST, WIREGUARD_HOST — в этом порядке.
//   - Все остальные вопросы устроены как «until [[ "$KEY" =~ шаблон ]]; do read …»:
//     если переменная окружения подходит под шаблон, вопрос пропускается.
//   - Опасность: стандартный ввод закончился (EOF), а переменная не подошла —
//     read возвращает ошибку сразу, until крутится вхолостую до предела времени
//     задачи. Поэтому каждое значение перед запуском проверяется по тем же
//     шаблонам, а не подошедшее — отказ с причиной.
//   - Ключи DISCORD_INCLUDE, ROBLOX_INCLUDE, AMAZON_INCLUDE, HETZNER_INCLUDE,
//     DIGITALOCEAN_INCLUDE, OVH_INCLUDE, GOOGLE_INCLUDE, AKAMAI_INCLUDE в
//     setup.sh не спрашиваются (вопросы закомментированы), но значение берётся
//     из окружения и записывается в setup — поэтому они передаются как есть.
//   - setup.sh сам жёстко записывает RECONNECT_WARP=n, CLEAR_HOSTS=y,
//     TXQUEUELEN=10000 и пустые ключи WARP/интерфейсов: окружением это не
//     изменить, после установки агент сверяет и сообщает о сбросе.
//   - setup.sh не берёт файлы из архива, в котором лежит: он сам делает
//     «git clone --depth 1 …/AntiZapret-VPN.git» (main на момент запуска).
//     Архив нужного коммита нужен только ради самого setup.sh.
//   - Из /root/backup*.tar.gz он восстанавливает easyrsa3, wireguard, config,
//     knot-resolver, custom и затем УДАЛЯЕТ все /root/backup*.tar.gz; если
//     файлов несколько, tar распакует только первый. Поэтому в /root на время
//     установки должен лежать ровно один такой файл — наш.
//   - Последняя команда скрипта — reboot.

// SetupShSkipKey — ключ, который в окружение setup.sh не передаётся: скрипт
// записывает его заново.
const SetupShSkipKey = "SETUP_DATE"

// promptKind — вид проверки ответа.
type promptKind int

const (
	promptYN     promptKind = iota // шаблон (y|n)
	promptDigits                   // ^[lo-hi]$
	promptMTU                      // целое 1280..1420
)

// shPrompt — вопрос setup.sh, пропускаемый переменной окружения.
type shPrompt struct {
	key     string
	kind    promptKind
	pattern string // шаблон из setup.sh дословно — сверяется тестом с testdata/setup.sh
	def     string // значение по умолчанию из «-i»; "$MTU" — ответ на вопрос про MTU
	lo, hi  byte   // для promptDigits
	// legacy — старые значения, которых нынешний setup.sh не знает, и их замена.
	legacy map[string]string
}

func ynPrompt(key, def string) shPrompt {
	return shPrompt{key: key, kind: promptYN, pattern: "(y|n)", def: def}
}

func digitsPrompt(key string, lo, hi byte, def string) shPrompt {
	return shPrompt{key: key, kind: promptDigits, pattern: fmt.Sprintf("^[%c-%c]$", lo, hi), def: def, lo: lo, hi: hi}
}

// shPrompts — вопросы setup.sh в порядке появления (кроме MTU и адресов серверов).
// Умолчания сняты с setup.sh; тест сверяет таблицу с testdata/setup.sh.
var shPrompts = []shPrompt{
	{key: "WARP_MTU", kind: promptMTU, pattern: "^[0-9]+$", def: "$MTU"},
	ynPrompt("OPENVPN_UDP_ENABLE", "y"),
	ynPrompt("OPENVPN_TCP_ENABLE", "n"),
	ynPrompt("WIREGUARD_ENABLE", "y"),
	digitsPrompt("OPENVPN_PATCH", '1', '4', "2"),
	ynPrompt("OPENVPN_DCO", "y"),
	withLegacy(digitsPrompt("ANTIZAPRET_WARP", '1', '4', "4"), map[string]string{"n": "1"}),
	withLegacy(digitsPrompt("VPN_WARP", '1', '3', "2"), map[string]string{"n": "1"}),
	ynPrompt("WARP_PROTECTION", "y"),
	digitsPrompt("ANTIZAPRET_DNS", '1', '7', "1"),
	digitsPrompt("VPN_DNS", '1', '2', "1"),
	ynPrompt("DNS_WARP", "n"),
	ynPrompt("ANTIZAPRET_ADBLOCK", "y"),
	ynPrompt("VPN_ADBLOCK", "n"),
	ynPrompt("ALTERNATIVE_CLIENT_IP", "n"),
	ynPrompt("ALTERNATIVE_FAKE_IP", "y"),
	ynPrompt("OPENVPN_BACKUP_UDP", "y"),
	ynPrompt("OPENVPN_BACKUP_TCP", "n"),
	ynPrompt("WIREGUARD_BACKUP", "y"),
	ynPrompt("OPENVPN_DUPLICATE", "y"),
	ynPrompt("OPENVPN_LOG", "n"),
	ynPrompt("SSH_PROTECTION", "y"),
	ynPrompt("ATTACK_PROTECTION", "y"),
	ynPrompt("SCAN_PROTECTION", "y"),
	ynPrompt("TORRENT_GUARD", "y"),
	ynPrompt("RESTRICT_FORWARD", "y"),
	ynPrompt("CLIENT_ISOLATION", "y"),
	ynPrompt("ROUTE_ALL", "n"),
	ynPrompt("CLOUDFLARE_INCLUDE", "y"),
	ynPrompt("TELEGRAM_INCLUDE", "y"),
	ynPrompt("WHATSAPP_INCLUDE", "y"),
}

func withLegacy(p shPrompt, legacy map[string]string) shPrompt {
	p.legacy = legacy
	return p
}

// shPassthrough — ключи, которых setup.sh не спрашивает, но переносит из окружения в setup.
var shPassthrough = []string{
	"DISCORD_INCLUDE", "ROBLOX_INCLUDE", "AMAZON_INCLUDE", "HETZNER_INCLUDE",
	"DIGITALOCEAN_INCLUDE", "OVH_INCLUDE", "GOOGLE_INCLUDE", "AKAMAI_INCLUDE",
}

// Ключи, спрашиваемые через стандартный ввод.
const (
	shKeyMTU           = "MTU"
	shKeyOpenVPNHost   = "OPENVPN_HOST"
	shKeyWireGuardHost = "WIREGUARD_HOST"
)

// SetupShPlan — как запускать setup.sh: окружение, ввод и пояснения.
type SetupShPlan struct {
	// Env — пары KEY=VALUE для окружения, по алфавиту. Без SETUP_DATE, без
	// ключей с секретами и без MTU/адресов (они идут вводом).
	Env []string
	// Stdin — MTU, OPENVPN_HOST, WIREGUARD_HOST — по строке.
	Stdin string
	// Notes — какие ключи взяты по умолчанию setup.sh.
	Notes []string
	// Problems — почему запускать нельзя; по одной причине в строке.
	Problems []string
}

var plainValueRe = regexp.MustCompile(`^[\x21-\x7e]*$`)

// PlanSetupSh собирает окружение и ввод для setup.sh из текущего файла setup
// и изменений overrides (ключи с применением reinstall). Значение, которое
// setup.sh не примет, — в Problems: иначе вопрос остался бы без ответа и
// скрипт завис бы в холостом цикле.
func PlanSetupSh(setup, overrides map[string]string) SetupShPlan {
	var p SetupShPlan
	values := make(map[string]string, len(setup)+len(overrides))
	for k, v := range setup {
		values[k] = v
	}
	known := map[string]bool{shKeyMTU: true, shKeyOpenVPNHost: true, shKeyWireGuardHost: true}
	for _, q := range shPrompts {
		known[q.key] = true
	}
	for _, k := range shPassthrough {
		known[k] = true
	}
	okeys := make([]string, 0, len(overrides))
	for k := range overrides {
		okeys = append(okeys, k)
	}
	sort.Strings(okeys)
	for _, k := range okeys {
		switch {
		case k == SetupShSkipKey || IsSecretSetupKey(k) || !known[k]:
			p.Problems = append(p.Problems, fmt.Sprintf("%s: setup.sh этот ключ не спрашивает — установкой он не меняется", k))
		default:
			values[k] = overrides[k]
		}
	}

	// MTU: первый вопрос, ответ вводом.
	mtu := values[shKeyMTU]
	if !validMTU(mtu) {
		p.Problems = append(p.Problems, fmt.Sprintf("MTU=%q: нужно целое число 1280..1420", mtu))
	}
	hosts := [2]string{}
	for i, k := range []string{shKeyOpenVPNHost, shKeyWireGuardHost} {
		h, err := checkHost(values[k])
		if err != nil {
			p.Problems = append(p.Problems, fmt.Sprintf("%s=%q: %v", k, values[k], err))
		}
		hosts[i] = h
	}
	p.Stdin = mtu + "\n" + hosts[0] + "\n" + hosts[1] + "\n"

	env := map[string]string{}
	for _, q := range shPrompts {
		v, present := values[q.key]
		if v == "" {
			present = false
		}
		if !present {
			v = q.def
			if v == "$MTU" {
				v = mtu
			}
			p.Notes = append(p.Notes, fmt.Sprintf("%s нет в setup — взято умолчание setup.sh: %s", q.key, v))
		}
		if nv, ok := q.legacy[v]; ok {
			p.Notes = append(p.Notes, fmt.Sprintf("%s=%s заменено на %s: нынешний setup.sh значения %s не знает", q.key, v, nv, v))
			v = nv
		}
		if !q.accepts(v) {
			p.Problems = append(p.Problems, fmt.Sprintf("%s=%q: setup.sh принимает только %s", q.key, v, q.describe()))
			continue
		}
		env[q.key] = v
	}
	for _, k := range shPassthrough {
		v, ok := values[k]
		if !ok {
			continue
		}
		if !plainValueRe.MatchString(v) {
			p.Problems = append(p.Problems, fmt.Sprintf("%s: недопустимые символы в значении", k))
			continue
		}
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.Env = append(p.Env, k+"="+env[k])
	}
	return p
}

func validMTU(v string) bool {
	n, err := strconv.Atoi(v)
	return err == nil && strconv.Itoa(n) == v && n >= 1280 && n <= 1420
}

func (q shPrompt) accepts(v string) bool {
	switch q.kind {
	case promptYN:
		return v == "y" || v == "n"
	case promptDigits:
		return len(v) == 1 && v[0] >= q.lo && v[0] <= q.hi
	case promptMTU:
		return validMTU(v)
	}
	return false
}

func (q shPrompt) describe() string {
	switch q.kind {
	case promptYN:
		return "y или n"
	case promptDigits:
		return fmt.Sprintf("цифра %c..%c", q.lo, q.hi)
	}
	return "целое 1280..1420"
}

// SetupShPromptKeys — ключи, на которые setup.sh получает ответ окружением.
func SetupShPromptKeys() []string {
	out := make([]string, 0, len(shPrompts))
	for _, q := range shPrompts {
		out = append(out, q.key)
	}
	return out
}

// JoinReasons склеивает причины отказа в одну строку для сообщения.
func JoinReasons(reasons []string) string { return strings.Join(reasons, "; ") }
