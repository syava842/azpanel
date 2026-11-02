// Package warp — WARP на узле: встроенный (интерфейсы warp-*) и AZ-WARP
// (команда warper): состояние без секретов, домены, подсети, обновление,
// установка под псевдотерминалом.
package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Умолчания AZ-WARP на узле.
const (
	DefaultDir = "/root/warper"
	DefaultBin = "warper"
)

// Runner запускает команду и возвращает объединённый вывод. Ненулевой код —
// ошибка, вывод при этом тоже возвращается.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner — настоящий запуск процесса.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

// Warper — вызовы команды warper.
type Warper struct {
	Dir string // /root/warper
	Bin string // warper
	Run Runner // nil — настоящий запуск
}

func (w *Warper) dir() string {
	if w.Dir != "" {
		return w.Dir
	}
	return DefaultDir
}

func (w *Warper) bin() string {
	if w.Bin != "" {
		return w.Bin
	}
	return DefaultBin
}

// queryTimeout — предел чтения (status json, domainslist, iplist): зависший
// warper не должен подвешивать GET /v1/warp. Шаги изменений (RunSteps) идут без него.
const queryTimeout = 10 * time.Second

// query — run со сроком queryTimeout.
func (w *Warper) query(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	return w.run(ctx, args...)
}

func (w *Warper) run(ctx context.Context, args ...string) ([]byte, error) {
	if w.Run != nil {
		return w.Run(ctx, w.bin(), args...)
	}
	return ExecRunner(ctx, w.bin(), args...)
}

// Version — версия установленного AZ-WARP из <Dir>/version; installed == false,
// если файла нет (AZ-WARP не установлен).
func (w *Warper) Version() (version string, installed bool) {
	data, err := os.ReadFile(filepath.Join(w.dir(), "version"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// secretKeyRe — имена полей, значения которых не покидают узел: пароли,
// ключи, токены. «key» ловит и warp_keys_source — лишнее в ответе безвредно,
// пропущенный ключ — нет.
var secretKeyRe = regexp.MustCompile(`(?i)pass|key|secret|token|private|psk|uuid|auth`)

// stripSecrets рекурсивно убирает из разобранного JSON поля с секретными именами.
func stripSecrets(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if secretKeyRe.MatchString(k) {
				delete(t, k)
				continue
			}
			t[k] = stripSecrets(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = stripSecrets(t[i])
		}
		return t
	case string:
		return RedactLinks(t)
	}
	return v
}

// linkRe — ссылки прокси-подписок: ключи и пароли лежат в самом адресе, а имя
// поля может быть любым (link, url, outbound…). credsRe — адрес с логином и паролем.
var (
	linkRe  = regexp.MustCompile(`(?i)\b(ss|ssr|vless|vmess|trojan|hy2|hysteria2|tuic|wireguard|socks5|socks)://[^\s"']+`)
	credsRe = regexp.MustCompile(`(?i)\bhttps?://[^\s/@"']+:[^\s/@"']*@[^\s"']*`)
)

// RedactLinks затирает ссылки ss://, vless://, vmess://, trojan://, hy2://,
// hysteria2://, wireguard:// (и адреса с логином и паролем) в любой строке.
func RedactLinks(s string) string {
	s = linkRe.ReplaceAllString(s, "${1}://***")
	return credsRe.ReplaceAllString(s, "***")
}

// SanitizeStatus вырезает секреты из «warper status json». Результат — JSON,
// пригодный для передачи панели и записи в журнал.
func SanitizeStatus(raw []byte) ([]byte, error) {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("warper status json не разобран: %w", err)
	}
	return json.Marshal(stripSecrets(v))
}

// Status — состояние AZ-WARP для панели. Секретов не содержит: Raw — тот же
// ответ warper после SanitizeStatus.
type Status struct {
	Installed       bool           `json:"installed"`
	Version         string         `json:"version,omitempty"`
	RemoteVersion   string         `json:"remote_version,omitempty"`
	UpdateAvailable bool           `json:"update_available"`
	OutboundMode    string         `json:"outbound_mode,omitempty"`
	OutboundLabel   string         `json:"outbound_label,omitempty"`
	AntizapretWarp  bool           `json:"antizapret_warp"`
	AntizapretMode  string         `json:"antizapret_warp_mode,omitempty"`
	VPNWarp         bool           `json:"vpn_warp"`
	VPNWarpMode     string         `json:"vpn_warp_mode,omitempty"`
	DomainsSynced   bool           `json:"domains_synced"`
	Subnet          Subnet         `json:"subnet"`
	IPRanges        IPRanges       `json:"ip_ranges"`
	Singbox         Singbox        `json:"singbox"`
	TrafficToday    string         `json:"traffic_today,omitempty"`
	Error           string         `json:"error,omitempty"`
	Raw             map[string]any `json:"raw,omitempty"`
}

// Subnet — фейковая подсеть доменов.
type Subnet struct {
	Fake         string `json:"fake,omitempty"`
	InAntiZapret bool   `json:"in_antizapret"`
	Conflict     bool   `json:"conflict"`
}

// IPRanges — подсети, идущие через WARP.
type IPRanges struct {
	Count       int    `json:"count"`
	RoutesCount int    `json:"routes_count"`
	Synced      bool   `json:"synced"`
	Mode        string `json:"mode,omitempty"`
}

// Singbox — состояние sing-box.
type Singbox struct {
	Running bool `json:"running"`
	Enabled bool `json:"enabled"`
	MTU     int  `json:"mtu,omitempty"`
}

// ParseStatus превращает вывод «warper status json» в Status без секретов.
func ParseStatus(raw []byte) (Status, error) {
	clean, err := SanitizeStatus(raw)
	if err != nil {
		return Status{}, err
	}
	var aux struct {
		Version         string                `json:"version"`
		RemoteVersion   string                `json:"remote_version"`
		UpdateAvailable bool                  `json:"update_available"`
		AZWarp          bool                  `json:"antizapret_warp"`
		AZMode          string                `json:"antizapret_warp_mode"`
		VPNWarp         bool                  `json:"vpn_warp"`
		VPNMode         string                `json:"vpn_warp_mode"`
		OutboundMode    string                `json:"outbound_mode"`
		OutboundLabel   string                `json:"outbound_label"`
		Singbox         Singbox               `json:"singbox"`
		Domains         struct{ Synced bool } `json:"domains"`
		Subnet          Subnet                `json:"subnet"`
		IPRanges        IPRanges              `json:"ip_ranges"`
		Traffic         string                `json:"traffic_today"`
	}
	if err := json.Unmarshal(clean, &aux); err != nil {
		return Status{}, fmt.Errorf("warper status json: %w", err)
	}
	st := Status{
		Installed: true, Version: aux.Version, RemoteVersion: aux.RemoteVersion, UpdateAvailable: aux.UpdateAvailable,
		OutboundMode: aux.OutboundMode, OutboundLabel: aux.OutboundLabel,
		AntizapretWarp: aux.AZWarp, AntizapretMode: aux.AZMode, VPNWarp: aux.VPNWarp, VPNWarpMode: aux.VPNMode,
		DomainsSynced: aux.Domains.Synced, Subnet: aux.Subnet, IPRanges: aux.IPRanges, Singbox: aux.Singbox,
		TrafficToday: aux.Traffic,
	}
	_ = json.Unmarshal(clean, &st.Raw)
	return st, nil
}

// Status читает состояние: версия из файла, остальное — из warper status json.
// AZ-WARP не установлен — Installed == false без ошибки.
func (w *Warper) Status(ctx context.Context) Status {
	ver, ok := w.Version()
	if !ok {
		return Status{}
	}
	out, err := w.query(ctx, "status", "json")
	if err != nil {
		return Status{Installed: true, Version: ver, Error: "warper status json: " + firstLine(RedactText(string(out)+" "+err.Error()))}
	}
	st, err := ParseStatus(out)
	if err != nil {
		return Status{Installed: true, Version: ver, Error: err.Error()}
	}
	if st.Version == "" {
		st.Version = ver
	}
	return st
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// StripANSI убирает управляющие последовательности цвета.
func StripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// listLines — непустые строки вывода без цвета; строки-комментарии (#) пропускаются.
func listLines(out []byte) []string {
	lines := []string{}
	for _, l := range strings.Split(StripANSI(string(out)), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines
}

// DomainEntry — строка «warper domainslist»: домен|источник|включён
// (например, «claud.ai|user|1»). Источник — user, gemini, chatgpt…
type DomainEntry struct {
	Domain  string `json:"domain"`
	Source  string `json:"source,omitempty"`
	Enabled bool   `json:"enabled"`
}

// parseDomainLine разбирает строку списка доменов. Строка без «|» — просто
// домен (включён, источник неизвестен): старый вывод warper.
func parseDomainLine(l string) DomainEntry {
	parts := strings.Split(l, "|")
	e := DomainEntry{Domain: strings.TrimSpace(parts[0]), Enabled: true}
	if len(parts) > 1 {
		e.Source = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		if f := strings.TrimSpace(parts[2]); f != "" {
			e.Enabled = f == "1"
		}
	}
	return e
}

// Domains — вывод «warper domainslist».
func (w *Warper) Domains(ctx context.Context) ([]DomainEntry, error) {
	out, err := w.query(ctx, "domainslist")
	if err != nil {
		return nil, err
	}
	entries := []DomainEntry{}
	for _, l := range listLines(out) {
		if e := parseDomainLine(l); e.Domain != "" {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// IPs — вывод «warper iplist»: подсети CIDR по строке.
func (w *Warper) IPs(ctx context.Context) ([]string, error) {
	out, err := w.query(ctx, "iplist")
	if err != nil {
		return nil, err
	}
	return listLines(out), nil
}

var domainRe = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// ValidDomain — домен для списка WARP.
func ValidDomain(s string) bool { return domainRe.MatchString(s) }

// ValidSubnet — адрес или подсеть (IPv4/IPv6) для списка WARP.
func ValidSubnet(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// Op — одна правка списков.
type Op struct {
	Op  string `json:"op"`            // add remove enable disable save sync ipadd ipremove ipsync
	Arg string `json:"arg,omitempty"` // домен, подсеть либо gemini|chatgpt
}

// Steps превращает правки в команды warper (без имени самой команды). Всё, что
// не проходит проверку, отклоняется целиком: частично применённый список хуже
// непримённого.
func Steps(ops []Op) ([][]string, error) {
	if len(ops) == 0 {
		return nil, errors.New("нет действий")
	}
	var steps [][]string
	for _, o := range ops {
		switch o.Op {
		case "add", "remove":
			if !ValidDomain(o.Arg) {
				return nil, fmt.Errorf("недопустимый домен %q", o.Arg)
			}
			steps = append(steps, []string{o.Op, o.Arg})
		case "enable", "disable":
			if o.Arg != "gemini" && o.Arg != "chatgpt" {
				return nil, fmt.Errorf("%s: поддерживаются gemini и chatgpt", o.Op)
			}
			steps = append(steps, []string{o.Op, o.Arg})
		case "ipadd", "ipremove":
			if !ValidSubnet(o.Arg) {
				return nil, fmt.Errorf("недопустимая подсеть %q", o.Arg)
			}
			steps = append(steps, []string{o.Op, o.Arg})
		case "save":
			steps = append(steps, []string{"domains", "save"})
		case "sync", "ipsync":
			steps = append(steps, []string{o.Op})
		default:
			return nil, fmt.Errorf("неизвестное действие %q", o.Op)
		}
	}
	return steps, nil
}

// StatusJSONStep — псевдокоманда шага: «warper status json» с вырезанными секретами.
const StatusJSONStep = "status-json"

// RunSteps выполняет команды warper по порядку и пишет в out их вывод без
// секретов. Первый сбой останавливает выполнение.
func (w *Warper) RunSteps(ctx context.Context, steps [][]string, out io.Writer) error {
	for _, st := range steps {
		if len(st) == 0 {
			continue
		}
		args := st
		pseudo := len(st) == 1 && st[0] == StatusJSONStep
		if pseudo {
			args = []string{"status", "json"}
		}
		fmt.Fprintf(out, "$ warper %s\n", strings.Join(args, " "))
		o, err := w.run(ctx, args...)
		if pseudo && err == nil {
			clean, serr := SanitizeStatus(o)
			if serr != nil {
				return serr
			}
			var buf bytes.Buffer
			json.Indent(&buf, clean, "", "  ")
			o = buf.Bytes()
		}
		fmt.Fprintln(out, strings.TrimRight(RedactText(StripANSI(string(o))), "\n"))
		if err != nil {
			return fmt.Errorf("warper %s: %w", strings.Join(args, " "), unwrapExit(err))
		}
	}
	return nil
}

func unwrapExit(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee
	}
	return err
}

var redactRe = regexp.MustCompile(`(?i)("?[\w.-]*(?:pass|key|secret|token|private|psk)[\w.-]*"?\s*[:=]\s*)("[^"]*"|\S+)`)

// RedactText затирает значения полей password, key, secret, token…: вывод
// warper попадает в журнал задачи.
func RedactText(s string) string { return RedactLinks(redactRe.ReplaceAllString(s, "${1}***")) }
