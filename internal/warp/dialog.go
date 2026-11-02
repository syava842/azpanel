package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule — известный вопрос установщика: образец последней строки вывода (без
// перевода строки в конце — это приглашение read -p) и ответ.
type Rule struct {
	Name    string
	Prompt  *regexp.Regexp // по последней строке окна
	Context *regexp.Regexp // по всему окну с прошлого ответа; nil — не проверять
	// Answer возвращает ответ; ok == false — остановить установку (с причиной).
	Answer func(m []string) (answer string, ok bool, reason string)
	Secret bool // ответ секретный: в журнал не пишется
	Max    int  // сколько раз можно ответить; 0 — 3 (повтор вопроса значит, что ответ не принят)
}

// Dialog ведёт диалог с установщиком по таблице правил. Неизвестный вопрос —
// остановка, а не ответ наугад.
type Dialog struct {
	Rules []Rule
	Log   io.Writer // журнал: вывод установщика с затёртыми секретами
	// Secrets — значения, которые затираются в журнале везде, где встретятся
	// (эхо терминала возвращает набранный ответ).
	Secrets []string
	// Quiet — сколько вывод должен молчать, чтобы последняя строка считалась
	// приглашением; Unknown — сколько молчания хватает, чтобы признать вопрос
	// неизвестным; Stall — после какого молчания установщик считается зависшим.
	Quiet, Unknown, Stall time.Duration
}

// ErrUnknownPrompt — установщик задал вопрос, которого нет в таблице.
var ErrUnknownPrompt = errors.New("неизвестный вопрос установщика")

var promptLike = regexp.MustCompile(`[:?\]>)]\s*$`)

type chunk struct {
	data []byte
	err  error
}

func (d *Dialog) durations() (quiet, unknown, stall time.Duration) {
	quiet, unknown, stall = d.Quiet, d.Unknown, d.Stall
	if quiet <= 0 {
		quiet = 400 * time.Millisecond
	}
	if unknown <= 0 {
		unknown = 4 * time.Second
	}
	if stall <= 0 {
		stall = 10 * time.Minute
	}
	return
}

func (d *Dialog) redact(s string) string {
	for _, sec := range d.Secrets {
		if len(sec) >= 3 {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return RedactText(s)
}

func (d *Dialog) logf(format string, a ...any) {
	if d.Log != nil {
		fmt.Fprintf(d.Log, format, a...)
	}
}

// Run читает вывод установщика из rw и отвечает в rw. Возвращает nil, когда
// поток закончился (установщик завершился; его код выхода проверяет вызывающий),
// ErrUnknownPrompt — на неизвестном вопросе, ошибку правила — если ответ невозможен.
func (d *Dialog) Run(ctx context.Context, rw io.ReadWriter) error {
	quiet, unknown, stall := d.durations()
	ch := make(chan chunk, 16)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				ch <- chunk{data: append([]byte(nil), buf[:n]...)}
			}
			if err != nil {
				ch <- chunk{err: err}
				return
			}
		}
	}()

	var (
		window  string // чистый вывод с прошлого ответа
		unlog   string // ещё не записанные в журнал строки
		asked   = map[string]int{}
		lastOut = time.Now()
	)
	flush := func(all bool) {
		for {
			i := strings.IndexByte(unlog, '\n')
			if i < 0 {
				break
			}
			d.logf("%s\n", d.redact(strings.TrimRight(unlog[:i], "\r")))
			unlog = unlog[i+1:]
		}
		if all && unlog != "" {
			d.logf("%s\n", d.redact(unlog))
			unlog = ""
		}
	}
	defer flush(true)

	for {
		timer := time.NewTimer(quiet)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case c := <-ch:
			timer.Stop()
			if c.err != nil {
				flush(true)
				return nil // EOF или EIO на ведущей стороне pty — установщик закончил
			}
			text := strings.ReplaceAll(StripANSI(string(c.data)), "\r", "")
			window += text
			unlog += text
			lastOut = time.Now()
			flush(false)
		case <-timer.C:
			if window == "" || strings.HasSuffix(window, "\n") {
				if time.Since(lastOut) >= stall {
					return fmt.Errorf("установщик молчит %s: остановлено", stall)
				}
				continue
			}
			last := window[strings.LastIndexByte(window, '\n')+1:]
			rule, m := d.match(last, window)
			if rule == nil {
				if promptLike.MatchString(strings.TrimSpace(last)) && time.Since(lastOut) >= unknown {
					flush(true)
					return fmt.Errorf("%w: %q", ErrUnknownPrompt, d.redact(strings.TrimSpace(last)))
				}
				continue
			}
			max := rule.Max
			if max == 0 {
				max = 3
			}
			if asked[rule.Name]++; asked[rule.Name] > max {
				flush(true)
				return fmt.Errorf("установщик повторяет вопрос %q больше %d раз — ответ не принят", rule.Name, max)
			}
			ans, ok, reason := rule.Answer(m)
			if !ok {
				flush(true)
				return fmt.Errorf("вопрос %q: %s", rule.Name, reason)
			}
			flush(true)
			if rule.Secret {
				d.logf("[ответ на %q: скрыт]\n", rule.Name)
			} else {
				d.logf("[ответ на %q: %q]\n", rule.Name, ans)
			}
			if _, err := io.WriteString(rw, ans+"\n"); err != nil {
				return fmt.Errorf("ответ не отправлен: %w", err)
			}
			window = ""
			lastOut = time.Now()
		}
	}
}

func (d *Dialog) match(last, window string) (*Rule, []string) {
	for i := range d.Rules {
		r := &d.Rules[i]
		m := r.Prompt.FindStringSubmatch(last)
		if m == nil {
			continue
		}
		if r.Context != nil && !r.Context.MatchString(window) {
			continue
		}
		return r, m
	}
	return nil, nil
}

// InstallAnswers — ответы на вопросы install.sh AZ-WARP.
type InstallAnswers struct {
	Mode string `json:"mode"` // warp | slave | wg | vless | hy2 | openvpn
	// Gemini и ChatGPT: по умолчанию домены добавляются (как Enter в установщике).
	NoGemini  bool `json:"no_gemini,omitempty"`
	NoChatGPT bool `json:"no_chatgpt,omitempty"`
	// Subnet — фейковая подсеть; пусто — 10.224.0.0/16. ForceSubnet — подтвердить
	// использование подсети, которую установщик считает занятой.
	Subnet      string    `json:"subnet,omitempty"`
	ForceSubnet bool      `json:"force_subnet,omitempty"`
	MTU         int       `json:"mtu,omitempty"`        // 0 — рекомендуемый установщиком
	WarpKey     int       `json:"warp_key,omitempty"`   // номер источника ключей WARP, 0 — первый
	SlaveLink   string    `json:"slave_link,omitempty"` // ss://… или адрес донора
	SlavePort   string    `json:"slave_port,omitempty"` // только для адреса донора
	SlaveKey    string    `json:"slave_key,omitempty"`  // только для адреса донора
	ProxyLink   string    `json:"proxy_link,omitempty"` // vless://… либо hy2://…
	WG          *WGManual `json:"wg,omitempty"`
	WGConfIndex int       `json:"wg_conf_index,omitempty"` // номер найденного .conf; 0 — ввести вручную
	OvpnPath    string    `json:"ovpn_path,omitempty"`
	OvpnUser    string    `json:"ovpn_user,omitempty"`
	OvpnPass    string    `json:"ovpn_pass,omitempty"`
}

// WGManual — данные WireGuard-соединения, вводимые вручную.
type WGManual struct {
	Endpoint     string `json:"endpoint"` // host:port
	Address      string `json:"address"`
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
	Keepalive    string `json:"keepalive,omitempty"`
}

const defaultSubnet = "10.224.0.0/16"

var (
	wgEndpointRe = regexp.MustCompile(`^[0-9a-zA-Z._-]+:[0-9]+$`)
	modeNumbers  = map[string]string{"warp": "1", "slave": "2", "wg": "3", "vless": "4", "hy2": "5", "openvpn": "6"}
)

// Validate проверяет ответы до запуска установщика.
func (a *InstallAnswers) Validate() error {
	if _, ok := modeNumbers[a.Mode]; !ok {
		return fmt.Errorf("режим %q неизвестен: warp, slave, wg, vless, hy2 или openvpn", a.Mode)
	}
	if a.Subnet != "" && !validSubnetV4(a.Subnet) {
		return errors.New("подсеть: ожидается X.X.X.0/XX с верными октетами и маской 1–32")
	}
	if a.MTU != 0 && (a.MTU < 1280 || a.MTU > 1500) {
		return errors.New("MTU вне диапазона 1280–1500")
	}
	if a.WarpKey < 0 {
		return errors.New("номер источника ключей WARP отрицательный")
	}
	switch a.Mode {
	case "slave":
		if a.SlaveLink == "" {
			return errors.New("для режима slave нужна ссылка ss:// либо адрес донора")
		}
		if !strings.Contains(a.SlaveLink, "://") && a.SlaveKey == "" {
			return errors.New("для адреса донора нужен ключ Shadowsocks")
		}
	case "wg":
		if a.WGConfIndex == 0 {
			w := a.WG
			if w == nil || !wgEndpointRe.MatchString(w.Endpoint) || w.Address == "" || w.PrivateKey == "" || w.PublicKey == "" {
				return errors.New("для режима wg нужны endpoint (host:порт), address, private_key и public_key")
			}
		}
	case "vless":
		if !strings.HasPrefix(a.ProxyLink, "vless://") {
			return errors.New("для режима vless нужна ссылка vless://")
		}
	case "hy2":
		if !strings.HasPrefix(a.ProxyLink, "hy2://") && !strings.HasPrefix(a.ProxyLink, "hysteria2://") {
			return errors.New("для режима hy2 нужна ссылка hy2://")
		}
	case "openvpn":
		if a.OvpnPath == "" {
			return errors.New("для режима openvpn нужен путь к .ovpn")
		}
	}
	for _, s := range []string{a.SlaveLink, a.SlavePort, a.SlaveKey, a.ProxyLink, a.OvpnPath, a.OvpnUser, a.OvpnPass, a.Subnet} {
		if strings.ContainsAny(s, "\r\n") {
			return errors.New("ответы не могут содержать переводы строк")
		}
	}
	if w := a.WG; w != nil {
		for _, s := range []string{w.Endpoint, w.Address, w.PrivateKey, w.PublicKey, w.PresharedKey, w.Keepalive} {
			if strings.ContainsAny(s, "\r\n") {
				return errors.New("ответы не могут содержать переводы строк")
			}
		}
	}
	return nil
}

var subnetV4Re = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0/(\d{1,2})$`)

func validSubnetV4(s string) bool {
	m := subnetV4Re.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	for _, o := range m[1:4] {
		if n, _ := strconv.Atoi(o); n > 255 {
			return false
		}
	}
	n, _ := strconv.Atoi(m[4])
	return n >= 1 && n <= 32
}

// SecretValues — значения ответов, затираемые в журнале.
func (a *InstallAnswers) SecretValues() []string {
	vals := []string{a.SlaveLink, a.SlaveKey, a.ProxyLink, a.OvpnPass}
	if a.WG != nil {
		vals = append(vals, a.WG.PrivateKey, a.WG.PresharedKey)
	}
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(s) }

func yn(yes bool) string {
	if yes {
		return "y"
	}
	return "n"
}

func fixed(s string) func([]string) (string, bool, string) {
	return func([]string) (string, bool, string) { return s, true, "" }
}

func required(name, s string) func([]string) (string, bool, string) {
	return func([]string) (string, bool, string) {
		if s == "" {
			return "", false, name + " не задано в ответах"
		}
		return s, true, ""
	}
}

// Rules — таблица «образец строки → ответ» по install.sh Liafanx/AZ-WARP
// (копия в testdata/install.sh). Обновился установщик и спросил новое —
// диалог остановится на неизвестном вопросе, а не ответит наугад.
func (a *InstallAnswers) Rules() []Rule {
	w := a.WG
	if w == nil {
		w = &WGManual{}
	}
	subnet := a.Subnet
	if subnet == "" {
		subnet = defaultSubnet
	}
	keepalive := w.Keepalive
	return []Rule{
		{Name: "gemini", Prompt: rx(`Добавить Gemini в список доменов для WARP\? \(Y/n\):\s*$`), Answer: fixed(yn(!a.NoGemini))},
		{Name: "chatgpt", Prompt: rx(`Добавить ChatGPT в список доменов для WARP\? \(Y/n\):\s*$`), Answer: fixed(yn(!a.NoChatGPT))},
		{Name: "subnet-default", Prompt: rx(`Использовать фейковую подсеть (\S+) \(рекомендуется\)\? \[Y/n\]:\s*$`),
			Answer: func(m []string) (string, bool, string) {
				if subnet == m[1] {
					return "Y", true, ""
				}
				return "n", true, ""
			}},
		{Name: "subnet-custom", Prompt: rx(`Введите новую подсеть \(.*\):\s*$`), Answer: fixed(subnet)},
		{Name: "subnet-force", Prompt: rx(`Использовать её всё равно\? \[y/N\]:\s*$`), Max: 1,
			Answer: func([]string) (string, bool, string) {
				if a.ForceSubnet {
					return "y", true, ""
				}
				return "", false, "подсеть " + subnet + " пересекается с локальной или Docker; повторите с force_subnet либо выберите другую"
			}},
		{Name: "mtu", Prompt: rx(`Использовать рекомендуемый MTU \d+\? \[Y/n\]`),
			Answer: func([]string) (string, bool, string) {
				if a.MTU == 0 {
					return "Y", true, ""
				}
				return strconv.Itoa(a.MTU), true, ""
			}},
		{Name: "mtu-custom", Prompt: rx(`Введите MTU \(1280-1500\):\s*$`), Max: 1, Answer: required("MTU", strconv.Itoa(a.MTU))},
		{Name: "mode", Prompt: rx(`Выбор \[1-6\] \(по умолчанию 1\):\s*$`), Answer: fixed(modeNumbers[a.Mode])},
		{Name: "slave-link", Prompt: rx(`Ссылка или адрес донора \(Enter — назад\):\s*$`), Max: 1, Secret: true, Answer: required("slave_link", a.SlaveLink)},
		{Name: "slave-port", Prompt: rx(`Порт \[по умолчанию 8444\]:\s*$`), Max: 1, Answer: fixed(a.SlavePort)},
		{Name: "slave-key", Prompt: rx(`Ключ Shadowsocks \(.*\):\s*$`), Max: 1, Secret: true, Answer: required("slave_key", a.SlaveKey)},
		{Name: "proxy-link", Prompt: rx(`Ссылка \(Enter — назад\):\s*$`), Max: 1, Secret: true, Answer: required("proxy_link", a.ProxyLink)},
		{Name: "wg-menu-found", Prompt: rx(`Выбор:\s*$`), Context: rx(`M\.\s+Ввести данные вручную`), Max: 2,
			Answer: func([]string) (string, bool, string) {
				if a.WGConfIndex > 0 {
					return strconv.Itoa(a.WGConfIndex), true, ""
				}
				return "M", true, ""
			}},
		{Name: "wg-menu-empty", Prompt: rx(`Выбор:\s*$`), Context: rx(`1\.\s+Ввести данные вручную`), Max: 1, Answer: fixed("1")},
		{Name: "wg-endpoint", Prompt: rx(`Endpoint \(IP:порт\):\s*$`), Max: 1, Answer: required("wg.endpoint", w.Endpoint)},
		{Name: "wg-address", Prompt: rx(`Address \(.*\):\s*$`), Max: 1, Answer: required("wg.address", w.Address)},
		{Name: "wg-private", Prompt: rx(`PrivateKey:\s*$`), Max: 1, Secret: true, Answer: required("wg.private_key", w.PrivateKey)},
		{Name: "wg-public", Prompt: rx(`PublicKey:\s*$`), Max: 1, Answer: required("wg.public_key", w.PublicKey)},
		{Name: "wg-preshared", Prompt: rx(`PresharedKey \(Enter — нет\):\s*$`), Max: 1, Secret: true, Answer: fixed(w.PresharedKey)},
		{Name: "wg-keepalive", Prompt: rx(`PersistentKeepalive \[15\]:\s*$`), Max: 1, Answer: fixed(keepalive)},
		{Name: "ovpn-path", Prompt: rx(`Номер или путь к \.ovpn \(Enter — назад\):\s*$`), Max: 1, Answer: required("ovpn_path", a.OvpnPath)},
		{Name: "ovpn-user", Prompt: rx(`Логин:\s*$`), Max: 1, Answer: fixed(a.OvpnUser)},
		{Name: "ovpn-pass", Prompt: rx(`Пароль:\s*$`), Max: 1, Secret: true, Answer: fixed(a.OvpnPass)},
		{Name: "warp-key", Prompt: rx(`Выбор \[по умолчанию 1\]:\s*$`), Max: 1,
			Answer: func([]string) (string, bool, string) {
				if a.WarpKey > 0 {
					return strconv.Itoa(a.WarpKey), true, ""
				}
				return "1", true, ""
			}},
		// Веб-панель warper-web панель не трогает: всегда «нет».
		{Name: "web-panel", Prompt: rx(`Установить веб-панель\? \(y/N\):\s*$`), Max: 1, Answer: fixed("n")},
	}
}

// NewDialog — диалог по ответам. log получает вывод установщика без секретов.
func (a *InstallAnswers) NewDialog(log io.Writer) *Dialog {
	return &Dialog{Rules: a.Rules(), Log: log, Secrets: a.SecretValues()}
}
