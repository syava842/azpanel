package warp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// WebState — состояние веб-панели AZ-WARP (warper-web). BackendPort — порт
// gunicorn на 127.0.0.1, куда панель azpanel пересылает запросы раздела WARP:
// внутренний при публикации через nginx, внешний — без nginx (тогда при
// HTTPS gunicorn говорит TLS сам, TLS == true).
type WebState struct {
	Installed   bool   `json:"installed"`
	Active      bool   `json:"active"`
	Mode        string `json:"mode,omitempty"`         // nginx | standalone
	Port        int    `json:"port,omitempty"`         // внешний порт (6060)
	BackendPort int    `json:"backend_port,omitempty"` // куда пересылать
	TLS         bool   `json:"tls,omitempty"`
}

// webUnitPath — юнит веб-панели: по нему видно, слушает ли gunicorn с TLS.
var webUnitPath = "/etc/systemd/system/warper-web.service"

// Web читает состояние веб-панели: `warper web status` и PORT из web/.env.
// AZ-WARP не установлен — пустое состояние без ошибки.
func (w *Warper) Web(ctx context.Context) (WebState, error) {
	if _, ok := w.Version(); !ok {
		return WebState{}, nil
	}
	out, err := w.query(ctx, "web", "status")
	if err != nil {
		return WebState{}, err
	}
	st := parseWebStatus(out)
	if !st.Installed {
		return st, nil
	}
	if st.Mode == "standalone" {
		// gunicorn слушает 0.0.0.0:<внешний порт>, PORT в .env — неиспользуемый внутренний.
		st.BackendPort = st.Port
		if unit, err := os.ReadFile(webUnitPath); err == nil {
			st.TLS = bytes.Contains(unit, []byte("--certfile"))
		}
		return st, nil
	}
	st.BackendPort = envPort(filepath.Join(w.dir(), "web", ".env"))
	return st, nil
}

// parseWebStatus разбирает строки «ключ=значение» вывода `warper web status`.
func parseWebStatus(out []byte) WebState {
	var st WebState
	sc := bufio.NewScanner(bytes.NewReader([]byte(StripANSI(string(out)))))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "installed":
			st.Installed = v == "true"
		case "active":
			st.Active = v == "active"
		case "external_port":
			st.Port, _ = strconv.Atoi(v)
		case "mode":
			st.Mode = v
		}
	}
	return st
}

// envPort — значение PORT из .env веб-панели; 0, если нет или не число.
func envPort(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PORT="); ok {
			n, err := strconv.Atoi(strings.Trim(v, `"' `))
			if err == nil && n > 0 && n < 65536 {
				return n
			}
		}
	}
	return 0
}

// WebAnswers — ответы установщику веб-панели AZ-WARP (web/install-web.sh).
// Пароль задаётся всегда: сгенерированный установщик печатает в вывод, а
// вывод попадает в журнал задачи. Остальное — как у установщика: порты 0 —
// его умолчания, HTTPS по умолчанию выключен, пустой домен при HTTPS —
// самоподписанный сертификат.
type WebAnswers struct {
	User        string `json:"user"`
	Password    string `json:"password"`
	Port        int    `json:"port,omitempty"`         // внешний; 0 — 6060
	BackendPort int    `json:"backend_port,omitempty"` // gunicorn; 0 — 16060
	HTTPS       bool   `json:"https,omitempty"`
	Domain      string `json:"domain,omitempty"` // для Let's Encrypt
	// Publish — режим публикации: "" — умолчание установщика (nginx, а если
	// порт 80 занят посторонним — напрямую), nginx, direct (gunicorn сам
	// слушает внешний порт).
	Publish string `json:"publish,omitempty"`
}

// Умолчания install-web.sh.
const (
	WebDefaultPort        = 6060
	WebDefaultBackendPort = 16060
)

var webDomainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

var webUserRe = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

// Validate — те же правила, что у install-web.sh.
func (a *WebAnswers) Validate() error {
	if !webUserRe.MatchString(a.User) {
		return errors.New("логин панели AZ-WARP: 3–32 символа, латиница, цифры, _ или -")
	}
	if n := len(a.Password); n < 6 || n > 256 {
		return errors.New("пароль панели AZ-WARP: от 6 до 256 символов")
	}
	if hasControl(a.Password) {
		return errors.New("пароль панели AZ-WARP: без управляющих символов и переводов строк")
	}
	for _, p := range []int{a.Port, a.BackendPort} {
		if p < 0 || p > 65535 {
			return errors.New("порт веб-панели: от 1 до 65535")
		}
	}
	port, backend := a.Port, a.BackendPort
	if port == 0 {
		port = WebDefaultPort
	}
	if backend == 0 {
		backend = WebDefaultBackendPort
	}
	if port == backend {
		return errors.New("внешний и внутренний порты веб-панели совпадают")
	}
	if a.Publish != "" && a.Publish != "nginx" && a.Publish != "direct" {
		return errors.New("режим публикации веб-панели: nginx или direct")
	}
	if a.Domain != "" {
		if !a.HTTPS {
			return errors.New("домен веб-панели нужен только с HTTPS")
		}
		if !webDomainRe.MatchString(a.Domain) {
			return errors.New("домен веб-панели: ожидается имя вида panel.example.com")
		}
	}
	return nil
}

func portAnswer(p int) string {
	if p == 0 {
		return "" // Enter — умолчание установщика
	}
	return strconv.Itoa(p)
}

// Rules — вопросы install-web.sh (копия в testdata/install-web.sh). Занят
// порт — установщик спросит снова, и диалог остановится на повторе.
func (a *WebAnswers) Rules() []Rule {
	return []Rule{
		{Name: "web-port", Prompt: rx(`Внешний порт веб-панели \[\d+\]:\s*$`), Max: 1, Answer: fixed(portAnswer(a.Port))},
		{Name: "web-backend-port", Prompt: rx(`Внутренний порт \(gunicorn\) \[\d+\]:\s*$`), Max: 1, Answer: fixed(portAnswer(a.BackendPort))},
		{Name: "web-user", Prompt: rx(`Логин администратора \[admin\]:\s*$`), Max: 1, Answer: fixed(a.User)},
		{Name: "web-pass", Prompt: rx(`(^|\s)Пароль:\s*$`), Max: 1, Secret: true, Answer: fixed(a.Password)},
		{Name: "web-pass-confirm", Prompt: rx(`Подтвердите пароль:\s*$`), Max: 1, Secret: true, Answer: fixed(a.Password)},
		{Name: "web-https", Prompt: rx(`Включить HTTPS\? \(y/N\):\s*$`), Max: 1, Answer: fixed(yn(a.HTTPS))},
		{Name: "web-domain", Prompt: rx(`Доменное имя \(для Let's Encrypt\) или Enter для самоподписанного:\s*$`), Max: 1, Answer: fixed(a.Domain)},
		{Name: "web-publish", Prompt: rx(`Выбор \[[12]\]:\s*$`), Context: rx(`Режим публикации панели`), Max: 1,
			Answer: fixed(map[string]string{"": "", "nginx": "1", "direct": "2"}[a.Publish])},
		// Порт 80 занят резервным OpenVPN AntiZapret, а нужен Let's Encrypt:
		// Enter — вариант установщика по умолчанию (остановить его на минуту).
		{Name: "web-le-port80", Prompt: rx(`Выбор \[1/2/3, по умолчанию 1\]:\s*$`), Max: 1, Answer: fixed("")},
	}
}

// NewDialog — диалог установки веб-панели; пароль в журнал не попадает.
func (a *WebAnswers) NewDialog(log io.Writer) *Dialog {
	return &Dialog{Rules: a.Rules(), Log: log, Secrets: []string{a.Password}}
}

// InstallWeb ставит веб-панель родной командой `warper web install` под
// псевдотерминалом.
func (w *Warper) InstallWeb(ctx context.Context, a WebAnswers, log io.Writer) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if _, ok := w.Version(); !ok {
		return errors.New("AZ-WARP не установлен")
	}
	return RunPTY(ctx, a.NewDialog(log), w.bin(), "web", "install")
}
