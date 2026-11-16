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

// WebState — состояние веб-панели AZ-WARP (warper-web). BackendPort —
// внутренний порт gunicorn на 127.0.0.1: на него панель azpanel пересылает
// запросы раздела WARP.
type WebState struct {
	Installed   bool `json:"installed"`
	Active      bool `json:"active"`
	Port        int  `json:"port,omitempty"`         // внешний порт nginx (6060)
	BackendPort int  `json:"backend_port,omitempty"` // внутренний порт gunicorn (16060)
}

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
	if st.Installed {
		st.BackendPort = envPort(filepath.Join(w.dir(), "web", ".env"))
	}
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
// вывод попадает в журнал задачи.
type WebAnswers struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

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
	return nil
}

// Rules — вопросы install-web.sh (копия в testdata/install-web.sh). Порты —
// по умолчанию; HTTPS — да, с самоподписанным сертификатом: внешний порт
// панели не остаётся открытым HTTP. Занят порт — установщик спросит снова, и
// диалог остановится на повторе.
func (a *WebAnswers) Rules() []Rule {
	return []Rule{
		{Name: "web-port", Prompt: rx(`Внешний порт веб-панели \[\d+\]:\s*$`), Max: 1, Answer: fixed("")},
		{Name: "web-backend-port", Prompt: rx(`Внутренний порт \(gunicorn\) \[\d+\]:\s*$`), Max: 1, Answer: fixed("")},
		{Name: "web-user", Prompt: rx(`Логин администратора \[admin\]:\s*$`), Max: 1, Answer: fixed(a.User)},
		{Name: "web-pass", Prompt: rx(`(^|\s)Пароль:\s*$`), Max: 1, Secret: true, Answer: fixed(a.Password)},
		{Name: "web-pass-confirm", Prompt: rx(`Подтвердите пароль:\s*$`), Max: 1, Secret: true, Answer: fixed(a.Password)},
		{Name: "web-https", Prompt: rx(`Включить HTTPS\? \(y/N\):\s*$`), Max: 1, Answer: fixed("y")},
		{Name: "web-domain", Prompt: rx(`Доменное имя \(для Let's Encrypt\) или Enter для самоподписанного:\s*$`), Max: 1, Answer: fixed("")},
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
