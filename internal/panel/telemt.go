package panel

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/syava842/azpanel/internal/nodeapi"
)

var (
	reTelemtUser = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	// reServerHost — адрес для ссылки: имя или IP, при необходимости с [] для IPv6.
	reServerHost = regexp.MustCompile(`^[A-Za-z0-9.:\[\]_-]{0,253}$`)
	reDomain     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

const (
	telemtDefaultPort = 902
	telemtGrewWindow  = 24 * time.Hour // о росте NRestarts предупреждаем сутки
	telemtQRSize      = 256
)

type telemtUserRow struct{ Name, Masked string }

// telemtLinkView — ссылка пользователя; единственное место, где секрет виден
// целиком, и только после явного нажатия.
type telemtLinkView struct {
	Name, Server, Link, WebLink string
	LinkHref, WebHref           template.URL
	QR                          template.URL
	Port                        int
}

// safeProxyURL: в href попадает только ссылка прокси Telegram.
func safeProxyURL(u string) template.URL {
	if strings.HasPrefix(u, "tg://proxy?") || strings.HasPrefix(u, "https://t.me/proxy?") {
		return template.URL(u)
	}
	return ""
}

func (s *Server) telemtPage(w http.ResponseWriter, r *http.Request) {
	s.telemtView(w, r, http.StatusOK, "", nil, nil)
}

// telemtView собирает страницу; link — показанная по нажатию ссылка.
func (s *Server) telemtView(w http.ResponseWriter, r *http.Request, status int, errText string, link *telemtLinkView, typed map[string]string) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	data := map[string]any{"Typed": typed}
	if errText != "" {
		data["Error"] = errText
	}
	st, err := n.TelemtStatus(ctx)
	if err != nil {
		_, tx := s.svcErr(err)
		data["StatusErr"] = "состояние telemt недоступно: " + tx
		s.render(w, r, status, "telemt", data)
		return
	}
	data["St"] = st
	if st.RestartsGrewAt != nil && s.now().Sub(*st.RestartsGrewAt) < telemtGrewWindow {
		data["Grew"] = formatTime(st.RestartsGrewAt)
	}
	users := make([]telemtUserRow, 0, len(st.Users))
	for _, u := range st.Users {
		users = append(users, telemtUserRow{Name: u.Name, Masked: u.SecretMasked})
	}
	data["Users"] = users
	if link != nil {
		data["Link"] = link
	}
	if st.Installed {
		if rel, err := n.TelemtRelease(ctx); err != nil {
			_, tx := s.svcErr(err)
			data["RelErr"] = "версия недоступна: " + tx
		} else {
			data["Rel"] = rel
			data["RelChecked"] = formatTime(&rel.Checked)
		}
	} else {
		port := telemtDefaultPort
		if p, err := strconv.Atoi(r.URL.Query().Get("port")); err == nil && p > 0 && p < 65536 {
			port = p
		}
		data["Port"] = port
		if pf, err := n.TelemtPreflight(ctx, port); err != nil {
			_, tx := s.svcErr(err)
			data["PreErr"] = "порт не проверен: " + tx
		} else {
			data["Pre"] = pf
			var busy []string
			for _, p := range []int{80, 443, 504, 508} {
				if pf.Busy[p] {
					busy = append(busy, strconv.Itoa(p))
				}
			}
			data["BusyPorts"] = strings.Join(busy, ", ")
		}
	}
	s.render(w, r, status, "telemt", data)
}

func pathTelemtUser(w http.ResponseWriter, r *http.Request, s *Server) (string, bool) {
	name := r.PathValue("name")
	if !reTelemtUser.MatchString(name) {
		s.errorPage(w, r, http.StatusBadRequest, "недопустимое имя пользователя telemt")
		return "", false
	}
	return name, true
}

// telemtAddUser добавляет пользователя. Введённый секрет в журнал, аудит и
// ответ не попадает.
func (s *Server) telemtAddUser(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if !reTelemtUser.MatchString(name) {
		s.telemtView(w, r, http.StatusBadRequest, "Имя: латиница, цифры, «_», «-», «.», до 64 знаков.", nil, nil)
		return
	}
	secret := strings.TrimSpace(r.PostForm.Get("secret"))
	res, err := n.TelemtAddUser(r.Context(), nodeapi.TelemtAddUser{Name: name, Secret: secret})
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "telemt_user_add", "target", name, "err", err)
		st, tx := s.svcErr(err)
		s.auditRefused(r, "telemt_user_add", name, st, tx)
		s.telemtView(w, r, st, tx, nil, nil)
		return
	}
	how := "секрет сгенерирован"
	if secret != "" {
		how = "секрет задан вручную"
	}
	s.taskStarted(w, r, "telemt_user_add", name, how+" ("+res.SecretMasked+");", res.Task)
}

func (s *Server) telemtRemoveUser(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	name, ok := pathTelemtUser(w, r, s)
	if !ok {
		return
	}
	if !formConfirmed(r) {
		s.telemtView(w, r, http.StatusBadRequest, "Отметьте подтверждение: ссылка пользователя перестанет работать.", nil, nil)
		return
	}
	res, err := n.TelemtRemoveUser(r.Context(), name)
	if err != nil {
		s.serviceRefused(w, r, "telemt_user_remove", name, err)
		return
	}
	s.taskStarted(w, r, "telemt_user_remove", name, "", res.Task)
}

// telemtShowLink — ссылка и QR пользователя по явному нажатию. POST, а не
// GET: ссылка с секретом не попадает в историю браузера, журналы прокси и
// Referer. Ответ не кешируется.
func (s *Server) telemtShowLink(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	name, ok := pathTelemtUser(w, r, s)
	if !ok {
		return
	}
	server := strings.TrimSpace(r.PostForm.Get("server"))
	if !reServerHost.MatchString(server) {
		s.telemtView(w, r, http.StatusBadRequest, "Адрес сервера: имя или IP.", nil, nil)
		return
	}
	li, err := n.TelemtLink(r.Context(), name, server)
	if err != nil {
		s.serviceRefused(w, r, "telemt_link", name, err)
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "telemt_link", "target", name)
	s.audit(r, "telemt_link", name, "", "ссылка показана")
	v := &telemtLinkView{Name: li.Name, Server: li.Server, Port: li.Port, Link: li.Link, WebLink: li.WebLink,
		LinkHref: safeProxyURL(li.Link), WebHref: safeProxyURL(li.WebLink)}
	if png, err := qrcode.Encode(li.Link, qrcode.Medium, telemtQRSize); err == nil {
		v.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	s.telemtView(w, r, http.StatusOK, "", v, nil)
}

func (s *Server) telemtRestart(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	t, err := n.TelemtRestart(r.Context())
	if err != nil {
		s.serviceRefused(w, r, "telemt_restart", "telemt", err)
		return
	}
	s.taskStarted(w, r, "telemt_restart", "telemt", "", t)
}

func (s *Server) telemtUpdate(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	if !formConfirmed(r) {
		s.telemtView(w, r, http.StatusBadRequest, "Отметьте подтверждение: telemt перезапустится; не пройдёт проверка — вернётся прежний бинарник.", nil, nil)
		return
	}
	t, err := n.TelemtUpdate(r.Context())
	if err != nil {
		s.serviceRefused(w, r, "telemt_update", "telemt", err)
		return
	}
	s.taskStarted(w, r, "telemt_update", "telemt", "", t)
}

// telemtInstall — форма вопросов установщика. Секрет, если задан, в журнал и
// аудит не пишется.
func (s *Server) telemtInstall(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	f := r.PostForm
	typed := map[string]string{"port": f.Get("port"), "domain": f.Get("domain"), "user": f.Get("user"),
		"max_connections": f.Get("max_connections"), "buf_divisor": f.Get("buf_divisor")}
	bad := func(text string) { s.telemtView(w, r, http.StatusBadRequest, text, nil, typed) }
	p := nodeapi.TelemtInstall{Domain: strings.TrimSpace(f.Get("domain")), Secret: strings.TrimSpace(f.Get("secret")),
		User: strings.TrimSpace(f.Get("user")), SkipDomainDNS: f.Get("skip_domain_dns") == "1"}
	if !reDomain.MatchString(p.Domain) {
		bad("Домен маскировки: например, www.example.com.")
		return
	}
	if p.User != "" && !reTelemtUser.MatchString(p.User) {
		bad("Имя пользователя: латиница, цифры, «_», «-», «.».")
		return
	}
	for _, x := range []struct {
		key string
		dst *int
		min int
		max int
		msg string
	}{
		{"port", &p.Port, 1, 65535, "Порт: от 1 до 65535."},
		{"max_connections", &p.MaxConnections, 1, 1_000_000, "Соединений: от 1 до 1 000 000."},
		{"buf_divisor", &p.BufDivisor, 1, 1024, "Делитель буферов: от 1 до 1024."},
	} {
		v := strings.TrimSpace(f.Get(x.key))
		if v == "" {
			continue // умолчание установщика
		}
		num, err := strconv.Atoi(v)
		if err != nil || num < x.min || num > x.max {
			bad(x.msg)
			return
		}
		*x.dst = num
	}
	t, err := n.InstallTelemt(r.Context(), p)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "telemt_install", "err", err)
		st, tx := s.svcErr(err)
		s.auditRefused(r, "telemt_install", "telemt", st, tx)
		s.telemtView(w, r, st, tx, nil, typed)
		return
	}
	detail := "домен " + p.Domain + ", порт " + strconv.Itoa(p.Port)
	if p.Secret != "" {
		detail += ", секрет задан вручную"
	}
	s.taskStarted(w, r, "telemt_install", "telemt", detail+";", t)
}
