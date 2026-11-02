package panel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	badTokenDelay = 300 * time.Millisecond // задержка ответа на неверный токен
	unlockMax     = 5                      // неверных кодов на токен портала
	unlockWindow  = time.Hour              // за какое время считаются попытки
	attemptsKeep  = 2 * time.Hour          // старше этого попытки стираются
	downloadTTL   = 24 * time.Hour         // жизнь одноразовой ссылки
	portalPrefix  = "/p/"
	dlPrefix      = "/dl/"
)

var pinRe = regexp.MustCompile(`^[0-9]{4,8}$`)

// isPortalPath: путь публичного портала или одноразовой ссылки — белый список
// адресов панели на них не действует.
func isPortalPath(p string) bool {
	return strings.HasPrefix(p, portalPrefix) || strings.HasPrefix(p, dlPrefix)
}

// publicLink строит ссылку: с panel.public_url — полную, без него — относительную.
func (s *Server) publicLink(path string) string {
	if s.PublicURL == "" {
		return s.url(path)
	}
	return strings.TrimRight(s.PublicURL, "/") + s.url(path)
}

// publicURLNote — подсказка к ссылкам, если адрес панели не задан.
func (s *Server) publicURLNote() string {
	if s.PublicURL != "" {
		return ""
	}
	return " Адрес панели не задан: укажите panel.public_url в настройках (config.toml), тогда ссылка будет полной."
}

// sameHostOf: адрес (Origin или Referer) относится к этой же панели: хост
// запроса или хост panel.public_url (за обратным прокси они различаются).
func (s *Server) sameHostOf(r *http.Request, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if s.PublicURL != "" {
		p, err := url.Parse(s.PublicURL)
		return err == nil && p.Host != "" && strings.EqualFold(u.Host, p.Host)
	}
	return false
}

// sameOriginPost: форма портала принимается, только если запрос с этого же
// сайта: Sec-Fetch-Site same-origin/none; без этого заголовка (старые
// браузеры, адрес без TLS) — Origin этой панели, а если Origin нет вовсе —
// Referer этой же панели. Origin: null и чужие адреса отклоняются.
func (s *Server) sameOriginPost(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		return s.sameHostOf(r, o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return s.sameHostOf(r, ref)
	}
	return false
}

// renderPortal показывает публичную страницу. Сессию панели не трогает: ни
// cookie, ни меню, ни CSRF-токена.
func (s *Server) renderPortal(w http.ResponseWriter, r *http.Request, status int, page string, data map[string]any) {
	t, ok := s.pages[page]
	if !ok {
		s.Log.Error("нет шаблона", "page", page)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	d := map[string]any{}
	for k, v := range data {
		d[k] = v
	}
	d["Msg"] = flashText(r)
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", d); err != nil {
		s.Log.Error("шаблон не выполнен", "page", page, "err", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) portalError(w http.ResponseWriter, r *http.Request, status int, text string) {
	s.renderPortal(w, r, status, "portal_error", map[string]any{"Error": text, "Status": status})
}

// portalGone — одинаковый ответ на неверный, отозванный и чужой токен.
func (s *Server) portalGone(w http.ResponseWriter, r *http.Request) {
	s.Sleep(badTokenDelay)
	s.portalError(w, r, http.StatusNotFound, "ссылка недействительна")
}

// portalLinkOf находит ссылку по токену из пути (c_<токен> или u_<токен>);
// вторая строка — путь для ссылок страницы. Не нашли — ответ уже отправлен.
func (s *Server) portalLinkOf(w http.ResponseWriter, r *http.Request) (store.PortalLink, string, bool) {
	raw := r.PathValue("token")
	if s.Store == nil {
		s.portalError(w, r, http.StatusServiceUnavailable, "сервис временно недоступен")
		return store.PortalLink{}, "", false
	}
	if len(raw) < 3 || raw[1] != '_' || (raw[0] != 'c' && raw[0] != 'u') {
		s.portalGone(w, r)
		return store.PortalLink{}, "", false
	}
	kind := store.LinkClient
	if raw[0] == 'u' {
		kind = store.LinkUser
	}
	link, err := s.Store.PortalLinkByToken(r.Context(), raw[2:])
	if errors.Is(err, store.ErrLinkGone) || (err == nil && link.Kind != kind) {
		s.portalGone(w, r)
		return store.PortalLink{}, "", false
	}
	if err != nil {
		s.Log.Error("ссылка портала не прочитана", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return store.PortalLink{}, "", false
	}
	if link.Kind == store.LinkUser { // отключённый пользователь: портал закрыт той же 404
		u, err := s.Store.UserByID(r.Context(), link.UserID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && u.Disabled) {
			s.portalGone(w, r)
			return store.PortalLink{}, "", false
		}
		if err != nil {
			s.Log.Error("пользователь ссылки не прочитан", "err", err)
			s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
			return store.PortalLink{}, "", false
		}
	}
	return link, raw, true
}

// portalNames — клиенты ссылки на этом узле: один у c_, все клиенты
// пользователя у u_.
func (s *Server) portalNames(r *http.Request, link store.PortalLink) ([]string, error) {
	if link.Kind == store.LinkClient {
		if link.Node != s.NodeID {
			return nil, nil
		}
		return []string{link.Client}, nil
	}
	refs, err := s.Store.ClientsOf(r.Context(), link.UserID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, x := range refs {
		if x.Node == s.NodeID {
			out = append(out, x.Name)
		}
	}
	return out, nil
}

func inList(list []string, name string) bool {
	for _, x := range list {
		if x == name {
			return true
		}
	}
	return false
}

// portalClient — клиент на странице портала.
type portalClient struct {
	Name        string
	Blocked     bool
	StatusText  string
	Until       string
	Limit       string
	Sessions    []sessionRow
	Chart       template.HTML
	Down, Up    string
	TrafficErr  string
	Profiles    []profileRow
	ProfilesErr string
}

func portalHref(tokenPath string) string { return portalPrefix + tokenPath }

// portalPage собирает страницу портала.
func (s *Server) portalPage(w http.ResponseWriter, r *http.Request, link store.PortalLink, tokenPath string, status int, errText string) {
	names, err := s.portalNames(r, link)
	if err != nil {
		s.Log.Error("клиенты ссылки не прочитаны", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	all, err := s.Node.Clients(r.Context())
	if err != nil {
		s.Log.Warn("портал: клиенты агента не получены", "err", err)
		s.portalError(w, r, http.StatusBadGateway, "сервер временно недоступен, попробуйте позже")
		return
	}
	var sess []nodeapi.Session
	sessErr := ""
	if ss, err := s.Node.Sessions(r.Context()); err != nil {
		s.Log.Warn("портал: сессии не получены", "err", err)
		sessErr = "данные о подключениях недоступны"
	} else {
		sess = ss
	}
	now := s.now()
	rows := []portalClient{}
	for _, c := range all {
		if !inList(names, c.Name) {
			continue
		}
		rows = append(rows, s.portalClientRow(r, c, tokenPath, sess, now))
	}
	if link.Kind == store.LinkClient && len(rows) == 0 {
		s.portalGone(w, r)
		return
	}
	data := map[string]any{"Clients": rows, "IsUser": link.Kind == store.LinkUser, "Base": portalHref(tokenPath),
		"SessErr": sessErr, "Range": histRanges[2].Name}
	if errText != "" {
		data["Error"] = errText
	}
	s.renderPortal(w, r, status, "portal", data)
}

func (s *Server) portalClientRow(r *http.Request, c nodeapi.Client, tokenPath string, sess []nodeapi.Session, now time.Time) portalClient {
	row := portalClient{Name: c.Name, Blocked: c.Blocked, Limit: "без ограничения", Until: "без срока", Sessions: []sessionRow{}}
	if c.Limit > 0 {
		row.Limit = fmt.Sprint(c.Limit)
	}
	card, err := s.Store.Card(r.Context(), s.NodeID, c.Name)
	if err != nil {
		s.Log.Warn("портал: карточка не прочитана", "client", c.Name, "err", err)
	}
	if eff, err := s.Store.EffectiveUntil(r.Context(), s.NodeID, c.Name); err == nil && eff != nil {
		row.Until = untilStamp(eff)
	}
	row.StatusText = "активен"
	if c.Blocked {
		row.StatusText = "заблокирован"
		if reason := autoBlockText(c, card); reason != "" {
			row.StatusText = reason
		}
	}
	for _, x := range sess {
		if x.Name == c.Name {
			row.Sessions = append(row.Sessions, newSessionRow(x))
		}
	}
	if chart, down, up, err := s.clientTraffic(r.Context(), c.Name, histRanges[2], now); err != nil {
		s.Log.Warn("портал: трафик не прочитан", "client", c.Name, "err", err)
		row.TrafficErr = "история трафика недоступна"
	} else {
		row.Chart, row.Down, row.Up = chart, down, up
	}
	row.Profiles = []profileRow{}
	if ps, err := s.Node.Profiles(r.Context(), c.Name); err != nil {
		s.Log.Warn("портал: профили не получены", "client", c.Name, "err", err)
		row.ProfilesErr = "профили временно недоступны"
	} else {
		base := portalHref(tokenPath)
		for _, p := range ps {
			tail := url.PathEscape(c.Name) + "/" + url.PathEscape(p.Kind) + "/" + url.PathEscape(p.Variant) + "/" + url.PathEscape(p.File)
			pr := profileRow{Kind: p.Kind, Variant: p.Variant, File: p.File, Href: base + "/profile/" + tail}
			if p.Kind == nodeapi.KindWireGuard {
				pr.QRHref = base + "/qr/" + tail
			}
			row.Profiles = append(row.Profiles, pr)
		}
	}
	return row
}

// portalIndex — GET /p/{token}.
func (s *Server) portalIndex(w http.ResponseWriter, r *http.Request) {
	link, tokenPath, ok := s.portalLinkOf(w, r)
	if !ok {
		return
	}
	s.portalPage(w, r, link, tokenPath, http.StatusOK, "")
}

// portalHelp — GET /p/{token}/help: статическая инструкция по приложениям.
func (s *Server) portalHelp(w http.ResponseWriter, r *http.Request) {
	_, tokenPath, ok := s.portalLinkOf(w, r)
	if !ok {
		return
	}
	s.renderPortal(w, r, http.StatusOK, "portal_help", map[string]any{"Base": portalHref(tokenPath)})
}

// portalProfileClient: клиент из пути входит в ссылку; иначе 404.
func (s *Server) portalProfileClient(w http.ResponseWriter, r *http.Request) (name string, ok bool) {
	link, _, ok := s.portalLinkOf(w, r)
	if !ok {
		return "", false
	}
	names, err := s.portalNames(r, link)
	if err != nil {
		s.Log.Error("клиенты ссылки не прочитаны", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return "", false
	}
	name = r.PathValue("name")
	if !inList(names, name) {
		s.portalGone(w, r)
		return "", false
	}
	return name, true
}

// portalProfile — файл профиля клиента ссылки.
func (s *Server) portalProfile(w http.ResponseWriter, r *http.Request) {
	name, ok := s.portalProfileClient(w, r)
	if !ok {
		return
	}
	data, err := s.Node.Profile(r.Context(), name, nodeapi.Profile{Kind: r.PathValue("kind"), Variant: r.PathValue("variant"), File: r.PathValue("file")})
	if err != nil {
		s.Log.Warn("портал: профиль не получен", "client", name, "err", err)
		s.portalError(w, r, http.StatusNotFound, "профиль не найден")
		return
	}
	writeProfile(w, r.PathValue("file"), data)
}

// portalQR — QR профиля WireGuard.
func (s *Server) portalQR(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("kind") != nodeapi.KindWireGuard {
		s.portalError(w, r, http.StatusNotFound, "QR есть только у профилей WireGuard")
		return
	}
	name, ok := s.portalProfileClient(w, r)
	if !ok {
		return
	}
	data, err := s.Node.Profile(r.Context(), name, nodeapi.Profile{Kind: nodeapi.KindWireGuard, Variant: r.PathValue("variant"), File: r.PathValue("file")})
	if err != nil {
		s.Log.Warn("портал: профиль не получен", "client", name, "err", err)
		s.portalError(w, r, http.StatusNotFound, "профиль не найден")
		return
	}
	png, ok := profileQRPNG(data)
	if !ok {
		s.portalError(w, r, http.StatusUnprocessableEntity, "профиль слишком велик для QR")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// closedText — сообщение о закрытом вводе с оставшимся временем.
func closedText(retry time.Duration) string {
	return fmt.Sprintf("слишком много неверных кодов: ввод закрыт, повторите через %d мин.", int(math.Ceil(retry.Minutes())))
}

// portalUnlock — POST /p/{token}/unlock: ввод кода продления. Неверные коды
// считаются по токену портала: пятая ошибка за час закрывает ввод на час.
func (s *Server) portalUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.sameOriginPost(r) {
		s.portalError(w, r, http.StatusForbidden, "запрос отклонён: отправьте форму со страницы портала")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.portalError(w, r, http.StatusBadRequest, "неверный запрос")
		return
	}
	link, tokenPath, ok := s.portalLinkOf(w, r)
	if !ok {
		return
	}
	names, err := s.portalNames(r, link)
	if err != nil {
		s.Log.Error("клиенты ссылки не прочитаны", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	name := link.Client
	if link.Kind == store.LinkUser {
		name = r.PostForm.Get("client")
	}
	if !inList(names, name) {
		s.portalPage(w, r, link, tokenPath, http.StatusBadRequest, "выберите клиента из списка")
		return
	}

	key := "code:" + link.Hash
	now := s.now()
	ticket, retry, err := s.openAttempt(r.Context(), key, now)
	if err != nil {
		s.Log.Error("попытки не прочитаны", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	if retry > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(math.Ceil(retry.Seconds()))))
		s.portalPage(w, r, link, tokenPath, http.StatusTooManyRequests, closedText(retry))
		return
	}
	// дальше замка нет: агент отвечает долго, а резерв попытки уже записан
	counted := false
	defer func() {
		if !counted {
			s.refundAttempt(context.WithoutCancel(r.Context()), ticket)
		}
	}()
	all, err := s.Node.Clients(r.Context())
	if err != nil {
		s.Log.Warn("портал: клиенты агента не получены", "err", err)
		s.portalError(w, r, http.StatusBadGateway, "сервер временно недоступен, попробуйте позже")
		return
	}
	var cl *nodeapi.Client
	for i := range all {
		if all[i].Name == name {
			cl = &all[i]
		}
	}
	if cl == nil {
		s.portalGone(w, r)
		return
	}
	var owner *int64
	if link.Kind == store.LinkUser {
		id := link.UserID
		owner = &id
	} else if id, has, err := s.Store.OwnerOf(r.Context(), s.NodeID, name); err != nil {
		s.Log.Error("владелец клиента не прочитан", "client", name, "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	} else if has {
		owner = &id
	}
	res, err := s.redeemForClient(r.Context(), *cl, owner, r.PostForm.Get("code"))
	switch {
	case errors.Is(err, store.ErrCodeInvalid):
		counted = true
		left := s.failAttempt(context.WithoutCancel(r.Context()), ticket, now)
		msg := fmt.Sprintf("%s. Осталось попыток: %d", store.ErrCodeInvalid.Error(), left)
		if left == 0 {
			msg = store.ErrCodeInvalid.Error() + ". Ввод закрыт на час"
		}
		s.portalPage(w, r, link, tokenPath, http.StatusBadRequest, msg)
		return
	case errors.Is(err, store.ErrNoLimit):
		s.portalPage(w, r, link, tokenPath, http.StatusBadRequest, "у клиента нет срока доступа: продлевать нечего")
		return
	case errors.Is(err, errManualBlock):
		s.portalPage(w, r, link, tokenPath, http.StatusBadRequest, errManualBlock.Error())
		return
	case err != nil:
		s.Log.Error("портал: код не применён", "client", name, "err", err)
		s.portalPage(w, r, link, tokenPath, http.StatusInternalServerError, "код не применён, обратитесь к администратору")
		return
	}
	detail := fmt.Sprintf("+%d дн., до %s", res.Days, untilStamp(&res.After))
	if res.CertRenewed {
		detail += "; сертификат перевыпущен"
	}
	if res.CertErr != nil {
		s.Log.Warn("портал: сертификат не перевыпущен после продления", "client", name, "err", res.CertErr)
		detail += "; сертификат не перевыпущен"
	}
	s.Log.Info("действие", "user", "портал", "op", "redeem", "client", name, "detail", detail)
	s.auditAs(r, "портал", "redeem", name, "до "+untilStamp(&res.Before), detail)
	s.redirectMsg(w, r, portalHref(tokenPath), "access_extended", int(res.Days))
}

// dlGone — ссылка недействительна: уже скачана, просрочена, закрыта PIN.
func (s *Server) dlGone(w http.ResponseWriter, r *http.Request) {
	s.Sleep(badTokenDelay)
	s.portalError(w, r, http.StatusGone, "ссылка недействительна: она уже использована, просрочена или закрыта")
}

// dlLive находит живую одноразовую ссылку; нет — ответ уже отправлен.
func (s *Server) dlLive(w http.ResponseWriter, r *http.Request) (store.DownloadLink, bool) {
	if s.Store == nil {
		s.portalError(w, r, http.StatusServiceUnavailable, "сервис временно недоступен")
		return store.DownloadLink{}, false
	}
	l, err := s.Store.DownloadLinkByToken(r.Context(), r.PathValue("token"), s.now().Unix())
	if errors.Is(err, store.ErrLinkGone) || (err == nil && l.Node != s.NodeID) {
		s.dlGone(w, r)
		return store.DownloadLink{}, false
	}
	if err != nil {
		s.Log.Error("одноразовая ссылка не прочитана", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return store.DownloadLink{}, false
	}
	return l, true
}

func (s *Server) dlForm(w http.ResponseWriter, r *http.Request, l store.DownloadLink, status int, errText string) {
	data := map[string]any{"File": l.File, "HasPIN": l.HasPIN, "Left": store.MaxPINFails - int(l.PINFails),
		"Expires": untilStamp(&l.Expires), "Action": dlPrefix + r.PathValue("token")}
	if errText != "" {
		data["Error"] = errText
	}
	s.renderPortal(w, r, status, "dl", data)
}

// dlPage — GET /dl/{token}: страница с PIN и кнопкой «Скачать»; сама ссылку
// не гасит (иначе её сожгут предпросмотры в мессенджерах).
func (s *Server) dlPage(w http.ResponseWriter, r *http.Request) {
	l, ok := s.dlLive(w, r)
	if !ok {
		return
	}
	s.dlForm(w, r, l, http.StatusOK, "")
}

// dlDownload — POST /dl/{token}: PIN, погашение и файл. Файл читается у
// агента до погашения: сбой агента ссылку не сжигает.
func (s *Server) dlDownload(w http.ResponseWriter, r *http.Request) {
	if !s.sameOriginPost(r) {
		s.portalError(w, r, http.StatusForbidden, "запрос отклонён: отправьте форму со страницы ссылки")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.portalError(w, r, http.StatusBadRequest, "неверный запрос")
		return
	}
	l, ok := s.dlLive(w, r)
	if !ok {
		return
	}
	token := r.PathValue("token")
	now := s.now().Unix()
	switch err := s.Store.CheckDownloadPIN(r.Context(), token, strings.TrimSpace(r.PostForm.Get("pin")), now); {
	case errors.Is(err, store.ErrPINWrong):
		left := store.MaxPINFails - int(l.PINFails) - 1
		l.PINFails++
		if left <= 0 {
			s.auditAs(r, "портал", "download_closed", l.Client, "", "ссылка закрыта: исчерпаны попытки PIN")
			s.dlGone(w, r)
			return
		}
		s.dlForm(w, r, l, http.StatusForbidden, fmt.Sprintf("неверный PIN. Осталось попыток: %d", left))
		return
	case errors.Is(err, store.ErrLinkGone):
		s.dlGone(w, r)
		return
	case err != nil:
		s.Log.Error("PIN не проверен", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	data, err := s.Node.Profile(r.Context(), l.Client, nodeapi.Profile{Kind: l.PKind, Variant: l.Variant, File: l.File})
	if err != nil {
		s.Log.Warn("одноразовая ссылка: профиль не получен", "client", l.Client, "err", err)
		s.portalError(w, r, http.StatusBadGateway, "профиль временно недоступен, попробуйте позже")
		return
	}
	if err := s.Store.MarkDownloadUsed(r.Context(), token, now); err != nil {
		if errors.Is(err, store.ErrLinkGone) { // параллельный запрос успел раньше
			s.dlGone(w, r)
			return
		}
		s.Log.Error("ссылка не погашена", "err", err)
		s.portalError(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	s.auditAs(r, "портал", "download", l.Client, "", l.PKind+"/"+l.Variant+"/"+l.File)
	writeProfile(w, l.File, data)
}

// addPortalInfo кладёт в карточку клиента состояние ссылки портала.
func (s *Server) addPortalInfo(r *http.Request, c nodeapi.Client, data map[string]any) {
	if s.Store == nil {
		return
	}
	data["PublicURLSet"] = s.PublicURL != ""
	created, ok, err := s.Store.ClientLinkCreated(r.Context(), s.NodeID, c.Name)
	if err != nil {
		s.Log.Warn("ссылка портала не прочитана", "client", c.Name, "err", err)
		return
	}
	if ok {
		t := time.Unix(created, 0)
		data["PortalCreated"] = formatTime(&t)
	}
}

// clientPortalLink — «Создать/перевыпустить ссылку портала» (администратор).
func (s *Server) clientPortalLink(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.Store == nil {
		s.card(w, r, c, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	_, had, _ := s.Store.ClientLinkCreated(r.Context(), s.NodeID, c.Name)
	token, err := s.Store.CreateClientLink(r.Context(), s.NodeID, c.Name, s.now().Unix())
	if err != nil {
		s.internalError(w, r, "ссылка портала не выпущена", err)
		return
	}
	after := "выпущена"
	before := "не было"
	if had {
		before, after = "была", "перевыпущена"
	}
	s.Log.Info("действие", "user", s.user(r), "op", "portal_link", "client", c.Name, "detail", after)
	s.audit(r, "portal_link", c.Name, before, after)
	s.showOnce(w, r, "Ссылка портала клиента "+c.Name,
		"Ссылка показывается один раз: сохраните её и передайте клиенту. Прежняя ссылка перестала работать."+s.publicURLNote(),
		clientHref(c.Name), "К карточке клиента", []string{s.publicLink(portalPrefix + "c_" + token)})
}

// userPortalLink — «Создать/перевыпустить ссылку портала пользователя».
func (s *Server) userPortalLink(w http.ResponseWriter, r *http.Request) {
	u, ok := s.pathUser(w, r)
	if !ok {
		return
	}
	_, had, _ := s.Store.UserLinkCreated(r.Context(), u.ID)
	token, err := s.Store.CreateUserLink(r.Context(), u.ID, s.now().Unix())
	if err != nil {
		s.internalError(w, r, "ссылка портала не выпущена", err)
		return
	}
	after, before := "выпущена", "не было"
	if had {
		before, after = "была", "перевыпущена"
	}
	s.audit(r, "portal_link", "user:"+u.Login, before, after)
	s.showOnce(w, r, "Ссылка портала пользователя "+u.Login,
		"Ссылка показывается один раз. В портале видны все клиенты пользователя. Прежняя ссылка перестала работать."+s.publicURLNote(),
		userHref(u), "К пользователю", []string{s.publicLink(portalPrefix + "u_" + token)})
}

// clientDownloadLink — «Одноразовая ссылка на профиль» (администратор).
func (s *Server) clientDownloadLink(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.Store == nil {
		s.card(w, r, c, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	parts := strings.Split(r.PostForm.Get("profile"), "/")
	if len(parts) != 3 {
		s.card(w, r, c, http.StatusBadRequest, "выберите профиль")
		return
	}
	for i := range parts {
		v, err := url.PathUnescape(parts[i])
		if err != nil {
			s.card(w, r, c, http.StatusBadRequest, "выберите профиль")
			return
		}
		parts[i] = v
	}
	want := nodeapi.Profile{Kind: parts[0], Variant: parts[1], File: parts[2]}
	ps, err := s.Node.Profiles(r.Context(), c.Name)
	if err != nil {
		st, tx := s.nodeErr(err)
		s.card(w, r, c, st, tx)
		return
	}
	found := false
	for _, p := range ps {
		found = found || p == want
	}
	if !found {
		s.card(w, r, c, http.StatusBadRequest, "такого профиля у клиента нет")
		return
	}
	pin := strings.TrimSpace(r.PostForm.Get("pin"))
	if pin != "" && !pinRe.MatchString(pin) {
		s.card(w, r, c, http.StatusBadRequest, "PIN: от 4 до 8 цифр или пусто")
		return
	}
	now := s.now()
	token, err := s.Store.CreateDownloadLink(r.Context(), store.DownloadParams{Node: s.NodeID, Client: c.Name,
		PKind: want.Kind, Variant: want.Variant, File: want.File, PIN: pin, Expires: now.Add(downloadTTL).Unix(), Now: now.Unix()})
	if err != nil {
		s.internalError(w, r, "одноразовая ссылка не выпущена", err)
		return
	}
	detail := want.Kind + "/" + want.Variant + "/" + want.File
	if pin != "" {
		detail += "; с PIN"
	}
	s.Log.Info("действие", "user", s.user(r), "op", "download_link", "client", c.Name, "detail", detail)
	s.audit(r, "download_link", c.Name, "", detail)
	note := "Ссылка показывается один раз и живёт 24 часа или до первого скачивания."
	if pin != "" {
		note += " PIN нужно передать отдельно."
	}
	s.showOnce(w, r, "Одноразовая ссылка на профиль "+c.Name, note+s.publicURLNote(),
		clientHref(c.Name), "К карточке клиента", []string{s.publicLink(dlPrefix + token)})
}
