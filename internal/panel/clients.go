package panel

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	maxQRProfile = 2900 // байт; больше в QR не помещается
	qrSize       = 512
	certWarnDays = 30
	notOnlyOVPN  = "блокировка действует только на OpenVPN"
)

// clientRow — строка списка клиентов, всё уже превращено в текст.
type clientRow struct {
	Name     string
	Href     string
	OpenVPN  bool
	WG       bool
	Cert     string
	CertSoon bool
	Online   int
	Limit    string
	Blocked  bool
	WGOnly   bool // заблокирован, но блокировка к нему не применима
	Auto     bool // блокировку поставила панель
	Traffic  string
	Until    string

	trafficBytes int64 // для сортировки
	untilTS      int64 // 0 — без срока
}

type sessionRow struct {
	Kind, Instance, Addr string
	Down, Up             string
	Time                 string // с какого времени (OpenVPN) или последнее рукопожатие (WireGuard)
}

type profileRow struct {
	Kind, Variant, File string
	Href, QRHref        string
}

func clientHref(name string) string { return "/clients/" + url.PathEscape(name) }

func certText(t *time.Time) (text string, soon bool) {
	if t == nil {
		return "—", false
	}
	days := int(time.Until(*t).Hours() / 24)
	if time.Until(*t) < 0 {
		return t.Local().Format("2006-01-02") + " (истёк)", true
	}
	return fmt.Sprintf("%s (осталось %d дн.)", t.Local().Format("2006-01-02"), days), days < certWarnDays
}

func newSessionRow(x nodeapi.Session) sessionRow {
	when := x.Since
	if x.Kind == nodeapi.KindWireGuard {
		when = x.LastHandshake
	}
	// ↓ — сколько клиент получил (сервер отправил), ↑ — сколько отдал.
	return sessionRow{Kind: x.Kind, Instance: x.Instance, Addr: x.Addr,
		Down: humanBytes(uint64(max(x.TxBytes, 0))), Up: humanBytes(uint64(max(x.RxBytes, 0))), Time: formatTime(when)}
}

// lookup находит клиента из пути среди клиентов агента; нет — 404 и false.
func (s *Server) lookup(w http.ResponseWriter, r *http.Request) (nodeapi.Client, bool) {
	name := r.PathValue("name")
	list, err := s.Node.Clients(r.Context())
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return nodeapi.Client{}, false
	}
	for _, c := range list {
		if c.Name == name {
			return c, true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "клиент не найден")
	return nodeapi.Client{}, false
}

func (s *Server) clientsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Node.Clients(r.Context())
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	online := map[string]int{}
	sessErr := ""
	if ss, err := s.Node.Sessions(r.Context()); err != nil {
		_, sessErr = s.nodeErr(err)
		sessErr = "сессии недоступны: " + sessErr
	} else {
		for _, x := range ss {
			online[x.Name]++
		}
	}
	var cards map[string]store.Card
	var traffic map[string]store.Bytes
	if s.Store != nil {
		var cerr, terr error
		cards, cerr = s.Store.Cards(r.Context(), s.NodeID)
		traffic, terr = s.traffic30(r.Context(), s.now())
		if cerr != nil || terr != nil {
			s.Log.Warn("история клиентов не прочитана", "cards", cerr, "traffic", terr)
			cards, traffic = nil, nil
		}
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	rows := []clientRow{}
	for _, c := range list {
		if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
			continue
		}
		row := clientRow{Name: c.Name, Href: clientHref(c.Name), OpenVPN: c.OpenVPN, WG: c.WireGuard,
			Online: online[c.Name], Limit: "—", Blocked: c.Blocked, WGOnly: c.Blocked && !c.OpenVPN}
		row.Cert, row.CertSoon = certText(c.CertExpires)
		if c.Limit > 0 {
			row.Limit = strconv.Itoa(c.Limit)
		}
		row.Traffic, row.Until = "—", "—"
		if card, ok := cards[c.Name]; ok {
			row.Until = untilText(card.AccessUntil)
			if card.AccessUntil != nil {
				row.untilTS = *card.AccessUntil
			}
			row.Auto = c.Blocked && card.AutoBlock != ""
		}
		if traffic != nil {
			b := traffic[c.Name]
			row.trafficBytes = b.Rx + b.Tx
			row.Traffic = humanBytes(uint64(max(row.trafficBytes, 0)))
		}
		rows = append(rows, row)
	}
	sortKey := r.URL.Query().Get("sort")
	sortRows(rows, sortKey)
	data := map[string]any{"Rows": rows, "Q": r.URL.Query().Get("q"), "NoOnline": sessErr != "", "NotOnlyOVPN": notOnlyOVPN,
		"Sort": sortKey, "HasStore": s.Store != nil}
	if sessErr != "" {
		data["Error"] = sessErr
	}
	s.render(w, r, http.StatusOK, "clients", data)
}

// sortRows: name (по умолчанию), traffic — по убыванию, until — ближайший
// срок первым, клиенты без срока в конце, online — по убыванию. Равные —
// по имени.
func sortRows(rows []clientRow, key string) {
	byName := func(a, b clientRow) bool { return strings.ToLower(a.Name) < strings.ToLower(b.Name) }
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case "traffic":
			if a.trafficBytes != b.trafficBytes {
				return a.trafficBytes > b.trafficBytes
			}
		case "until":
			if (a.untilTS == 0) != (b.untilTS == 0) {
				return a.untilTS != 0
			}
			if a.untilTS != b.untilTS {
				return a.untilTS < b.untilTS
			}
		case "online":
			if a.Online != b.Online {
				return a.Online > b.Online
			}
		}
		return byName(a, b)
	})
}

func (s *Server) newForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "new", map[string]any{"Kind": nodeapi.KindOpenVPN})
}

func validKind(k string) bool { return k == nodeapi.KindOpenVPN || k == nodeapi.KindWireGuard }

// atoiRange разбирает целое поле формы; вне диапазона — ошибка с причиной.
func atoiRange(label, v string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s: нужно целое число от %d до %d", label, lo, hi)
	}
	return n, nil
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	kind := r.PostForm.Get("kind")
	daysText := strings.TrimSpace(r.PostForm.Get("days"))
	fail := func(status int, text string) {
		s.render(w, r, status, "new", map[string]any{"Error": text, "Name": name, "Kind": kind, "Days": daysText})
	}
	if name == "" {
		fail(http.StatusBadRequest, "имя клиента не задано")
		return
	}
	if !validKind(kind) {
		fail(http.StatusBadRequest, "тип: openvpn или wireguard")
		return
	}
	days := 0
	if kind == nodeapi.KindOpenVPN && daysText != "" {
		var err error
		if days, err = atoiRange("срок", daysText, 1, 3650); err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
	}
	if _, err := s.Node.CreateClient(r.Context(), nodeapi.CreateClient{Name: name, Kind: kind, Days: days}); err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "create", "client", name, "err", err)
		st, tx := s.nodeErr(err)
		fail(st, tx)
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "create", "client", name, "detail", kind)
	s.audit(r, "create", name, "", kind)
	redirectMsg(w, r, clientHref(name), "created")
}

func (s *Server) user(r *http.Request) string {
	sess, _ := session(r)
	return sess.User
}

// msgTexts — тексты уведомлений по кодам из ?msg=. Текст берётся только
// отсюда: произвольная строка из адреса на странице не показывается.
// %d подставляется из числового параметра n.
var msgTexts = map[string]string{
	"created":    "создан",
	"deleted":    "удалён",
	"renewed":    "продлён на %d дн.",
	"limit_set":  "лимит: %d",
	"limit_off":  "лимит снят",
	"blocked":    "заблокирован, разорвано сессий: %d",
	"unblocked":  "разблокирован",
	"card_saved": "карточка сохранена",
}

// redirectMsg ведёт на страницу с уведомлением по коду; n — число для
// кодов с %d.
func redirectMsg(w http.ResponseWriter, r *http.Request, to, code string, n ...int) {
	q := "?msg=" + url.QueryEscape(code)
	if len(n) > 0 {
		q += "&n=" + strconv.Itoa(n[0])
	}
	http.Redirect(w, r, to+q, http.StatusSeeOther)
}

// flashText: текст уведомления по ?msg= и ?n=; неизвестный код или
// неразобранное число — пустая строка, ничего не показывается.
func flashText(r *http.Request) string {
	text, ok := msgTexts[r.URL.Query().Get("msg")]
	if !ok {
		return ""
	}
	if !strings.Contains(text, "%d") {
		return text
	}
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	if err != nil || n < 0 || n > 1_000_000 {
		return ""
	}
	return fmt.Sprintf(text, n)
}

// card показывает карточку клиента; сбой сессий или профилей карточку не
// роняет, а выводится на ней текстом. errText — ошибка действия, если была.
func (s *Server) card(w http.ResponseWriter, r *http.Request, c nodeapi.Client, status int, errText string) {
	data := map[string]any{"Client": c, "Name": c.Name, "Href": clientHref(c.Name), "NotOnlyOVPN": notOnlyOVPN,
		"WGOnlyBlock": c.Blocked && !c.OpenVPN}
	data["Cert"], data["CertSoon"] = certText(c.CertExpires)
	data["Limit"] = "—"
	if c.Limit > 0 {
		data["Limit"] = strconv.Itoa(c.Limit)
	}
	if errText != "" {
		data["Error"] = errText
	}
	sessions := []sessionRow{}
	if ss, err := s.Node.Sessions(r.Context()); err != nil {
		_, tx := s.nodeErr(err)
		data["SessionsErr"] = "сессии недоступны: " + tx
	} else {
		for _, x := range ss {
			if x.Name == c.Name {
				sessions = append(sessions, newSessionRow(x))
			}
		}
	}
	data["Sessions"] = sessions
	profiles := []profileRow{}
	if ps, err := s.Node.Profiles(r.Context(), c.Name); err != nil {
		_, tx := s.nodeErr(err)
		data["ProfilesErr"] = "профили недоступны: " + tx
	} else {
		for _, p := range ps {
			tail := url.PathEscape(p.Kind) + "/" + url.PathEscape(p.Variant) + "/" + url.PathEscape(p.File)
			row := profileRow{Kind: p.Kind, Variant: p.Variant, File: p.File, Href: clientHref(c.Name) + "/profiles/" + tail}
			if p.Kind == nodeapi.KindWireGuard {
				row.QRHref = clientHref(c.Name) + "/qr/" + tail
			}
			profiles = append(profiles, row)
		}
	}
	data["Profiles"] = profiles
	s.addHistory(r, c, data)
	s.render(w, r, status, "client", data)
}

func (s *Server) clientCard(w http.ResponseWriter, r *http.Request) {
	if c, ok := s.lookup(w, r); ok {
		s.card(w, r, c, http.StatusOK, "")
	}
}

func (s *Server) profileFile(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	data, err := s.Node.Profile(r.Context(), c.Name, nodeapi.Profile{Kind: r.PathValue("kind"), Variant: r.PathValue("variant"), File: r.PathValue("file")})
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	cd := mime.FormatMediaType("attachment", map[string]string{"filename": r.PathValue("file")})
	if cd == "" {
		cd = "attachment"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", cd)
	w.Write(data)
}

func (s *Server) profileQR(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("kind") != nodeapi.KindWireGuard {
		s.errorPage(w, r, http.StatusNotFound, "QR есть только у профилей WireGuard")
		return
	}
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	data, err := s.Node.Profile(r.Context(), c.Name, nodeapi.Profile{Kind: nodeapi.KindWireGuard, Variant: r.PathValue("variant"), File: r.PathValue("file")})
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	tooBig := "профиль слишком велик для QR"
	if len(data) > maxQRProfile {
		s.errorPage(w, r, http.StatusUnprocessableEntity, tooBig)
		return
	}
	png, err := qrcode.Encode(string(data), qrcode.Medium, qrSize)
	if err != nil {
		s.errorPage(w, r, http.StatusUnprocessableEntity, tooBig)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// done пишет успешное действие в журнал и возвращает на карточку.
func (s *Server) done(w http.ResponseWriter, r *http.Request, c nodeapi.Client, op, before, detail, code string, n ...int) {
	s.Log.Info("действие", "user", s.user(r), "op", op, "client", c.Name, "detail", detail)
	s.audit(r, op, c.Name, before, detail)
	redirectMsg(w, r, clientHref(c.Name), code, n...)
}

// failed — ошибка агента: в журнал и на карточку с текстом агента.
func (s *Server) failed(w http.ResponseWriter, r *http.Request, c nodeapi.Client, op string, err error) {
	s.Log.Warn("действие", "user", s.user(r), "op", op, "client", c.Name, "err", err)
	st, tx := s.nodeErr(err)
	s.card(w, r, c, st, tx)
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	days, err := atoiRange("срок", r.PostForm.Get("days"), 1, 3650)
	if err != nil {
		s.card(w, r, c, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Node.Renew(r.Context(), c.Name, days); err != nil {
		s.failed(w, r, c, "renew", err)
		return
	}
	before, _ := certText(c.CertExpires)
	s.done(w, r, c, "renew", before, fmt.Sprintf("продлён на %d дн.", days), "renewed", days)
}

func (s *Server) setLimit(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	limit, err := atoiRange("лимит", r.PostForm.Get("limit"), 0, 1000)
	if err != nil {
		s.card(w, r, c, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Node.SetLimit(r.Context(), c.Name, limit); err != nil {
		s.failed(w, r, c, "limit", err)
		return
	}
	before := "—"
	if c.Limit > 0 {
		before = strconv.Itoa(c.Limit)
	}
	if limit == 0 {
		s.done(w, r, c, "limit", before, "—", "limit_off")
		return
	}
	s.done(w, r, c, "limit", before, strconv.Itoa(limit), "limit_set", limit)
}

func (s *Server) block(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	var blocked bool
	switch r.PostForm.Get("blocked") {
	case "1":
		blocked = true
	case "0":
	default:
		s.card(w, r, c, http.StatusBadRequest, "поле blocked: 1 или 0")
		return
	}
	res, err := s.Node.SetBlocked(r.Context(), c.Name, blocked)
	if err != nil {
		s.failed(w, r, c, map[bool]string{true: "block", false: "unblock"}[blocked], err)
		return
	}
	if blocked {
		s.done(w, r, c, "block", "не заблокирован", fmt.Sprintf("заблокирован, разорвано сессий: %d", res.Killed), "blocked", res.Killed)
		return
	}
	s.forgetAutoBlock(r, c)
	s.done(w, r, c, "unblock", "заблокирован", "не заблокирован", "unblocked")
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	kind := r.PostForm.Get("kind")
	if !validKind(kind) {
		s.card(w, r, c, http.StatusBadRequest, "тип: openvpn или wireguard")
		return
	}
	if r.PostForm.Get("confirm") != c.Name {
		s.card(w, r, c, http.StatusBadRequest, "для удаления впишите имя клиента")
		return
	}
	if _, err := s.Node.DeleteClient(r.Context(), kind, c.Name); err != nil {
		s.failed(w, r, c, "delete", err)
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "delete", "client", c.Name, "detail", kind)
	s.audit(r, "delete", c.Name, kind, "удалён")
	// карточка уходит вместе с клиентом; пока остался другой тип — она нужна
	if s.Store != nil && !(kind == nodeapi.KindOpenVPN && c.WireGuard) && !(kind == nodeapi.KindWireGuard && c.OpenVPN) {
		if err := s.Store.DeleteCard(r.Context(), s.NodeID, c.Name); err != nil {
			s.Log.Warn("карточка клиента не удалена", "client", c.Name, "err", err)
		}
	}
	redirectMsg(w, r, "/", "deleted")
}
