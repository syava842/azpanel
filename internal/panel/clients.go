package panel

import (
	"context"
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
	Value               string // kind/variant/file для формы одноразовой ссылки
}

func clientHref(name string) string { return "/clients/" + url.PathEscape(name) }

func certText(t *time.Time) (text string, soon bool) {
	if t == nil {
		return "—", false
	}
	days := int(time.Until(*t).Hours() / 24)
	if time.Until(*t) < 0 {
		return t.UTC().Format("2006-01-02") + " UTC (истёк)", true
	}
	return fmt.Sprintf("%s UTC (осталось %d дн.)", t.UTC().Format("2006-01-02"), days), days < certWarnDays
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
	list, err := s.nodeFor(r).Clients(r.Context())
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return nodeapi.Client{}, false
	}
	for _, c := range list {
		if c.Name == name && s.visibleClient(r, name) {
			return c, true
		}
	}
	// чужой клиент отвечает так же, как несуществующий
	s.errorPage(w, r, http.StatusNotFound, "клиент не найден")
	return nodeapi.Client{}, false
}

func (s *Server) clientsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.nodeFor(r).Clients(r.Context())
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	online := map[string]int{}
	sessErr := ""
	if ss, err := s.nodeFor(r).Sessions(r.Context()); err != nil {
		_, sessErr = s.nodeErr(err)
		sessErr = "сессии недоступны: " + sessErr
	} else {
		for _, x := range ss {
			online[x.Name]++
		}
	}
	var cards map[string]store.Card
	var limits map[string]store.ClientLimit
	var traffic map[string]store.Bytes
	if s.Store != nil {
		var cerr, lerr, terr error
		cards, cerr = s.Store.Cards(r.Context(), s.nodeIDFor(r))
		limits, lerr = s.Store.ClientLimits(r.Context(), s.nodeIDFor(r))
		traffic, terr = s.traffic30(r.Context(), s.now())
		if cerr != nil || lerr != nil || terr != nil {
			s.Log.Warn("история клиентов не прочитана", "cards", cerr, "limits", lerr, "traffic", terr)
			cards, limits, traffic = nil, nil, nil
		}
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	var owned map[string]bool // для пользователя — только его клиенты
	if sess, _ := session(r); !sess.IsAdmin() {
		var err error
		if s.Store == nil {
			owned = map[string]bool{}
		} else if owned, err = s.ownedNames(r, sess.UserID); err != nil {
			s.internalError(w, r, "клиенты пользователя не прочитаны", err)
			return
		}
	}
	rows := []clientRow{}
	for _, c := range list {
		if owned != nil && !owned[c.Name] {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
			continue
		}
		row := clientRow{Name: c.Name, Href: clientHref(c.Name), OpenVPN: c.OpenVPN, WG: c.WireGuard,
			Online: online[c.Name], Limit: "—", Blocked: c.Blocked}
		row.Cert, row.CertSoon = certText(c.CertExpires)
		if c.Limit > 0 {
			row.Limit = strconv.Itoa(c.Limit)
		}
		row.Traffic, row.Until = "—", "—"
		if card, ok := cards[c.Name]; ok {
			// действующий срок: меньший из срока карточки и срока владельца
			eff := card.AccessUntil
			if l, ok := limits[c.Name]; ok {
				eff = l.Effective()
			}
			row.Until = untilText(eff)
			if eff != nil {
				row.untilTS = *eff
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
	data := map[string]any{"Rows": rows, "Q": r.URL.Query().Get("q"), "NoOnline": sessErr != "",
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
	existed, known := s.clientExists(r.Context(), name)
	if _, err := s.nodeFor(r).CreateClient(r.Context(), nodeapi.CreateClient{Name: name, Kind: kind, Days: days}); err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "create", "client", name, "err", err)
		st, tx := s.nodeErr(err)
		fail(st, tx)
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "create", "client", name, "detail", kind)
	s.audit(r, "create", name, "", kind)
	if known && !existed {
		s.dropStaleHistory(r.Context(), name)
	}
	s.redirectMsg(w, r, clientHref(name), "created")
}

// clientExists: есть ли клиент с таким именем у агента; второе значение —
// удалось ли узнать (нет — историю не трогаем).
func (s *Server) clientExists(ctx context.Context, name string) (exists, known bool) {
	if s.Store == nil {
		return false, false
	}
	list, err := s.nodeCtx(ctx).Clients(ctx)
	if err != nil {
		return false, false
	}
	for _, c := range list {
		if c.Name == name {
			return true, true
		}
	}
	return false, true
}

// dropStaleHistory: нового клиента с именем, которого у агента не было,
// карточка и трафик прежнего владельца имени (удалённого мимо панели) не
// должны блокировать и считаться в лимит.
func (s *Server) dropStaleHistory(ctx context.Context, name string) {
	if err := s.Store.DeleteCard(ctx, s.nodeIDCtx(ctx), name); err != nil {
		s.Log.Warn("старая карточка не удалена", "client", name, "err", err)
	}
	if err := s.Store.DeleteTraffic(ctx, s.nodeIDCtx(ctx), name); err != nil {
		s.Log.Warn("старый трафик не удалён", "client", name, "err", err)
	}
	if err := s.Store.DeleteClientLink(ctx, s.nodeIDCtx(ctx), name); err != nil {
		s.Log.Warn("старая ссылка портала не удалена", "client", name, "err", err)
	}
	if err := s.Store.DeleteDownloadLinks(ctx, s.nodeIDCtx(ctx), name); err != nil {
		s.Log.Warn("старые одноразовые ссылки не удалены", "client", name, "err", err)
	}
	if err := s.Store.DeleteClientKinds(ctx, s.nodeIDCtx(ctx), name); err != nil {
		s.Log.Warn("старое ограничение профилей бота не удалено", "client", name, "err", err)
	}
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

	"password_changed": "пароль изменён, остальные сессии завершены",
	"2fa_off":          "двухфакторная проверка выключена",
	"session_revoked":  "сессия отозвана",
	"user_created":     "пользователь создан",
	"user_deleted":     "пользователь удалён",
	"user_disabled":    "пользователь отключён, его сессии завершены",
	"user_enabled":     "пользователь включён",
	"role_set":         "роль изменена",
	"2fa_reset":        "2FA сброшена, сессии завершены",
	"owner_set":        "владелец назначен",
	"owner_cleared":    "владелец снят",

	"tg_unlinked": "Telegram отвязан",
	"kinds_saved": "типы профилей для бота сохранены",
	"tg_saved":    "настройки Telegram сохранены",

	"access_extended":   "доступ продлён на %d дн.",
	"user_access_saved": "срок доступа пользователя сохранён",
	"code_revoked":      "код отозван",
	"codes_revoked":     "отозвано кодов: %d",

	"proxy_apply_failed": "прокси записан в allow-ips.txt, но применение не запущено: запустите «Применить» на странице «Маршрутизация»",
	"proxy_deleted":      "прокси удалён; строки в allow-ips.txt уже не было",
	"proxy_deleted_kept": "прокси удалён из списка; строка в allow-ips.txt оставлена: её добавили не через панель",

	"routing_changed": "список изменён; изменения вступят в силу после применения",
	"setup_saved":     "настройки сохранены; чтобы они вступили в силу, запустите задачи ниже",
	"setup_nochange":  "ничего не изменилось",

	"update_checked": "проверка выполнена",
	"update_started": "обновление azpanel запущено; панель и агент перезапустятся, итог появится на этой странице",

	"az_started":         "обновление AntiZapret запущено; сервер перезагрузится",
	"az_restore_started": "восстановление из бэкапа запущено; сервер перезагрузится",
	"az_retry_started":   "повторная установка запущена; сервер перезагрузится",
}

// redirectMsg ведёт на страницу с уведомлением по коду; n — число для
// кодов с %d.
func (s *Server) redirectMsg(w http.ResponseWriter, r *http.Request, to, code string, n ...int) {
	q := "?msg=" + url.QueryEscape(code)
	if len(n) > 0 {
		q += "&n=" + strconv.Itoa(n[0])
	}
	s.redirect(w, r, to+q, http.StatusSeeOther)
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
	data := map[string]any{"Client": c, "Name": c.Name, "Href": clientHref(c.Name)}
	sess, _ := session(r)
	data["CanManage"] = sess.IsAdmin()
	if sess.IsAdmin() {
		s.addOwner(r, c, data)
	}
	data["Cert"], data["CertSoon"] = certText(c.CertExpires)
	data["Limit"] = "—"
	if c.Limit > 0 {
		data["Limit"] = strconv.Itoa(c.Limit)
	}
	if errText != "" {
		data["Error"] = errText
	}
	sessions := []sessionRow{}
	if ss, err := s.nodeFor(r).Sessions(r.Context()); err != nil {
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
	if ps, err := s.nodeFor(r).Profiles(r.Context(), c.Name); err != nil {
		_, tx := s.nodeErr(err)
		data["ProfilesErr"] = "профили недоступны: " + tx
	} else {
		for _, p := range ps {
			tail := url.PathEscape(p.Kind) + "/" + url.PathEscape(p.Variant) + "/" + url.PathEscape(p.File)
			row := profileRow{Kind: p.Kind, Variant: p.Variant, File: p.File, Href: clientHref(c.Name) + "/profiles/" + tail, Value: tail}
			if p.Kind == nodeapi.KindWireGuard {
				row.QRHref = clientHref(c.Name) + "/qr/" + tail
			}
			profiles = append(profiles, row)
		}
	}
	data["Profiles"] = profiles
	s.addHistory(r, c, data)
	if sess.IsAdmin() {
		s.addPortalInfo(r, c, data)
		s.addKinds(r, c, data)
	}
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
	data, err := s.nodeFor(r).Profile(r.Context(), c.Name, nodeapi.Profile{Kind: r.PathValue("kind"), Variant: r.PathValue("variant"), File: r.PathValue("file")})
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	data = s.fixProfile(r.Context(), s.nodeIDFor(r), r.PathValue("kind"), r.PathValue("file"), data)
	writeProfile(w, r.PathValue("file"), data)
}

// writeProfile отдаёт файл профиля вложением.
func writeProfile(w http.ResponseWriter, file string, data []byte) {
	cd := mime.FormatMediaType("attachment", map[string]string{"filename": file})
	if cd == "" {
		cd = "attachment"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", cd)
	w.Write(data)
}

// profileQRPNG рисует QR профиля WireGuard; false — профиль не помещается.
func profileQRPNG(data []byte) ([]byte, bool) {
	if len(data) > maxQRProfile {
		return nil, false
	}
	png, err := qrcode.Encode(string(data), qrcode.Medium, qrSize)
	return png, err == nil
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
	data, err := s.nodeFor(r).Profile(r.Context(), c.Name, nodeapi.Profile{Kind: nodeapi.KindWireGuard, Variant: r.PathValue("variant"), File: r.PathValue("file")})
	if err != nil {
		st, tx := s.nodeErr(err)
		s.errorPage(w, r, st, tx)
		return
	}
	png, ok := profileQRPNG(data)
	if !ok {
		s.errorPage(w, r, http.StatusUnprocessableEntity, "профиль слишком велик для QR")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// done пишет успешное действие в журнал и возвращает на карточку.
func (s *Server) done(w http.ResponseWriter, r *http.Request, c nodeapi.Client, op, before, detail, code string, n ...int) {
	s.Log.Info("действие", "user", s.user(r), "op", op, "client", c.Name, "detail", detail)
	s.audit(r, op, c.Name, before, detail)
	s.redirectMsg(w, r, clientHref(c.Name), code, n...)
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
	if _, err := s.nodeFor(r).Renew(r.Context(), c.Name, days); err != nil {
		s.failed(w, r, c, "renew", err)
		return
	}
	// файл профиля OpenVPN после перевыпуска другой: прежние одноразовые ссылки гасим
	if s.Store != nil && c.OpenVPN {
		if err := s.Store.DeleteDownloadLinks(r.Context(), s.nodeIDFor(r), c.Name); err != nil {
			s.Log.Warn("одноразовые ссылки клиента не удалены", "client", c.Name, "err", err)
		}
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
	if err := s.nodeFor(r).SetLimit(r.Context(), c.Name, limit); err != nil {
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
	res, err := s.nodeFor(r).SetBlocked(r.Context(), c.Name, blocked)
	if err != nil {
		s.failed(w, r, c, map[bool]string{true: "block", false: "unblock"}[blocked], err)
		return
	}
	if blocked {
		// ручной блок поверх автоблока становится ручным: сборщик его не снимет
		s.makeManualBlock(r.Context(), c)
		after := fmt.Sprintf("заблокирован, разорвано сессий: %d", res.Killed)
		s.done(w, r, c, "block", "не заблокирован", after, "blocked", res.Killed)
		return
	}
	s.forgetAutoBlock(r.Context(), c)
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
	if _, err := s.nodeFor(r).DeleteClient(r.Context(), kind, c.Name); err != nil {
		s.failed(w, r, c, "delete", err)
		return
	}
	s.Log.Info("действие", "user", s.user(r), "op", "delete", "client", c.Name, "detail", kind)
	s.audit(r, "delete", c.Name, kind, "удалён")
	s.dropDeletedRecords(r.Context(), c, kind)
	s.redirectMsg(w, r, "/", "deleted")
}

// dropDeletedRecords: карточка, ссылка портала и одноразовые ссылки уходят вместе с клиентом;
// пока остался другой тип — они нужны.
func (s *Server) dropDeletedRecords(ctx context.Context, c nodeapi.Client, kind string) {
	if s.Store == nil || (kind == nodeapi.KindOpenVPN && c.WireGuard) || (kind == nodeapi.KindWireGuard && c.OpenVPN) {
		return
	}
	if err := s.Store.DeleteCard(ctx, s.nodeIDCtx(ctx), c.Name); err != nil {
		s.Log.Warn("карточка клиента не удалена", "client", c.Name, "err", err)
	}
	// ссылка портала клиента уходит вместе с ним
	if err := s.Store.DeleteClientLink(ctx, s.nodeIDCtx(ctx), c.Name); err != nil {
		s.Log.Warn("ссылка портала клиента не удалена", "client", c.Name, "err", err)
	}
	// одноразовые ссылки ищут профиль по имени: пересозданный клиент отдал бы новые ключи
	if err := s.Store.DeleteDownloadLinks(ctx, s.nodeIDCtx(ctx), c.Name); err != nil {
		s.Log.Warn("одноразовые ссылки клиента не удалены", "client", c.Name, "err", err)
	}
	// ограничение типов профилей для бота относится к имени: новый клиент не должен его унаследовать
	if err := s.Store.DeleteClientKinds(ctx, s.nodeIDCtx(ctx), c.Name); err != nil {
		s.Log.Warn("ограничение профилей бота не снято", "client", c.Name, "err", err)
	}
}

// addOwner кладёт в данные карточки выбор владельца: пользователей и
// текущего владельца.
func (s *Server) addOwner(r *http.Request, c nodeapi.Client, data map[string]any) {
	if s.Store == nil {
		return
	}
	users, err := s.Store.Users(r.Context())
	if err != nil {
		s.Log.Warn("пользователи не прочитаны", "err", err)
		return
	}
	owner, has, err := s.Store.OwnerOf(r.Context(), s.nodeIDFor(r), c.Name)
	if err != nil {
		s.Log.Warn("владелец клиента не прочитан", "client", c.Name, "err", err)
		return
	}
	type option struct {
		ID       int64
		Login    string
		Selected bool
	}
	opts := []option{}
	for _, u := range users {
		opts = append(opts, option{u.ID, u.Login, has && u.ID == owner})
	}
	data["Owners"], data["NoOwner"] = opts, !has
}

// setOwner назначает владельца клиента; пустое значение снимает.
func (s *Server) setOwner(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.Store == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	var uid *int64
	login := "нет"
	if v := strings.TrimSpace(r.PostForm.Get("owner")); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			s.card(w, r, c, http.StatusBadRequest, "владелец: неверный пользователь")
			return
		}
		u, err := s.Store.UserByID(r.Context(), id)
		if err != nil {
			s.card(w, r, c, http.StatusBadRequest, "владелец: такого пользователя нет")
			return
		}
		uid, login = &u.ID, u.Login
	}
	before := "нет"
	if old, has, err := s.Store.OwnerOf(r.Context(), s.nodeIDFor(r), c.Name); err == nil && has {
		if u, err := s.Store.UserByID(r.Context(), old); err == nil {
			before = u.Login
		}
	}
	if err := s.Store.SetOwner(r.Context(), s.nodeIDFor(r), c.Name, uid); err != nil {
		s.internalError(w, r, "владелец не сохранён", err)
		return
	}
	code := "owner_cleared"
	if uid != nil {
		code = "owner_set"
	}
	s.done(w, r, c, "owner", before, login, code)
}
