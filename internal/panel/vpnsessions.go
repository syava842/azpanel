package panel

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

// Вкладка «Сеансы» раздела: кто подключён сейчас — как в StatusOpenVPN:
// реальный адрес, адрес в VPN, трафик и скорость, с какого времени и
// сколько, протокол и порт.

// vpnSessRow — строка таблицы сеансов.
type vpnSessRow struct {
	Name, Href string
	Addr       string // реальный IP:порт
	VPNAddr    string
	City, ISP  string
	Flapping   bool // у WG-клиента адрес меняется часто

	Down, Up         string // клиент получил / отправил
	DownRate, UpRate string // скорость, пусто — ещё не известна
	Since            string // ISO-время начала (для браузера); пусто — неизвестно
	SinceText        string // то же для таблицы без скриптов, UTC
	Duration         string
	Handshake        string // WireGuard: последнее рукопожатие, «N с назад»
	Proto            string // «UDP :50443»
	Route            string // AntiZapret или VPN (весь трафик)

	down, up int64
	since    time.Time
	addrKey  string
}

// sessSortKeys — столбцы, по которым сортируется таблица.
var sessSortKeys = []struct{ Key, Title string }{
	{"name", "Клиент"}, {"addr", "Реальный IP"}, {"vpn", "IP в VPN"},
	{"down", "Получено"}, {"up", "Отправлено"}, {"since", "Подключён"},
	{"dur", "Длительность"}, {"proto", "Протокол"},
}

// sortHead — заголовок столбца: ссылка, повторный щелчок меняет порядок.
type sortHead struct {
	Key, Title, Href string
	Current, Desc    bool
}

func sortHeads(base string, keys []struct{ Key, Title string }, key string, desc bool, extra string) []sortHead {
	out := make([]sortHead, 0, len(keys))
	for _, k := range keys {
		h := sortHead{Key: k.Key, Title: k.Title, Current: k.Key == key, Desc: desc}
		order := "asc"
		if h.Current && !desc {
			order = "desc"
		}
		h.Href = base + "?sort=" + url.QueryEscape(k.Key) + "&order=" + order + extra
		out = append(out, h)
	}
	return out
}

// routeOf — что идёт через экземпляр: antizapret-* и интерфейс antizapret —
// только заблокированное, vpn-* — весь трафик.
func routeOf(instance string) string {
	if strings.HasPrefix(instance, "vpn") {
		return "VPN"
	}
	return "AntiZapret"
}

func rateText(r int64, ok bool) string {
	if !ok {
		return ""
	}
	return humanBytes(uint64(max(r, 0))) + "/с"
}

// durationText — «1 д 5 ч 3 мин», «12 мин», «40 с».
func durationText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d / (24 * time.Hour))
	h := int(d/time.Hour) % 24
	m := int(d/time.Minute) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d д %d ч %d мин", days, h, m)
	case h > 0:
		return fmt.Sprintf("%d ч %d мин", h, m)
	case m > 0:
		return fmt.Sprintf("%d мин", m)
	}
	return fmt.Sprintf("%d с", int(d/time.Second))
}

// newVPNSessRow собирает строку; start — начало сеанса WireGuard из истории
// подключений (у WG своего «подключён с» нет), нулевое — неизвестно.
func newVPNSessRow(x nodeapi.Session, now, start time.Time) vpnSessRow {
	r := vpnSessRow{Name: x.Name, Href: clientHref(x.Name), Addr: x.Addr, VPNAddr: x.VPNAddr,
		Down: humanBytes(uint64(max(x.TxBytes, 0))), Up: humanBytes(uint64(max(x.RxBytes, 0))),
		DownRate: rateText(x.TxRate, x.RateOK), UpRate: rateText(x.RxRate, x.RateOK),
		Route: routeOf(x.Instance), down: x.TxBytes, up: x.RxBytes, addrKey: addrSortKey(x.Addr)}
	if x.Proto != "" {
		r.Proto = strings.ToUpper(x.Proto)
		if x.Port > 0 {
			r.Proto += fmt.Sprintf(" :%d", x.Port)
		}
	}
	since := start
	if x.Since != nil {
		since = *x.Since
	}
	if !since.IsZero() {
		r.since = since
		r.Since = since.UTC().Format(time.RFC3339)
		r.SinceText = formatTime(&since)
		r.Duration = durationText(now.Sub(since))
	}
	if x.LastHandshake != nil {
		r.Handshake = durationText(now.Sub(*x.LastHandshake)) + " назад"
	}
	return r
}

// addrSortKey — адрес для сортировки: IPv4 по числам, а не по строке.
func addrSortKey(a string) string {
	host := a
	if i := strings.LastIndexByte(a, ':'); i > 0 && !strings.HasSuffix(a, "]") {
		host = a[:i]
	}
	parts := strings.Split(strings.Trim(host, "[]"), ".")
	if len(parts) != 4 {
		return host
	}
	var b strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&b, "%3s.", p)
	}
	return b.String()
}

// sortSessRows: по умолчанию по имени; равные — по имени по возрастанию.
func sortSessRows(rows []vpnSessRow, key string, desc bool) {
	cmp := func(a, b vpnSessRow) int {
		switch key {
		case "addr":
			return strings.Compare(a.addrKey, b.addrKey)
		case "vpn":
			return strings.Compare(addrSortKey(a.VPNAddr+":0"), addrSortKey(b.VPNAddr+":0"))
		case "down":
			return cmpInt(a.down, b.down)
		case "up":
			return cmpInt(a.up, b.up)
		case "since":
			return cmpInt(a.since.Unix(), b.since.Unix())
		case "dur":
			return cmpInt(b.since.Unix(), a.since.Unix())
		case "proto":
			return strings.Compare(a.Proto+a.Route, b.Proto+b.Route)
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	}
	sort.SliceStable(rows, func(i, j int) bool {
		c := cmp(rows[i], rows[j])
		if desc {
			c = -c
		}
		if c == 0 {
			return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
		}
		return c < 0
	})
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// sortParams — sort и order из запроса; неизвестный столбец — по имени.
func sortParams(q url.Values, keys []struct{ Key, Title string }, def string, defDesc bool) (string, bool) {
	key := q.Get("sort")
	ok := false
	for _, k := range keys {
		if k.Key == key {
			ok = true
		}
	}
	if !ok {
		return def, defDesc
	}
	return key, q.Get("order") == "desc"
}

// histRow — строка вкладки «История».
type histRow struct {
	Name, Href       string
	Addr, VPNAddr    string
	Start, StartText string
	End, EndText     string // пусто — сеанс идёт
	Duration         string
	Proto, Route     string
	Down, Up         string
}

// pageLink — ссылка постраничного перехода; Num 0 — разрыв «…».
type pageLink struct {
	Num     int
	Href    string
	Current bool
}

const histPageSize = 50

// pageLinks — первая, последняя и соседние с текущей страницы.
func pageLinks(base string, q string, page, pages int) []pageLink {
	if pages <= 1 {
		return nil
	}
	var out []pageLink
	gap := false
	for p := 1; p <= pages; p++ {
		if p == 1 || p == pages || (p >= page-2 && p <= page+2) {
			h := base + "?page=" + fmt.Sprint(p)
			if q != "" {
				h += "&q=" + url.QueryEscape(q)
			}
			out = append(out, pageLink{Num: p, Href: h, Current: p == page})
			gap = false
		} else if !gap {
			out = append(out, pageLink{})
			gap = true
		}
	}
	return out
}

// vpnHistory — вкладка «История»: подключения раздела по убыванию времени,
// фильтр по имени, адресу или протоколу, по 50 на страницу. Ведёт её
// сборщик панели раз в collect_seconds; хранится history_days.
func (s *Server) vpnHistory(sec vpnSection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := sec.tab("history")
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		data := map[string]any{"VPN": v, "Q": q, "Base": sec.Base + "/history"}
		if s.Store == nil {
			data["HistErr"] = "история не ведётся: у панели нет базы"
			s.render(w, r, http.StatusOK, "vpn", data)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		list, total, err := s.Store.ConnLog(r.Context(), s.nodeIDFor(r), store.ConnLogQuery{Kind: sec.Kind, Q: q,
			Limit: histPageSize, Offset: (page - 1) * histPageSize})
		if err != nil {
			s.internalError(w, r, "история подключений не прочитана", err)
			return
		}
		now := s.now()
		rows := make([]histRow, 0, len(list))
		for _, e := range list {
			h := histRow{Name: e.Name, Href: clientHref(e.Name), Addr: e.RealAddr, VPNAddr: e.VPNAddr, Route: routeOf(e.Instance),
				Down: humanBytes(uint64(max(e.Tx, 0))), Up: humanBytes(uint64(max(e.Rx, 0)))}
			if e.Proto != "" {
				h.Proto = strings.ToUpper(e.Proto)
				if e.Port > 0 {
					h.Proto += fmt.Sprintf(" :%d", e.Port)
				}
			}
			start := time.Unix(e.Start, 0)
			h.Start, h.StartText = start.UTC().Format(time.RFC3339), formatTime(&start)
			end := now
			if e.Ended > 0 {
				end = time.Unix(e.Ended, 0)
				h.End, h.EndText = end.UTC().Format(time.RFC3339), formatTime(&end)
			}
			h.Duration = durationText(end.Sub(start))
			rows = append(rows, h)
		}
		pages := (total + histPageSize - 1) / histPageSize
		data["Rows"], data["Total"] = rows, total
		data["Pages"] = pageLinks(sec.Base+"/history", q, page, pages)
		s.render(w, r, http.StatusOK, "vpn", data)
	}
}
