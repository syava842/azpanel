package panel

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	// allowIPsFile — список адресов, которые AntiZapret пускает мимо блокировок:
	// в него дописывается адрес российского VPS-прокси.
	allowIPsFile = "allow-ips.txt"
	// proxyInstaller — оригинальный установщик прокси AntiZapret, его запускают
	// на самом VPS; панель на VPS не ходит.
	proxyInstaller = "bash <(wget --no-hsts -qO- https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/proxy.sh)"

	maxProxyName = 64
	maxProxyNote = 200
)

// proxyMask — строка allow-ips.txt для одного адреса.
func proxyMask(ip string) string { return ip + "/32" }

// proxyRow — строка таблицы прокси.
type proxyRow struct {
	ID         int64
	Name, IP   string
	Note       string
	Created    string
	ByPanel    bool
	InFile     bool
	Unknown    bool // наличие в allow-ips.txt проверить не удалось
	DeleteHref string
}

// proxyForm — введённые значения формы (возвращаются при ошибке).
type proxyForm struct{ Name, IP, Note string }

// ipInAllowList: есть ли адрес в allow-ips.txt как «ip» или «ip/32».
func ipInAllowList(ctx context.Context, n Node, ip string) (bool, error) {
	pg, err := n.RoutingLines(ctx, allowIPsFile, nodeapi.RoutingListOpts{Query: ip, Limit: 200})
	if err != nil {
		return false, err
	}
	for _, l := range pg.Lines {
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == ip || f[0] == proxyMask(ip)) {
			return true, nil
		}
	}
	return false, nil
}

// proxyServerAddr — адрес этого сервера для вопросов proxy.sh: OPENVPN_HOST
// из настроек AntiZapret, иначе хост panel.public_url; пусто — не известен.
func (s *Server) proxyServerAddr(r *http.Request) string {
	if entries, err := s.nodeFor(r).Setup(r.Context()); err == nil {
		for _, e := range entries {
			if e.Key == "OPENVPN_HOST" && e.Present && strings.TrimSpace(e.Value) != "" {
				return strings.TrimSpace(e.Value)
			}
		}
	}
	if u, err := url.Parse(s.PublicURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return ""
}

func (s *Server) proxyView(w http.ResponseWriter, r *http.Request, status int, form proxyForm, errText string) {
	list, err := s.Store.Proxies(r.Context())
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "прокси не прочитаны: "+err.Error())
		return
	}
	node := s.nodeFor(r)
	rows := make([]proxyRow, 0, len(list))
	checkErr := ""
	for _, p := range list {
		created := "—"
		if p.Created > 0 {
			t := time.Unix(p.Created, 0)
			created = formatTime(&t)
		}
		row := proxyRow{ID: p.ID, Name: p.Name, IP: p.IP, Note: p.Note, ByPanel: p.AddedByPanel,
			Created: created, DeleteHref: "/proxy/" + strconv.FormatInt(p.ID, 10) + "/delete"}
		in, err := ipInAllowList(r.Context(), node, p.IP)
		if err != nil {
			row.Unknown = true
			if checkErr == "" {
				_, checkErr = s.agentErr(err)
			}
		}
		row.InFile = in
		rows = append(rows, row)
	}
	addr := s.proxyServerAddr(r)
	data := map[string]any{
		"Rows": rows, "Form": form, "Command": proxyInstaller,
		"ServerAddr": addr, "AllowFile": allowIPsFile,
	}
	if checkErr != "" {
		data["CheckErr"] = "Наличие адресов в " + allowIPsFile + " не проверено: " + checkErr
	}
	if errText != "" {
		data["Error"] = errText
	}
	s.render(w, r, status, "proxy", data)
}

func (s *Server) proxyPage(w http.ResponseWriter, r *http.Request) {
	s.proxyView(w, r, http.StatusOK, proxyForm{}, "")
}

// parseProxyIP: только публичный IPv4-адрес в обычной записи.
func parseProxyIP(v string) (string, error) {
	a, err := netip.ParseAddr(v)
	if err != nil || !a.Is4() || a.String() != v {
		return "", errors.New("адрес должен быть IPv4 вида 203.0.113.5")
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || v == "255.255.255.255" {
		return "", errors.New("этот адрес не может быть адресом прокси")
	}
	return v, nil
}

func (s *Server) proxyAdd(w http.ResponseWriter, r *http.Request) {
	form := proxyForm{
		Name: strings.TrimSpace(r.PostForm.Get("name")),
		IP:   strings.TrimSpace(r.PostForm.Get("ip")),
		Note: strings.TrimSpace(r.PostForm.Get("note")),
	}
	fail := func(status int, text string) { s.proxyView(w, r, status, form, text) }
	switch {
	case form.Name == "":
		fail(http.StatusBadRequest, "Укажите имя прокси.")
		return
	case utf8.RuneCountInString(form.Name) > maxProxyName, utf8.RuneCountInString(form.Note) > maxProxyNote:
		fail(http.StatusBadRequest, "Имя — до "+strconv.Itoa(maxProxyName)+" знаков, заметка — до "+strconv.Itoa(maxProxyNote)+".")
		return
	case strings.ContainsAny(form.Name+form.Note, "\r\n\x00"):
		fail(http.StatusBadRequest, "Имя и заметка — одной строкой.")
		return
	}
	ip, err := parseProxyIP(form.IP)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Store.ProxyByIP(r.Context(), ip); err == nil {
		fail(http.StatusConflict, store.ErrProxyExists.Error()+".")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		fail(http.StatusInternalServerError, "База панели: "+err.Error())
		return
	}
	node := s.nodeFor(r)
	res, err := node.PatchRouting(r.Context(), allowIPsFile, nodeapi.RoutingPatch{Add: []string{proxyMask(ip)}})
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "proxy_add", "ip", ip, "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "proxy_add", ip, st, tx)
		fail(st, tx)
		return
	}
	if !res.Applied && !noChange(res) { // дубликат — не ошибка, а ошибка строки — да
		fail(http.StatusBadRequest, strings.Join(errorsOrDefault(lineErrors(res.Errors, nil)), "; "))
		return
	}
	byPanel := res.Applied && res.Added > 0
	p, err := s.Store.CreateProxy(r.Context(), store.Proxy{
		Name: form.Name, IP: ip, Note: form.Note, Created: s.now().UTC().Unix(), AddedByPanel: byPanel,
	})
	if err != nil {
		if byPanel { // записи нет — строку, добавленную только что, возвращаем
			_, _ = node.PatchRouting(r.Context(), allowIPsFile, nodeapi.RoutingPatch{Remove: []string{proxyMask(ip)}})
		}
		fail(http.StatusInternalServerError, "Прокси не записан: "+err.Error())
		return
	}
	how := "строка добавлена в " + allowIPsFile
	if !byPanel {
		how = "строка уже была в " + allowIPsFile
	}
	s.audit(r, "proxy_add", ip, "", p.Name+"; "+how)
	t, err := node.ApplyRouting(r.Context())
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "task_start", "kind", "doall", "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "task_start", "doall", st, tx)
		s.redirectMsg(w, r, "/proxy", "proxy_apply_failed")
		return
	}
	s.taskStarted(w, r, "task_start", "doall", "прокси "+ip+".", t)
}

func (s *Server) proxyDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "прокси не найден")
		return
	}
	p, err := s.Store.ProxyByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "прокси не найден")
		return
	}
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "База панели: "+err.Error())
		return
	}
	node := s.nodeFor(r)
	changed := false
	if p.AddedByPanel { // чужую строку не трогаем
		res, err := node.PatchRouting(r.Context(), allowIPsFile, nodeapi.RoutingPatch{Remove: []string{proxyMask(p.IP)}})
		if err != nil {
			s.Log.Warn("действие", "user", s.user(r), "op", "proxy_delete", "ip", p.IP, "err", err)
			st, tx := s.agentErr(err)
			s.auditRefused(r, "proxy_delete", p.IP, st, tx)
			s.proxyView(w, r, st, proxyForm{}, tx)
			return
		}
		changed = res.Applied && res.Removed > 0
	}
	if err := s.Store.DeleteProxy(r.Context(), p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusInternalServerError, "Прокси не удалён: "+err.Error())
		return
	}
	switch {
	case changed:
		s.audit(r, "proxy_delete", p.IP, p.Name, "строка убрана из "+allowIPsFile)
	case p.AddedByPanel:
		s.audit(r, "proxy_delete", p.IP, p.Name, "строки в "+allowIPsFile+" уже не было")
	default:
		s.audit(r, "proxy_delete", p.IP, p.Name, "строка в "+allowIPsFile+" оставлена: добавлена не панелью")
		s.redirectMsg(w, r, "/proxy", "proxy_deleted_kept")
		return
	}
	if !changed {
		s.redirectMsg(w, r, "/proxy", "proxy_deleted")
		return
	}
	t, err := node.ApplyRouting(r.Context())
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "task_start", "kind", "doall", "err", err)
		st, tx := s.agentErr(err)
		s.auditRefused(r, "task_start", "doall", st, tx)
		s.redirectMsg(w, r, "/proxy", "proxy_apply_failed")
		return
	}
	s.taskStarted(w, r, "task_start", "doall", "прокси "+p.IP+" удалён.", t)
}
