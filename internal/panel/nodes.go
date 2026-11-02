package panel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
)

const (
	nodeDefaultPort  = 9100
	proxyDefaultPort = 9101
	metaKeyIP        = "node_key_ip:" // + id: адрес панели из ключа узла
)

var reNodeName = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,38}[\p{L}\p{N}]$|^[\p{L}\p{N}]$`)

func init() {
	for k, v := range map[string]string{
		"node_added":   "узел добавлен; установите агент по команде ниже",
		"node_pinned":  "узел подключён, отпечаток закреплён",
		"node_deleted": "узел удалён из панели",
	} {
		msgTexts[k] = v
	}
}

// parseAddr приводит «хост», «хост:порт» или «https://хост:порт/» к «хост:порт».
func parseAddr(in string, defPort int) (string, error) {
	in = strings.TrimSpace(in)
	in = strings.TrimPrefix(strings.TrimPrefix(in, "https://"), "HTTPS://")
	in = strings.TrimRight(in, "/")
	if in == "" || strings.ContainsAny(in, " /\\?#@") {
		return "", errors.New("адрес узла: «хост» или «хост:порт»")
	}
	host, port, err := net.SplitHostPort(in)
	if err != nil {
		host, port = strings.Trim(in, "[]"), strconv.Itoa(defPort)
	}
	if host == "" {
		return "", errors.New("адрес узла: пустое имя хоста")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", errors.New("адрес узла: порт от 1 до 65535")
	}
	return net.JoinHostPort(host, port), nil
}

func (s *Server) probeAddr(ctx context.Context, addr string) (string, error) {
	p := s.hub.probe
	if p == nil {
		p = agenttls.Probe
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return p(pctx, addr)
}

// nodeRow — строка списка узлов.
type nodeRow struct {
	ID                     int64
	Href                   string
	Name, Addr             string
	Role, Group            string
	Version, Proto, Status string
	Online, Pending, Old   bool
	Local                  bool
}

func syncRoleText(role string) string {
	switch role {
	case store.RolePrimary:
		return "основной"
	case store.RoleReplica:
		return "реплика"
	}
	return "—"
}

// groupNames — имена групп по id.
func (s *Server) groupNames(ctx context.Context) map[int64]string {
	out := map[int64]string{}
	if gs, err := s.Store.Groups(ctx); err == nil {
		for _, g := range gs {
			out[g.ID] = g.Name
		}
	}
	return out
}

// checkNodes спрашивает Info у всех подключённых записей параллельно.
func (s *Server) checkNodes(ctx context.Context, recs []store.NodeRec) map[int64]infoEntry {
	out := map[int64]infoEntry{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, rec := range recs {
		if !rec.Connected() {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := infoEntry{}
			c, err := s.connect(rec)
			if err != nil {
				e.err = err
			} else {
				e.info, e.err = s.infoFresh(ctx, c)
			}
			mu.Lock()
			out[rec.ID] = e
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func (s *Server) nodesPage(w http.ResponseWriter, r *http.Request) {
	recs, err := s.nodeRecs(r.Context())
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "узлы не прочитаны")
		return
	}
	var nodes []store.NodeRec
	for _, n := range recs {
		if n.Kind == store.KindNode {
			nodes = append(nodes, n)
		}
	}
	infos := s.checkNodes(r.Context(), nodes)
	groups := s.groupNames(r.Context())
	rows := make([]nodeRow, 0, len(nodes))
	for _, n := range nodes {
		rows = append(rows, s.newNodeRow(n, infos[n.ID], groups))
	}
	s.render(w, r, http.StatusOK, "nodes", map[string]any{"Rows": rows})
}

func (s *Server) newNodeRow(n store.NodeRec, e infoEntry, groups map[int64]string) nodeRow {
	row := nodeRow{ID: n.ID, Href: "/nodes/" + strconv.FormatInt(n.ID, 10), Name: n.Name, Addr: strings.TrimPrefix(n.URL, "https://"),
		Role: syncRoleText(n.Role), Group: groups[n.GroupID], Local: n.ID == store.LocalNode}
	if row.Local {
		row.Addr = "этот сервер"
	}
	if !n.Connected() {
		row.Pending, row.Status = true, "ожидает подключения"
		return row
	}
	switch {
	case e.err != nil:
		row.Status = "нет связи: " + connErrText(e.err)
	default:
		row.Online = true
		row.Version, row.Proto, row.Status = e.info.Version, strconv.Itoa(e.info.Proto), "связь есть"
		if agentOutdated(e.info) {
			row.Old, row.Status = true, "агент устарел: обновите"
		}
	}
	return row
}

// connErrText — причина отсутствия связи человеческими словами.
func connErrText(err error) string {
	var ne *nodeapi.Error
	switch {
	case errors.Is(err, nodeapi.ErrCertChanged):
		return "сертификат узла сменился"
	case errors.As(err, &ne) && (ne.Status == http.StatusUnauthorized || ne.Status == http.StatusForbidden):
		return "узел не принял токен"
	case errors.As(err, &ne):
		return ne.Message
	}
	return err.Error()
}

func (s *Server) nodeNewForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "node_new", map[string]any{"PanelIP": s.defaultPanelIP(r)})
}

// defaultPanelIP: адрес, с которого панель ходит к узлу, панель не знает
// наверняка; подсказка — адрес из panel.public_url, если там IP.
func (s *Server) defaultPanelIP(r *http.Request) string {
	h := strings.TrimPrefix(strings.TrimPrefix(s.PublicURL, "https://"), "http://")
	h = strings.SplitN(h, "/", 2)[0]
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	if net.ParseIP(h) != nil {
		return h
	}
	return ""
}

// nodeCreate выпускает ключ: запись узла без адреса, токен зашифрован.
func (s *Server) nodeCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	ip := strings.TrimSpace(r.PostForm.Get("panel_ip"))
	fail := func(status int, text string) {
		s.render(w, r, status, "node_new", map[string]any{"Error": text, "Name": name, "PanelIP": ip})
	}
	if !reNodeName.MatchString(name) {
		fail(http.StatusBadRequest, "Имя узла: до 40 знаков — буквы, цифры, пробел, точка, дефис, подчёркивание.")
		return
	}
	token, err := secrets.NewToken()
	if err != nil {
		fail(http.StatusInternalServerError, "токен не создан: "+err.Error())
		return
	}
	if _, err := (nodeapi.NodeKey{PanelIP: ip, Token: token}).Encode(); err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	sealed, err := s.sealToken(token)
	if err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}
	id, err := s.Store.AddNode(r.Context(), store.NodeRec{Name: name, Kind: store.KindNode, Token: sealed, Created: s.now().Unix()})
	if errors.Is(err, store.ErrNodeExists) {
		fail(http.StatusConflict, "Узел с таким именем уже есть.")
		return
	}
	if err != nil {
		s.Log.Error("узел не добавлен", "err", err)
		fail(http.StatusInternalServerError, "узел не добавлен")
		return
	}
	if err := s.Store.SetMeta(r.Context(), metaKeyIP+strconv.FormatInt(id, 10), ip); err != nil {
		s.Log.Warn("адрес панели для ключа не запомнен", "err", err)
	}
	s.hubReload()
	s.Log.Info("действие", "user", s.user(r), "op", "node_add", "node", name)
	s.audit(r, "node_add", name, "", "выдан ключ узла, адрес панели "+ip)
	s.redirectMsg(w, r, "/nodes/"+strconv.FormatInt(id, 10), "node_added")
}

// nodeFromPath — запись узла (kind=node) по {id}; нет — 404.
func (s *Server) nodeFromPath(w http.ResponseWriter, r *http.Request) (store.NodeRec, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		rec, ok, rerr := s.nodeRec(r.Context(), id)
		if rerr != nil {
			s.errorPage(w, r, http.StatusInternalServerError, "узлы не прочитаны")
			return store.NodeRec{}, false
		}
		if ok && rec.Kind == store.KindNode {
			return rec, true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "узел не найден")
	return store.NodeRec{}, false
}

// installCommand — готовая команда установки узла по ключу.
func (s *Server) installCommand(ctx context.Context, rec store.NodeRec) (string, bool) {
	token, err := s.tokenOf(rec)
	if err != nil {
		return "", false
	}
	ip, _, _ := s.Store.Meta(ctx, metaKeyIP+strconv.FormatInt(rec.ID, 10))
	key, err := (nodeapi.NodeKey{PanelIP: ip, Token: token}).Encode()
	if err != nil {
		return "", false
	}
	return "azpanel install --non-interactive AZPANEL_MODE=node AZPANEL_NODE_KEY=" + key, true
}

func (s *Server) nodePage(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.nodeFromPath(w, r)
	if !ok {
		return
	}
	s.nodeView(w, r, http.StatusOK, rec, nil)
}

func (s *Server) nodeView(w http.ResponseWriter, r *http.Request, status int, rec store.NodeRec, extra map[string]any) {
	d := map[string]any{"Node": rec, "Href": "/nodes/" + strconv.FormatInt(rec.ID, 10), "Local": rec.ID == store.LocalNode,
		"Addr": strings.TrimPrefix(rec.URL, "https://"), "Role": syncRoleText(rec.Role), "Pending": !rec.Connected()}
	if rec.Fingerprint != "" {
		d["Fingerprint"] = agenttls.FormatFingerprint(rec.Fingerprint)
	}
	if g := s.groupNames(r.Context())[rec.GroupID]; g != "" {
		d["Group"] = g
	}
	if !rec.Connected() {
		if cmd, ok := s.installCommand(r.Context(), rec); ok {
			d["Command"] = cmd
		}
	}
	for k, v := range extra {
		d[k] = v
	}
	s.render(w, r, status, "node", d)
}

// nodeProbe знакомится с узлом: показывает отпечаток для сверки с тем, что
// напечатал узел при установке. Закрепляется он только после подтверждения.
func (s *Server) nodeProbe(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.nodeFromPath(w, r)
	if !ok || rec.ID == store.LocalNode {
		if ok {
			s.errorPage(w, r, http.StatusBadRequest, "локальный узел подключать не нужно")
		}
		return
	}
	addr, err := parseAddr(r.PostForm.Get("addr"), nodeDefaultPort)
	if err != nil {
		s.nodeView(w, r, http.StatusBadRequest, rec, map[string]any{"Error": err.Error(), "TypedAddr": r.PostForm.Get("addr")})
		return
	}
	fp, err := s.probeAddr(r.Context(), addr)
	if err != nil {
		s.nodeView(w, r, http.StatusBadGateway, rec, map[string]any{"Error": "Узел не отвечает по TLS на " + addr + ": " + err.Error(), "TypedAddr": addr})
		return
	}
	extra := map[string]any{"ProbeAddr": addr, "ProbeFP": fp, "ProbeFPText": agenttls.FormatFingerprint(fp), "TypedAddr": addr}
	if rec.Fingerprint != "" && rec.Fingerprint != fp {
		extra["Changed"] = true
	}
	s.nodeView(w, r, http.StatusOK, rec, extra)
}

// nodeConnect закрепляет отпечаток после подтверждения человека и проверяет
// связь: узел должен принять токен.
func (s *Server) nodeConnect(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.nodeFromPath(w, r)
	if !ok {
		return
	}
	addr, aerr := parseAddr(r.PostForm.Get("addr"), nodeDefaultPort)
	fp, ferr := agenttls.NormalizeFingerprint(r.PostForm.Get("fp"))
	if aerr != nil || ferr != nil || rec.ID == store.LocalNode {
		s.errorPage(w, r, http.StatusBadRequest, "неверный адрес или отпечаток")
		return
	}
	extra := map[string]any{"ProbeAddr": addr, "ProbeFP": fp, "ProbeFPText": agenttls.FormatFingerprint(fp), "TypedAddr": addr}
	if !formConfirmed(r) {
		extra["Error"] = "Отметьте, что отпечаток совпадает с напечатанным на узле."
		s.nodeView(w, r, http.StatusBadRequest, rec, extra)
		return
	}
	now, err := s.probeAddr(r.Context(), addr)
	if err != nil || now != fp {
		extra["Error"] = "Сертификат узла изменился после показа отпечатка (или узел не отвечает): начните подключение заново."
		delete(extra, "ProbeFP")
		s.nodeView(w, r, http.StatusConflict, rec, extra)
		return
	}
	cand := rec
	cand.URL, cand.Fingerprint = "https://"+addr, fp
	c, err := s.connect(cand)
	if err == nil {
		_, err = s.infoFresh(r.Context(), c)
	}
	if err != nil {
		extra["Error"] = "Связь не установлена: " + connErrText(err) + ". Проверьте, что агент установлен по ключу этого узла и адрес панели есть в его белом списке."
		s.nodeView(w, r, http.StatusBadGateway, rec, extra)
		return
	}
	if err := s.Store.SetNodeConn(r.Context(), rec.ID, cand.URL, fp); err != nil {
		s.Log.Error("узел не подключён", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "узел не сохранён")
		return
	}
	s.hubReload()
	s.Log.Info("действие", "user", s.user(r), "op", "node_connect", "node", rec.Name)
	s.audit(r, "node_connect", rec.Name, rec.URL, cand.URL+" отпечаток "+fp)
	s.redirectMsg(w, r, "/nodes/"+strconv.FormatInt(rec.ID, 10), "node_pinned")
}

// nodeCheck — «проверить связь»: свежий Info.
func (s *Server) nodeCheck(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.nodeFromPath(w, r)
	if !ok {
		return
	}
	if !rec.Connected() {
		s.nodeView(w, r, http.StatusBadRequest, rec, map[string]any{"Error": "Узел ещё не подключён."})
		return
	}
	c, err := s.connect(rec)
	var info nodeapi.Info
	if err == nil {
		info, err = s.infoFresh(r.Context(), c)
	}
	if err != nil {
		s.nodeView(w, r, http.StatusBadGateway, rec, map[string]any{"Error": "Нет связи: " + connErrText(err)})
		return
	}
	text := fmt.Sprintf("Связь есть: azpanel %s, протокол %d, хост %s.", info.Version, info.Proto, info.Hostname)
	if agentOutdated(info) {
		text += " Агент устарел: обновите его, пока команды недоступны."
	}
	s.nodeView(w, r, http.StatusOK, rec, map[string]any{"Check": text})
}

func (s *Server) nodeDelete(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.nodeFromPath(w, r)
	if !ok {
		return
	}
	switch {
	case rec.ID == store.LocalNode:
		s.nodeView(w, r, http.StatusBadRequest, rec, map[string]any{"Error": "Локальный узел удалить нельзя."})
		return
	case rec.GroupID != 0:
		s.nodeView(w, r, http.StatusConflict, rec, map[string]any{"Error": "Узел состоит в группе: сначала выведите его из группы."})
		return
	case !formConfirmed(r):
		s.nodeView(w, r, http.StatusBadRequest, rec, map[string]any{"Error": "Отметьте подтверждение: карточки и история клиентов этого узла будут удалены из панели."})
		return
	}
	if err := s.Store.DeleteNode(r.Context(), rec.ID); err != nil {
		s.Log.Error("узел не удалён", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "узел не удалён")
		return
	}
	s.hubReload()
	s.Log.Info("действие", "user", s.user(r), "op", "node_delete", "node", rec.Name)
	s.audit(r, "node_delete", rec.Name, rec.URL, "")
	s.redirectMsg(w, r, "/nodes", "node_deleted")
}

// sortedNodes — узлы (kind=node) по имени для выбора в формах.
func sortedNodes(recs []store.NodeRec, kind string) []store.NodeRec {
	var out []store.NodeRec
	for _, n := range recs {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
