package panel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/proxyapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	nodeCookie     = "azpanel_node" // выбранный узел: запоминается, когда в адресе есть ?node=
	infoTTL        = 30 * time.Second
	infoTimeout    = 5 * time.Second
	tokenAAD       = "azpanel-node-token"
	maxNodeNameLen = 40
)

// panelProto — протокол панели; агент протокола panelProto или предыдущего —
// работа, старше — «обновите агент».
var panelProto = nodeapi.Proto

// conn — подключение к узлу: запись, клиент и его роли. raw — исходный
// объект клиента (для интерфейсов синхронизации и прокси через приведение).
type conn struct {
	rec  store.NodeRec
	raw  any
	node Node
	svc  ServiceNode
}

type infoEntry struct {
	at   time.Time
	info nodeapi.Info
	err  error
}

// hubState — узлы панели: записи из базы, готовые клиенты, кэш Info и
// сборщики по узлам. Нулевое значение годится.
type hubState struct {
	mu      sync.Mutex
	recs    []store.NodeRec
	loaded  bool
	conns   map[int64]*conn
	stamps  map[int64]string
	infos   map[int64]infoEntry
	dial    func(rec store.NodeRec, token string) (any, error)
	probe   func(ctx context.Context, addr string) (string, error)
	cols    map[int64]*Collector
	groupMu keyedMutex // одна операция группы за раз
	groups  map[int64]*groupRuntime
	inline  bool // операции групп выполняются на месте (тесты)
}

// dialNode — настоящее подключение: узел по https с закреплённым отпечатком,
// прокси-агент — тем же транспортом.
func dialNode(rec store.NodeRec, token string) (any, error) {
	if rec.URL == "" || rec.Fingerprint == "" {
		return nil, errors.New("узел не подключён: нет адреса или отпечатка")
	}
	if !strings.HasPrefix(strings.ToLower(rec.URL), "https://") {
		return nil, errors.New("удалённый узел подключается только по https")
	}
	c, err := nodeapi.NewPinned(rec.URL, token, rec.Fingerprint)
	if err != nil {
		return nil, err
	}
	if rec.Kind == store.KindProxy {
		pc := proxyapi.New(rec.URL, token)
		pc.HTTP = c.HTTP
		return pc, nil
	}
	return c, nil
}

// nodeRecs — записи узлов из базы (кэш до изменения).
func (s *Server) nodeRecs(ctx context.Context) ([]store.NodeRec, error) {
	if s.Store == nil {
		return nil, errors.New("база панели недоступна")
	}
	h := &s.hub
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loaded {
		recs, err := s.Store.Nodes(ctx)
		if err != nil {
			return nil, err
		}
		h.recs, h.loaded = recs, true
	}
	return append([]store.NodeRec(nil), h.recs...), nil
}

// hubReload сбрасывает кэш записей и клиентов после правки узлов и групп.
func (s *Server) hubReload() {
	h := &s.hub
	h.mu.Lock()
	h.loaded = false
	h.conns, h.stamps, h.infos = nil, nil, nil
	h.mu.Unlock()
}

// nodeRec — запись по id.
func (s *Server) nodeRec(ctx context.Context, id int64) (store.NodeRec, bool, error) {
	recs, err := s.nodeRecs(ctx)
	if err != nil {
		return store.NodeRec{}, false, err
	}
	for _, r := range recs {
		if r.ID == id {
			return r, true, nil
		}
	}
	return store.NodeRec{}, false, nil
}

// tokenOf расшифровывает токен узла из записи.
func (s *Server) tokenOf(rec store.NodeRec) (string, error) {
	if rec.Token == "" {
		return "", errors.New("у узла нет токена")
	}
	if len(s.DataKey) != 32 {
		return "", errors.New("нет ключа данных панели: токены узлов расшифровать нельзя")
	}
	sealed, err := base64.StdEncoding.DecodeString(rec.Token)
	if err != nil {
		return "", errors.New("токен узла повреждён")
	}
	plain, err := OpenAAD(s.DataKey, sealed, []byte(tokenAAD))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// sealToken шифрует токен для записи в базу.
func (s *Server) sealToken(token string) (string, error) {
	if len(s.DataKey) != 32 {
		return "", errors.New("нет ключа данных панели: токены узлов хранить нельзя")
	}
	sealed, err := SealAAD(s.DataKey, []byte(token), []byte(tokenAAD))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// connect даёт подключение к узлу; клиент кэшируется, пока запись не менялась.
func (s *Server) connect(rec store.NodeRec) (*conn, error) {
	if rec.ID == store.LocalNode {
		return &conn{rec: rec, raw: s.Node, node: s.Node, svc: s.serviceNode()}, nil
	}
	stamp := rec.URL + "|" + rec.Fingerprint + "|" + rec.Token + "|" + rec.Kind
	h := &s.hub
	h.mu.Lock()
	if c, ok := h.conns[rec.ID]; ok && h.stamps[rec.ID] == stamp {
		h.mu.Unlock()
		c.rec = rec
		return c, nil
	}
	h.mu.Unlock()
	token, err := s.tokenOf(rec)
	if err != nil {
		return nil, err
	}
	dial := h.dial
	if dial == nil {
		dial = dialNode
	}
	raw, err := dial(rec, token)
	if err != nil {
		return nil, err
	}
	c := &conn{rec: rec, raw: raw}
	c.node, _ = raw.(Node)
	c.svc, _ = raw.(ServiceNode)
	h.mu.Lock()
	if h.conns == nil {
		h.conns, h.stamps = map[int64]*conn{}, map[int64]string{}
	}
	h.conns[rec.ID], h.stamps[rec.ID] = c, stamp
	h.mu.Unlock()
	return c, nil
}

// connByID — подключение по id узла.
func (s *Server) connByID(ctx context.Context, id int64) (*conn, error) {
	rec, ok, err := s.nodeRec(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("узел не найден")
	}
	return s.connect(rec)
}

// infoOf — Info узла с кэшем на infoTTL. Ошибка тоже кэшируется: недоступный
// узел не должен замедлять каждую страницу.
func (s *Server) infoOf(ctx context.Context, c *conn) (nodeapi.Info, error) {
	h := &s.hub
	h.mu.Lock()
	if e, ok := h.infos[c.rec.ID]; ok && s.now().Sub(e.at) < infoTTL {
		h.mu.Unlock()
		return e.info, e.err
	}
	h.mu.Unlock()
	return s.infoFresh(ctx, c)
}

// infoFresh спрашивает Info заново и обновляет кэш.
func (s *Server) infoFresh(ctx context.Context, c *conn) (nodeapi.Info, error) {
	type infoer interface {
		Info(ctx context.Context) (nodeapi.Info, error)
	}
	in, ok := c.raw.(infoer)
	if !ok {
		return nodeapi.Info{}, errors.New("агент не отвечает на Info")
	}
	ictx, cancel := context.WithTimeout(ctx, infoTimeout)
	defer cancel()
	info, err := in.Info(ictx)
	h := &s.hub
	h.mu.Lock()
	if h.infos == nil {
		h.infos = map[int64]infoEntry{}
	}
	h.infos[c.rec.ID] = infoEntry{at: s.now(), info: info, err: err}
	h.mu.Unlock()
	return info, err
}

// agentOutdated: протокол агента старше предыдущего протокола панели.
func agentOutdated(info nodeapi.Info) bool { return info.Proto < panelProto-1 }

type selKeyType struct{}

var selKey selKeyType

// selected — узел, выбранный для запроса; nil — выбора нет (панель без базы
// или маршрут не про узел): работает единственный узел Server.Node.
func selected(r *http.Request) *conn {
	c, _ := r.Context().Value(selKey).(*conn)
	return c
}

// nodeFor — агент выбранного узла.
func (s *Server) nodeFor(r *http.Request) Node {
	if c := selected(r); c != nil && c.node != nil {
		return c.node
	}
	return s.Node
}

// nodeIDFor — идентификатор выбранного узла в базе панели.
func (s *Server) nodeIDFor(r *http.Request) int64 {
	if c := selected(r); c != nil {
		return c.rec.ID
	}
	return s.NodeID
}

// replicaFor: выбранный узел — реплика группы; изменения клиентов, списков и
// setup на нём делаются на основном.
func replicaFor(r *http.Request) bool {
	c := selected(r)
	return c != nil && c.rec.Role == store.RoleReplica
}

// nodeScopedPattern: маршруты, работающие с выбранным узлом.
func nodeScopedPattern(pattern string) bool {
	_, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return false
	}
	switch {
	case path == "/{$}", path == "/monitor", path == "/tasks":
		return true
	}
	for _, p := range []string{"/clients", "/routing", "/settings/antizapret", "/tasks/", "/antizapret/", "/telemt", "/warp", "/update"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// scoped оборачивает обработчик выбором узла: ?node=<id> в адресе, иначе
// запомненный выбор (cookie), иначе первый узел.
func (s *Server) scoped(pattern string, h http.HandlerFunc) http.HandlerFunc {
	if !nodeScopedPattern(pattern) {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Store == nil {
			h(w, r)
			return
		}
		recs, err := s.nodeRecs(r.Context())
		if err != nil {
			s.errorPage(w, r, http.StatusInternalServerError, "узлы не прочитаны")
			return
		}
		var want int64
		fromQuery := false
		if v := r.URL.Query().Get("node"); v != "" {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				s.errorPage(w, r, http.StatusNotFound, "узел не найден")
				return
			}
			want, fromQuery = id, true
		} else if ck, err := r.Cookie(nodeCookie); err == nil {
			want, _ = strconv.ParseInt(ck.Value, 10, 64)
		}
		var pick *store.NodeRec
		for i := range recs {
			if recs[i].Kind != store.KindNode {
				continue
			}
			if pick == nil {
				pick = &recs[i] // первый узел — по умолчанию
			}
			if want != 0 && recs[i].ID == want {
				pick = &recs[i]
				break
			}
		}
		if fromQuery && (pick == nil || pick.ID != want) {
			s.errorPage(w, r, http.StatusNotFound, "узел не найден")
			return
		}
		if pick == nil {
			h(w, r)
			return
		}
		c, err := s.connect(*pick)
		if err != nil {
			s.errorPage(w, r, http.StatusBadGateway, "узел «"+pick.Name+"»: "+err.Error())
			return
		}
		if fromQuery {
			if ck, err := r.Cookie(nodeCookie); err != nil || ck.Value != strconv.FormatInt(pick.ID, 10) {
				http.SetCookie(w, &http.Cookie{Name: nodeCookie, Value: strconv.FormatInt(pick.ID, 10), Path: s.cookiePath(),
					HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.isHTTPS(r)})
			}
		}
		if pick.ID != store.LocalNode && !strings.HasPrefix(r.URL.Path, "/update") {
			if info, err := s.infoOf(r.Context(), c); err == nil && agentOutdated(info) {
				s.errorPage(w, r, http.StatusConflict, fmt.Sprintf(
					"агент узла «%s» устарел (протокол %d, нужен не ниже %d): обновите агент, пока команды недоступны",
					pick.Name, info.Proto, panelProto-1))
				return
			}
		}
		h(w, r.WithContext(contextWithConn(r.Context(), c)))
	}
}

func contextWithConn(ctx context.Context, c *conn) context.Context {
	return context.WithValue(ctx, selKey, c)
}

// nodeSwitch — пункт переключателя узлов в шапке.
type nodeSwitch struct {
	Name, Path string
	ID         int64
	Current    bool
}

// switchData добавляет в данные страницы переключатель узлов и пометку
// реплики. Переключатель виден, когда узлов больше одного.
func (s *Server) switchData(r *http.Request, d map[string]any) {
	c := selected(r)
	if c == nil || s.Store == nil {
		return
	}
	recs, err := s.nodeRecs(r.Context())
	if err != nil {
		return
	}
	d["NodeName"] = c.rec.Name
	if c.rec.Role == store.RoleReplica {
		d["Replica"] = true
		if gs, err := s.Store.Groups(r.Context()); err == nil {
			for _, g := range gs {
				if g.ID == c.rec.GroupID {
					d["ReplicaGroup"] = g.Name
				}
			}
		}
	}
	var items []nodeSwitch
	for _, n := range recs {
		if n.Kind != store.KindNode {
			continue
		}
		items = append(items, nodeSwitch{Name: n.Name, ID: n.ID, Current: n.ID == c.rec.ID,
			Path: s.switchPath(r)})
	}
	if len(items) > 1 {
		d["NodeSwitch"] = items
	}
}

// switchHref — тот же список на другом узле; со страниц одного клиента или
// задачи переключение ведёт на список.
func (s *Server) switchPath(r *http.Request) string {
	p := r.URL.Path
	switch p {
	case "/", "/monitor", "/routing", "/tasks", "/settings/antizapret", "/antizapret/update", "/telemt", "/warp", "/update":
	default:
		p = "/"
	}
	return p
}

// selectedCtx — узел, выбранный для запроса, по контексту запроса.
func selectedCtx(ctx context.Context) *conn {
	c, _ := ctx.Value(selKey).(*conn)
	return c
}

// nodeCtx — агент выбранного узла по контексту запроса.
func (s *Server) nodeCtx(ctx context.Context) Node {
	if c := selectedCtx(ctx); c != nil && c.node != nil {
		return c.node
	}
	return s.Node
}

// nodeIDCtx — идентификатор выбранного узла по контексту запроса.
func (s *Server) nodeIDCtx(ctx context.Context) int64 {
	if c := selectedCtx(ctx); c != nil {
		return c.rec.ID
	}
	return s.NodeID
}
