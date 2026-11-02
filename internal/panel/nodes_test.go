package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const testAgentToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// tlsAgent — поддельный агент по TLS: токен проверяется, протокол и версия
// задаются, остальное — по маршрутам.
func tlsAgent(t *testing.T, proto int, routes map[string]any) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"неверный токен"}`))
			return
		}
		if r.URL.Path == "/v1/info" {
			json.NewEncoder(w).Encode(nodeapi.Info{Proto: proto, Version: "9.9.9", Hostname: "remote-host"})
			return
		}
		if v, ok := routes[r.URL.Path]; ok {
			json.NewEncoder(w).Encode(v)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"нет маршрута"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, agenttls.Fingerprint(srv.Certificate().Raw)
}

func nodesEnv(t *testing.T) (*testEnv, *http.Cookie, string) {
	t.Helper()
	e := newEnv(t, adminHash(t))
	e.srv.DataKey = make([]byte, 32)
	e.srv.DataKey[0] = 7
	c, sess := e.sessionCookie(t)
	return e, c, sess.CSRF
}

func hostOf(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "https://") }

// addRemoteNode заводит подключённый удалённый узел напрямую в базе.
func addRemoteNode(t *testing.T, e *testEnv, name string, srv *httptest.Server, fp string) store.NodeRec {
	t.Helper()
	sealed, err := e.srv.sealToken(testAgentToken)
	if err != nil {
		t.Fatal(err)
	}
	id, err := e.st.AddNode(context.Background(), store.NodeRec{Name: name, URL: srv.URL, Fingerprint: fp, Token: sealed, Created: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.hubReload()
	rec, _, _ := e.st.NodeByID(context.Background(), id)
	return rec
}

func TestNodeAddFlowKeyProbeConfirmConnect(t *testing.T) {
	e, c, csrf := nodesEnv(t)
	srv, fp := tlsAgent(t, nodeapi.Proto, nil)

	// 1. Ключ узла и готовая команда установки.
	rec := post(e, c, "/nodes", url.Values{"csrf": {csrf}, "name": {"Берлин"}, "panel_ip": {"203.0.113.9"}})
	if rec.Code != 303 {
		t.Fatalf("создание: %d %s", rec.Code, rec.Body)
	}
	page := get(e, c, rec.Header().Get("Location"))
	body := page.Body.String()
	if !strings.Contains(body, "azpanel install --non-interactive AZPANEL_MODE=node AZPANEL_NODE_KEY=azn1.") {
		t.Fatalf("нет команды установки: %s", body)
	}
	nodes, _ := e.st.Nodes(context.Background())
	var rn store.NodeRec
	for _, n := range nodes {
		if n.Name == "Берлин" {
			rn = n
		}
	}
	if rn.Token == "" || strings.Contains(rn.Token, testAgentToken) || rn.Connected() {
		t.Fatalf("запись: %+v", rn)
	}
	// Токен из ключа открывается тем же ключом панели.
	tok, err := e.srv.tokenOf(rn)
	if err != nil || len(tok) != 64 || !strings.Contains(body, nodeapi.NodeKeyPrefix) {
		t.Fatalf("токен: %q %v", tok, err)
	}

	// 2. Знакомство: показан отпечаток, ничего не закреплено.
	path := "/nodes/" + strconv.FormatInt(rn.ID, 10)
	rec = post(e, c, path+"/probe", url.Values{"csrf": {csrf}, "addr": {hostOf(srv)}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), agenttls.FormatFingerprint(fp)) {
		t.Fatalf("probe: %d %s", rec.Code, rec.Body)
	}
	if n, _, _ := e.st.NodeByID(context.Background(), rn.ID); n.Connected() {
		t.Fatal("отпечаток закреплён до подтверждения")
	}

	// 3. Без подтверждения — отказ; с чужим отпечатком — отказ.
	f := url.Values{"csrf": {csrf}, "addr": {hostOf(srv)}, "fp": {fp}}
	if rec = post(e, c, path+"/connect", f); rec.Code != 400 {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	f.Set("confirm", "1")
	f.Set("fp", strings.Repeat("ab", 32))
	if rec = post(e, c, path+"/connect", f); rec.Code != 409 {
		t.Fatalf("чужой отпечаток: %d %s", rec.Code, rec.Body)
	}

	// 4. Подтверждено: закреплено и записано в журнал.
	f.Set("fp", fp)
	if rec = post(e, c, path+"/connect", f); rec.Code != 303 {
		t.Fatalf("connect: %d %s", rec.Code, rec.Body)
	}
	n, _, _ := e.st.NodeByID(context.Background(), rn.ID)
	if !n.Connected() || n.Fingerprint != fp || n.URL != srv.URL {
		t.Fatalf("после connect: %+v", n)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "node_connect")
	if len(list) != 1 {
		t.Fatalf("журнал: %+v", list)
	}

	// 5. Список показывает связь и версию агента.
	body = get(e, c, "/nodes").Body.String()
	if !strings.Contains(body, "связь есть") || !strings.Contains(body, "9.9.9") || !strings.Contains(body, "Берлин") {
		t.Fatalf("список: %s", body)
	}
}

func TestNodeCertChangedIsRefused(t *testing.T) {
	e, c, csrf := nodesEnv(t)
	srv, _ := tlsAgent(t, nodeapi.Proto, nil)
	rec := addRemoteNode(t, e, "r1", srv, strings.Repeat("cd", 32)) // закреплён другой сертификат
	out := post(e, c, "/nodes/"+strconv.FormatInt(rec.ID, 10)+"/check", url.Values{"csrf": {csrf}})
	if out.Code != 502 || !strings.Contains(out.Body.String(), "сертификат узла сменился") {
		t.Fatalf("%d %s", out.Code, out.Body)
	}
	if !strings.Contains(get(e, c, "/nodes").Body.String(), "сертификат узла сменился") {
		t.Fatal("в списке нет причины")
	}
}

func TestNodePagesWithNodeParam(t *testing.T) {
	e, c, _ := nodesEnv(t)
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "local-client", OpenVPN: true}}, nil
	}
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	srv, fp := tlsAgent(t, nodeapi.Proto, map[string]any{
		"/v1/clients":  []nodeapi.Client{{Name: "remote-client", OpenVPN: true}},
		"/v1/sessions": []nodeapi.Session{},
	})
	rn := addRemoteNode(t, e, "r1", srv, fp)

	body := get(e, c, "/").Body.String()
	if !strings.Contains(body, "local-client") || strings.Contains(body, "remote-client") {
		t.Fatalf("по умолчанию — первый узел: %s", body)
	}
	if !strings.Contains(body, "?node="+strconv.FormatInt(rn.ID, 10)) {
		t.Fatal("нет переключателя узлов")
	}
	rec := get(e, c, "/?node="+strconv.FormatInt(rn.ID, 10))
	if body = rec.Body.String(); !strings.Contains(body, "remote-client") || strings.Contains(body, "local-client") {
		t.Fatalf("?node=: %s", body)
	}
	var ck *http.Cookie
	for _, x := range rec.Result().Cookies() {
		if x.Name == nodeCookie {
			ck = x
		}
	}
	if ck == nil || ck.Value != strconv.FormatInt(rn.ID, 10) {
		t.Fatalf("выбор не запомнен: %+v", ck)
	}
	// Выбор в cookie действует на ссылки без ?node=.
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	r.AddCookie(ck)
	if body = e.do(r).Body.String(); !strings.Contains(body, "remote-client") {
		t.Fatalf("cookie: %s", body)
	}
	if rec = get(e, c, "/?node=999"); rec.Code != 404 {
		t.Fatalf("неизвестный узел: %d", rec.Code)
	}
	if rec = get(e, c, "/?node=abc"); rec.Code != 404 {
		t.Fatalf("мусор в node: %d", rec.Code)
	}
}

func TestOutdatedAgentGetsNoCommands(t *testing.T) {
	e, c, _ := nodesEnv(t)
	old := panelProto
	panelProto = 3
	t.Cleanup(func() { panelProto = old })
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/info" {
			json.NewEncoder(w).Encode(nodeapi.Info{Proto: 1})
			return
		}
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)
	rn := addRemoteNode(t, e, "old", srv, agenttls.Fingerprint(srv.Certificate().Raw))
	rec := get(e, c, "/?node="+strconv.FormatInt(rn.ID, 10))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "обновите агент") || hits.Load() != 0 {
		t.Fatalf("%d hits=%d %s", rec.Code, hits.Load(), rec.Body)
	}
}

func TestNodeDeleteRefusedInGroupAndOnLocal(t *testing.T) {
	e, c, csrf := nodesEnv(t)
	srv, fp := tlsAgent(t, nodeapi.Proto, nil)
	rn := addRemoteNode(t, e, "r1", srv, fp)
	if rec := post(e, c, "/nodes/1/delete", url.Values{"csrf": {csrf}, "confirm": {"1"}}); rec.Code != 400 {
		t.Fatalf("локальный: %d", rec.Code)
	}
	gid, _ := e.st.AddGroup(context.Background(), "g", rn.ID, 1)
	e.srv.hubReload()
	if rec := post(e, c, "/nodes/"+strconv.FormatInt(rn.ID, 10)+"/delete", url.Values{"csrf": {csrf}, "confirm": {"1"}}); rec.Code != 409 {
		t.Fatalf("в группе: %d", rec.Code)
	}
	e.st.DeleteGroup(context.Background(), gid)
	e.srv.hubReload()
	if rec := post(e, c, "/nodes/"+strconv.FormatInt(rn.ID, 10)+"/delete", url.Values{"csrf": {csrf}}); rec.Code != 400 {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	if rec := post(e, c, "/nodes/"+strconv.FormatInt(rn.ID, 10)+"/delete", url.Values{"csrf": {csrf}, "confirm": {"1"}}); rec.Code != 303 {
		t.Fatalf("удаление: %d %s", rec.Code, rec.Body)
	}
	if n, ok, _ := e.st.NodeByID(context.Background(), rn.ID); ok {
		t.Fatalf("узел остался: %+v", n)
	}
}

func TestNodesAdminOnly(t *testing.T) {
	e, _, _ := nodesEnv(t)
	u, err := e.st.CreateUser(context.Background(), store.User{Login: "bob", Hash: adminHash(t), Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	uc, _ := e.sessionFor(t, u, false)
	for _, p := range []string{"/nodes", "/nodes/new", "/nodes/1"} {
		if rec := get(e, uc, p); rec.Code != 403 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

// Сборщик ведёт оба узла параллельно: у каждого свой ряд ресурсов.
func TestCollectorsRunForAllNodes(t *testing.T) {
	e, _, _ := nodesEnv(t)
	sys := func(context.Context) (nodeapi.System, error) { return nodeapi.System{}, nil }
	e.node.SystemFn = sys
	e.node.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) { return nil, nil }
	e.node.DenialsFn = func(context.Context, time.Time) ([]nodeapi.Denial, error) { return nil, nil }
	remote := &fakeNode{SystemFn: sys,
		SessionsFn: func(context.Context) ([]nodeapi.Session, error) { return nil, nil },
		ClientsFn:  func(context.Context) ([]nodeapi.Client, error) { return nil, nil },
		DenialsFn:  func(context.Context, time.Time) ([]nodeapi.Denial, error) { return nil, nil },
		InfoFn:     func(context.Context) (nodeapi.Info, error) { return nodeapi.Info{Proto: nodeapi.Proto}, nil }}
	e.srv.hub.dial = func(rec store.NodeRec, token string) (any, error) { return remote, nil }
	srv, fp := tlsAgent(t, nodeapi.Proto, nil)
	rn := addRemoteNode(t, e, "r1", srv, fp)

	col := &Collector{Node: e.node, Store: e.st, NodeID: store.LocalNode, Every: 20 * time.Millisecond, HistoryDays: 30}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.srv.RunCollectors(ctx, col); close(done) }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var gotLocal, gotRemote int
		now := time.Now().Unix()
		if pts, err := e.st.ResourceSeries(context.Background(), store.LocalNode, now-3600, now+3600, store.Minute); err == nil {
			gotLocal = len(pts)
		}
		if pts, err := e.st.ResourceSeries(context.Background(), rn.ID, now-3600, now+3600, store.Minute); err == nil {
			gotRemote = len(pts)
		}
		if gotLocal > 0 && gotRemote > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ряды: локальный %d, удалённый %d", gotLocal, gotRemote)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("сборщики не остановились")
	}
}
