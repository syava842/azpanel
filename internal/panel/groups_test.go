package panel

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

const (
	pathLimits = "/opt/azpanel/data/limits.json"
	pathHosts  = "/root/antizapret/config/include-hosts.txt"
	pathSetup  = "/root/antizapret/setup"
	pathProf   = "/root/antizapret/client/openvpn/vpn/vpn-bob.ovpn"
)

// syncFake — поддельный агент группы: файлы набора в памяти, роль, журнал вызовов.
type syncFake struct {
	*svcNode
	name string
	log  *[]string
	mu   sync.Mutex

	files    map[string][]byte
	role     nodeapi.SyncRole
	removed  []string
	applyErr error
	azErr    error
}

func newSyncFake(name string, log *[]string) *syncFake {
	f := &syncFake{svcNode: &svcNode{fakeNode: &fakeNode{}}, name: name, log: log, files: map[string][]byte{}}
	f.InfoFn = func(context.Context) (nodeapi.Info, error) {
		return nodeapi.Info{Proto: nodeapi.Proto, Version: "1.0", Hostname: name}, nil
	}
	f.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		var out []nodeapi.Client
		f.mu.Lock()
		defer f.mu.Unlock()
		for p := range f.files {
			if strings.Contains(p, "/client/openvpn/") {
				out = append(out, nodeapi.Client{Name: strings.TrimSuffix(p[strings.LastIndex(p, "-")+1:], ".ovpn"), OpenVPN: true})
			}
		}
		return out, nil
	}
	f.TaskFn = func(_ context.Context, id string) (nodeapi.TaskDetail, error) {
		now, zero := time.Now(), 0
		return nodeapi.TaskDetail{Task: nodeapi.Task{ID: id, Finished: &now, ExitCode: &zero}}, nil
	}
	f.RestartAntiZapretFn = func(context.Context) (nodeapi.Task, error) {
		f.note("restart")
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	f.ApplyRoutingFn = func(context.Context) (nodeapi.Task, error) {
		f.note("doall")
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	f.RebuildProfilesFn = func(context.Context) (nodeapi.Task, error) {
		f.note("profiles")
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	f.SetSetupFn = func(_ context.Context, v map[string]string) (nodeapi.SetupResult, error) {
		f.note(fmt.Sprintf("setup:%s=%s,%s=%s", "OPENVPN_HOST", v["OPENVPN_HOST"], "WIREGUARD_HOST", v["WIREGUARD_HOST"]))
		return nodeapi.SetupResult{}, nil
	}
	f.AZPreflightFn = func(context.Context) (nodeapi.AZPreflight, error) { return nodeapi.AZPreflight{OK: true}, nil }
	f.AZUpdateFn = func(context.Context, nodeapi.AZUpdateRequest) (nodeapi.AZUpdateState, error) {
		f.note("azupdate")
		if f.azErr != nil {
			return nodeapi.AZUpdateState{}, f.azErr
		}
		return nodeapi.AZUpdateState{Status: nodeapi.AZStatusRunning, Started: time.Now()}, nil
	}
	f.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) {
		return nodeapi.AZUpdateState{Status: nodeapi.AZStatusOK, Started: time.Now().Add(time.Second)}, nil
	}
	return f
}

var logMu sync.Mutex

func (f *syncFake) note(s string) {
	logMu.Lock()
	defer logMu.Unlock()
	*f.log = append(*f.log, f.name+":"+s)
}

func (f *syncFake) set(path, content string) {
	f.mu.Lock()
	f.files[path] = []byte(content)
	f.mu.Unlock()
}

func (f *syncFake) get(path string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[path]
	return string(b), ok
}

func (f *syncFake) SyncManifest(context.Context) (nodeapi.SyncManifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var m nodeapi.SyncManifest
	for p, b := range f.files {
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, nodeapi.SyncEntry{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b)), Mode: "0640"})
	}
	for i := range m.Files { // порядок по пути
		for j := i + 1; j < len(m.Files); j++ {
			if m.Files[j].Path < m.Files[i].Path {
				m.Files[i], m.Files[j] = m.Files[j], m.Files[i]
			}
		}
	}
	return m, nil
}

func (f *syncFake) SyncFile(_ context.Context, path string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[path]
	if !ok {
		return nil, &nodeapi.Error{Status: 404, Message: "нет файла"}
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *syncFake) SyncApply(_ context.Context, r io.Reader, _ nodeapi.SyncApplyOpts) (nodeapi.Task, error) {
	f.note("apply")
	if f.applyErr != nil {
		return nodeapi.Task{}, f.applyErr
	}
	tr := tar.NewReader(r)
	files := map[string][]byte{}
	var rm []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nodeapi.Task{}, err
		}
		b, _ := io.ReadAll(tr)
		if h.Name == nodeapi.SyncRemoveEntry {
			json.Unmarshal(b, &rm)
			continue
		}
		files[h.Name] = b
	}
	f.mu.Lock()
	for p, b := range files {
		f.files[p] = b
	}
	for _, p := range rm {
		delete(f.files, p)
	}
	f.removed = append(f.removed, rm...)
	f.mu.Unlock()
	return nodeapi.Task{ID: "0123456789ab"}, nil
}

func (f *syncFake) SyncRole(context.Context) (nodeapi.SyncRole, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.role.Role == "" {
		return nodeapi.SyncRole{Role: nodeapi.RolePrimary}, nil
	}
	return f.role, nil
}

func (f *syncFake) SetSyncRole(_ context.Context, r nodeapi.SyncRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.role.Role == "down" {
		return errors.New("узел не отвечает")
	}
	f.role = r
	f.noteLocked("role=" + r.Role)
	return nil
}

func (f *syncFake) CreateBackup(context.Context) (nodeapi.Task, error) {
	f.note("backup")
	return nodeapi.Task{ID: "0123456789ab"}, nil
}

type groupTest struct {
	*testEnv
	c       *http.Cookie
	csrf    string
	log     []string
	primary *syncFake
	replica *syncFake
	fakes   map[string]*syncFake
	repID   int64
}

// groupEnv: локальный узел — основной будущей группы, «r1» — удалённый узел-реплика.
func groupEnv(t *testing.T) *groupTest {
	t.Helper()
	e, c, csrf := nodesEnv(t)
	oldPoll, oldAZ := taskPoll, azPoll
	taskPoll, azPoll = time.Millisecond, time.Millisecond
	t.Cleanup(func() { taskPoll, azPoll = oldPoll, oldAZ })
	g := &groupTest{testEnv: e, c: c, csrf: csrf, fakes: map[string]*syncFake{}}
	g.primary = newSyncFake("p", &g.log)
	g.replica = newSyncFake("r1", &g.log)
	g.fakes["r1"] = g.replica
	e.srv.Node, e.srv.Svc = g.primary, g.primary
	e.srv.hub.inline = true
	e.srv.hub.dial = func(rec store.NodeRec, _ string) (any, error) {
		if f, ok := g.fakes[rec.Name]; ok {
			return f, nil
		}
		return nil, errors.New("нет такого поддельного узла")
	}
	g.repID = g.addNode(t, "r1")
	// набор основного
	g.primary.set(pathLimits, "{}")
	g.primary.set(pathHosts, "a.example\n")
	g.primary.set(pathSetup, "OPENVPN_HOST=\n")
	g.primary.set(pathProf, "remote old.example 1194 udp\nclient\n")
	return g
}

func (g *groupTest) addNode(t *testing.T, name string) int64 {
	t.Helper()
	sealed, err := g.srv.sealToken(testAgentToken)
	if err != nil {
		t.Fatal(err)
	}
	id, err := g.st.AddNode(context.Background(), store.NodeRec{Name: name, URL: "https://" + name + ":9100", Fingerprint: strings.Repeat("ab", 32), Token: sealed, Created: 1})
	if err != nil {
		t.Fatal(err)
	}
	g.srv.hubReload()
	return id
}

// makeGroup создаёт группу «main» с основным p и репликой r1.
func (g *groupTest) makeGroup(t *testing.T) store.Group {
	t.Helper()
	f := url.Values{"csrf": {g.csrf}, "name": {"main"}, "primary": {"1"}}
	if rec := post(g.testEnv, g.c, "/groups", f); rec.Code != 303 {
		t.Fatalf("создание группы: %d %s", rec.Code, rec.Body)
	}
	gs, _ := g.st.Groups(context.Background())
	if len(gs) != 1 {
		t.Fatalf("групп %d", len(gs))
	}
	f = url.Values{"csrf": {g.csrf}, "node": {strconv.FormatInt(g.repID, 10)}}
	if rec := post(g.testEnv, g.c, "/groups/"+strconv.FormatInt(gs[0].ID, 10)+"/members", f); rec.Code != 303 {
		t.Fatalf("добавление реплики: %d %s", rec.Code, rec.Body)
	}
	return gs[0]
}

func (g *groupTest) call(t *testing.T, path string, extra url.Values) *httptestResult {
	t.Helper()
	f := url.Values{"csrf": {g.csrf}, "confirm": {"1"}}
	for k, v := range extra {
		f[k] = v
	}
	rec := post(g.testEnv, g.c, path, f)
	return &httptestResult{Code: rec.Code, Body: rec.Body.String(), Loc: rec.Header().Get("Location")}
}

type httptestResult struct {
	Code int
	Body string
	Loc  string
}

func gpath(g store.Group, tail string) string { return "/groups/" + strconv.FormatInt(g.ID, 10) + tail }

func (g *groupTest) enableNotify() {
	g.srv.Telegram.Enabled = true
	g.srv.Telegram.Notify = []string{"sync_mismatch", "proxy_failover"}
}

func TestGroupVerifyFindsDifferencesAndNotifiesOnce(t *testing.T) {
	g := groupEnv(t)
	g.enableNotify()
	grp := g.makeGroup(t)
	// Реплика: другое содержимое списка, нет setup и профиля, лишний файл.
	g.replica.set(pathLimits, "{}")
	g.replica.set(pathHosts, "other.example\n")
	g.replica.set("/root/antizapret/client/openvpn/vpn/vpn-zed.ovpn", "x")

	if c := g.call(t, gpath(grp, "/verify"), nil); c.Code != 303 {
		t.Fatalf("verify: %d %s", c.Code, c.Body)
	}
	body := get(g.testEnv, g.c, gpath(grp, "")).Body.String()
	for _, want := range []string{pathHosts + " — содержимое отличается", pathSetup + " — нет на реплике", pathProf + " — нет на реплике", "vpn-zed.ovpn — лишний на реплике", "Нет клиентов: bob"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q в странице группы", want)
		}
	}
	kinds, texts := outboxTexts(t, g.testEnv)
	if len(kinds) != 1 || kinds[0] != "sync_mismatch" || !strings.Contains(texts[0], "main") {
		t.Fatalf("уведомления: %v %v", kinds, texts)
	}
	// Повторная сверка с тем же расхождением уведомление не множит.
	g.call(t, gpath(grp, "/verify"), nil)
	if kinds, _ = outboxTexts(t, g.testEnv); len(kinds) != 1 {
		t.Fatalf("повторное уведомление: %v", kinds)
	}
	// Выровняли — расхождений нет, метка снята: новое расхождение снова уведомит.
	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	g.call(t, gpath(grp, "/verify"), nil)
	if body = get(g.testEnv, g.c, gpath(grp, "")).Body.String(); !strings.Contains(body, "совпадает с основным") {
		t.Fatalf("после выравнивания: %s", body)
	}
	g.replica.set(pathLimits, `{"x":1}`)
	g.call(t, gpath(grp, "/verify"), nil)
	if kinds, _ = outboxTexts(t, g.testEnv); len(kinds) != 2 {
		t.Fatalf("новое расхождение не уведомило: %v", kinds)
	}
}

func TestChangeOnPrimaryGoesToReplica(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	g.log = nil
	g.primary.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}}, nil
	}
	g.primary.SetLimitFn = func(_ context.Context, name string, limit int) error {
		g.primary.set(pathLimits, fmt.Sprintf(`{"%s":%d}`, name, limit))
		g.primary.set(pathHosts, "a.example\nb.example\n")
		return nil
	}
	f := url.Values{"csrf": {g.csrf}, "limit": {"3"}}
	if rec := post(g.testEnv, g.c, "/clients/bob/limit", f); rec.Code != 303 {
		t.Fatalf("limit: %d %s", rec.Code, rec.Body)
	}
	waitFor(t, "условие", func() bool { v, _ := g.replica.get(pathLimits); return v == `{"bob":3}` })
	if v, _ := g.replica.get(pathHosts); v != "a.example\nb.example\n" {
		t.Fatalf("список на реплике: %q", v)
	}
	waitFor(t, "условие", func() bool { return logHas(&g.log, "r1:doall") })
	if logHas(&g.log, "p:apply") {
		t.Fatal("основной принял запись")
	}
}

func logHas(log *[]string, s string) bool {
	logMu.Lock()
	defer logMu.Unlock()
	for _, x := range *log {
		if x == s {
			return true
		}
	}
	return false
}

func TestChangeFailureMarksGroupAndNotifies(t *testing.T) {
	g := groupEnv(t)
	g.enableNotify()
	grp := g.makeGroup(t)
	g.replica.applyErr = errors.New("реплика отвергла набор")
	g.primary.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}}, nil
	}
	g.primary.SetLimitFn = func(context.Context, string, int) error {
		g.primary.set(pathLimits, `{"bob":1}`)
		return nil
	}
	post(g.testEnv, g.c, "/clients/bob/limit", url.Values{"csrf": {g.csrf}, "limit": {"1"}})
	waitFor(t, "условие", func() bool { kinds, _ := outboxTexts(t, g.testEnv); return len(kinds) == 1 })
	if body := get(g.testEnv, g.c, gpath(grp, "")).Body.String(); !strings.Contains(body, "Копирование изменений на реплики не удалось") {
		t.Fatalf("группа не помечена: %s", body)
	}
}

func TestAlignMakesBackupFirstAndRemovesExtras(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.replica.set(pathHosts, "stale\n")
	g.replica.set("/root/antizapret/client/openvpn/vpn/vpn-old.ovpn", "x")
	g.log = nil
	if c := g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil); c.Code != 303 {
		t.Fatalf("align: %d %s", c.Code, c.Body)
	}
	if len(g.log) < 3 || g.log[0] != "r1:backup" || g.log[1] != "r1:apply" {
		t.Fatalf("порядок вызовов: %v", g.log)
	}
	if v, _ := g.replica.get(pathHosts); v != "a.example\n" {
		t.Fatalf("список не заменён: %q", v)
	}
	if _, ok := g.replica.get("/root/antizapret/client/openvpn/vpn/vpn-old.ovpn"); ok || len(g.replica.removed) != 1 {
		t.Fatalf("лишний файл не удалён: %v", g.replica.removed)
	}
	if !logHas(&g.log, "r1:doall") {
		t.Fatalf("после замены нет применения списков: %v", g.log)
	}
	page := get(g.testEnv, g.c, gpath(grp, "")).Body.String()
	if !strings.Contains(page, "Бэкап реплики") || !strings.Contains(page, "выполнено") {
		t.Fatalf("ход операции не показан: %s", page)
	}
	// Без подтверждения ничего не делается.
	g.log = nil
	rec := post(g.testEnv, g.c, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), url.Values{"csrf": {g.csrf}})
	if rec.Code != 400 || len(g.log) != 0 {
		t.Fatalf("без подтверждения: %d %v", rec.Code, g.log)
	}
}

func TestAlignStopsWhenBackupFails(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.replica.TaskFn = func(_ context.Context, id string) (nodeapi.TaskDetail, error) {
		now, one := time.Now(), 1
		return nodeapi.TaskDetail{Task: nodeapi.Task{ID: id, Finished: &now, ExitCode: &one}, Tail: "нет места"}, nil
	}
	g.log = nil
	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	if logHas(&g.log, "r1:apply") {
		t.Fatalf("запись после неудачного бэкапа: %v", g.log)
	}
}

func TestPromoteSwapsRoles(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.log = nil
	if c := g.call(t, gpath(grp, "/promote/"+strconv.FormatInt(g.repID, 10)), nil); c.Code != 303 {
		t.Fatalf("promote: %d %s", c.Code, c.Body)
	}
	recs, _ := g.st.Nodes(context.Background())
	roles := map[string]string{}
	for _, n := range recs {
		roles[n.Name] = n.Role
	}
	if roles["r1"] != store.RolePrimary || roles["local"] != store.RoleReplica {
		t.Fatalf("роли в базе: %v", roles)
	}
	if g.replica.role.Role != nodeapi.RolePrimary || g.primary.role.Role != nodeapi.RoleReplica {
		t.Fatalf("роли на узлах: %q %q", g.replica.role.Role, g.primary.role.Role)
	}
	// Прежний основной вперёд: двух основных не бывает.
	if len(g.log) != 2 || g.log[0] != "p:role=replica" {
		t.Fatalf("порядок: %v", g.log)
	}
}

func TestPromoteWithUnreachableOldPrimaryRemovesIt(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.primary.mu.Lock()
	g.primary.role.Role = "down" // SetSyncRole теперь отказывает
	g.primary.mu.Unlock()
	if c := g.call(t, gpath(grp, "/promote/"+strconv.FormatInt(g.repID, 10)), nil); c.Code != 303 {
		t.Fatalf("promote: %d %s", c.Code, c.Body)
	}
	local, _, _ := g.st.NodeByID(context.Background(), store.LocalNode)
	rep, _, _ := g.st.NodeByID(context.Background(), g.repID)
	if local.GroupID != 0 || rep.Role != store.RolePrimary {
		t.Fatalf("local %+v, r1 %+v", local, rep)
	}
}

func TestGroupAZUpdateRepliesFirstAndStopsOnError(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.log = nil
	if c := g.call(t, gpath(grp, "/update"), nil); c.Code != 303 {
		t.Fatalf("update: %d %s", c.Code, c.Body)
	}
	if len(g.log) != 2 || g.log[0] != "r1:azupdate" || g.log[1] != "p:azupdate" {
		t.Fatalf("порядок: %v", g.log)
	}
	// Реплика не обновилась — основной не трогается.
	g.log = nil
	g.replica.AZUpdateStateFn = func(context.Context) (nodeapi.AZUpdateState, error) {
		return nodeapi.AZUpdateState{Status: nodeapi.AZStatusFailed, Started: time.Now().Add(time.Second), Reasons: []string{"setup.sh упал"}}, nil
	}
	g.call(t, gpath(grp, "/update"), nil)
	if len(g.log) != 1 || g.log[0] != "r1:azupdate" {
		t.Fatalf("после ошибки реплики: %v", g.log)
	}
	if body := get(g.testEnv, g.c, gpath(grp, "")).Body.String(); !strings.Contains(body, "остановлено на узле «r1»") {
		t.Fatalf("ошибка не показана: %s", body)
	}
	// Без подтверждения — отказ.
	g.log = nil
	if rec := post(g.testEnv, g.c, gpath(grp, "/update"), url.Values{"csrf": {g.csrf}}); rec.Code != 400 || len(g.log) != 0 {
		t.Fatalf("без подтверждения: %d %v", rec.Code, g.log)
	}
}

func TestGroupDomainWritesHostsRebuildsAndSyncs(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	g.log = nil
	g.primary.RebuildProfilesFn = func(context.Context) (nodeapi.Task, error) {
		g.primary.note("profiles")
		g.primary.set(pathProf, "remote vpn.example.org 1194 udp\nclient\n")
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	if c := g.call(t, gpath(grp, "/addrs"), url.Values{"domain": {"vpn.example.org"}, "remotes": {""}}); c.Code != 303 {
		t.Fatalf("addrs: %d %s", c.Code, c.Body)
	}
	want := []string{"p:setup:OPENVPN_HOST=vpn.example.org,WIREGUARD_HOST=vpn.example.org", "p:profiles", "r1:apply"}
	if len(g.log) < 3 || strings.Join(g.log[:3], "|") != strings.Join(want, "|") {
		t.Fatalf("порядок: %v", g.log)
	}
	if v, _ := g.replica.get(pathProf); !strings.Contains(v, "vpn.example.org") {
		t.Fatalf("профиль на реплике: %q", v)
	}
	if got, _, _ := g.st.GroupByID(context.Background(), grp.ID); got.Domain != "vpn.example.org" {
		t.Fatalf("домен: %+v", got)
	}
	// Плохой домен — отказ, ничего не меняется.
	if rec := post(g.testEnv, g.c, gpath(grp, "/addrs"), url.Values{"csrf": {g.csrf}, "domain": {"bad host!"}}); rec.Code != 400 {
		t.Fatalf("плохой домен: %d", rec.Code)
	}
}

func TestOvpnRemoteListRewritesDownloadedProfile(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	if c := g.call(t, gpath(grp, "/addrs"), url.Values{"remotes": {"one.example\r\ntwo.example:443\r\n"}}); c.Code != 303 {
		t.Fatalf("addrs: %d %s", c.Code, c.Body)
	}
	g.primary.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}}, nil
	}
	g.primary.ProfileFn = func(context.Context, string, nodeapi.Profile) ([]byte, error) {
		return []byte("client\nremote old.example 1194 udp\nremote-cert-tls server\n"), nil
	}
	rec := get(g.testEnv, g.c, "/clients/bob/profiles/openvpn/vpn/bob.ovpn")
	want := "client\nremote one.example 1194 udp\nremote two.example 443 udp\nremote-cert-tls server\n"
	if rec.Code != 200 || rec.Body.String() != want {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestRewriteOvpn(t *testing.T) {
	in := "a\r\nremote x 1 tcp\r\nremote y 2 tcp\r\nb\r\n"
	got := string(rewriteOvpn([]byte(in), []string{"h1", "h2:9"}))
	if got != "a\r\nremote h1 1 tcp\r\nremote h2 9 tcp\r\nb\r\n" {
		t.Fatalf("%q", got)
	}
	if string(rewriteOvpn([]byte("no remote here"), []string{"h"})) != "no remote here" {
		t.Fatal("без remote файл не меняется")
	}
	if string(rewriteOvpn([]byte(in), nil)) != in {
		t.Fatal("пустой список не меняет файл")
	}
}

func TestReplicaNodeHidesWritesAndShowsBanner(t *testing.T) {
	g := groupEnv(t)
	g.makeGroup(t)
	g.replica.ClientsFn = func(context.Context) ([]nodeapi.Client, error) { return nil, nil }
	g.replica.SessionsFn = func(context.Context) ([]nodeapi.Session, error) { return nil, nil }
	body := get(g.testEnv, g.c, "/?node="+strconv.FormatInt(g.repID, 10)).Body.String()
	if !strings.Contains(body, "реплика группы «main»") || strings.Contains(body, "Новый клиент") {
		t.Fatalf("реплика: %s", body)
	}
}

func TestGroupDeleteResetsRoles(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	if c := g.call(t, gpath(grp, "/delete"), nil); c.Code != 303 {
		t.Fatalf("delete: %d %s", c.Code, c.Body)
	}
	if gs, _ := g.st.Groups(context.Background()); len(gs) != 0 {
		t.Fatalf("группа осталась: %+v", gs)
	}
	if g.replica.role.Role != nodeapi.RolePrimary {
		t.Fatalf("роль реплики не сброшена: %+v", g.replica.role)
	}
}

func (f *syncFake) noteLocked(s string) {
	logMu.Lock()
	defer logMu.Unlock()
	*f.log = append(*f.log, f.name+":"+s)
}

func TestAlignRefusedRemovalAsksForForce(t *testing.T) {
	g := groupEnv(t)
	grp := g.makeGroup(t)
	g.replica.applyErr = &nodeapi.Error{Status: 422, Message: "удаление pki/ca.crt"}
	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	if body := get(g.testEnv, g.c, gpath(grp, "")).Body.String(); !strings.Contains(body, "разрешить удаление ключевых файлов») ") && !strings.Contains(body, "агент отказал в удалении файлов") {
		t.Fatalf("нет подсказки про force: %s", body)
	}
}
