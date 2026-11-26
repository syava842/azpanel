package panel

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

// alignedGroup — группа «main», реплика выровнена, журнал вызовов очищен.
func alignedGroup(t *testing.T) (*groupTest, store.Group) {
	t.Helper()
	g := groupEnv(t)
	g.enableNotify()
	grp := g.makeGroup(t)
	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	if rep, err := g.srv.verifyGroup(context.Background(), grp); err != nil || !rep.InSync() {
		t.Fatalf("после выравнивания: %+v %v", rep, err)
	}
	logMu.Lock()
	g.log = nil
	logMu.Unlock()
	return g, grp
}

func outboxLen(t *testing.T, e *testEnv) int {
	t.Helper()
	kinds, _ := outboxTexts(t, e)
	return len(kinds)
}

// Правка на основном мимо панели (client.sh, cron) уходит на реплику по
// таймеру сама, без «Выровнять» и без уведомления; limits.json не требует ни
// doall, ни перезапуска AntiZapret. Проход без расхождений ничего не пишет.
func TestGroupWatchCopiesConsoleChange(t *testing.T) {
	g, grp := alignedGroup(t)
	before := outboxLen(t, g.testEnv)
	g.primary.set(pathLimits, `{"bob":2}`)

	g.srv.verifyAllGroups(context.Background())
	if v, _ := g.replica.get(pathLimits); v != `{"bob":2}` {
		t.Fatalf("limits.json на реплике: %q", v)
	}
	if logHas(&g.log, "r1:doall") || logHas(&g.log, "r1:restart") {
		t.Fatalf("doall или перезапуск из-за limits.json: %v", g.log)
	}
	if n := outboxLen(t, g.testEnv); n != before {
		t.Fatalf("уведомление при успешном копировании: %d → %d", before, n)
	}
	rt := g.srv.runtime(grp.ID)
	g.srv.hub.mu.Lock()
	inSync := rt.report != nil && rt.report.InSync()
	g.srv.hub.mu.Unlock()
	if !inSync {
		t.Fatal("итог прохода — не «совпадает»")
	}

	logMu.Lock()
	g.log = nil
	logMu.Unlock()
	g.srv.verifyAllGroups(context.Background())
	if logHas(&g.log, "r1:apply") {
		t.Fatalf("проход без расхождений писал на реплику: %v", g.log)
	}
}

// Список маршрутизации требует doall на реплике, но не перезапуска AntiZapret.
func TestGroupWatchRoutingChangeRunsDoallOnly(t *testing.T) {
	g, _ := alignedGroup(t)
	g.primary.set(pathHosts, "a.example\nc.example\n")
	g.srv.verifyAllGroups(context.Background())
	if v, _ := g.replica.get(pathHosts); v != "a.example\nc.example\n" {
		t.Fatalf("список на реплике: %q", v)
	}
	if !logHas(&g.log, "r1:doall") {
		t.Fatalf("нет doall после смены списка: %v", g.log)
	}
	if logHas(&g.log, "r1:restart") {
		t.Fatalf("перезапуск AntiZapret из-за списка: %v", g.log)
	}
}

// Отказ агента (422, защита от удаления) — одно уведомление на причину, а
// группа помечена; защита не ослаблена (force не посылается).
func TestGroupWatchRefusedCopyNotifiesOnce(t *testing.T) {
	g, grp := alignedGroup(t)
	before := outboxLen(t, g.testEnv)
	g.replica.applyErr = &nodeapi.Error{Status: 422, Message: "удаление pki/ca.crt"}
	g.primary.set(pathLimits, `{"bob":5}`)

	g.srv.verifyAllGroups(context.Background())
	g.srv.verifyAllGroups(context.Background())
	kinds, texts := outboxTexts(t, g.testEnv)
	if len(kinds) != before+1 || kinds[len(kinds)-1] != "sync_mismatch" || !strings.Contains(texts[len(texts)-1], "агент отказал в удалении файлов") {
		t.Fatalf("уведомления: %v %v", kinds, texts)
	}
	if body := get(g.testEnv, g.c, gpath(grp, "")).Body.String(); !strings.Contains(body, "по таймеру не удалось") {
		t.Fatalf("группа не помечена: %s", body)
	}
	// Причина ушла — копирование прошло, метка снята.
	g.replica.applyErr = nil
	g.srv.verifyAllGroups(context.Background())
	if v, _ := g.replica.get(pathLimits); v != `{"bob":5}` {
		t.Fatalf("после снятия отказа: %q", v)
	}
	if body := get(g.testEnv, g.c, gpath(grp, "")).Body.String(); strings.Contains(body, "по таймеру не удалось") {
		t.Fatal("метка ошибки не снята")
	}
}

// Группа занята операцией — проход таймера её не трогает.
func TestGroupWatchSkipsBusyGroup(t *testing.T) {
	g, grp := alignedGroup(t)
	g.primary.set(pathLimits, `{"bob":7}`)
	unlock := g.srv.hub.groupMu.Lock(groupKey(grp.ID))
	g.srv.verifyAllGroups(context.Background())
	unlock()
	if logHas(&g.log, "r1:apply") {
		t.Fatalf("копирование при занятой группе: %v", g.log)
	}
}

// Задача на основном копируется по успешному завершению, а не после запуска;
// неуспешная не копируется вовсе.
func TestTaskStartSyncsAfterFinish(t *testing.T) {
	g, _ := alignedGroup(t)
	var done atomic.Bool
	var exit atomic.Int32
	g.primary.TaskFn = func(_ context.Context, id string) (nodeapi.TaskDetail, error) {
		if !done.Load() {
			return nodeapi.TaskDetail{Task: nodeapi.Task{ID: id}}, nil
		}
		now, code := time.Now(), int(exit.Load())
		return nodeapi.TaskDetail{Task: nodeapi.Task{ID: id, Finished: &now, ExitCode: &code}}, nil
	}
	g.primary.ApplyRoutingFn = func(context.Context) (nodeapi.Task, error) {
		g.primary.set(pathHosts, "half.example\n") // промежуточный список
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	if rec := post(g.testEnv, g.c, "/tasks/start", url.Values{"csrf": {g.csrf}, "kind": {"doall"}}); rec.Code != 303 {
		t.Fatalf("tasks/start: %d %s", rec.Code, rec.Body)
	}
	time.Sleep(100 * time.Millisecond)
	if logHas(&g.log, "r1:apply") {
		t.Fatal("копирование ушло до конца задачи")
	}
	g.primary.set(pathHosts, "full.example\n")
	done.Store(true)
	waitFor(t, "копирование после задачи", func() bool { v, _ := g.replica.get(pathHosts); return v == "full.example\n" })

	// Задача с ошибкой: на реплику ничего не уходит.
	logMu.Lock()
	g.log = nil
	logMu.Unlock()
	exit.Store(1)
	g.primary.ApplyRoutingFn = func(context.Context) (nodeapi.Task, error) {
		g.primary.set(pathHosts, "broken.example\n")
		return nodeapi.Task{ID: "0123456789ac"}, nil
	}
	post(g.testEnv, g.c, "/tasks/start", url.Values{"csrf": {g.csrf}, "kind": {"doall"}})
	time.Sleep(200 * time.Millisecond)
	if logHas(&g.log, "r1:apply") {
		t.Fatal("неуспешная задача скопирована")
	}
}

// Клиенты без сертификата (только сеанс или limits.json) расхождением не
// считаются ни на основном, ни на реплике; клиент WireGuard с пометкой NoCert
// — настоящий и сверяется.
func TestGroupVerifyIgnoresNoCertClients(t *testing.T) {
	g, grp := alignedGroup(t)
	g.primary.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}, {Name: "ghost", OpenVPN: true, NoCert: true}}, nil
	}
	g.replica.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}, {Name: "ghost2", OpenVPN: true, NoCert: true}}, nil
	}
	rep, err := g.srv.verifyGroup(context.Background(), grp)
	if err != nil || !rep.InSync() {
		t.Fatalf("клиенты без сертификата дали расхождение: %+v %v", rep, err)
	}
	sig := rep.signature()
	// Сменился состав сеансов — подпись та же.
	g.primary.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}, {Name: "ghost3", OpenVPN: true, NoCert: true}}, nil
	}
	if rep, _ = g.srv.verifyGroup(context.Background(), grp); rep.signature() != sig {
		t.Fatal("подпись зависит от клиентов без сертификата")
	}
	g.primary.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "bob", OpenVPN: true}, {Name: "wg1", WireGuard: true, OpenVPN: true, NoCert: true}}, nil
	}
	if rep, _ = g.srv.verifyGroup(context.Background(), grp); len(rep.Replicas) != 1 || strings.Join(rep.Replicas[0].ClientsMissing, ",") != "wg1" {
		t.Fatalf("клиент WireGuard не сверен: %+v", rep)
	}
}

func TestKeyedMutexTryLock(t *testing.T) {
	var k keyedMutex
	unlock := k.Lock("a")
	if _, ok := k.TryLock("a"); ok {
		t.Fatal("TryLock взял занятый замок")
	}
	u2, ok := k.TryLock("b")
	if !ok {
		t.Fatal("TryLock не взял свободный замок")
	}
	u2()
	unlock()
	u3, ok := k.TryLock("a")
	if !ok {
		t.Fatal("замок не освободился")
	}
	u3()
	if len(k.m) != 0 {
		t.Fatalf("в карте остались записи: %d", len(k.m))
	}
}

const (
	pathCA     = "/etc/openvpn/easyrsa3/pki/ca.crt"
	pathIndex  = "/etc/openvpn/easyrsa3/pki/index.txt"
	pathWGConf = "/etc/wireguard/antizapret.conf"
)

func wgConf(privKey string, peers ...string) string {
	s := "[Interface]\nPrivateKey = " + privKey + "\nAddress = 10.29.8.1/24\n"
	for _, p := range peers {
		s += "\n[Peer]\n# Client = " + p + "\nPublicKey = pub-" + p + "\n"
	}
	return s
}

// identityGroup — выровненная группа, у основного есть CA, index.txt и
// конфиг WireGuard с пиром.
func identityGroup(t *testing.T) (*groupTest, store.Group) {
	t.Helper()
	g := groupEnv(t)
	g.enableNotify()
	g.primary.set(pathCA, "CA основного")
	g.primary.set(pathIndex, "V\tbob\n")
	g.primary.set(pathWGConf, wgConf("KEYA=", "bob"))
	grp := g.makeGroup(t)
	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	if rep, err := g.srv.verifyGroup(context.Background(), grp); err != nil || !rep.InSync() {
		t.Fatalf("после выравнивания: %+v %v", rep, err)
	}
	logMu.Lock()
	g.log = nil
	logMu.Unlock()
	return g, grp
}

// checkIdentityStop: два прохода таймера — на реплику ничего не записано,
// уведомление одно, группа помечена.
func checkIdentityStop(t *testing.T, g *groupTest, grp store.Group, before int) {
	t.Helper()
	g.srv.verifyAllGroups(context.Background())
	g.srv.verifyAllGroups(context.Background())
	if logHas(&g.log, "r1:apply") {
		t.Fatalf("на реплику с другой личностью писали: %v", g.log)
	}
	if v, _ := g.replica.get(pathLimits); v == `{"carol":1}` {
		t.Fatal("limits.json скопирован на реплику с другой личностью")
	}
	kinds, texts := outboxTexts(t, g.testEnv)
	if len(kinds) != before+1 || !strings.Contains(texts[len(texts)-1], "У основного и реплики «r1» разные CA/ключи сервера — автокопирование остановлено; проверьте и выполните «Выровнять»") {
		t.Fatalf("уведомления: %v %v", kinds, texts)
	}
	if body := get(g.testEnv, g.c, gpath(grp, "")).Body.String(); !strings.Contains(body, "разные CA/ключи сервера") {
		t.Fatalf("группа не помечена: %s", body)
	}
}

// Реплика с другим pki/ca.crt — таймер ничего не пишет, одно уведомление;
// копирование по событию — тоже стоп; «Выровнять» (ручное) копирует всё.
func TestGroupWatchStopsOnDifferentCA(t *testing.T) {
	g, grp := identityGroup(t)
	before := outboxLen(t, g.testEnv)
	g.replica.set(pathCA, "CA другого сервера")
	g.primary.set(pathLimits, `{"carol":1}`)
	checkIdentityStop(t, g, grp, before)

	if err := g.srv.syncGroup(context.Background(), grp).err(); err == nil || !strings.Contains(err.Error(), "разные CA") {
		t.Fatalf("копирование по событию: %v", err)
	}
	if logHas(&g.log, "r1:apply") {
		t.Fatal("копирование по событию записало на реплику")
	}

	g.call(t, gpath(grp, "/align/"+strconv.FormatInt(g.repID, 10)), nil)
	if v, _ := g.replica.get(pathCA); v != "CA основного" {
		t.Fatalf("«Выровнять» не заменило CA: %q", v)
	}
}

// Другой PrivateKey интерфейса WireGuard — то же самое.
func TestGroupWatchStopsOnDifferentWGKey(t *testing.T) {
	g, grp := identityGroup(t)
	before := outboxLen(t, g.testEnv)
	g.replica.set(pathWGConf, wgConf("KEYB=", "bob"))
	g.primary.set(pathLimits, `{"carol":1}`)
	checkIdentityStop(t, g, grp, before)
}

// Другие пиры WireGuard при том же ключе интерфейса и новый клиент в
// index.txt — обычное расхождение: копируются.
func TestGroupWatchCopiesWGPeers(t *testing.T) {
	g, _ := identityGroup(t)
	before := outboxLen(t, g.testEnv)
	g.primary.set(pathWGConf, wgConf("KEYA=", "bob", "carol"))
	g.primary.set(pathIndex, "V\tbob\nV\tcarol\n")
	g.srv.verifyAllGroups(context.Background())
	if v, _ := g.replica.get(pathWGConf); v != wgConf("KEYA=", "bob", "carol") {
		t.Fatalf("пиры не скопированы: %q", v)
	}
	if v, _ := g.replica.get(pathIndex); v != "V\tbob\nV\tcarol\n" {
		t.Fatalf("index.txt не скопирован: %q", v)
	}
	if n := outboxLen(t, g.testEnv); n != before {
		t.Fatalf("уведомление при обычном копировании: %d → %d", before, n)
	}
}

// Основной занят (задача или скрипт AntiZapret, агент отвечает 423) —
// проход пропущен: ни записи, ни уведомления, ни отметки; следующий
// проход копирует.
func TestGroupWatchSkipsBusyPrimary(t *testing.T) {
	g, grp := alignedGroup(t)
	before := outboxLen(t, g.testEnv)
	g.primary.set(pathLimits, `{"bob":9}`)
	g.primary.mu.Lock()
	g.primary.busy = 1
	g.primary.mu.Unlock()
	g.srv.verifyAllGroups(context.Background())
	if logHas(&g.log, "r1:apply") {
		t.Fatalf("копирование при занятом основном: %v", g.log)
	}
	if n := outboxLen(t, g.testEnv); n != before {
		t.Fatalf("уведомление о занятом основном: %d → %d", before, n)
	}
	if body := get(g.testEnv, g.c, gpath(grp, "")).Body.String(); strings.Contains(body, "не удалось") {
		t.Fatal("группа помечена ошибкой из-за занятого основного")
	}
	g.srv.verifyAllGroups(context.Background())
	if v, _ := g.replica.get(pathLimits); v != `{"bob":9}` {
		t.Fatalf("следующий проход не скопировал: %q", v)
	}
}

// Копирование после задачи ждёт, пока основной освободится (служба после
// задачи ещё гонит doall), и не шлёт уведомлений.
func TestTaskSyncWaitsWhileBusy(t *testing.T) {
	g, _ := alignedGroup(t)
	old := syncBusyPause
	syncBusyPause = time.Millisecond
	t.Cleanup(func() { syncBusyPause = old })
	before := outboxLen(t, g.testEnv)
	g.primary.set(pathLimits, `{"bob":11}`)
	g.primary.mu.Lock()
	g.primary.busy = 2
	g.primary.mu.Unlock()
	if rec := post(g.testEnv, g.c, "/tasks/start", url.Values{"csrf": {g.csrf}, "kind": {"doall"}}); rec.Code != 303 {
		t.Fatalf("tasks/start: %d %s", rec.Code, rec.Body)
	}
	waitFor(t, "копирование после занятого основного", func() bool { v, _ := g.replica.get(pathLimits); return v == `{"bob":11}` })
	if n := outboxLen(t, g.testEnv); n != before {
		t.Fatalf("уведомление: %d → %d", before, n)
	}
}

// Локальный узел (сервер панели) репликой не добавляется и в форме не
// предлагается.
func TestLocalNodeNotAddedAsReplica(t *testing.T) {
	g := groupEnv(t)
	f := url.Values{"csrf": {g.csrf}, "name": {"remote"}, "primary": {strconv.FormatInt(g.repID, 10)}}
	if rec := post(g.testEnv, g.c, "/groups", f); rec.Code != 303 {
		t.Fatalf("создание группы: %d %s", rec.Code, rec.Body)
	}
	gs, _ := g.st.Groups(context.Background())
	if len(gs) != 1 {
		t.Fatalf("групп %d", len(gs))
	}
	page := get(g.testEnv, g.c, gpath(gs[0], "")).Body.String()
	if strings.Contains(page, `<option value="1">`) {
		t.Fatal("локальный узел предложен репликой")
	}
	f = url.Values{"csrf": {g.csrf}, "node": {strconv.FormatInt(store.LocalNode, 10)}}
	rec := post(g.testEnv, g.c, gpath(gs[0], "/members"), f)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "не может быть репликой") {
		t.Fatalf("локальный узел репликой: %d %s", rec.Code, rec.Body)
	}
	if n, _, _ := g.st.NodeByID(context.Background(), store.LocalNode); n.GroupID != 0 {
		t.Fatalf("локальный узел попал в группу: %+v", n)
	}
}

// Отступ: после записи у реплики осталось то же расхождение — следующий
// проход не пишет снова и не шлёт второе уведомление; пишет, когда
// расхождение изменилось или прошло 6 часов.
func TestGroupWatchBacksOffSameLeftover(t *testing.T) {
	g, _ := alignedGroup(t)
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	g.srv.Now = func() time.Time { return time.Unix(clock.Load(), 0) }
	before := outboxLen(t, g.testEnv)
	g.replica.mu.Lock()
	g.replica.drop = pathLimits // реплика «не принимает» limits.json
	g.replica.mu.Unlock()
	g.primary.set(pathLimits, `{"bob":3}`)

	applies := func() int {
		logMu.Lock()
		defer logMu.Unlock()
		n := 0
		for _, l := range g.log {
			if l == "r1:apply" {
				n++
			}
		}
		return n
	}
	g.srv.verifyAllGroups(context.Background())
	if applies() != 1 {
		t.Fatalf("первый проход: записей %d", applies())
	}
	g.srv.verifyAllGroups(context.Background())
	g.srv.verifyAllGroups(context.Background())
	if applies() != 1 {
		t.Fatalf("то же расхождение записано снова: %d", applies())
	}
	if n := outboxLen(t, g.testEnv); n != before+1 {
		t.Fatalf("уведомлений %d, ждали одно", n-before)
	}
	// Расхождение изменилось — пишем.
	g.primary.set(pathLimits, `{"bob":4}`)
	g.srv.verifyAllGroups(context.Background())
	if applies() != 2 {
		t.Fatalf("новое расхождение не записано: %d", applies())
	}
	// До 6 часов — не пишем; прошло 6 часов — пишем снова.
	g.srv.verifyAllGroups(context.Background())
	if applies() != 2 {
		t.Fatalf("до 6 часов записано снова: %d", applies())
	}
	clock.Add(int64(6*time.Hour/time.Second) + 1)
	g.srv.verifyAllGroups(context.Background())
	if applies() != 3 {
		t.Fatalf("после 6 часов не записано: %d", applies())
	}
}
