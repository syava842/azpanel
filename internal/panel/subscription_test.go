package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

var codeInPageRe = regexp.MustCompile(`[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}`)

const dayS = int64(86400)

func ptr[T any](v T) *T { return &v }

// issueFor выпускает коды напрямую через хранилище (минуя форму).
func issueFor(t *testing.T, st *store.Store, p store.IssueParams) []string {
	t.Helper()
	if p.Count == 0 {
		p.Count = 1
	}
	if p.Days == 0 {
		p.Days = 30
	}
	if p.ValidUntil == 0 {
		p.ValidUntil = histNow.Add(48 * time.Hour).Unix()
	}
	p.Now = histNow.Unix()
	_, codes, err := st.IssueCodes(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

// unblockAll: тестовый узел отдаёт всех клиентов без блокировки.
func unblockAll(e *testEnv) {
	base := e.node.ClientsFn
	e.node.ClientsFn = func(c context.Context) ([]nodeapi.Client, error) {
		list, err := base(c)
		for i := range list {
			list[i].Blocked = false
		}
		return list, err
	}
}

func redeem(e *testEnv, c *http.Cookie, csrf, client, code string) *httptest.ResponseRecorder {
	return post(e, c, "/clients/"+client+"/redeem", url.Values{"csrf": {csrf}, "code": {code}})
}

func cardUntil(t *testing.T, st *store.Store, name string) *int64 {
	t.Helper()
	c, err := st.Card(context.Background(), store.LocalNode, name)
	if err != nil {
		t.Fatal(err)
	}
	return c.AccessUntil
}

func TestRedeemExtendsFromFutureAndPast(t *testing.T) {
	e, c, csrf := storeEnv(t)
	unblockAll(e) // продление работает на клиентах без ручной блокировки
	ctx := context.Background()
	st := e.srv.Store
	st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "bob", AccessUntil: ptr(histNow.Unix() + 10*dayS)})
	codes := issueFor(t, st, store.IssueParams{Count: 2, Days: 30})
	// от будущего срока
	if rec := redeem(e, c, csrf, "bob", strings.ToLower(codes[0])); rec.Code != 303 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got := cardUntil(t, st, "bob"); got == nil || *got != histNow.Unix()+40*dayS {
		t.Fatalf("срок от будущего: %v", got)
	}
	// от прошлого срока: считается от «сейчас»
	st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "bob", AccessUntil: ptr(histNow.Unix() - 5*dayS)})
	if rec := redeem(e, c, csrf, "bob", codes[1]); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	if got := cardUntil(t, st, "bob"); got == nil || *got != histNow.Unix()+30*dayS {
		t.Fatalf("срок от прошлого: %v", got)
	}
	used, _ := st.Codes(ctx, store.CodeFilter{State: store.CodeUsed}, histNow.Unix())
	if len(used) != 2 || used[0].UsedClient != "bob" || used[0].UsedNode == nil {
		t.Fatalf("использованные коды: %+v", used)
	}
	list, _, _ := st.AuditList(ctx, 10, 0, "redeem")
	if len(list) != 2 || strings.Contains(list[0].After+list[0].Before, codes[1]) || !strings.Contains(list[0].After, "UTC") {
		t.Fatalf("журнал: %+v", list)
	}
}

func TestRedeemCertRenewedOnlyWhenMarginShort(t *testing.T) {
	e, c, csrf := storeEnv(t)
	ctx := context.Background()
	st := e.srv.Store
	far := histNow.Add(400 * 24 * time.Hour)
	soon := histNow.Add(20 * 24 * time.Hour)
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{
			{Name: "far", OpenVPN: true, CertExpires: &far},
			{Name: "soon", OpenVPN: true, CertExpires: &soon},
			{Name: "wg", WireGuard: true},
		}, nil
	}
	var renewed []string
	var renewDays int
	e.node.RenewFn = func(_ context.Context, name string, days int) (nodeapi.Result, error) {
		renewed = append(renewed, name)
		renewDays = days
		return nodeapi.Result{}, nil
	}
	for _, n := range []string{"far", "soon", "wg"} {
		st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: n, AccessUntil: ptr(histNow.Unix() + 10*dayS)})
	}
	codes := issueFor(t, st, store.IssueParams{Count: 3, Days: 30})
	for i, n := range []string{"far", "soon", "wg"} {
		if rec := redeem(e, c, csrf, n, codes[i]); rec.Code != 303 {
			t.Fatalf("%s: %d %s", n, rec.Code, rec.Body.String())
		}
	}
	// far: после продления (+40 дн.) остаётся 360 дн. — не трогаем; wg — сертификата нет
	if len(renewed) != 1 || renewed[0] != "soon" {
		t.Fatalf("перевыпущено: %v", renewed)
	}
	if renewDays < 40+30 || renewDays > 3650 {
		t.Fatalf("дней при перевыпуске: %d", renewDays)
	}
}

func TestRedeemCertErrorStillExtends(t *testing.T) {
	e, c, csrf := storeEnv(t)
	st := e.srv.Store
	soon := histNow.Add(5 * 24 * time.Hour)
	e.node.ClientsFn = func(context.Context) ([]nodeapi.Client, error) {
		return []nodeapi.Client{{Name: "soon", OpenVPN: true, CertExpires: &soon}}, nil
	}
	e.node.RenewFn = func(context.Context, string, int) (nodeapi.Result, error) {
		return nodeapi.Result{}, &nodeapi.Error{Status: 500, Message: "client.sh упал"}
	}
	st.SaveCard(context.Background(), store.Card{Node: store.LocalNode, Name: "soon", AccessUntil: ptr(histNow.Unix() + dayS)})
	codes := issueFor(t, st, store.IssueParams{})
	rec := redeem(e, c, csrf, "soon", codes[0])
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "сертификат не перевыпущен") {
		t.Fatalf("%d", rec.Code)
	}
	if got := cardUntil(t, st, "soon"); got == nil || *got != histNow.Unix()+31*dayS {
		t.Fatalf("срок: %v", got)
	}
}

func TestRedeemUserBoundCodeOnlyForOwnersClients(t *testing.T) {
	e, c, csrf := storeEnv(t)
	unblockAll(e) // продление работает на клиентах без ручной блокировки
	ctx := context.Background()
	st := e.srv.Store
	alice, _ := st.CreateUser(ctx, store.User{Login: "alice", Hash: "x", Role: store.RoleUser})
	carol, _ := st.CreateUser(ctx, store.User{Login: "carol", Hash: "x", Role: store.RoleUser})
	st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "bob", AccessUntil: ptr(histNow.Unix() + dayS)})
	st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "azpanel-test-1", AccessUntil: ptr(histNow.Unix() + dayS)})
	st.SetOwner(ctx, store.LocalNode, "bob", &carol.ID)
	st.SetOwner(ctx, store.LocalNode, "azpanel-test-1", &alice.ID)
	e.node.RenewFn = func(context.Context, string, int) (nodeapi.Result, error) { return nodeapi.Result{}, nil }
	codes := issueFor(t, st, store.IssueParams{UserID: &alice.ID, Count: 1})
	// клиент carol — отказ, код цел
	if rec := redeem(e, c, csrf, "bob", codes[0]); rec.Code != 400 || !strings.Contains(rec.Body.String(), "код неверен или уже использован") {
		t.Fatalf("чужой клиент: %d", rec.Code)
	}
	// клиент без владельца — тоже отказ
	if rec := redeem(e, c, csrf, "wg-only", codes[0]); rec.Code != 400 {
		t.Fatalf("без владельца: %d", rec.Code)
	}
	if got := cardUntil(t, st, "bob"); *got != histNow.Unix()+dayS {
		t.Fatal("срок чужого клиента изменён")
	}
	// клиент alice — успех
	if rec := redeem(e, c, csrf, "azpanel-test-1", codes[0]); rec.Code != 303 {
		t.Fatalf("свой клиент: %d", rec.Code)
	}
}

func TestRedeemOnceAndParallel(t *testing.T) {
	e, c, csrf := storeEnv(t)
	unblockAll(e) // продление работает на клиентах без ручной блокировки
	st := e.srv.Store
	st.SaveCard(context.Background(), store.Card{Node: store.LocalNode, Name: "bob", AccessUntil: ptr(histNow.Unix() + dayS)})
	codes := issueFor(t, st, store.IssueParams{Count: 2, Days: 10})
	if rec := redeem(e, c, csrf, "bob", codes[0]); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	if rec := redeem(e, c, csrf, "bob", codes[0]); rec.Code != 400 {
		t.Fatalf("повторный ввод: %d", rec.Code)
	}
	// два параллельных ввода второго кода — один успех
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := redeem(e, c, csrf, "bob", codes[1]); rec.Code == 303 {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("успехов %d, ждали 1", ok)
	}
	if got := cardUntil(t, st, "bob"); *got != histNow.Unix()+21*dayS { // 1 + 10 + 10
		t.Fatalf("срок после двух кодов: %d дн.", (*got-histNow.Unix())/dayS)
	}
}

func TestRedeemClientWithoutLimitKeepsCode(t *testing.T) {
	e, c, csrf := storeEnv(t)
	st := e.srv.Store
	codes := issueFor(t, st, store.IssueParams{})
	rec := redeem(e, c, csrf, "bob", codes[0]) // карточки нет — срока нет
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "продлевать нечего") {
		t.Fatalf("%d", rec.Code)
	}
	left, _ := st.Codes(context.Background(), store.CodeFilter{State: store.CodeActive}, histNow.Unix())
	if len(left) != 1 {
		t.Fatalf("код погашен зря: %+v", left)
	}
}

func TestRedeemExtendsOwnerLimit(t *testing.T) {
	e, _, _, _, bob := userEnv(t)
	unblockAll(e) // продление работает на клиентах без ручной блокировки
	st := e.srv.Store
	e.srv.Now = func() time.Time { return histNow }
	user, s := e.sessionFor(t, bob, false)
	st.SetUserAccessUntil(context.Background(), bob.ID, ptr(histNow.Unix()-dayS)) // срок пользователя прошёл
	codes := issueFor(t, st, store.IssueParams{Days: 30})
	// чужой клиент — 404, код цел
	if rec := redeem(e, user, s.CSRF, foreignClient, codes[0]); rec.Code != 404 {
		t.Fatalf("чужой: %d", rec.Code)
	}
	if rec := redeem(e, user, s.CSRF, ownClient, codes[0]); rec.Code != 303 {
		t.Fatalf("свой: %d %s", rec.Code, rec.Body.String())
	}
	u, _ := st.UserByID(context.Background(), bob.ID)
	if u.AccessUntil == nil || *u.AccessUntil != histNow.Unix()+30*dayS {
		t.Fatalf("срок пользователя: %v", u.AccessUntil)
	}
	eff, _ := st.EffectiveUntil(context.Background(), store.LocalNode, ownClient)
	if eff == nil || *eff != histNow.Unix()+30*dayS {
		t.Fatalf("действующий срок: %v", eff)
	}
}

// --- страницы кодов ---

func issueViaForm(e *testEnv, c *http.Cookie, csrf string, f url.Values) (code int, body string) {
	f.Set("csrf", csrf)
	rec := post(e, c, "/codes", f)
	return rec.Code, rec.Body.String()
}

func TestCodesIssueValidation(t *testing.T) {
	e, c, csrf := storeEnv(t)
	good := func() url.Values {
		return url.Values{"count": {"3"}, "days": {"30"}, "until": {"2026-12-31"}, "user": {""}}
	}
	for name, mut := range map[string]func(url.Values){
		"ноль кодов":     func(v url.Values) { v.Set("count", "0") },
		"501 код":        func(v url.Values) { v.Set("count", "501") },
		"ноль дней":      func(v url.Values) { v.Set("days", "0") },
		"3651 день":      func(v url.Values) { v.Set("days", "3651") },
		"дата прошла":    func(v url.Values) { v.Set("until", "2026-11-01") },
		"нет даты":       func(v url.Values) { v.Set("until", "") },
		"мусор в дате":   func(v url.Values) { v.Set("until", "31.12.2026") },
		"нет пользов.":   func(v url.Values) { v.Set("user", "9999") },
		"пользов. мусор": func(v url.Values) { v.Set("user", "abc") },
	} {
		v := good()
		mut(v)
		if code, _ := issueViaForm(e, c, csrf, v); code != 400 {
			t.Errorf("%s: код %d, ждали 400", name, code)
		}
	}
	all, _ := e.srv.Store.Codes(context.Background(), store.CodeFilter{}, histNow.Unix())
	if len(all) != 0 {
		t.Fatalf("при ошибках выпущено %d кодов", len(all))
	}
	// границы допустимого
	v := good()
	v.Set("count", "500")
	v.Set("days", "3650")
	if code, _ := issueViaForm(e, c, csrf, v); code != 303 {
		t.Fatalf("500 кодов на 3650 дней: %d", code)
	}
}

func TestCodesIssueShowOnceAndDownload(t *testing.T) {
	e, c, csrf := storeEnv(t)
	code, _ := issueViaForm(e, c, csrf, url.Values{"count": {"3"}, "days": {"30"}, "until": {"2026-12-31"}})
	if code != 303 {
		t.Fatalf("%d", code)
	}
	page := get(e, c, pathAccountOnce)
	body := page.Body.String()
	all3 := codeInPageRe.FindAllString(body, -1) // каждый код дважды: в тексте и в форме скачивания
	if len(all3) != 6 {
		t.Fatalf("упоминаний кодов: %d", len(all3))
	}
	shown := all3[:3]
	if page.Code != 200 || !strings.Contains(body, "Скачать .txt") {
		t.Fatalf("страница кодов: %d, кодов %d", page.Code, len(shown))
	}
	// коды в базе — только хеши; погасить показанный код можно
	if _, err := e.srv.Store.RedeemCode(context.Background(), shown[0], nil, 1, "x", histNow.Unix()); err != nil {
		t.Fatalf("показанный код не подходит: %v", err)
	}
	// второй показ — пусто: уходит на аккаунт
	if again := get(e, c, pathAccountOnce); again.Code != http.StatusSeeOther {
		t.Fatalf("повторный показ: %d", again.Code)
	}
	// список не содержит открытых кодов
	list := get(e, c, "/codes").Body.String()
	if codeInPageRe.MatchString(list) {
		t.Fatal("в списке открытый код")
	}
	// скачивание
	all, _ := e.srv.Store.Codes(context.Background(), store.CodeFilter{}, histNow.Unix())
	batch := all[0].Batch
	rec := post(e, c, "/codes/download", url.Values{"csrf": {csrf}, "batch": {batch},
		"codes": {strings.Join(shown, ",") + ",мусор,<script>"}})
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment;") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), batch+".txt") ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("заголовки: %v", rec.Header())
	}
	if got := strings.Fields(rec.Body.String()); len(got) != 3 || strings.Contains(rec.Body.String(), "script") {
		t.Fatalf("тело: %q", rec.Body.String())
	}
	if bad := post(e, c, "/codes/download", url.Values{"csrf": {csrf}, "batch": {"../x"}}); bad.Code != 400 {
		t.Fatalf("плохая пачка: %d", bad.Code)
	}
}

func TestCodesListStatesAndRevoke(t *testing.T) {
	e, c, csrf := storeEnv(t)
	ctx := context.Background()
	st := e.srv.Store
	alice, _ := st.CreateUser(ctx, store.User{Login: "alice", Hash: "x", Role: store.RoleUser})
	active := issueFor(t, st, store.IssueParams{Count: 3, UserID: &alice.ID})
	_, expired, err := st.IssueCodes(ctx, store.IssueParams{Count: 1, Days: 5, ValidUntil: histNow.Unix() - 10, CreatedBy: "root", Now: histNow.Unix() - 100})
	if err != nil || len(expired) != 1 {
		t.Fatal(err)
	}
	st.RedeemCode(ctx, active[0], &alice.ID, store.LocalNode, "azpanel-test-1", histNow.Unix()-60)
	all, _ := st.Codes(ctx, store.CodeFilter{}, histNow.Unix())
	var revokeID int64
	var activeBatch string
	for _, x := range all {
		if x.State(histNow.Unix()) == store.CodeActive {
			revokeID, activeBatch = x.ID, x.Batch
		}
	}
	body := get(e, c, "/codes").Body.String()
	for _, want := range []string{"не использован", "использован", "просрочен", "alice", "azpanel-test-1", "UTC"} {
		if !strings.Contains(body, want) {
			t.Errorf("в списке нет %q", want)
		}
	}
	// отзыв одного кода
	if rec := post(e, c, "/codes/"+strconv.FormatInt(revokeID, 10)+"/revoke", url.Values{"csrf": {csrf}}); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	rv, _ := st.Codes(ctx, store.CodeFilter{State: store.CodeRevoked}, histNow.Unix())
	if len(rv) != 1 || rv[0].ID != revokeID {
		t.Fatalf("отозванные: %+v", rv)
	}
	// отзыв использованного — 404
	var usedID int64
	us, _ := st.Codes(ctx, store.CodeFilter{State: store.CodeUsed}, histNow.Unix())
	if len(us) > 0 {
		usedID = us[0].ID
	}
	if rec := post(e, c, "/codes/"+strconv.FormatInt(usedID, 10)+"/revoke", url.Values{"csrf": {csrf}}); rec.Code != 404 {
		t.Fatalf("отзыв использованного: %d", rec.Code)
	}
	// отзыв пачки
	if rec := post(e, c, "/codes/batch/"+activeBatch+"/revoke", url.Values{"csrf": {csrf}}); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	if act, _ := st.Codes(ctx, store.CodeFilter{State: store.CodeActive}, histNow.Unix()); len(act) != 0 {
		t.Fatalf("после отзыва пачки остались активные: %d", len(act))
	}
	// фильтр по состоянию
	only := get(e, c, "/codes?state=used").Body.String()
	if !strings.Contains(only, "azpanel-test-1") {
		t.Error("фильтр used не показал использованный код")
	}
}

// --- «доступ до» пользователя ---

func TestUserAccessUntilForm(t *testing.T) {
	e, _, _, _, bob := userEnv(t)
	e.srv.Now = func() time.Time { return histNow }
	ac, as := e.sessionFor(t, e.admin, false)
	path := "/users/" + strconv.FormatInt(bob.ID, 10) + "/access"
	if rec := post(e, ac, path, url.Values{"csrf": {as.CSRF}, "until": {"31.12.2026"}}); rec.Code != 400 {
		t.Fatalf("плохая дата: %d", rec.Code)
	}
	if rec := post(e, ac, path, url.Values{"csrf": {as.CSRF}, "until": {"2026-12-31"}}); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	u, _ := e.srv.Store.UserByID(context.Background(), bob.ID)
	want := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
	if u.AccessUntil == nil || *u.AccessUntil != want {
		t.Fatalf("срок: %v", u.AccessUntil)
	}
	page := get(e, ac, "/users/"+strconv.FormatInt(bob.ID, 10)).Body.String()
	if !strings.Contains(page, "2026-12-31 23:59 UTC") || !strings.Contains(page, `value="2026-12-31"`) {
		t.Error("на странице пользователя нет срока")
	}
	list, _, _ := e.srv.Store.AuditList(context.Background(), 5, 0, "user_access")
	if len(list) != 1 || !strings.Contains(list[0].After, "2026-12-31") {
		t.Fatalf("журнал: %+v", list)
	}
	// пусто — снять срок; прочие поля пользователя целы
	if rec := post(e, ac, path, url.Values{"csrf": {as.CSRF}, "until": {""}}); rec.Code != 303 {
		t.Fatalf("%d", rec.Code)
	}
	if u, _ := e.srv.Store.UserByID(context.Background(), bob.ID); u.AccessUntil != nil || u.Login != "bob-user" {
		t.Fatalf("после снятия: %+v", u)
	}
}

func TestCardShowsEffectiveUntilAndRedeemForm(t *testing.T) {
	e, c, _ := storeEnv(t)
	ctx := context.Background()
	alice, _ := e.srv.Store.CreateUser(ctx, store.User{Login: "alice", Hash: "x", Role: store.RoleUser})
	e.srv.Store.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "bob", AccessUntil: ptr(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Unix())})
	e.srv.Store.SetOwner(ctx, store.LocalNode, "bob", &alice.ID)
	e.srv.Store.SetUserAccessUntil(ctx, alice.ID, ptr(time.Date(2026, 12, 1, 8, 30, 0, 0, time.UTC).Unix()))
	body := get(e, c, "/clients/bob").Body.String()
	if !strings.Contains(body, "<dt>Действует до</dt><dd>2026-12-01 08:30 UTC</dd>") || !strings.Contains(body, `action="/clients/bob/redeem"`) {
		t.Errorf("карточка: нет действующего срока или формы кода")
	}
}

// --- сборщик: срок владельца, напоминания ---

func TestCollectorBlocksByOwnerLimit(t *testing.T) {
	e := newCollEnv(t)
	ctx := context.Background()
	u, _ := e.st.CreateUser(ctx, store.User{Login: "alice", Hash: "x", Role: store.RoleUser})
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}, {Name: "w", WireGuard: true}}
	future := e.now.Add(100 * 24 * time.Hour).Unix()
	for _, n := range []string{"a", "w"} {
		e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: n, AccessUntil: &future})
		e.st.SetOwner(ctx, store.LocalNode, n, &u.ID)
	}
	e.st.SetUserAccessUntil(ctx, u.ID, ptr(e.now.Add(-time.Hour).Unix()))
	e.tick(t)
	if len(e.blocks) != 2 {
		t.Fatalf("блокировки: %v", e.blocks)
	}
	if c, _ := e.st.Card(ctx, store.LocalNode, "a"); c.AutoBlock != store.AutoBlockExpired || *c.AccessUntil != future {
		t.Fatalf("карточка: %+v", c)
	}
	// срок пользователя продлён — разблокировка обоих
	e.st.SetUserAccessUntil(ctx, u.ID, ptr(e.now.Add(24*time.Hour).Unix()))
	e.tick(t)
	if len(e.blocks) != 4 || e.blocks[2] == e.blocks[3] {
		t.Fatalf("блокировки: %v", e.blocks)
	}
	for _, b := range e.blocks[2:] {
		if !strings.HasSuffix(b, ":false") {
			t.Fatalf("блокировки: %v", e.blocks)
		}
	}
}

func remindEnv(t *testing.T) (*collEnv, store.User) {
	t.Helper()
	e := newCollEnv(t)
	u, _ := e.st.CreateUser(context.Background(), store.User{Login: "alice", Hash: "x", Role: store.RoleUser})
	e.clients = []nodeapi.Client{{Name: "a", OpenVPN: true}, {Name: "b", WireGuard: true}}
	return e, u
}

func pending(t *testing.T, st *store.Store) []store.OutboxItem {
	t.Helper()
	p, err := st.Pending(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRemindersThreeDaysAndTodayOnce(t *testing.T) {
	e, u := remindEnv(t)
	ctx := context.Background()
	// сейчас среда 2026-11-04 10:00 UTC; до пятницы-воскресенья
	in3 := time.Date(2026, 11, 7, 23, 59, 59, 0, time.UTC).Unix()
	today := time.Date(2026, 11, 4, 23, 59, 59, 0, time.UTC).Unix()
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a"})
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "b"})
	e.st.SetOwner(ctx, store.LocalNode, "a", &u.ID)
	e.st.SetOwner(ctx, store.LocalNode, "b", &u.ID)
	e.st.SetUserAccessUntil(ctx, u.ID, &in3)
	e.tick(t)
	p := pending(t, e.st)
	if len(p) != 1 || p[0].Kind != "access_expiring" || p[0].UserID == nil || *p[0].UserID != u.ID {
		t.Fatalf("очередь: %+v", p)
	}
	var pl remindPayload
	if err := json.Unmarshal([]byte(p[0].Payload), &pl); err != nil || pl.Days != 3 || pl.Until != in3 || len(pl.Clients) != 2 {
		t.Fatalf("содержимое: %s %v", p[0].Payload, err)
	}
	// повторные проходы в тот же день — ничего нового
	for i := 0; i < 3; i++ {
		e.advance(time.Minute)
		e.tick(t)
	}
	if len(pending(t, e.st)) != 1 {
		t.Fatalf("напоминание повторено: %+v", pending(t, e.st))
	}
	// «сегодня»: срок карточки раньше срока пользователя, в тот же день уже не повторяется
	e.st.SaveCardFields(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &today})
	e.advance(time.Minute)
	e.tick(t)
	if len(pending(t, e.st)) != 1 {
		t.Fatal("второе напоминание в тот же день")
	}
	// на следующий день: a истекает не сегодня и не через 3 дня (вчера прошёл) — тишина;
	// b (срок пользователя 7.11) остаётся за 2 дня — тоже тишина
	e.advance(24 * time.Hour)
	e.tick(t)
	if len(pending(t, e.st)) != 1 {
		t.Fatalf("лишнее напоминание: %+v", pending(t, e.st))
	}
}

func TestRemindersTodayAndNotBefore9(t *testing.T) {
	e, u := remindEnv(t)
	ctx := context.Background()
	today := time.Date(2026, 11, 4, 23, 59, 59, 0, time.UTC).Unix()
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &today})
	e.st.SetOwner(ctx, store.LocalNode, "a", &u.ID)
	e.now = time.Date(2026, 11, 4, 8, 59, 0, 0, time.UTC)
	e.tick(t)
	if len(pending(t, e.st)) != 0 {
		t.Fatal("напоминание до 09:00 UTC")
	}
	e.advance(2 * time.Minute) // 09:01
	e.tick(t)
	p := pending(t, e.st)
	if len(p) != 1 {
		t.Fatalf("очередь: %+v", p)
	}
	var pl remindPayload
	json.Unmarshal([]byte(p[0].Payload), &pl)
	if pl.Days != 0 || len(pl.Clients) != 1 || pl.Clients[0] != "a" {
		t.Fatalf("содержимое: %s", p[0].Payload)
	}
}

func TestRemindersSkipUnownedExpiredAndNoLimit(t *testing.T) {
	e, u := remindEnv(t)
	ctx := context.Background()
	in3 := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).Unix()
	past := e.now.Add(-time.Hour).Unix()
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "a", AccessUntil: &in3})  // без владельца
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "b", AccessUntil: &past}) // уже истёк
	e.st.SetOwner(ctx, store.LocalNode, "b", &u.ID)
	e.st.SaveCard(ctx, store.Card{Node: store.LocalNode, Name: "c"}) // без срока
	e.st.SetOwner(ctx, store.LocalNode, "c", &u.ID)
	e.tick(t)
	if p := pending(t, e.st); len(p) != 0 {
		t.Fatalf("очередь: %+v", p)
	}
}
