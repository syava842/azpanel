package panel

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// proxyEnv — окружение с записью вызовов агента.
type proxyEnv struct {
	*testEnv
	cookie  *http.Cookie
	csrf    string
	patches []nodeapi.RoutingPatch
	files   []string
	applied int
	// inFile — строки allow-ips.txt на «агенте»
	inFile  []string
	patchFn func(p nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error)
}

func newProxyEnv(t *testing.T) *proxyEnv {
	t.Helper()
	e, c, sess := clientsEnv(t)
	pe := &proxyEnv{testEnv: e, cookie: c, csrf: sess.CSRF}
	e.node.PatchRoutingFn = func(_ context.Context, name string, p nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		pe.files = append(pe.files, name)
		pe.patches = append(pe.patches, p)
		if pe.patchFn != nil {
			return pe.patchFn(p)
		}
		return nodeapi.RoutingPatchResult{Applied: true, Added: len(p.Add), Removed: len(p.Remove)}, nil
	}
	e.node.RoutingLinesFn = func(_ context.Context, name string, o nodeapi.RoutingListOpts) (nodeapi.RoutingPage, error) {
		var out []string
		for _, l := range pe.inFile {
			if strings.Contains(l, o.Query) {
				out = append(out, l)
			}
		}
		return nodeapi.RoutingPage{Name: name, Lines: out, Total: len(out)}, nil
	}
	e.node.ApplyRoutingFn = func(context.Context) (nodeapi.Task, error) {
		pe.applied++
		return nodeapi.Task{ID: "t-77"}, nil
	}
	e.node.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) {
		return []nodeapi.SetupEntry{{Key: "OPENVPN_HOST", Value: "vpn.example.org", Present: true}}, nil
	}
	return pe
}

func (pe *proxyEnv) post(path string, f url.Values) (code int, loc string, body string) {
	f.Set("csrf", pe.csrf)
	rec := post(pe.testEnv, pe.cookie, path, f)
	return rec.Code, rec.Header().Get("Location"), rec.Body.String()
}

func (pe *proxyEnv) auditActions(t *testing.T) []string {
	t.Helper()
	list, _, err := pe.st.AuditList(context.Background(), 50, 0, "proxy_")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range list {
		out = append(out, a.Action+" "+a.Target)
	}
	return out
}

func TestProxyAddWritesAllowIPsAndStartsDoall(t *testing.T) {
	pe := newProxyEnv(t)
	code, loc, body := pe.post("/proxy", url.Values{"name": {"ru-1"}, "ip": {"203.0.113.5"}, "note": {"основной"}})
	if code != http.StatusSeeOther || loc != "/tasks/t-77" {
		t.Fatalf("%d %q\n%s", code, loc, body)
	}
	if len(pe.patches) != 1 || pe.files[0] != "allow-ips.txt" || len(pe.patches[0].Add) != 1 || pe.patches[0].Add[0] != "203.0.113.5/32" {
		t.Fatalf("PATCH: %v %v", pe.files, pe.patches)
	}
	if pe.applied != 1 {
		t.Fatalf("doall запущен %d раз", pe.applied)
	}
	list, _ := pe.st.Proxies(context.Background())
	if len(list) != 1 || list[0].Name != "ru-1" || list[0].Note != "основной" || !list[0].AddedByPanel || list[0].Created == 0 {
		t.Fatalf("запись: %+v", list)
	}
	if got := pe.auditActions(t); len(got) != 1 || got[0] != "proxy_add 203.0.113.5" {
		t.Fatalf("журнал: %v", got)
	}
}

// Адрес уже был в файле (дубликат — не ошибка): запись есть, но флаг «добавила
// панель» не ставится, и удаление строку не тронет.
func TestProxyAddDuplicateLineIsOKAndNotOwned(t *testing.T) {
	pe := newProxyEnv(t)
	pe.patchFn = func(nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		return nodeapi.RoutingPatchResult{Applied: false, Skipped: 1}, nil
	}
	code, loc, _ := pe.post("/proxy", url.Values{"name": {"ru-1"}, "ip": {"203.0.113.5"}})
	if code != http.StatusSeeOther || loc != "/tasks/t-77" {
		t.Fatalf("%d %q", code, loc)
	}
	list, _ := pe.st.Proxies(context.Background())
	if len(list) != 1 || list[0].AddedByPanel {
		t.Fatalf("запись: %+v", list)
	}
	pe.patches = nil
	code, loc, _ = pe.post("/proxy/"+itoa(list[0].ID)+"/delete", url.Values{})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/proxy?msg=proxy_deleted_kept") {
		t.Fatalf("удаление: %d %q", code, loc)
	}
	if len(pe.patches) != 0 {
		t.Fatalf("чужая строка тронута: %v", pe.patches)
	}
	if pe.applied != 1 {
		t.Fatalf("лишний doall: %d", pe.applied)
	}
	if left, _ := pe.st.Proxies(context.Background()); len(left) != 0 {
		t.Fatalf("запись не удалена: %+v", left)
	}
}

func TestProxyAddValidation(t *testing.T) {
	pe := newProxyEnv(t)
	for name, f := range map[string]url.Values{
		"нет имени":    {"ip": {"203.0.113.5"}},
		"не IP":        {"name": {"x"}, "ip": {"example.org"}},
		"IPv6":         {"name": {"x"}, "ip": {"2001:db8::1"}},
		"сеть":         {"name": {"x"}, "ip": {"203.0.113.0/24"}},
		"loopback":     {"name": {"x"}, "ip": {"127.0.0.1"}},
		"нули":         {"name": {"x"}, "ip": {"0.0.0.0"}},
		"с нулями":     {"name": {"x"}, "ip": {"203.000.113.5"}},
		"перевод":      {"name": {"x\ny"}, "ip": {"203.0.113.5"}},
		"длинное имя":  {"name": {strings.Repeat("я", 65)}, "ip": {"203.0.113.5"}},
		"длинная заме": {"name": {"x"}, "ip": {"203.0.113.5"}, "note": {strings.Repeat("я", 201)}},
	} {
		code, _, body := pe.post("/proxy", f)
		if code != http.StatusBadRequest {
			t.Errorf("%s: код %d\n%s", name, code, body)
		}
	}
	if len(pe.patches) != 0 || pe.applied != 0 {
		t.Fatalf("агент тронут при неверном вводе: %v %d", pe.patches, pe.applied)
	}
}

func TestProxyAddSameIPTwiceConflict(t *testing.T) {
	pe := newProxyEnv(t)
	pe.post("/proxy", url.Values{"name": {"a"}, "ip": {"203.0.113.5"}})
	pe.patches = nil
	code, _, body := pe.post("/proxy", url.Values{"name": {"b"}, "ip": {"203.0.113.5"}})
	if code != http.StatusConflict || !strings.Contains(body, "уже есть") {
		t.Fatalf("%d %s", code, body)
	}
	if len(pe.patches) != 0 {
		t.Fatal("агент тронут при повторе")
	}
}

func TestProxyAddAgentRefusal(t *testing.T) {
	pe := newProxyEnv(t)
	pe.patchFn = func(nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		return nodeapi.RoutingPatchResult{}, &nodeapi.Error{Status: 409, Message: "идёт задача"}
	}
	code, _, body := pe.post("/proxy", url.Values{"name": {"a"}, "ip": {"203.0.113.5"}})
	if code != http.StatusConflict || !strings.Contains(body, "идёт задача") {
		t.Fatalf("%d %s", code, body)
	}
	if list, _ := pe.st.Proxies(context.Background()); len(list) != 0 {
		t.Fatalf("запись создана при отказе агента: %+v", list)
	}
	if pe.applied != 0 {
		t.Fatal("doall запущен при отказе")
	}
}

// Запись есть, но doall не стартовал (идёт другая задача): остаёмся на странице.
func TestProxyAddDoallBusy(t *testing.T) {
	pe := newProxyEnv(t)
	pe.node.ApplyRoutingFn = func(context.Context) (nodeapi.Task, error) {
		return nodeapi.Task{}, &nodeapi.Error{Status: 409, Message: "занято"}
	}
	code, loc, _ := pe.post("/proxy", url.Values{"name": {"a"}, "ip": {"203.0.113.5"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/proxy?msg=proxy_apply_failed") {
		t.Fatalf("%d %q", code, loc)
	}
	if list, _ := pe.st.Proxies(context.Background()); len(list) != 1 {
		t.Fatalf("записи: %+v", list)
	}
}

func TestProxyDeleteRemovesOwnLine(t *testing.T) {
	pe := newProxyEnv(t)
	pe.post("/proxy", url.Values{"name": {"a"}, "ip": {"203.0.113.5"}})
	pe.patches, pe.applied = nil, 0
	list, _ := pe.st.Proxies(context.Background())
	code, loc, _ := pe.post("/proxy/"+itoa(list[0].ID)+"/delete", url.Values{})
	if code != http.StatusSeeOther || loc != "/tasks/t-77" {
		t.Fatalf("%d %q", code, loc)
	}
	if len(pe.patches) != 1 || len(pe.patches[0].Remove) != 1 || pe.patches[0].Remove[0] != "203.0.113.5/32" {
		t.Fatalf("PATCH: %v", pe.patches)
	}
	if pe.applied != 1 {
		t.Fatalf("doall: %d", pe.applied)
	}
	if left, _ := pe.st.Proxies(context.Background()); len(left) != 0 {
		t.Fatalf("запись осталась: %+v", left)
	}
	got := pe.auditActions(t)
	if len(got) != 2 || got[0] != "proxy_delete 203.0.113.5" {
		t.Fatalf("журнал: %v", got)
	}
}

func TestProxyDeleteAgentRefusalKeepsRecord(t *testing.T) {
	pe := newProxyEnv(t)
	pe.post("/proxy", url.Values{"name": {"a"}, "ip": {"203.0.113.5"}})
	list, _ := pe.st.Proxies(context.Background())
	pe.patchFn = func(nodeapi.RoutingPatch) (nodeapi.RoutingPatchResult, error) {
		return nodeapi.RoutingPatchResult{}, &nodeapi.Error{Status: 500, Message: "сбой"}
	}
	code, _, _ := pe.post("/proxy/"+itoa(list[0].ID)+"/delete", url.Values{})
	if code != http.StatusBadGateway {
		t.Fatalf("код %d", code)
	}
	if left, _ := pe.st.Proxies(context.Background()); len(left) != 1 {
		t.Fatal("запись удалена при отказе агента")
	}
}

func TestProxyDeleteUnknown(t *testing.T) {
	pe := newProxyEnv(t)
	for _, id := range []string{"999", "x"} {
		if code, _, _ := pe.post("/proxy/"+id+"/delete", url.Values{}); code != http.StatusNotFound {
			t.Errorf("%s: %d", id, code)
		}
	}
}

func TestProxyPageShowsPresenceAndInstruction(t *testing.T) {
	pe := newProxyEnv(t)
	pe.post("/proxy", url.Values{"name": {"ru-1"}, "ip": {"203.0.113.5"}, "note": {"заметка"}})
	pe.post("/proxy", url.Values{"name": {"ru-2"}, "ip": {"203.0.113.50"}})
	// в файле — только первый (второй — подстрока-двойник не считается)
	pe.inFile = []string{"203.0.113.5/32", "# комментарий", "198.51.100.1/32"}
	body := get(pe.testEnv, pe.cookie, "/proxy").Body.String()
	if !strings.Contains(body, "ru-1") || !strings.Contains(body, "заметка") {
		t.Fatalf("нет прокси в списке:\n%s", body)
	}
	if strings.Count(body, `<span class="ok">есть</span>`) != 1 || strings.Count(body, `<span class="bad">нет</span>`) != 1 {
		t.Fatalf("пометки наличия в allow-ips.txt:\n%s", body)
	}
	// html/template экранирует «<» в тексте
	for _, want := range []string{"bash &lt;(wget --no-hsts -qO- https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/proxy.sh)", "vpn.example.org", "root"} {
		if !strings.Contains(body, want) {
			t.Errorf("в инструкции нет %q", want)
		}
	}
}

func TestProxyPageServerAddrFallbacks(t *testing.T) {
	pe := newProxyEnv(t)
	pe.node.SetupFn = func(context.Context) ([]nodeapi.SetupEntry, error) {
		return []nodeapi.SetupEntry{{Key: "OPENVPN_HOST", Value: "", Present: true}}, nil
	}
	pe.srv.PublicURL = "https://panel.example.net/azpanel/"
	if body := get(pe.testEnv, pe.cookie, "/proxy").Body.String(); !strings.Contains(body, "panel.example.net") {
		t.Errorf("нет хоста из public_url:\n%s", body)
	}
	pe.srv.PublicURL = ""
	if body := get(pe.testEnv, pe.cookie, "/proxy").Body.String(); !strings.Contains(body, "IP этого сервера") {
		t.Errorf("нет запасной подписи:\n%s", body)
	}
}

// Агент не ответил на проверку: страница открывается, строка помечена.
func TestProxyPageCheckFailure(t *testing.T) {
	pe := newProxyEnv(t)
	pe.post("/proxy", url.Values{"name": {"ru-1"}, "ip": {"203.0.113.5"}})
	pe.node.RoutingLinesFn = func(context.Context, string, nodeapi.RoutingListOpts) (nodeapi.RoutingPage, error) {
		return nodeapi.RoutingPage{}, &nodeapi.Error{Status: 500, Message: "сбой"}
	}
	rec := get(pe.testEnv, pe.cookie, "/proxy")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "не проверено") {
		t.Fatalf("%d\n%s", rec.Code, rec.Body)
	}
}
