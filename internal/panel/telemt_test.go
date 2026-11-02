package panel

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

const telemtSecretFull = "ee0123456789abcdef0123456789abcdef7777772e6578616d706c652e636f6d"

func telemtInstalled(n *svcNode) {
	grew := time.Now().Add(-time.Hour)
	n.TelemtStatusFn = func(context.Context) (nodeapi.TelemtStatus, error) {
		return nodeapi.TelemtStatus{Installed: true, Version: "3.5.7", ActiveState: "active", NRestarts: 3, RestartsGrewAt: &grew,
			Port: 902, Domain: "www.example.com",
			Users: []nodeapi.TelemtUserInfo{{Name: "alice", SecretMasked: "0123…cdef"}, {Name: "<b>x</b>", SecretMasked: "aaaa…bbbb"}}}, nil
	}
	n.TelemtReleaseFn = func(context.Context) (nodeapi.TelemtRelease, error) {
		return nodeapi.TelemtRelease{Current: "3.5.7", Latest: "3.6.0", UpdateAvailable: true, Checked: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)}, nil
	}
}

func TestTelemtPageMasksSecretsAndShowsGrowth(t *testing.T) {
	e, n, c, _ := svcEnv(t)
	telemtInstalled(n)
	rec := get(e, c, "/telemt")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	b := rec.Body.String()
	for _, want := range []string{"0123…cdef", "3.6.0", "перезапускался сам", "2026-11-02 09:00 UTC", "&lt;b&gt;x&lt;/b&gt;", "Показать ссылку и QR"} {
		if !strings.Contains(b, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(b, "tg://") || strings.Contains(b, "ee0123") {
		t.Error("секрет или ссылка на странице без нажатия")
	}
	if n.called("TelemtLink") != 0 {
		t.Error("ссылка запрошена без нажатия")
	}
}

func TestTelemtLinkOnlyOnPostNoStoreQR(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	telemtInstalled(n)
	link := "tg://proxy?server=1.2.3.4&port=902&secret=" + telemtSecretFull
	var gotName, gotServer string
	n.TelemtLinkFn = func(_ context.Context, name, server string) (nodeapi.TelemtLink, error) {
		gotName, gotServer = name, server
		return nodeapi.TelemtLink{Name: name, Server: "1.2.3.4", Port: 902, Link: link, WebLink: "https://t.me/proxy?server=1.2.3.4&port=902&secret=" + telemtSecretFull}, nil
	}
	if rec := get(e, c, "/telemt/users/alice/link"); rec.Code == 200 {
		t.Fatalf("GET ссылки открыт: %d", rec.Code)
	}
	rec := post(e, c, "/telemt/users/alice/link", url.Values{"csrf": {csrf}, "server": {"vpn.example.org"}})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control: %q", cc)
	}
	b := rec.Body.String()
	if !strings.Contains(b, telemtSecretFull) || !strings.Contains(b, `src="data:image/png;base64,`) || !strings.Contains(b, `href="tg://proxy?`) {
		t.Fatalf("страница ссылки неполна: %s", b)
	}
	if gotName != "alice" || gotServer != "vpn.example.org" {
		t.Fatalf("агенту: %q %q", gotName, gotServer)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "telemt_link")
	if len(list) != 1 || strings.Contains(list[0].After+list[0].Target+list[0].Before, "0123456789abcdef") {
		t.Fatalf("журнал: %+v", list)
	}
	// чужой адрес сервера и имя отвергаются до агента
	n.Calls = nil
	if rec := post(e, c, "/telemt/users/alice/link", url.Values{"csrf": {csrf}, "server": {"a b<script>"}}); rec.Code != 400 || n.called("TelemtLink") != 0 {
		t.Fatalf("плохой адрес: %d", rec.Code)
	}
	if rec := post(e, c, "/telemt/users/..%2Fx/link", url.Values{"csrf": {csrf}}); rec.Code == 200 || n.called("TelemtLink") != 0 {
		t.Fatalf("плохое имя: %d", rec.Code)
	}
}

func TestTelemtLinkHostileAgentLinkNotClickable(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	telemtInstalled(n)
	n.TelemtLinkFn = func(context.Context, string, string) (nodeapi.TelemtLink, error) {
		return nodeapi.TelemtLink{Name: "alice", Link: "javascript:alert(1)", WebLink: "https://evil.example/x"}, nil
	}
	rec := post(e, c, "/telemt/users/alice/link", url.Values{"csrf": {csrf}})
	if strings.Contains(rec.Body.String(), `href="javascript:`) || strings.Contains(rec.Body.String(), `href="https://evil`) {
		t.Fatalf("чужая ссылка стала href: %s", rec.Body)
	}
}

func TestTelemtAddAndRemoveUser(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	telemtInstalled(n)
	var added nodeapi.TelemtAddUser
	n.TelemtAddUserFn = func(_ context.Context, req nodeapi.TelemtAddUser) (nodeapi.TelemtUserResult, error) {
		added = req
		return nodeapi.TelemtUserResult{Task: nodeapi.Task{ID: "0123456789ab"}, Name: req.Name, SecretMasked: "feed…beef"}, nil
	}
	rec := post(e, c, "/telemt/users", url.Values{"csrf": {csrf}, "name": {"bob"}, "secret": {telemtSecretFull}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/tasks/0123456789ab" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	if added.Name != "bob" || added.Secret != telemtSecretFull {
		t.Fatalf("агенту: %+v", added)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "telemt_user_add")
	if len(list) != 1 || strings.Contains(list[0].After, "0123456789abcdef") || !strings.Contains(list[0].After, "feed…beef") {
		t.Fatalf("секрет попал в журнал или маски нет: %+v", list)
	}
	if rec := post(e, c, "/telemt/users", url.Values{"csrf": {csrf}, "name": {"bad name"}}); rec.Code != 400 {
		t.Fatalf("плохое имя: %d", rec.Code)
	}
	// агент отказал (чужой домен) — текст агента на странице, секрет не эхом
	n.TelemtAddUserFn = func(context.Context, nodeapi.TelemtAddUser) (nodeapi.TelemtUserResult, error) {
		return nodeapi.TelemtUserResult{}, &nodeapi.Error{Status: 400, Message: "домен ключа не совпадает с tls_domain"}
	}
	rec = post(e, c, "/telemt/users", url.Values{"csrf": {csrf}, "name": {"bob2"}, "secret": {telemtSecretFull}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "не совпадает с tls_domain") || strings.Contains(rec.Body.String(), "0123456789abcdef") {
		t.Fatalf("отказ: %d %s", rec.Code, rec.Body)
	}
	// удаление — только с подтверждением
	removed := ""
	n.TelemtRemoveUserFn = func(_ context.Context, name string) (nodeapi.TelemtUserResult, error) {
		removed = name
		return nodeapi.TelemtUserResult{Task: nodeapi.Task{ID: "0123456789ab"}}, nil
	}
	if rec := post(e, c, "/telemt/users/alice/delete", url.Values{"csrf": {csrf}}); rec.Code != 400 || removed != "" {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	if rec := post(e, c, "/telemt/users/alice/delete", url.Values{"csrf": {csrf}, "confirm": {"1"}}); rec.Code != 303 || removed != "alice" {
		t.Fatalf("удаление: %d %q", rec.Code, removed)
	}
}

func TestTelemtInstallFormAndPreflight(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	n.TelemtStatusFn = func(context.Context) (nodeapi.TelemtStatus, error) {
		return nodeapi.TelemtStatus{Users: []nodeapi.TelemtUserInfo{}}, nil
	}
	var port int
	n.TelemtPreflightFn = func(_ context.Context, p int) (nodeapi.TelemtPreflight, error) {
		port = p
		return nodeapi.TelemtPreflight{Port: p, PortFree: false, Busy: map[int]bool{443: true, 504: true}}, nil
	}
	rec := get(e, c, "/telemt?port=904")
	b := rec.Body.String()
	if rec.Code != 200 || port != 904 || !strings.Contains(b, "telemt не установлен") || !strings.Contains(b, "Порт 904 занят") || !strings.Contains(b, "Заняты: 443, 504") {
		t.Fatalf("%d port=%d %s", rec.Code, port, b)
	}
	var got nodeapi.TelemtInstall
	n.InstallTelemtFn = func(_ context.Context, p nodeapi.TelemtInstall) (nodeapi.Task, error) {
		got = p
		return nodeapi.Task{ID: "0123456789ab"}, nil
	}
	f := url.Values{"csrf": {csrf}, "port": {"902"}, "domain": {"www.example.com"}, "max_connections": {"2000"}, "secret": {"0123456789abcdef0123456789abcdef"}}
	rec = post(e, c, "/telemt/install", f)
	if rec.Code != 303 || got.Port != 902 || got.Domain != "www.example.com" || got.MaxConnections != 2000 || got.Secret == "" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "telemt_install")
	if len(list) != 1 || strings.Contains(list[0].After, "0123456789abcdef") {
		t.Fatalf("журнал установки: %+v", list)
	}
	for name, bad := range map[string]url.Values{
		"домен": {"csrf": {csrf}, "domain": {"bad domain!"}},
		"порт":  {"csrf": {csrf}, "domain": {"a.example.com"}, "port": {"70000"}},
		"число": {"csrf": {csrf}, "domain": {"a.example.com"}, "max_connections": {"x"}},
		"имя":   {"csrf": {csrf}, "domain": {"a.example.com"}, "user": {"a b"}},
	} {
		n.Calls = nil
		if rec := post(e, c, "/telemt/install", bad); rec.Code != 400 || n.called("InstallTelemt") != 0 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func TestTelemtUpdateAndRestart(t *testing.T) {
	e, n, c, csrf := svcEnv(t)
	telemtInstalled(n)
	n.TelemtUpdateFn = func(context.Context) (nodeapi.Task, error) { return nodeapi.Task{ID: "0123456789ab"}, nil }
	n.TelemtRestartFn = func(context.Context) (nodeapi.Task, error) { return nodeapi.Task{ID: "ba9876543210"}, nil }
	if rec := post(e, c, "/telemt/update", url.Values{"csrf": {csrf}}); rec.Code != 400 || n.called("TelemtUpdate") != 0 {
		t.Fatalf("обновление без подтверждения: %d", rec.Code)
	}
	if rec := post(e, c, "/telemt/update", url.Values{"csrf": {csrf}, "confirm": {"1"}}); rec.Code != 303 {
		t.Fatalf("обновление: %d", rec.Code)
	}
	if rec := post(e, c, "/telemt/restart", url.Values{"csrf": {csrf}}); rec.Code != 303 || rec.Header().Get("Location") != "/tasks/ba9876543210" {
		t.Fatalf("перезапуск: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	n.TelemtUpdateFn = func(context.Context) (nodeapi.Task, error) {
		return nodeapi.Task{}, &nodeapi.Error{Status: 409, Message: "идёт другая задача"}
	}
	rec := post(e, c, "/telemt/update", url.Values{"csrf": {csrf}, "confirm": {"1"}})
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "идёт другая задача") {
		t.Fatalf("409: %d", rec.Code)
	}
}

func TestTelemtRoutesAdminOnly(t *testing.T) {
	for _, p := range []string{"GET /telemt", "POST /telemt/users", "POST /telemt/users/{name}/delete", "POST /telemt/users/{name}/link",
		"POST /telemt/restart", "POST /telemt/update", "POST /telemt/install"} {
		if routes[p] != accAdmin {
			t.Errorf("%s: не администратор", p)
		}
	}
}
