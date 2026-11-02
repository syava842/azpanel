package panel

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/store"
)

func TestAllowListMatching(t *testing.T) {
	nets := func(l ...string) *AllowList {
		p, err := config.ParseAllowIPs(l)
		if err != nil {
			t.Fatal(err)
		}
		return NewAllowList(p)
	}
	cases := []struct {
		list []string
		host string
		want bool
	}{
		{nil, "203.0.113.9", true}, // пустой список — без ограничения
		{[]string{"10.0.0.0/8"}, "10.1.2.3", true},
		{[]string{"10.0.0.0/8"}, "11.0.0.1", false},
		{[]string{"192.0.2.7"}, "192.0.2.7", true}, // одиночный IP
		{[]string{"192.0.2.7"}, "192.0.2.8", false},
		{[]string{"2001:db8::/32"}, "2001:db8::5", true},
		{[]string{"2001:db8::/32"}, "2001:db9::5", false},
		{[]string{"10.0.0.0/8"}, "::ffff:10.0.0.9", true}, // IPv4 в IPv6
		{[]string{"10.0.0.0/8"}, "не адрес", false},
	}
	for _, c := range cases {
		if got := nets(c.list...).Allows(c.host); got != c.want {
			t.Errorf("%v / %s: %v, ждали %v", c.list, c.host, got, c.want)
		}
	}
	var nilList *AllowList
	if !nilList.Allows("1.2.3.4") {
		t.Error("nil-список должен пускать всех")
	}
}

// accessEnv — окружение с файлом config.toml и управляемыми часами.
type accessEnv struct {
	*testEnv
	cfgFile string
	now     time.Time
}

func newAccessEnv(t *testing.T) *accessEnv {
	t.Helper()
	e := &accessEnv{testEnv: newEnv(t, adminHash(t)), now: time.Unix(1_800_000_000, 0)}
	e.cfgFile = filepath.Join(t.TempDir(), "config.toml")
	if err := config.Save(e.cfgFile, config.Default()); err != nil {
		t.Fatal(err)
	}
	e.srv.ConfigFile = e.cfgFile
	e.srv.Now = func() time.Time { return e.now }
	return e
}

func (e *accessEnv) cfgList(t *testing.T) []string {
	t.Helper()
	c, err := config.Load(e.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	return c.Panel.AllowIPs
}

// post — POST администратора с адреса from.
func (e *accessEnv) post(t *testing.T, path, from string, f url.Values) *httptest.ResponseRecorder {
	t.Helper()
	c, sess := e.sessionCookie(t)
	f.Set("csrf", sess.CSRF)
	req := postForm(path, f)
	req.AddCookie(c)
	req.RemoteAddr = from + ":4000"
	return e.do(req)
}

func (e *accessEnv) get(path, from string, c *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	req.RemoteAddr = from + ":4000"
	return e.do(req)
}

func TestAllowGateBlocks(t *testing.T) {
	e := newAccessEnv(t)
	nets, _ := config.ParseAllowIPs([]string{"10.0.0.0/8"})
	e.srv.Allow.Set(nets)
	rec := e.get("/login", "192.0.2.5", nil)
	if rec.Code != 403 || strings.TrimSpace(rec.Body.String()) != "доступ запрещён" {
		t.Fatalf("чужой адрес: %d %q", rec.Code, rec.Body)
	}
	if rec := e.get("/healthz", "192.0.2.5", nil); rec.Code != 200 {
		t.Fatalf("/healthz: %d", rec.Code)
	}
	if rec := e.get("/login", "10.2.3.4", nil); rec.Code != 200 {
		t.Fatalf("свой адрес: %d", rec.Code)
	}
	e.srv.Allow.Set(nil)
	if rec := e.get("/login", "192.0.2.5", nil); rec.Code != 200 {
		t.Fatalf("пустой список: %d", rec.Code)
	}
}

func TestAccessPageAdminOnly(t *testing.T) {
	e := newAccessEnv(t)
	u, err := e.st.CreateUser(context.Background(), store.User{Login: "bob", Hash: "x", Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	c, sess := e.sessionFor(t, u, false)
	if rec := e.get("/settings/access", "10.0.0.1", c); rec.Code != 403 {
		t.Fatalf("GET пользователем: %d", rec.Code)
	}
	req := postForm("/settings/access", url.Values{"csrf": {sess.CSRF}, "ips": {"10.0.0.0/8"}})
	req.AddCookie(c)
	if rec := e.do(req); rec.Code != 403 {
		t.Fatalf("POST пользователем: %d", rec.Code)
	}
	ac, _ := e.sessionCookie(t)
	if rec := e.get("/settings/access", "10.0.0.1", ac); rec.Code != 200 {
		t.Fatalf("GET администратором: %d", rec.Code)
	}
}

func TestAccessRevertsWithoutConfirm(t *testing.T) {
	e := newAccessEnv(t)
	rec := e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/8"}})
	if rec.Code != 200 {
		t.Fatalf("сохранение: %d %s", rec.Code, rec.Body)
	}
	if got := e.cfgList(t); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("в файле: %v", got)
	}
	if e.srv.Allow.Allows("192.0.2.5") {
		t.Fatal("новый список не действует сразу")
	}
	// Срок не вышел: возврата нет.
	e.now = e.now.Add(accessConfirmTTL - time.Second)
	e.srv.CheckPending(context.Background())
	if e.srv.Allow.Allows("192.0.2.5") {
		t.Fatal("вернулось раньше срока")
	}
	e.now = e.now.Add(2 * time.Second)
	e.srv.CheckPending(context.Background())
	if !e.srv.Allow.Allows("192.0.2.5") {
		t.Fatal("после срока список не вернулся в работу")
	}
	if got := e.cfgList(t); len(got) != 0 {
		t.Fatalf("после возврата в файле: %v", got)
	}
	list, _, _ := e.st.AuditList(context.Background(), 20, 0, "")
	var set, revert bool
	for _, a := range list {
		set = set || a.Action == "access_set"
		revert = revert || (a.Action == "setting_revert" && a.User == "система")
	}
	if !set || !revert {
		t.Fatalf("журнал: set=%v revert=%v", set, revert)
	}
}

func TestAccessConfirmKeeps(t *testing.T) {
	e := newAccessEnv(t)
	e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/8"}})
	// Подтверждает адрес, проходящий новый список.
	if rec := e.post(t, "/settings/access/confirm", "10.0.0.1", url.Values{}); rec.Code != 200 {
		t.Fatalf("подтверждение: %d %s", rec.Code, rec.Body)
	}
	e.now = e.now.Add(10 * time.Minute)
	e.srv.CheckPending(context.Background())
	if e.srv.Allow.Allows("192.0.2.5") {
		t.Fatal("подтверждённый список откатился")
	}
	if got := e.cfgList(t); len(got) != 1 {
		t.Fatalf("в файле: %v", got)
	}
	// Подтверждать нечего.
	if rec := e.post(t, "/settings/access/confirm", "10.0.0.1", url.Values{}); rec.Code != 409 {
		t.Fatalf("повторное подтверждение: %d", rec.Code)
	}
}

func TestAccessConfirmAfterDeadlineRefused(t *testing.T) {
	e := newAccessEnv(t)
	e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/8"}})
	e.now = e.now.Add(accessConfirmTTL + time.Second)
	if rec := e.post(t, "/settings/access/confirm", "10.0.0.1", url.Values{}); rec.Code != 409 {
		t.Fatalf("подтверждение после срока: %d", rec.Code)
	}
	e.srv.CheckPending(context.Background())
	if !e.srv.Allow.Allows("192.0.2.5") {
		t.Fatal("возврат не выполнен")
	}
}

// Перезапуск панели в середине таймера: новый экземпляр на той же базе и
// том же файле всё равно возвращает прежний список по сроку.
func TestAccessRevertSurvivesRestart(t *testing.T) {
	e := newAccessEnv(t)
	e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/8"}})

	cfg, err := config.Load(e.cfgFile) // как при старте: список из файла
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Server{
		Store: e.st, NodeID: store.LocalNode, Limiter: NewLimiter(), ConfigFile: e.cfgFile,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return e.now },
	}
	if err := restarted.SeedAllow(cfg.Panel.AllowIPs); err != nil {
		t.Fatal(err)
	}
	restarted.CheckPending(context.Background())
	if restarted.Allow.Allows("192.0.2.5") {
		t.Fatal("до срока список уже откатился")
	}
	e.now = e.now.Add(accessConfirmTTL + time.Second)
	restarted.CheckPending(context.Background())
	if !restarted.Allow.Allows("192.0.2.5") {
		t.Fatal("после перезапуска возврат не произошёл")
	}
	if got := e.cfgList(t); len(got) != 0 {
		t.Fatalf("в файле после возврата: %v", got)
	}
}

func TestAccessLockoutNeedsSecondConfirm(t *testing.T) {
	e := newAccessEnv(t)
	rec := e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"192.0.2.0/24"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "не включает ваш адрес") {
		t.Fatalf("предупреждения нет: %d %s", rec.Code, rec.Body)
	}
	if !e.srv.Allow.Allows("203.0.113.1") || len(e.cfgList(t)) != 0 {
		t.Fatal("список применён без второго подтверждения")
	}
	rec = e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"192.0.2.0/24"}, "lockout": {"1"}})
	if rec.Code != 200 || e.srv.Allow.Allows("203.0.113.1") {
		t.Fatalf("со вторым подтверждением не применилось: %d", rec.Code)
	}
}

func TestAccessRejectsBadAndRepeated(t *testing.T) {
	e := newAccessEnv(t)
	if rec := e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/8\nмусор"}}); rec.Code != 400 {
		t.Fatalf("неверная запись: %d", rec.Code)
	}
	e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/8"}})
	if rec := e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/16"}}); rec.Code != 409 {
		t.Fatalf("второе изменение без подтверждения первого: %d", rec.Code)
	}
}

func TestAccessConfigFileKeepsOtherSettings(t *testing.T) {
	e := newAccessEnv(t)
	c, _ := config.Load(e.cfgFile)
	c.Log.Keep = 9
	if err := config.Save(e.cfgFile, c); err != nil {
		t.Fatal(err)
	}
	e.post(t, "/settings/access", "10.0.0.1", url.Values{"ips": {"10.0.0.0/8"}})
	got, err := config.Load(e.cfgFile)
	if err != nil || got.Log.Keep != 9 {
		t.Fatalf("прочие настройки потеряны: %v %+v", err, got.Log)
	}
	if _, err := os.Stat(e.cfgFile); err != nil {
		t.Fatal(err)
	}
}
