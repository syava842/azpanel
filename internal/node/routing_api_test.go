package node

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
)

func routingEnv(t *testing.T, files map[string]string) apiEnv {
	t.Helper()
	e := newAPI(t)
	cfg := filepath.Join(e.api.AntiZapretDir, "config")
	os.MkdirAll(cfg, 0o755)
	for n, c := range files {
		os.WriteFile(filepath.Join(cfg, n), []byte(c), 0o640)
	}
	e.api.Routing = &antizapret.Routing{
		ConfigDir: cfg,
		Backups:   &antizapret.Backups{Dir: filepath.Join(filepath.Dir(e.api.AntiZapretDir), "backup", "antizapret"), Now: time.Now},
	}
	return e
}

func authReq(t *testing.T, e apiEnv, method, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	return req
}

func readCfg(t *testing.T, e apiEnv, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.api.AntiZapretDir, "config", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAPIRoutingFilesAndLines(t *testing.T) {
	e := routingEnv(t, map[string]string{
		"include-hosts.txt": "# c\na.example.com\nb.example.org\n",
		"allow-ips.txt":     "1.2.3.0/24\n",
	})
	ctx := context.Background()
	files, err := e.client.RoutingFiles(ctx)
	if err != nil || len(files) != 2 || files[0].Name != "allow-ips.txt" || files[0].Kind != "ips" ||
		files[1].Kind != "hosts" || files[1].Lines != 2 || files[1].Title == "" {
		t.Fatalf("%+v, %v", files, err)
	}
	pg, err := e.client.RoutingLines(ctx, "include-hosts.txt", nodeapi.RoutingListOpts{Query: "ORG"})
	if err != nil || pg.Total != 1 || pg.Lines[0] != "b.example.org" || pg.Limit != 200 || pg.Offset != 0 {
		t.Fatalf("%+v, %v", pg, err)
	}
	pg, err = e.client.RoutingLines(ctx, "include-hosts.txt", nodeapi.RoutingListOpts{Offset: 1, Limit: 1})
	if err != nil || pg.Total != 2 || len(pg.Lines) != 1 || pg.Lines[0] != "b.example.org" {
		t.Fatalf("%+v, %v", pg, err)
	}
	// limit больше 1000 урезается.
	pg, _ = e.client.RoutingLines(ctx, "include-hosts.txt", nodeapi.RoutingListOpts{Limit: 5000})
	if pg.Limit != 1000 {
		t.Fatalf("limit %d", pg.Limit)
	}
	for _, q := range []string{"?offset=-1", "?offset=x", "?limit=0", "?limit=x"} {
		resp, err := http.DefaultClient.Do(authReq(t, e, http.MethodGet, "/v1/routing/files/include-hosts.txt"+q))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%s: %d", q, resp.StatusCode)
		}
	}
}

func TestAPIRoutingPatch(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "# c\nold.example.com\n"})
	ctx := context.Background()
	res, err := e.client.PatchRouting(ctx, "include-hosts.txt", nodeapi.RoutingPatch{
		Add: []string{"azpanel-test.example.com", "other.example.com"}, Remove: []string{"old.example.com", "absent.example.com"},
	})
	if err != nil || !res.Applied || res.Added != 2 || res.Removed != 1 || res.Skipped != 1 || res.Errors == nil || len(res.Errors) != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := readCfg(t, e, "include-hosts.txt"); got != "# c\nazpanel-test.example.com\nother.example.com\n" {
		t.Fatalf("%q", got)
	}

	// Ошибка строки: 200, applied=false, файл цел.
	before := readCfg(t, e, "include-hosts.txt")
	res, err = e.client.PatchRouting(ctx, "include-hosts.txt", nodeapi.RoutingPatch{Add: []string{"fine.example.com", "bad_host"}})
	if err != nil || res.Applied || len(res.Errors) != 1 || res.Errors[0].Line != 2 || res.Errors[0].Value != "bad_host" || res.Errors[0].Reason == "" {
		t.Fatalf("%+v, %v", res, err)
	}
	if readCfg(t, e, "include-hosts.txt") != before {
		t.Fatal("файл изменён при ошибке")
	}
	// Пустое тело — 400.
	req := authReq(t, e, http.MethodPatch, "/v1/routing/files/include-hosts.txt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("пустое тело: %d", resp.StatusCode)
	}
}

func TestAPIRoutingNames(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	ctx := context.Background()
	setup := filepath.Join(e.api.AntiZapretDir, "setup")
	before, _ := os.ReadFile(setup)
	for _, n := range []string{"setup", "nope.txt", "../setup", "..%2Fsetup", "a/b.txt"} {
		if _, err := e.client.RoutingLines(ctx, n, nodeapi.RoutingListOpts{}); err == nil {
			t.Errorf("RoutingLines(%q) должно отказывать", n)
		}
		if _, err := e.client.PatchRouting(ctx, n, nodeapi.RoutingPatch{Add: []string{"a.example.com"}}); err == nil {
			t.Errorf("PatchRouting(%q) должно отказывать", n)
		}
		if _, err := e.client.ReplaceRouting(ctx, n, "x.example.com\n", ""); err == nil {
			t.Errorf("ReplaceRouting(%q) должно отказывать", n)
		}
	}
	for _, n := range []string{"setup", "nope.txt"} {
		if _, err := e.client.RoutingLines(ctx, n, nodeapi.RoutingListOpts{}); status(err) != 404 {
			t.Errorf("%q: %v", n, err)
		}
		if _, err := e.client.RoutingBackups(ctx, n); status(err) != 404 {
			t.Errorf("копии %q: %v", n, err)
		}
	}
	after, _ := os.ReadFile(setup)
	if string(before) != string(after) {
		t.Fatal("setup изменён")
	}
}

func TestAPIRoutingPut(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	ctx := context.Background()
	res, err := e.client.ReplaceRouting(ctx, "include-hosts.txt", "# новое\nB.example.com\n", "")
	if err != nil || !res.Applied || res.Lines != 1 || len(res.Errors) != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	res, err = e.client.ReplaceRouting(ctx, "include-hosts.txt", "ok.example.com\nbad host\n", "")
	if err != nil || res.Applied || len(res.Errors) != 1 || res.Errors[0].Line != 2 {
		t.Fatalf("%+v, %v", res, err)
	}
	// Больше 1 МБ — 413.
	big := strings.Repeat("a.example.com\n", 80000)
	if _, err := e.client.ReplaceRouting(ctx, "include-hosts.txt", big, ""); status(err) != 413 || !strings.Contains(err.Error(), "по строкам") {
		t.Fatalf("1 МБ: %v", err)
	}
	// Больше лимита тела запроса — тоже 413.
	huge := strings.Repeat("a.example.com\n", 700000)
	if _, err := e.client.ReplaceRouting(ctx, "include-hosts.txt", huge, ""); status(err) != 413 {
		t.Fatalf("лимит тела: %v", err)
	}
	if got := readCfg(t, e, "include-hosts.txt"); got != "# новое\nb.example.com\n" {
		t.Fatalf("%q", got)
	}
}

// Тело PATCH списков больше обычных 64 КБ.
func TestAPIRoutingPatchBodyLargerThanDefault(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	add := make([]string, 0, 20000)
	for i := 0; i < 20000; i++ {
		add = append(add, "host-"+strconv.Itoa(i)+".example.com")
	}
	res, err := e.client.PatchRouting(context.Background(), "include-hosts.txt", nodeapi.RoutingPatch{Add: add})
	if err != nil || res.Added != 20000 {
		t.Fatalf("%+v, %v", res, err)
	}
}

func TestAPIRoutingBackupsAndRestore(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "v0.example.com\n"})
	ctx := context.Background()
	for _, v := range []string{"v1", "v2"} {
		if _, err := e.client.ReplaceRouting(ctx, "include-hosts.txt", v+".example.com\n", ""); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	list, err := e.client.RoutingBackups(ctx, "include-hosts.txt")
	if err != nil || len(list) != 2 || list[0].Stamp <= list[1].Stamp || list[1].Bytes == 0 {
		t.Fatalf("%+v, %v", list, err)
	}
	f, err := e.client.RestoreRouting(ctx, "include-hosts.txt", list[1].Stamp) // самая старая: v0
	if err != nil || f.Name != "include-hosts.txt" || f.Lines != 1 {
		t.Fatalf("%+v, %v", f, err)
	}
	if got := readCfg(t, e, "include-hosts.txt"); got != "v0.example.com\n" {
		t.Fatalf("%q", got)
	}
	if list, _ = e.client.RoutingBackups(ctx, "include-hosts.txt"); len(list) != 3 {
		t.Fatalf("версия перед возвратом должна копироваться: %+v", list)
	}
	for _, st := range []string{"20260101T000000.000Z", "bad"} {
		_, err := e.client.RestoreRouting(ctx, "include-hosts.txt", st)
		if s := status(err); s != 404 && s != 400 {
			t.Errorf("метка %q: %v", st, err)
		}
	}
}

func TestAPIRoutingNotConfigured(t *testing.T) {
	e := newAPI(t)
	if _, err := e.client.RoutingFiles(context.Background()); status(err) != 503 {
		t.Fatal(err)
	}
}

func TestAPIRoutingRequiresToken(t *testing.T) {
	e := routingEnv(t, map[string]string{"include-hosts.txt": "a.example.com\n"})
	for _, c := range [][2]string{
		{"GET", "/v1/routing/files"}, {"GET", "/v1/routing/files/include-hosts.txt"},
		{"PATCH", "/v1/routing/files/include-hosts.txt"}, {"PUT", "/v1/routing/files/include-hosts.txt"},
		{"GET", "/v1/routing/backups/include-hosts.txt"},
		{"POST", "/v1/routing/backups/include-hosts.txt/20260101T000000.000Z/restore"},
	} {
		req, _ := http.NewRequest(c[0], e.srv.URL+c[1], nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s %s: %d", c[0], c[1], resp.StatusCode)
		}
	}
}
