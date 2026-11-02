package node

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/warp"
)

type warpEnv struct {
	apiEnv
	f      *fakeExec
	tk     *Tasks
	dir    string
	params string
}

func newWarpEnv(t *testing.T, installed bool) warpEnv {
	t.Helper()
	e, f, tk := tasksEnv(t)
	dir := t.TempDir()
	status, err := os.ReadFile("../warp/testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	if installed {
		os.WriteFile(filepath.Join(dir, "version"), []byte("1.5.7\n"), 0o644)
	}
	w := &warp.Warper{Dir: dir, Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "status json":
			return status, nil
		case "domainslist":
			return []byte("example.com|user|1\n# c\ngemini.google.com|gemini|0\n"), nil
		case "iplist":
			return []byte("198.51.100.0/24\n"), nil
		}
		return nil, nil
	}}
	params := filepath.Join(dir, "params")
	e.api.Warp = &WarpService{Warper: w, Self: "/opt/azpanel/bin/azpanel", ParamsDir: params}
	now := time.Unix(2_000_000_000, 0)
	e.api.WGCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("antizapret vpn warp-az warp-vpn\n"), nil
	}
	e.api.WGShow = func(_ context.Context, iface string) ([]antizapret.WGPeer, error) {
		if !strings.HasPrefix(iface, "warp") {
			t.Errorf("wg show для постороннего интерфейса %s", iface)
		}
		return []antizapret.WGPeer{{Interface: iface, PublicKey: "ПУБЛИЧНЫЙ-КЛЮЧ-ПИРА", Endpoint: "162.159.192.1:2408", LatestHandshake: now.Add(-time.Minute), RxBytes: 7, TxBytes: 9}}, nil
	}
	return warpEnv{apiEnv: e, f: f, tk: tk, dir: dir, params: params}
}

func (e warpEnv) rawGet(t *testing.T, path string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// Ответ API не содержит подменённых значений из status json.
func TestWarpSummaryHasNoSecrets(t *testing.T) {
	e := newWarpEnv(t, true)
	body := e.rawGet(t, "/v1/warp")
	for _, p := range []string{"ПОДМЕНЁН==", "ПОДМЕНЁН", "ПУБЛИЧНЫЙ-КЛЮЧ-ПИРА"} {
		if strings.Contains(body, p) {
			t.Fatalf("%q в ответе: %s", p, body)
		}
	}
	sum, err := e.client.Warp(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sum.AZ.Installed || sum.AZ.Version != "1.5.7" || sum.AZ.RemoteVersion != "1.5.8" || !sum.AZ.UpdateAvailable {
		t.Fatalf("%+v", sum.AZ)
	}
	if len(sum.Builtin) != 2 || sum.Builtin[0].Name != "warp-az" || sum.Builtin[0].Peers[0].RxBytes != 7 || sum.Builtin[0].Peers[0].LatestHandshake == nil {
		t.Fatalf("%+v", sum.Builtin)
	}
}

func TestWarpSummaryNotInstalled(t *testing.T) {
	e := newWarpEnv(t, false)
	sum, err := e.client.Warp(context.Background())
	if err != nil || sum.AZ.Installed {
		t.Fatalf("%+v %v", sum, err)
	}
	if _, err := e.client.WarpDomains(context.Background()); status(err) != 409 {
		t.Fatalf("%v", err)
	}
	if _, err := e.client.WarpSync(context.Background()); status(err) != 409 {
		t.Fatalf("%v", err)
	}
}

func TestWarpLists(t *testing.T) {
	e := newWarpEnv(t, true)
	d, err := e.client.WarpDomains(context.Background())
	if err != nil || strings.Join(d.Lines, "|") != "example.com|gemini.google.com" {
		t.Fatalf("%+v %v", d, err)
	}
	if len(d.Domains) != 2 || d.Domains[0] != (nodeapi.WarpDomain{Domain: "example.com", Source: "user", Enabled: true}) ||
		d.Domains[1].Source != "gemini" || d.Domains[1].Enabled {
		t.Fatalf("разобранные домены: %+v", d.Domains)
	}
	ips, err := e.client.WarpIPs(context.Background())
	if err != nil || len(ips.Lines) != 1 {
		t.Fatalf("%+v %v", ips, err)
	}
}

func (e warpEnv) lastCommand(t *testing.T, id string) string {
	t.Helper()
	e.f.done()
	waitFinished(t, e.tk, id)
	return strings.Join(argvOf(e.f.calls[0]), " ")
}

func TestWarpEditDomainsRunsStepsInOneTask(t *testing.T) {
	e := newWarpEnv(t, true)
	task, err := e.client.EditWarpDomains(context.Background(), nodeapi.WarpEdit{
		Ops:  []nodeapi.WarpOp{{Op: "add", Arg: "azpanel-test.example.com"}, {Op: "disable", Arg: "gemini"}},
		Sync: true,
	})
	if err != nil || task.Kind != TaskWarpSync {
		t.Fatalf("%+v %v", task, err)
	}
	want := "/opt/azpanel/bin/azpanel internal warp-run -- add azpanel-test.example.com -- disable gemini -- sync"
	if got := e.lastCommand(t, task.ID); got != want {
		t.Fatalf("команда: %s", got)
	}
}

func TestWarpEditIPs(t *testing.T) {
	e := newWarpEnv(t, true)
	task, err := e.client.EditWarpIPs(context.Background(), nodeapi.WarpEdit{Ops: []nodeapi.WarpOp{{Op: "ipadd", Arg: "198.51.100.0/24"}}, Sync: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.lastCommand(t, task.ID); !strings.HasSuffix(got, "warp-run -- ipadd 198.51.100.0/24 -- ipsync") {
		t.Fatalf("команда: %s", got)
	}
}

func TestWarpEditRejects(t *testing.T) {
	e := newWarpEnv(t, true)
	ctx := context.Background()
	bad := []struct {
		name string
		call func() error
	}{
		{"домен с пробелом", func() error {
			_, err := e.client.EditWarpDomains(ctx, nodeapi.WarpEdit{Ops: []nodeapi.WarpOp{{Op: "add", Arg: "a b"}}})
			return err
		}},
		{"ipadd в доменах", func() error {
			_, err := e.client.EditWarpDomains(ctx, nodeapi.WarpEdit{Ops: []nodeapi.WarpOp{{Op: "ipadd", Arg: "1.2.3.0/24"}}})
			return err
		}},
		{"add в подсетях", func() error {
			_, err := e.client.EditWarpIPs(ctx, nodeapi.WarpEdit{Ops: []nodeapi.WarpOp{{Op: "add", Arg: "a.example"}}})
			return err
		}},
		{"подсеть мусор", func() error {
			_, err := e.client.EditWarpIPs(ctx, nodeapi.WarpEdit{Ops: []nodeapi.WarpOp{{Op: "ipadd", Arg: "не-сеть"}}})
			return err
		}},
		{"пусто", func() error {
			_, err := e.client.EditWarpDomains(ctx, nodeapi.WarpEdit{})
			return err
		}},
	}
	for _, c := range bad {
		if status(c.call()) != 400 {
			t.Errorf("%s: ждали 400", c.name)
		}
	}
	if len(e.f.calls) != 0 {
		t.Fatal("отклонённые правки не должны запускать задач")
	}
}

func TestWarpUpdateTask(t *testing.T) {
	e := newWarpEnv(t, true)
	task, err := e.client.WarpUpdate(context.Background())
	if err != nil || task.Kind != TaskWarpUpdate {
		t.Fatalf("%+v %v", task, err)
	}
	if got := e.lastCommand(t, task.ID); !strings.HasSuffix(got, "warp-run -- update -- status-json -- doctor") {
		t.Fatalf("команда: %s", got)
	}
}

func TestWarpInstallTask(t *testing.T) {
	e := newWarpEnv(t, false)
	ctx := context.Background()
	if _, err := e.client.InstallWarp(ctx, nodeapi.WarpInstallAnswers{Mode: "wg"}); status(err) != 400 {
		t.Fatalf("валидация: %v", err)
	}
	if len(e.f.calls) != 0 || len(paramsGlob(e.params)) != 0 {
		t.Fatal("при отказе ничего не создаётся")
	}
	ans := nodeapi.WarpInstallAnswers{Mode: "vless", ProxyLink: "vless://СЕКРЕТНЫЙ-UUID@203.0.113.9:443?security=reality"}
	task, err := e.client.InstallWarp(ctx, ans)
	if err != nil || task.Kind != TaskWarpInstall {
		t.Fatalf("%+v %v", task, err)
	}
	files := paramsGlob(e.params)
	if len(files) != 1 {
		t.Fatalf("файлов параметров %d", len(files))
	}
	data, _ := os.ReadFile(files[0])
	if !strings.Contains(string(data), "СЕКРЕТНЫЙ-UUID") {
		t.Fatalf("ответы не записаны: %s", data)
	}
	got := e.lastCommand(t, task.ID)
	if !strings.HasSuffix(got, "internal warp-install --params "+files[0]) {
		t.Fatalf("команда: %s", got)
	}
	if strings.Contains(strings.Join(e.f.calls[0], " "), "СЕКРЕТНЫЙ-UUID") {
		t.Fatal("секрет в командной строке")
	}
	// Уже установлен.
	e2 := newWarpEnv(t, true)
	if _, err := e2.client.InstallWarp(ctx, nodeapi.WarpInstallAnswers{Mode: "warp"}); status(err) != 409 {
		t.Fatalf("повторная установка: %v", err)
	}
}

func paramsGlob(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "params-*.json"))
	return m
}

func TestWarpNotConfigured(t *testing.T) {
	e := newAPI(t)
	if _, err := e.client.Warp(context.Background()); status(err) != 503 {
		t.Fatalf("%v", err)
	}
}

func TestWarpTaskTimeouts(t *testing.T) {
	want := map[string]time.Duration{TaskWarpUpdate: 900 * time.Second, TaskWarpInstall: 1800 * time.Second, TaskWarpSync: 600 * time.Second}
	for k, d := range want {
		if DefaultTaskTimeouts[k] != d {
			t.Errorf("%s: %v", k, DefaultTaskTimeouts[k])
		}
	}
}
