package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/telemt"
)

const (
	telemtSecret  = "00112233445566778899aabbccddeeff"
	telemtDomain  = "www.example.com"
	telemtJournal = "MAESTRO: EE-TLS: tg://proxy?server=192.0.2.94&port=902&secret=ee00112233445566778899aabbccddeeff7777772e6578616d706c652e636f6d\n"
)

type telemtEnv struct {
	apiEnv
	f         *fakeExec
	tk        *Tasks
	env       *telemt.Env
	params    string
	restarts  *atomic.Int32
	installed bool
}

func newTelemtEnv(t *testing.T, installed bool) telemtEnv {
	t.Helper()
	e, f, tk := tasksEnv(t)
	dir := t.TempDir()
	var restarts atomic.Int32
	env := &telemt.Env{
		Binary: filepath.Join(dir, "telemt"), Config: filepath.Join(dir, "etc", "config.toml"), Unit: "telemt",
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			switch {
			case name == "systemctl" && args[0] == "show":
				return []byte(fmt.Sprintf("ActiveState=active\nNRestarts=%d\n", restarts.Load())), nil
			case name == "journalctl":
				return []byte(telemtJournal), nil
			case len(args) == 1 && args[0] == "--version":
				return []byte("telemt 3.5.7\n"), nil
			}
			return nil, nil
		},
		PortFree: func(port int) error {
			if port == 80 || port == 902 && installed {
				return fmt.Errorf("занят")
			}
			return nil
		},
	}
	if installed {
		os.MkdirAll(filepath.Dir(env.Config), 0o755)
		cfg, err := os.ReadFile("../telemt/testdata/config-example.toml")
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(env.Config, cfg, 0o640)
		os.WriteFile(env.Binary, []byte("bin"), 0o755)
	}
	params := filepath.Join(dir, "params")
	e.api.Telemt = &TelemtService{Env: env, Self: "/opt/azpanel/bin/azpanel", ParamsDir: params}
	return telemtEnv{apiEnv: e, f: f, tk: tk, env: env, params: params, restarts: &restarts, installed: installed}
}

// argvOf — команда задачи после "--" systemd-run и обёртки (с "internal").
func argvOf(call []string) []string {
	for i, a := range call {
		if a == "internal" && i > 0 {
			return call[i-1:]
		}
	}
	return call
}

func (e telemtEnv) rawGet(t *testing.T, path string) string {
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

func (e telemtEnv) paramsFiles(t *testing.T) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(e.params, "params-*.json"))
	return m
}

func TestTelemtStatusMasksSecrets(t *testing.T) {
	e := newTelemtEnv(t, true)
	body := e.rawGet(t, "/v1/telemt")
	if strings.Contains(body, telemtSecret) || strings.Contains(body, "445566778899") {
		t.Fatalf("секрет в ответе: %s", body)
	}
	st, err := e.client.TelemtStatus(context.Background())
	if err != nil || !st.Installed || st.Version != "3.5.7" || st.Port != 902 || st.Domain != telemtDomain || len(st.Users) != 1 || st.Users[0].Name != "user" {
		t.Fatalf("%+v %v", st, err)
	}
	// Не установлен.
	e2 := newTelemtEnv(t, false)
	if st, _ := e2.client.TelemtStatus(context.Background()); st.Installed {
		t.Fatal("пустой узел не установлен")
	}
}

func TestTelemtRestartsGrowthReported(t *testing.T) {
	e := newTelemtEnv(t, true)
	ctx := context.Background()
	if st, _ := e.client.TelemtStatus(ctx); st.RestartsGrewAt != nil {
		t.Fatal("первый опрос — только базовая точка")
	}
	e.restarts.Store(3)
	st, _ := e.client.TelemtStatus(ctx)
	if st.NRestarts != 3 || st.RestartsGrewAt == nil {
		t.Fatalf("рост не замечен: %+v", st)
	}
}

func TestTelemtLinkIsExplicitAndComplete(t *testing.T) {
	e := newTelemtEnv(t, true)
	li, err := e.client.TelemtLink(context.Background(), "user", "")
	if err != nil {
		t.Fatal(err)
	}
	want := "tg://proxy?server=192.0.2.94&port=902&secret=ee" + telemtSecret + "7777772e6578616d706c652e636f6d"
	if li.Link != want || !strings.HasPrefix(li.WebLink, "https://t.me/proxy?") {
		t.Fatalf("%+v", li)
	}
	if _, err := e.client.TelemtLink(context.Background(), "нет", ""); status(err) != 404 {
		t.Fatalf("неизвестный пользователь: %v", err)
	}
	li, _ = e.client.TelemtLink(context.Background(), "user", "203.0.113.5")
	if !strings.Contains(li.Link, "server=203.0.113.5") {
		t.Fatal(li.Link)
	}
}

func TestTelemtAddUserStartsTaskWithoutSecretInArgv(t *testing.T) {
	e := newTelemtEnv(t, true)
	ctx := context.Background()
	res, err := e.client.TelemtAddUser(ctx, nodeapi.TelemtAddUser{Name: "azpanel-test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Task.Kind != TaskTelemtRestart || res.Name != "azpanel-test" || res.SecretMasked == "" || strings.Contains(res.SecretMasked, "…") == false {
		t.Fatalf("%+v", res)
	}
	files := e.paramsFiles(t)
	if len(files) != 1 {
		t.Fatalf("файлов параметров %d", len(files))
	}
	data, _ := os.ReadFile(files[0])
	var p telemt.ApplyParams
	if err := json.Unmarshal(data, &p); err != nil || p.Op != "add" || p.Name != "azpanel-test" || !telemt.ValidSecret(p.Secret) {
		t.Fatalf("параметры: %s %v", data, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(files[0]); st.Mode().Perm() != 0o600 {
			t.Fatalf("права файла параметров %v", st.Mode().Perm())
		}
	}
	e.f.done()
	waitFinished(t, e.tk, res.Task.ID)
	call := strings.Join(argvOf(e.f.calls[0]), " ")
	if !strings.Contains(call, "/opt/azpanel/bin/azpanel internal telemt-apply --params "+files[0]) {
		t.Fatalf("команда: %s", call)
	}
	if strings.Contains(strings.Join(e.f.calls[0], " "), p.Secret) {
		t.Fatal("секрет попал в командную строку задачи")
	}
	if tail, _ := e.tk.Tail(res.Task); strings.Contains(tail, p.Secret) {
		t.Fatal("секрет попал в журнал задачи")
	}
}

func TestTelemtAddUserKeyValidation(t *testing.T) {
	e := newTelemtEnv(t, true)
	ctx := context.Background()
	good := "ee" + "ffeeddccbbaa99887766554433221100" + "7777772e6578616d706c652e636f6d"
	cases := []struct {
		name string
		req  nodeapi.TelemtAddUser
		want int
	}{
		{"плохое имя", nodeapi.TelemtAddUser{Name: "a b"}, 400},
		{"чужой домен", nodeapi.TelemtAddUser{Name: "x", Secret: "ee" + "ffeeddccbbaa99887766554433221100" + "6f746865722e6578616d706c65"}, 400},
		{"неверная длина", nodeapi.TelemtAddUser{Name: "x", Secret: "ee1234"}, 400},
		{"дубль имени", nodeapi.TelemtAddUser{Name: "user"}, 409},
		{"дубль секрета", nodeapi.TelemtAddUser{Name: "x", Secret: telemtSecret}, 409},
	}
	for _, c := range cases {
		if _, err := e.client.TelemtAddUser(ctx, c.req); status(err) != c.want {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if len(e.paramsFiles(t)) != 0 {
		t.Fatal("при отказе файлы параметров не создаются")
	}
	res, err := e.client.TelemtAddUser(ctx, nodeapi.TelemtAddUser{Name: "ok", Secret: good})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(e.paramsFiles(t)[0])
	if !strings.Contains(string(data), "ffeeddccbbaa99887766554433221100") || strings.Contains(string(data), "7777772e") {
		t.Fatalf("из ключа должен браться только секрет: %s", data)
	}
	e.f.done()
	waitFinished(t, e.tk, res.Task.ID)
}

func TestTelemtRemoveUser(t *testing.T) {
	e := newTelemtEnv(t, true)
	ctx := context.Background()
	if _, err := e.client.TelemtRemoveUser(ctx, "user"); status(err) != 409 {
		t.Fatalf("последнего пользователя удалять нельзя: %v", err)
	}
	if _, err := e.client.TelemtRemoveUser(ctx, "нет"); status(err) != 404 {
		t.Fatalf("неизвестный: %v", err)
	}
	if len(e.paramsFiles(t)) != 0 {
		t.Fatal("файлы параметров при отказе")
	}
}

func TestTelemtBusyRemovesParams(t *testing.T) {
	e := newTelemtEnv(t, true)
	ctx := context.Background()
	first, err := e.client.TelemtRestart(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.paramsFiles(t)) != 1 {
		t.Fatal("файл параметров первой задачи")
	}
	_, err = e.client.TelemtAddUser(ctx, nodeapi.TelemtAddUser{Name: "second"})
	if status(err) != 409 {
		t.Fatalf("вторая задача: %v", err)
	}
	if len(e.paramsFiles(t)) != 1 {
		t.Fatal("файл параметров отклонённой задачи не удалён")
	}
	e.f.done()
	waitFinished(t, e.tk, first.ID)
}

func TestTelemtInstallChecks(t *testing.T) {
	e := newTelemtEnv(t, false)
	ctx := context.Background()
	if _, err := e.client.InstallTelemt(ctx, nodeapi.TelemtInstall{Port: 70000, Domain: telemtDomain}); status(err) != 400 {
		t.Fatalf("порт: %v", err)
	}
	if _, err := e.client.InstallTelemt(ctx, nodeapi.TelemtInstall{Port: 80, Domain: telemtDomain}); status(err) != 409 {
		t.Fatalf("занятый порт: %v", err)
	}
	pf, err := e.client.TelemtPreflight(ctx, 80)
	if err != nil || pf.PortFree || !pf.Busy[80] || pf.Busy[443] {
		t.Fatalf("%+v %v", pf, err)
	}
	task, err := e.client.InstallTelemt(ctx, nodeapi.TelemtInstall{Port: 902, Domain: telemtDomain, Secret: telemtSecret})
	if err != nil || task.Kind != TaskTelemtInstall {
		t.Fatalf("%+v %v", task, err)
	}
	e.f.done()
	waitFinished(t, e.tk, task.ID)
	if strings.Contains(strings.Join(e.f.calls[0], " "), telemtSecret) {
		t.Fatal("секрет в командной строке установки")
	}
	files := e.paramsFiles(t)
	data, _ := os.ReadFile(files[0])
	var p telemt.InstallParams
	json.Unmarshal(data, &p)
	if p.Secret != telemtSecret || p.MaxConnections != 4000 || p.BufDivisor != 16 || p.User != "user" {
		t.Fatalf("умолчания не применены: %+v", p)
	}
	// Уже установлен.
	e2 := newTelemtEnv(t, true)
	if _, err := e2.client.InstallTelemt(ctx, nodeapi.TelemtInstall{Port: 903, Domain: telemtDomain}); status(err) != 409 {
		t.Fatalf("повторная установка: %v", err)
	}
}

func TestTelemtUpdateRequiresInstalled(t *testing.T) {
	e := newTelemtEnv(t, false)
	if _, err := e.client.TelemtUpdate(context.Background()); status(err) != 409 {
		t.Fatalf("%v", err)
	}
	e2 := newTelemtEnv(t, true)
	task, err := e2.client.TelemtUpdate(context.Background())
	if err != nil || task.Kind != TaskTelemtUpdate {
		t.Fatalf("%+v %v", task, err)
	}
	e2.f.done()
	waitFinished(t, e2.tk, task.ID)
	if got := strings.Join(argvOf(e2.f.calls[0]), " "); !strings.HasSuffix(got, "/opt/azpanel/bin/azpanel internal telemt-update") {
		t.Fatalf("команда: %s", got)
	}
}

func TestTelemtTaskTimeouts(t *testing.T) {
	want := map[string]time.Duration{
		TaskTelemtUpdate: 600 * time.Second, TaskTelemtInstall: 900 * time.Second, TaskTelemtRestart: 120 * time.Second,
	}
	for k, d := range want {
		if DefaultTaskTimeouts[k] != d {
			t.Errorf("%s: %v", k, DefaultTaskTimeouts[k])
		}
	}
}

func TestTelemtReleaseCheck(t *testing.T) {
	e := newTelemtEnv(t, true)
	var hits atomic.Int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `{"tag_name":"3.5.16","assets":[]}`)
	}))
	defer gh.Close()
	e.env.APIBase, e.env.HTTP = gh.URL, gh.Client()
	for i := 0; i < 2; i++ {
		rel, err := e.client.TelemtRelease(context.Background())
		if err != nil || rel.Current != "3.5.7" || rel.Latest != "3.5.16" || !rel.UpdateAvailable {
			t.Fatalf("%+v %v", rel, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("GitHub опрошен %d раз, ждали кеш на час", hits.Load())
	}
}

func TestTelemtNotConfigured(t *testing.T) {
	e := newAPI(t)
	if _, err := e.client.TelemtStatus(context.Background()); status(err) != 503 {
		t.Fatalf("%v", err)
	}
}
