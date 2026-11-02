package node

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

const apiSetup = `WIREGUARD_ENABLE=y
ROUTE_ALL=n
SCAN_PROTECTION=y
OPENVPN_HOST=
ALTERNATIVE_FAKE_IP=n
VPN_WARP_PRIVATE_KEY=TOPSECRETKEY
VPN_WARP_PUBLIC_KEY=PUBKEY
UNKNOWN_KEY=zzz
`

func setupEnv(t *testing.T) (apiEnv, string) {
	t.Helper()
	e := newAPI(t)
	p := filepath.Join(e.api.AntiZapretDir, "setup")
	if err := os.WriteFile(p, []byte(apiSetup), 0o640); err != nil {
		t.Fatal(err)
	}
	e.api.Setup = &antizapret.SetupFile{
		Path:    p,
		Backups: &antizapret.Backups{Dir: filepath.Join(filepath.Dir(e.api.AntiZapretDir), "backup", "antizapret"), Now: time.Now},
	}
	return e, p
}

func TestAPISetupGetHidesSecrets(t *testing.T) {
	e, _ := setupEnv(t)
	list, err := e.client.Setup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for i, s := range list {
		by[s.Key] = i
		if strings.Contains(s.Key, "PRIVATE_KEY") || strings.Contains(s.Value, "TOPSECRET") {
			t.Fatalf("секрет в ответе: %+v", s)
		}
		if s.Apply == nil {
			t.Fatalf("apply должен быть массивом: %+v", s)
		}
	}
	if len(list) != 7 || list[0].Key != "WIREGUARD_ENABLE" {
		t.Fatalf("%+v", list)
	}
	if s := list[by["ROUTE_ALL"]]; s.Kind != "yn" || !s.Editable || strings.Join(s.Apply, ",") != "doall" || s.Value != "n" || s.Title == "" {
		t.Fatalf("%+v", s)
	}
	if s := list[by["ALTERNATIVE_FAKE_IP"]]; s.Editable || strings.Join(s.Apply, ",") != "reinstall" {
		t.Fatalf("%+v", s)
	}
	if s := list[by["UNKNOWN_KEY"]]; s.Editable || s.Kind != "" || len(s.Apply) != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestAPISetupPut(t *testing.T) {
	e, p := setupEnv(t)
	ctx := context.Background()
	res, err := e.client.SetSetup(ctx, map[string]string{"ROUTE_ALL": "y", "SCAN_PROTECTION": "n"})
	if err != nil || strings.Join(res.Changed, ",") != "ROUTE_ALL,SCAN_PROTECTION" || strings.Join(res.Apply, ",") != "doall,restart" {
		t.Fatalf("%+v, %v", res, err)
	}
	b, _ := os.ReadFile(p)
	want := strings.NewReplacer("ROUTE_ALL=n", "ROUTE_ALL=y", "SCAN_PROTECTION=y", "SCAN_PROTECTION=n").Replace(apiSetup)
	if string(b) != want {
		t.Fatalf("%q", b)
	}
	// Задачи сами не запускаются.
	if e.api.Tasks != nil {
		t.Fatal("тест предполагает отсутствие задач")
	}
}

func TestAPISetupPutRejections(t *testing.T) {
	e, p := setupEnv(t)
	ctx := context.Background()
	for name, vals := range map[string]map[string]string{
		"reinstall":   {"ALTERNATIVE_FAKE_IP": "y"},
		"секрет":      {"VPN_WARP_PRIVATE_KEY": "x"},
		"неизвестный": {"UNKNOWN_KEY": "x"},
		"значение":    {"ROUTE_ALL": "maybe"},
		"смесь":       {"ROUTE_ALL": "y", "ALTERNATIVE_FAKE_IP": "y"},
	} {
		_, err := e.client.SetSetup(ctx, vals)
		if status(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
		if b, _ := os.ReadFile(p); string(b) != apiSetup {
			t.Fatalf("%s: файл изменён", name)
		}
	}
	if _, err := e.client.SetSetup(ctx, map[string]string{}); status(err) != 400 {
		t.Errorf("пустой запрос: %v", err)
	}
}

func TestAPISetupNotConfiguredAndToken(t *testing.T) {
	e := newAPI(t)
	if _, err := e.client.Setup(context.Background()); status(err) != 503 {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		req, _ := http.NewRequest(m, e.srv.URL+"/v1/setup", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d", m, resp.StatusCode)
		}
	}
}
