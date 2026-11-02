package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/proxyapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type apiEnv struct {
	k      *kernel
	api    *API
	client *proxyapi.HTTPClient
	srv    *httptest.Server
}

func newAPI(t *testing.T) apiEnv {
	t.Helper()
	proc := t.TempDir()
	os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu  100 0 50 800 50 0 0 0\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), 0o644)
	k := newKernel(t)
	api := &API{
		Token: testToken, Version: "t1", Apply: k.applier(),
		Conntrack: ProcConntrack("testdata/nf_conntrack.txt"),
		Sampler:   &sysinfo.Sampler{Proc: proc, DiskPath: t.TempDir()},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       func() time.Time { return time.Unix(2_000_000_000, 0) },
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return apiEnv{k: k, api: api, client: proxyapi.New(srv.URL, testToken), srv: srv}
}

func TestAPIRequiresToken(t *testing.T) {
	e := newAPI(t)
	for _, tok := range []string{"", "чужой"} {
		_, err := proxyapi.New(e.srv.URL, tok).State(context.Background())
		var ae *nodeapi.Error
		if !errors.As(err, &ae) || ae.Status != 401 {
			t.Fatalf("токен %q: %v", tok, err)
		}
	}
	resp, err := http.Get(e.srv.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || resp.Header.Get(nodeapi.ProtoHeader) != "1" {
		t.Fatalf("статус %d, заголовок %q", resp.StatusCode, resp.Header.Get(nodeapi.ProtoHeader))
	}
}

func TestAPIInfo(t *testing.T) {
	e := newAPI(t)
	in, err := e.client.Info(context.Background())
	if err != nil || in.Proto != nodeapi.Proto || in.Version != "t1" || in.Hostname == "" {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestAPIState(t *testing.T) {
	e := newAPI(t)
	st, err := e.client.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Alive || len(st.Forwards) != 20 || len(st.Groups) != 2 {
		t.Fatalf("%+v", st)
	}
	if st.Groups[0].Target != "198.51.100.20" || st.Groups[1].Target != "198.51.100.20" {
		t.Errorf("группы %+v", st.Groups)
	}
	if st.Connections != 5 {
		t.Errorf("соединений %d", st.Connections)
	}
	if st.Resources.Memory.TotalBytes == 0 {
		t.Errorf("ресурсы пусты: %+v", st.Resources)
	}
}

func TestAPIStateSurvivesBrokenConntrack(t *testing.T) {
	e := newAPI(t)
	e.api.Conntrack = func(context.Context) (io.ReadCloser, error) { return nil, errors.New("нет") }
	st, err := e.client.State(context.Background())
	if err != nil || st.Connections != 0 || len(st.Forwards) != 20 {
		t.Fatalf("%+v %v", st, err)
	}
	_, err = e.client.Conntrack(context.Background())
	var ae *nodeapi.Error
	if !errors.As(err, &ae) || ae.Status != 500 {
		t.Fatalf("conntrack: %v", err)
	}
}

func TestAPIConntrack(t *testing.T) {
	e := newAPI(t)
	cs, err := e.client.Conntrack(context.Background())
	if err != nil || len(cs) != 5 {
		t.Fatalf("%+v %v", cs, err)
	}
}

func TestAPISetTarget(t *testing.T) {
	e := newAPI(t)
	res, err := e.client.SetTarget(context.Background(), "wireguard", "198.51.100.99")
	if err != nil || res.To != "198.51.100.99" || !res.Saved || res.Changed != 7 {
		t.Fatalf("%+v %v", res, err)
	}
	st, _ := e.client.State(context.Background())
	if st.Groups[1].Target != "198.51.100.99" || st.Groups[0].Target != "198.51.100.20" {
		t.Fatalf("группы %+v", st.Groups)
	}
}

func TestAPISetTargetErrors(t *testing.T) {
	e := newAPI(t)
	cases := []struct {
		group, ip string
		status    int
	}{
		{"x", "198.51.100.1", 400}, {"openvpn", "не-адрес", 400}, {"openvpn", "0.0.0.0", 400},
	}
	for _, c := range cases {
		_, err := e.client.SetTarget(context.Background(), c.group, c.ip)
		var ae *nodeapi.Error
		if !errors.As(err, &ae) || ae.Status != c.status {
			t.Errorf("%+v: %v", c, err)
		}
	}
	// Тело с лишним полем и нет правил группы.
	req, _ := http.NewRequest(http.MethodPut, e.srv.URL+"/v1/proxy/target", strings.NewReader(`{"group":"openvpn","ip":"198.51.100.1","extra":1}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("лишнее поле: %d", resp.StatusCode)
	}
	e.k.rules = "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n"
	_, err := e.client.SetTarget(context.Background(), "openvpn", "198.51.100.1")
	var ae *nodeapi.Error
	if !errors.As(err, &ae) || ae.Status != 409 {
		t.Errorf("нет правил: %v", err)
	}
	if len(e.k.restores) != 0 {
		t.Error("правила трогать было нельзя")
	}
}

func TestAPISetTargetRestoreFailureIs500AndRolledBack(t *testing.T) {
	e := newAPI(t)
	orig := e.k.rules
	e.k.failRestoreAt = 1
	_, err := e.client.SetTarget(context.Background(), "openvpn", "198.51.100.99")
	var ae *nodeapi.Error
	if !errors.As(err, &ae) || ae.Status != 500 || !strings.Contains(ae.Message, "возвращены") || e.k.rules != orig {
		t.Fatalf("%v", err)
	}
}
