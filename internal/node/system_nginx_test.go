package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

func nginxEnv(t *testing.T, present bool) (apiEnv, *fakeExec, *Tasks, string) {
	e, f, tk := tasksEnv(t)
	params := filepath.Join(t.TempDir(), "params")
	e.api.Nginx = &NginxService{Self: "/opt/azpanel/bin/azpanel", ParamsDir: params, Present: func() bool { return present }}
	return e, f, tk, params
}

func TestNginxSnippetStartsTask(t *testing.T) {
	e, f, tk, params := nginxEnv(t, true)
	res, err := e.client.UpdateNginxSnippet(context.Background(), nodeapi.NginxSnippetRequest{BasePath: "/azpanel/", Upstream: "127.0.0.1:8080"})
	if err != nil || !res.Done || res.Task == nil || res.Task.Kind != TaskNginxSnippet {
		t.Fatalf("%+v %v", res, err)
	}
	f.done()
	waitFinished(t, tk, res.Task.ID)
	call := strings.Join(f.calls[0], " ")
	if !strings.Contains(call, "internal nginx-snippet --params ") || !strings.Contains(call, "RuntimeMaxSec=120") {
		t.Fatalf("команда задачи: %s", call)
	}
	files, _ := filepath.Glob(filepath.Join(params, "params-*.json"))
	if len(files) != 1 {
		t.Fatalf("файл параметров: %v", files)
	}
	data, _ := os.ReadFile(files[0])
	var p nodeapi.NginxSnippetRequest
	if json.Unmarshal(data, &p) != nil || p.BasePath != "/azpanel/" || p.Upstream != "127.0.0.1:8080" {
		t.Fatalf("параметры: %s", data)
	}
	if DefaultTaskTimeouts[TaskNginxSnippet] != 120*time.Second {
		t.Fatal("предел задачи")
	}
}

func TestNginxSnippetAbsentIsNoop(t *testing.T) {
	e, f, _, _ := nginxEnv(t, false)
	res, err := e.client.UpdateNginxSnippet(context.Background(), nodeapi.NginxSnippetRequest{BasePath: "/azpanel/", Upstream: "127.0.0.1:8080"})
	if err != nil || res.Done || res.Task != nil || len(f.calls) != 0 {
		t.Fatalf("%+v %v %v", res, err, f.calls)
	}
}

func TestNginxSnippetRejectsInjection(t *testing.T) {
	e, f, _, _ := nginxEnv(t, true)
	for _, r := range []nodeapi.NginxSnippetRequest{
		{BasePath: "/x; } server {", Upstream: "127.0.0.1:8080"},
		{BasePath: "/../x/", Upstream: "127.0.0.1:8080"},
		{BasePath: "azpanel", Upstream: "127.0.0.1:8080"},
		{BasePath: "/azpanel/", Upstream: "10.0.0.1:8080"},
		{BasePath: "/azpanel/", Upstream: "127.0.0.1:8080;evil"},
		{BasePath: "/azpanel/", Upstream: "localhost:8080"},
	} {
		if _, err := e.client.UpdateNginxSnippet(context.Background(), r); status(err) != 400 {
			t.Errorf("%+v: %v", r, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("задача запущена: %v", f.calls)
	}
}

func TestNginxSnippetBusyIs409(t *testing.T) {
	e, _, _, _ := nginxEnv(t, true)
	if _, err := e.client.ApplyRouting(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := e.client.UpdateNginxSnippet(context.Background(), nodeapi.NginxSnippetRequest{BasePath: "/a/", Upstream: "[::1]:8080"})
	if status(err) != 409 {
		t.Fatalf("%v", err)
	}
}
