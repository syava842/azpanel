package panel

import (
	"context"
	"errors"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
)

type fakeNginxAgent struct {
	got nodeapi.NginxSnippetRequest
	res nodeapi.NginxSnippetResult
	err error
}

func (f *fakeNginxAgent) UpdateNginxSnippet(_ context.Context, req nodeapi.NginxSnippetRequest) (nodeapi.NginxSnippetResult, error) {
	f.got = req
	return f.res, f.err
}

var _ nginxSnippetUpdater = (*nodeapi.HTTPClient)(nil)

// Правка фрагмента nginx идёт через агента: запрос несёт префикс и адрес, а
// done берётся из ответа.
func TestNginxSyncViaAgent(t *testing.T) {
	a := &fakeNginxAgent{res: nodeapi.NginxSnippetResult{Done: true, Task: &nodeapi.Task{ID: "t1", Kind: "nginx-snippet"}}}
	done, err := nginxSyncVia(a)("/azpanel/", "127.0.0.1:8080")
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if a.got.BasePath != "/azpanel/" || a.got.Upstream != "127.0.0.1:8080" {
		t.Fatalf("запрос агенту: %+v", a.got)
	}
	// фрагмента нет: done=false, ошибки нет, ничего не запущено
	a = &fakeNginxAgent{res: nodeapi.NginxSnippetResult{Done: false}}
	if done, err := nginxSyncVia(a)("", "127.0.0.1:8080"); err != nil || done {
		t.Fatalf("без фрагмента: done=%v err=%v", done, err)
	}
	// отказ агента: ошибка с текстом агента
	a = &fakeNginxAgent{err: &nodeapi.Error{Status: 409, Message: "идёт другая задача"}}
	if _, err := nginxSyncVia(a)("/x/", "127.0.0.1:8080"); err == nil || err.Error() != "идёт другая задача" {
		t.Fatalf("отказ: %v", err)
	}
	a = &fakeNginxAgent{err: errors.New("connection refused")}
	if _, err := nginxSyncVia(a)("/x/", "127.0.0.1:8080"); err == nil {
		t.Fatal("сетевая ошибка потеряна")
	}
}
