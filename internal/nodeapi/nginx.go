package nodeapi

import (
	"context"
	"net/http"
)

// NginxSnippetRequest — новые параметры фрагмента nginx панели: panel.base_path
// и panel.listen (петлевой адрес:порт).
type NginxSnippetRequest struct {
	BasePath string `json:"base_path"`
	Upstream string `json:"upstream"`
}

// NginxSnippetResult — ответ на смену фрагмента. Done=false: фрагмента панели
// в nginx нет, ничего не запущено. Done=true: запущена задача Task.
type NginxSnippetResult struct {
	Done bool  `json:"done"`
	Task *Task `json:"task,omitempty"`
}

// UpdateNginxSnippet просит агента переписать фрагмент nginx панели задачей
// nginx-snippet (копия, nginx -t, откат, reload).
func (c *HTTPClient) UpdateNginxSnippet(ctx context.Context, req NginxSnippetRequest) (NginxSnippetResult, error) {
	var v NginxSnippetResult
	return v, c.do(ctx, http.MethodPost, "/v1/system/nginx-snippet", req, &v)
}
