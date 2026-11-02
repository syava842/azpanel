package nodeapi

import (
	"context"
	"net/http"
	"time"
)

// AZCommit — коммит репозитория AntiZapret-VPN (ветка main).
type AZCommit struct {
	SHA     string    `json:"sha"`
	Message string    `json:"message"` // первая строка сообщения
	Date    time.Time `json:"date"`
}

// AZVersion — версия AntiZapret на узле. Current пуст — версия неизвестна
// (скрипты отличаются от всех коммитов последних 200): Message объясняет.
type AZVersion struct {
	Current       string    `json:"current"`
	CurrentSource string    `json:"current_source,omitempty"` // recorded — поставлено панелью; scripts — найдено по хешам скриптов
	Latest        *AZCommit `json:"latest,omitempty"`
	UpToDate      bool      `json:"up_to_date"`
	// Behind — коммиты новее установленного, новые сверху. При неизвестной
	// версии — последние 20.
	Behind    []AZCommit `json:"behind"`
	Truncated bool       `json:"truncated,omitempty"` // установленная версия старше 200 коммитов
	Message   string     `json:"message,omitempty"`
	Error     string     `json:"error,omitempty"` // GitHub не ответил
}

// AZVersion — версия AntiZapret на узле и список новых коммитов.
func (c *HTTPClient) AZVersion(ctx context.Context) (AZVersion, error) {
	var v AZVersion
	return v, c.do(ctx, http.MethodGet, "/v1/antizapret/version", nil, &v)
}
