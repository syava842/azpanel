package nodeapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/syava842/azpanel/internal/telemt"
)

// Типы telemt общие у агента и панели.
type (
	TelemtStatus   = telemt.Status
	TelemtLink     = telemt.LinkInfo
	TelemtInstall  = telemt.InstallParams
	TelemtUserInfo = telemt.UserInfo
)

// TelemtRelease — установленная и последняя версии telemt.
type TelemtRelease struct {
	Current         string    `json:"current,omitempty"`
	Latest          string    `json:"latest"`
	UpdateAvailable bool      `json:"update_available"`
	Checked         time.Time `json:"checked"`
}

// TelemtPreflight — занятость портов перед установкой.
type TelemtPreflight struct {
	Port     int          `json:"port"`
	PortFree bool         `json:"port_free"`
	Busy     map[int]bool `json:"busy"` // 80, 443, 504, 508: бывают заняты OpenVPN и nginx
}

// TelemtAddUser — запрос на добавление пользователя. Secret: пусто — сгенерировать;
// иначе 32 hex либо ключ/ссылка целиком (домен обязан совпасть с tls_domain).
type TelemtAddUser struct {
	Name   string `json:"name"`
	Secret string `json:"secret,omitempty"`
}

// TelemtUserResult — задача правки пользователей; секрет только маской.
type TelemtUserResult struct {
	Task         Task   `json:"task"`
	Name         string `json:"name"`
	SecretMasked string `json:"secret_masked,omitempty"`
}

// TelemtStatus — состояние telemt без секретов.
func (c *HTTPClient) TelemtStatus(ctx context.Context) (TelemtStatus, error) {
	var v TelemtStatus
	return v, c.do(ctx, http.MethodGet, "/v1/telemt", nil, &v)
}

// TelemtRelease сверяет установленную версию с последним релизом.
func (c *HTTPClient) TelemtRelease(ctx context.Context) (TelemtRelease, error) {
	var v TelemtRelease
	return v, c.do(ctx, http.MethodGet, "/v1/telemt/release", nil, &v)
}

// TelemtPreflight проверяет порт установки.
func (c *HTTPClient) TelemtPreflight(ctx context.Context, port int) (TelemtPreflight, error) {
	var v TelemtPreflight
	return v, c.do(ctx, http.MethodGet, "/v1/telemt/preflight?port="+strconv.Itoa(port), nil, &v)
}

// TelemtAddUser добавляет пользователя (задача telemt-restart).
func (c *HTTPClient) TelemtAddUser(ctx context.Context, req TelemtAddUser) (TelemtUserResult, error) {
	var v TelemtUserResult
	return v, c.do(ctx, http.MethodPost, "/v1/telemt/users", req, &v)
}

// TelemtRemoveUser удаляет пользователя (задача telemt-restart).
func (c *HTTPClient) TelemtRemoveUser(ctx context.Context, name string) (TelemtUserResult, error) {
	var v TelemtUserResult
	return v, c.do(ctx, http.MethodDelete, "/v1/telemt/users/"+url.PathEscape(name), nil, &v)
}

// TelemtLink — ссылка пользователя; единственный вызов, возвращающий секрет целиком.
// server — адрес для клиента Telegram; пусто — из журнала telemt.
func (c *HTTPClient) TelemtLink(ctx context.Context, name, server string) (TelemtLink, error) {
	var v TelemtLink
	p := "/v1/telemt/users/" + url.PathEscape(name) + "/link"
	if server != "" {
		p += "?server=" + url.QueryEscape(server)
	}
	return v, c.do(ctx, http.MethodGet, p, nil, &v)
}

// TelemtRestart перезапускает telemt задачей с проверкой.
func (c *HTTPClient) TelemtRestart(ctx context.Context) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/telemt/restart", nil, &v)
}

// TelemtUpdate обновляет telemt до последнего релиза задачей, с откатом.
func (c *HTTPClient) TelemtUpdate(ctx context.Context) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/telemt/update", nil, &v)
}

// InstallTelemt ставит telemt задачей telemt-install.
func (c *HTTPClient) InstallTelemt(ctx context.Context, p TelemtInstall) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/telemt/install", p, &v)
}
