// Package nodeapi — HTTP API агента узла: типы запросов и ответов и клиент,
// которым пользуется панель. Proto растёт при несовместимых изменениях;
// панель работает с агентами своей и предыдущей версии протокола.
package nodeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/sysinfo"
)

const (
	Proto       = 1
	ProtoHeader = "X-Azpanel-Proto"

	KindOpenVPN   = "openvpn"
	KindWireGuard = "wireguard"

	maxResponse = 16 << 20
)

type Info struct {
	Proto     int    `json:"proto"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname"`
	WireGuard bool   `json:"wireguard"` // WIREGUARD_ENABLE=y в setup
}

type Client struct {
	Name        string     `json:"name"`
	OpenVPN     bool       `json:"openvpn"`
	WireGuard   bool       `json:"wireguard"`
	CertExpires *time.Time `json:"cert_expires,omitempty"`
	Limit       int        `json:"limit"` // 0 — без ограничения
	Blocked     bool       `json:"blocked"`
}

type Session struct {
	Kind          string     `json:"kind"`     // openvpn, wireguard
	Instance      string     `json:"instance"` // экземпляр OpenVPN или интерфейс WG
	Name          string     `json:"name"`
	Addr          string     `json:"addr"`
	RxBytes       int64      `json:"rx_bytes"` // принято сервером от клиента
	TxBytes       int64      `json:"tx_bytes"`
	Since         *time.Time `json:"since,omitempty"`          // OpenVPN
	LastHandshake *time.Time `json:"last_handshake,omitempty"` // WireGuard
}

type System struct {
	Resources sysinfo.Snapshot  `json:"resources"`
	Services  []sysinfo.Service `json:"services"`
}

type Profile struct {
	Kind    string `json:"kind"`
	Variant string `json:"variant"`
	File    string `json:"file"`
}

type CreateClient struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Days int    `json:"days,omitempty"` // только OpenVPN; 0 — 3650
}

type Renew struct {
	Days int `json:"days"`
}

type SetLimit struct {
	Limit int `json:"limit"` // 0 — снять лимит
}

type SetBlocked struct {
	Blocked bool `json:"blocked"`
}

type Result struct {
	Output string `json:"output,omitempty"` // хвост вывода client.sh
	Killed int    `json:"killed,omitempty"` // разорвано сессий при блокировке
}

type ErrorBody struct {
	Error string `json:"error"`
}

// Error — ответ агента с кодом 4xx или 5xx.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("агент ответил %d: %s", e.Status, e.Message)
}

type HTTPClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New: тайм-аут с запасом на самый долгий client.sh (до 10 минут по
// настройке узла).
func New(baseURL, token string) *HTTPClient {
	return &HTTPClient{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 11 * time.Minute}}
}

func (c *HTTPClient) Info(ctx context.Context) (Info, error) {
	var v Info
	return v, c.do(ctx, http.MethodGet, "/v1/info", nil, &v)
}

func (c *HTTPClient) Clients(ctx context.Context) ([]Client, error) {
	var v []Client
	return v, c.do(ctx, http.MethodGet, "/v1/clients", nil, &v)
}

func (c *HTTPClient) Sessions(ctx context.Context) ([]Session, error) {
	var v []Session
	return v, c.do(ctx, http.MethodGet, "/v1/sessions", nil, &v)
}

func (c *HTTPClient) System(ctx context.Context) (System, error) {
	var v System
	return v, c.do(ctx, http.MethodGet, "/v1/system", nil, &v)
}

func (c *HTTPClient) Profiles(ctx context.Context, name string) ([]Profile, error) {
	var v []Profile
	return v, c.do(ctx, http.MethodGet, "/v1/clients/"+url.PathEscape(name)+"/profiles", nil, &v)
}

func (c *HTTPClient) Profile(ctx context.Context, name string, p Profile) ([]byte, error) {
	path := "/v1/clients/" + url.PathEscape(name) + "/profiles/" +
		url.PathEscape(p.Kind) + "/" + url.PathEscape(p.Variant) + "/" + url.PathEscape(p.File)
	return c.raw(ctx, http.MethodGet, path, nil)
}

func (c *HTTPClient) CreateClient(ctx context.Context, req CreateClient) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodPost, "/v1/clients", req, &v)
}

func (c *HTTPClient) Renew(ctx context.Context, name string, days int) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodPost, "/v1/clients/openvpn/"+url.PathEscape(name)+"/renew", Renew{Days: days}, &v)
}

func (c *HTTPClient) DeleteClient(ctx context.Context, kind, name string) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodDelete, "/v1/clients/"+url.PathEscape(kind)+"/"+url.PathEscape(name), nil, &v)
}

func (c *HTTPClient) SetLimit(ctx context.Context, name string, limit int) error {
	return c.do(ctx, http.MethodPut, "/v1/clients/"+url.PathEscape(name)+"/limit", SetLimit{Limit: limit}, nil)
}

func (c *HTTPClient) SetBlocked(ctx context.Context, name string, blocked bool) (Result, error) {
	var v Result
	return v, c.do(ctx, http.MethodPut, "/v1/clients/"+url.PathEscape(name)+"/blocked", SetBlocked{Blocked: blocked}, &v)
}

func (c *HTTPClient) do(ctx context.Context, method, path string, in, out any) error {
	body, err := c.raw(ctx, method, path, in)
	if err != nil || out == nil || len(body) == 0 {
		return err
	}
	return json.Unmarshal(body, out)
}

func (c *HTTPClient) raw(ctx context.Context, method, path string, in any) ([]byte, error) {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode >= 400 {
		var e ErrorBody
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return nil, &Error{Status: resp.StatusCode, Message: e.Error}
	}
	return body, err
}
