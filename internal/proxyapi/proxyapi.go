// Package proxyapi — HTTP API прокси-агента (azpanel proxy): типы запросов и
// ответов и клиент, которым пользуется панель. Заголовок и номер протокола —
// те же, что у агента узла (nodeapi).
package proxyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

const maxResponse = 16 << 20

// Группы проброшенных портов proxy.sh: OpenVPN и WireGuard/AmneziaWG. У
// каждой группы свой адрес назначения (OPENVPN_IP и WIREGUARD_IP).
const (
	GroupOpenVPN   = "openvpn"
	GroupWireGuard = "wireguard"
)

// Forward — одно DNAT-правило proxy.sh: порт на прокси → адрес назначения.
type Forward struct {
	Group  string `json:"group"`
	Proto  string `json:"proto"`   // tcp | udp
	Port   int    `json:"port"`    // порт на прокси
	ToIP   string `json:"to_ip"`   // адрес назначения
	ToPort int    `json:"to_port"` // порт назначения
	SSH    bool   `json:"ssh,omitempty"`
}

// Group — состояние группы: куда сейчас уходит её трафик.
type Group struct {
	Name    string `json:"name"`
	Target  string `json:"target"`          // пусто — правил группы нет
	Mixed   bool   `json:"mixed,omitempty"` // правила смотрят на разные адреса
	Targets int    `json:"targets"`         // сколько разных адресов назначения
	Ports   []int  `json:"ports"`           // порты на прокси (без SSH), по возрастанию
}

// State — ответ GET /v1/proxy/state.
type State struct {
	Alive       bool             `json:"alive"`
	Groups      []Group          `json:"groups"`
	Forwards    []Forward        `json:"forwards"`
	Connections int              `json:"connections"` // соединений через проброшенные порты
	Resources   sysinfo.Snapshot `json:"resources"`
}

// Conn — соединение клиента через прокси.
// ProxyPort — порт на прокси со стороны сервера назначения: сервер видит
// клиента как «адрес прокси:ProxyPort», по нему панель находит настоящий
// адрес рядом с сессией.
type Conn struct {
	Proto      string `json:"proto"`
	Group      string `json:"group"`
	ListenPort int    `json:"listen_port"` // порт, на который пришёл клиент
	ClientIP   string `json:"client_ip"`
	ClientPort int    `json:"client_port"`
	ProxyPort  int    `json:"proxy_port"`
	Target     string `json:"target"` // адрес:порт сервера назначения
}

// SetTarget — тело PUT /v1/proxy/target.
type SetTarget struct {
	Group string `json:"group"` // openvpn | wireguard
	IP    string `json:"ip"`    // IPv4 нового адреса назначения
}

// TargetResult — итог смены адреса.
type TargetResult struct {
	Group   string `json:"group"`
	From    string `json:"from"`
	To      string `json:"to"`
	Changed int    `json:"changed"` // изменено DNAT-правил
	Saved   bool   `json:"saved"`   // правила сохранены (netfilter-persistent save)
}

// HTTPClient — клиент API прокси-агента.
type HTTPClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *HTTPClient {
	return &HTTPClient{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *HTTPClient) Info(ctx context.Context) (nodeapi.Info, error) {
	var v nodeapi.Info
	return v, c.do(ctx, http.MethodGet, "/v1/info", nil, &v)
}

func (c *HTTPClient) State(ctx context.Context) (State, error) {
	var v State
	return v, c.do(ctx, http.MethodGet, "/v1/proxy/state", nil, &v)
}

func (c *HTTPClient) Conntrack(ctx context.Context) ([]Conn, error) {
	var v []Conn
	return v, c.do(ctx, http.MethodGet, "/v1/proxy/conntrack", nil, &v)
}

func (c *HTTPClient) SetTarget(ctx context.Context, group, ip string) (TargetResult, error) {
	var v TargetResult
	return v, c.do(ctx, http.MethodPut, "/v1/proxy/target", SetTarget{Group: group, IP: ip}, &v)
}

func (c *HTTPClient) do(ctx context.Context, method, path string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode >= 400 {
		var e nodeapi.ErrorBody
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return &nodeapi.Error{Status: resp.StatusCode, Message: e.Error}
	}
	if err != nil || out == nil || len(body) == 0 {
		return err
	}
	return json.Unmarshal(body, out)
}
