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
	"strconv"
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

// Denial — отказ хука в подключении. Reason: limit (сверх лимита
// подключений) или blocked (клиент заблокирован).
type Denial struct {
	Time     time.Time `json:"time"`
	Name     string    `json:"name"`
	Instance string    `json:"instance"`
	Addr     string    `json:"addr"`
	Reason   string    `json:"reason"`
	Count    int       `json:"count,omitempty"` // сессий клиента на момент отказа
	Limit    int       `json:"limit,omitempty"`
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

// Task — фоновая задача AntiZapret (doall, restart, profiles).
type Task struct {
	ID          string     `json:"id"`   // 12 hex
	Kind        string     `json:"kind"` // doall | restart | profiles
	Started     time.Time  `json:"started"`
	Finished    *time.Time `json:"finished,omitempty"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	Interrupted bool       `json:"interrupted,omitempty"` // агент перезапускался: код выхода неизвестен
	Log         string     `json:"log"`                   // путь журнала на узле
}

// TaskDetail — задача и хвост её журнала (до 64 КБ).
type TaskDetail struct {
	Task
	Tail string `json:"tail"`
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

// Denials — отказы хука новее since (нулевое время — все), по возрастанию.
func (c *HTTPClient) Denials(ctx context.Context, since time.Time) ([]Denial, error) {
	var ts int64
	if !since.IsZero() {
		ts = since.Unix()
	}
	var v []Denial
	return v, c.do(ctx, http.MethodGet, "/v1/denials?since="+strconv.FormatInt(ts, 10), nil, &v)
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

// Tasks — последние задачи, новые сверху.
func (c *HTTPClient) Tasks(ctx context.Context) ([]Task, error) {
	var v []Task
	return v, c.do(ctx, http.MethodGet, "/v1/tasks", nil, &v)
}

func (c *HTTPClient) Task(ctx context.Context, id string) (TaskDetail, error) {
	var v TaskDetail
	return v, c.do(ctx, http.MethodGet, "/v1/tasks/"+url.PathEscape(id), nil, &v)
}

// ApplyRouting запускает doall.sh; 409, если уже идёт другая задача.
func (c *HTTPClient) ApplyRouting(ctx context.Context) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/routing/apply", nil, &v)
}

// RestartAntiZapret перезапускает службу antizapret задачей.
func (c *HTTPClient) RestartAntiZapret(ctx context.Context) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/antizapret/restart", nil, &v)
}

// RebuildProfiles запускает client.sh 7 — пересоздание профилей клиентов.
func (c *HTTPClient) RebuildProfiles(ctx context.Context) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/clients/profiles/rebuild", nil, &v)
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

// --- списки маршрутизации (config/*.txt) ---

// RoutingFile — один список. Kind: hosts, ips, rpz; пусто — файл не относится
// к спискам и только читается. Lines — записи без комментариев и пустых строк.
type RoutingFile struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Title string `json:"title"`
	Lines int    `json:"lines"`
	Bytes int64  `json:"bytes"`
}

// RoutingPage — страница записей списка; Total — сколько нашлось по фильтру.
type RoutingPage struct {
	Name   string   `json:"name"`
	Lines  []string `json:"lines"`
	Total  int      `json:"total"`
	Offset int      `json:"offset"`
	Limit  int      `json:"limit"`
}

// RoutingLineError — ошибка строки. Line считается с единицы в присланном
// списке (PATCH add) или тексте (PUT content).
type RoutingLineError struct {
	Line   int    `json:"line"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// RoutingPatch — правка списка по строкам.
type RoutingPatch struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// RoutingPatchResult — итог PATCH. Ошибки строк приходят с кодом 200 и
// applied=false: файл не менялся.
type RoutingPatchResult struct {
	Applied bool               `json:"applied"`
	Added   int                `json:"added"`
	Removed int                `json:"removed"`
	Skipped int                `json:"skipped"`
	Errors  []RoutingLineError `json:"errors"`
}

// RoutingPut — полная замена содержимого (файлы до 1 МБ).
type RoutingPut struct {
	Content string `json:"content"`
}

// RoutingPutResult — итог PUT. applied=false при ошибках строк.
type RoutingPutResult struct {
	Applied bool               `json:"applied"`
	Lines   int                `json:"lines"` // записей в новом файле
	Errors  []RoutingLineError `json:"errors"`
}

// RoutingBackup — копия списка, сделанная перед записью. Stamp — UTC-метка
// вида 20261102T101500.123Z.
type RoutingBackup struct {
	Stamp string `json:"stamp"`
	Bytes int64  `json:"bytes"`
}

// RoutingListOpts — параметры страницы списка. Limit 0 — по умолчанию (200),
// не больше 1000.
type RoutingListOpts struct {
	Query  string
	Offset int
	Limit  int
}

// RoutingFiles — списки каталога config.
func (c *HTTPClient) RoutingFiles(ctx context.Context) ([]RoutingFile, error) {
	var v []RoutingFile
	return v, c.do(ctx, http.MethodGet, "/v1/routing/files", nil, &v)
}

// RoutingLines — страница записей списка с фильтром по подстроке.
func (c *HTTPClient) RoutingLines(ctx context.Context, name string, o RoutingListOpts) (RoutingPage, error) {
	q := url.Values{}
	if o.Query != "" {
		q.Set("q", o.Query)
	}
	if o.Offset > 0 {
		q.Set("offset", strconv.Itoa(o.Offset))
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	path := "/v1/routing/files/" + url.PathEscape(name)
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var v RoutingPage
	return v, c.do(ctx, http.MethodGet, path, nil, &v)
}

// PatchRouting добавляет и удаляет строки списка.
func (c *HTTPClient) PatchRouting(ctx context.Context, name string, p RoutingPatch) (RoutingPatchResult, error) {
	var v RoutingPatchResult
	return v, c.do(ctx, http.MethodPatch, "/v1/routing/files/"+url.PathEscape(name), p, &v)
}

// ReplaceRouting заменяет список целиком; для файла больше 1 МБ — 413.
func (c *HTTPClient) ReplaceRouting(ctx context.Context, name, content string) (RoutingPutResult, error) {
	var v RoutingPutResult
	return v, c.do(ctx, http.MethodPut, "/v1/routing/files/"+url.PathEscape(name), RoutingPut{Content: content}, &v)
}

// RoutingBackups — копии списка, новые сверху (до 20).
func (c *HTTPClient) RoutingBackups(ctx context.Context, name string) ([]RoutingBackup, error) {
	var v []RoutingBackup
	return v, c.do(ctx, http.MethodGet, "/v1/routing/backups/"+url.PathEscape(name), nil, &v)
}

// RestoreRouting возвращает копию на место списка; прежняя версия тоже копируется.
func (c *HTTPClient) RestoreRouting(ctx context.Context, name, stamp string) (RoutingFile, error) {
	var v RoutingFile
	return v, c.do(ctx, http.MethodPost, "/v1/routing/backups/"+url.PathEscape(name)+"/"+url.PathEscape(stamp)+"/restore", nil, &v)
}

// --- ключи setup AntiZapret ---

// Способы применения изменённого ключа setup (SetupEntry.Apply, SetupResult.Apply):
// doall — POST /v1/routing/apply; restart — POST /v1/antizapret/restart;
// profiles — POST /v1/clients/profiles/rebuild; reinstall — только повторный
// setup.sh (ключ редактировать нельзя).
const (
	ApplyDoall     = "doall"
	ApplyRestart   = "restart"
	ApplyProfiles  = "profiles"
	ApplyReinstall = "reinstall"
)

// SetupEntry — один ключ файла setup. Kind: yn, enum, int, host; пусто —
// ключ неизвестен агенту (только чтение). Options — для enum, Min/Max — для int.
// Ключи *_PRIVATE_KEY в список не попадают.
type SetupEntry struct {
	Key      string   `json:"key"`
	Value    string   `json:"value"`
	Kind     string   `json:"kind"`
	Apply    []string `json:"apply"`
	Title    string   `json:"title"`
	Editable bool     `json:"editable"`
	Hint     string   `json:"hint,omitempty"`
	Options  []string `json:"options,omitempty"`
	Min      int      `json:"min,omitempty"`
	Max      int      `json:"max,omitempty"`
}

// SetupPut — новые значения ключей.
type SetupPut struct {
	Values map[string]string `json:"values"`
}

// SetupResult — итог PUT /v1/setup: какие ключи изменились и какие способы
// применения нужны (в порядке doall, restart, profiles). Сами задачи не запускаются.
type SetupResult struct {
	Changed []string `json:"changed"`
	Apply   []string `json:"apply"`
}

// Setup — ключи файла setup в порядке файла, без секретов.
func (c *HTTPClient) Setup(ctx context.Context) ([]SetupEntry, error) {
	var v []SetupEntry
	return v, c.do(ctx, http.MethodGet, "/v1/setup", nil, &v)
}

// SetSetup меняет ключи. Хоть одно значение не принято — 400 с причиной по
// каждому ключу в сообщении, ничего не записано.
func (c *HTTPClient) SetSetup(ctx context.Context, values map[string]string) (SetupResult, error) {
	var v SetupResult
	return v, c.do(ctx, http.MethodPut, "/v1/setup", SetupPut{Values: values}, &v)
}
