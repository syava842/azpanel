package nodeapi

import (
	"context"
	"net/http"
	"time"

	"github.com/syava842/azpanel/internal/warp"
)

// Типы WARP общие у агента и панели.
type (
	WarpStatus         = warp.Status
	WarpOp             = warp.Op
	WarpInstallAnswers = warp.InstallAnswers
	WarpWGManual       = warp.WGManual
	// WarpDomain — строка списка доменов: домен, источник (user, gemini, chatgpt…), включён.
	WarpDomain = warp.DomainEntry
)

// WarpPeer — пир встроенного WARP (публичные ключи не передаются).
type WarpPeer struct {
	Endpoint        string     `json:"endpoint,omitempty"`
	LatestHandshake *time.Time `json:"latest_handshake,omitempty"`
	RxBytes         int64      `json:"rx_bytes"`
	TxBytes         int64      `json:"tx_bytes"`
}

// WarpIface — интерфейс warp-* встроенного WARP AntiZapret (wg show).
type WarpIface struct {
	Name  string     `json:"name"`
	Peers []WarpPeer `json:"peers"`
}

// Warp — сводка WARP: встроенный и AZ-WARP.
type Warp struct {
	Builtin []WarpIface `json:"builtin"`
	AZ      WarpStatus  `json:"az"`
}

// WarpList — вывод warper domainslist либо iplist. Lines — домены (без
// источника и флага) либо подсети; Domains — те же домены с источником и
// флагом, только для списка доменов.
type WarpList struct {
	Lines   []string     `json:"lines"`
	Domains []WarpDomain `json:"domains,omitempty"`
}

// WarpEdit — правки списков. Sync: после правок выполнить синхронизацию
// (sync для доменов, ipsync для подсетей).
type WarpEdit struct {
	Ops  []WarpOp `json:"ops"`
	Sync bool     `json:"sync,omitempty"`
}

// Warp — сводка WARP.
func (c *HTTPClient) Warp(ctx context.Context) (Warp, error) {
	var v Warp
	return v, c.do(ctx, http.MethodGet, "/v1/warp", nil, &v)
}

// WarpDomains — домены списка AZ-WARP.
func (c *HTTPClient) WarpDomains(ctx context.Context) (WarpList, error) {
	var v WarpList
	return v, c.do(ctx, http.MethodGet, "/v1/warp/domains", nil, &v)
}

// WarpIPs — подсети списка AZ-WARP.
func (c *HTTPClient) WarpIPs(ctx context.Context) (WarpList, error) {
	var v WarpList
	return v, c.do(ctx, http.MethodGet, "/v1/warp/ips", nil, &v)
}

// EditWarpDomains правит домены задачей warp-sync. Ops: add, remove, enable,
// disable (gemini|chatgpt), save.
func (c *HTTPClient) EditWarpDomains(ctx context.Context, e WarpEdit) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/warp/domains", e, &v)
}

// EditWarpIPs правит подсети задачей warp-sync. Ops: ipadd, ipremove.
func (c *HTTPClient) EditWarpIPs(ctx context.Context, e WarpEdit) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/warp/ips", e, &v)
}

// WarpSync выполняет warper sync задачей warp-sync.
func (c *HTTPClient) WarpSync(ctx context.Context) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/warp/sync", nil, &v)
}

// WarpUpdate обновляет AZ-WARP задачей warp-update (затем статус и doctor в журнал).
func (c *HTTPClient) WarpUpdate(ctx context.Context) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/warp/update", nil, &v)
}

// InstallWarp ставит AZ-WARP задачей warp-install (install.sh под псевдотерминалом).
func (c *HTTPClient) InstallWarp(ctx context.Context, a WarpInstallAnswers) (Task, error) {
	var v Task
	return v, c.do(ctx, http.MethodPost, "/v1/warp/install", a, &v)
}
