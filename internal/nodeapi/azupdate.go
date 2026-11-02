package nodeapi

import (
	"context"
	"net/http"
	"time"

	"github.com/syava842/azpanel/internal/sysinfo"
)

// Состояния обновления и восстановления (AZUpdateState.Status).
const (
	AZStatusRunning = "running"
	AZStatusOK      = "ok"
	AZStatusFailed  = "failed"
	// AZStatusFailedLate — setup.sh начал установку (остановил службы, стёр
	// /etc/openvpn/server) и не дошёл до конца: узел без рабочего VPN. Нужны
	// действия: «повторить установку с сохранённым бэкапом» (CanRetry) или, как
	// запасной путь, «восстановить из бэкапа» (CanRestore). Правки клиентов,
	// списков и setup в этом состоянии не блокируются, новое обновление — да.
	AZStatusFailedLate = "failed_late"
)

// Этапы идущего обновления (AZUpdateState.Phase).
const (
	AZPhasePrepare = "prepare" // проверки, бэкап, setup.sh — задача на узле
	AZPhaseReboot  = "reboot"  // setup.sh отработал, узел перезагружается
	AZPhaseVerify  = "verify"  // узел поднялся, агент проверяет службы и клиентов
)

// Действия (AZUpdateState.Action).
const (
	AZActionUpdate  = "update"
	AZActionRestore = "restore"
)

// AZUpdateState — состояние обновления AntiZapret (data/azupdate.json на узле).
// Status пуст — обновлений не было. Пока Status == running, правки клиентов,
// списков и setup на узле отклоняются.
type AZUpdateState struct {
	Action   string     `json:"action,omitempty"` // update | restore
	Status   string     `json:"status,omitempty"` // running | ok | failed | failed_late
	Phase    string     `json:"phase,omitempty"`  // для running: prepare | reboot | verify
	Commit   string     `json:"commit,omitempty"` // на какой коммит обновляем
	From     string     `json:"from,omitempty"`   // с какого (пусто — был неизвестен)
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	// Backup — имя бэкапа в /opt/azpanel/backup; такая же копия лежит в /root
	// под тем же именем, пока setup.sh её не заберёт.
	Backup  string   `json:"backup,omitempty"`
	Clients []string `json:"clients,omitempty"` // клиенты до обновления
	TaskID  string   `json:"task_id,omitempty"` // задача azupdate или azrestore
	// Reasons — почему итог failed (по строке на причину).
	Reasons []string `json:"reasons,omitempty"`
	// Warnings — замечания: например, ключи, которые setup.sh сбросил.
	Warnings []string `json:"warnings,omitempty"`
	// Notes — как собрано окружение setup.sh (ключи, взятые по умолчанию).
	Notes []string `json:"notes,omitempty"`
	// Services — службы на момент последней проверки после загрузки.
	Services []sysinfo.Service `json:"services,omitempty"`
	// Extras — состояние сопутствующих служб после обновления: warper, telemt.
	Extras map[string]string `json:"extras,omitempty"`
	// CanRestore — есть бэкап и установка что-то тронула (failed_late, либо
	// установка прошла, а проверка нет): панель показывает «Восстановить из
	// бэкапа». Ранний отказ setup.sh (ничего не тронуто) её не включает.
	CanRestore bool `json:"can_restore,omitempty"`
	// CanRetry — итог failed_late и бэкап на месте: панель показывает «Повторить
	// установку» (POST /v1/antizapret/update/retry).
	CanRetry bool `json:"can_retry,omitempty"`
	// Retries — сколько раз установку повторяли после failed_late.
	Retries int `json:"retries,omitempty"`
	// Backups — бэкапы на узле, новые сверху (только в ответе GET).
	Backups []AZBackup `json:"backups,omitempty"`
}

// AZBackup — бэкап конфигурации и клиентов, сделанный перед обновлением.
type AZBackup struct {
	Name  string    `json:"name"`
	Bytes int64     `json:"bytes"`
	Time  time.Time `json:"time"`
}

// AZUpdateRequest — запуск обновления. Commit пуст — последний коммит main.
// Values — значения ключей setup, которые нужно изменить при этой установке
// (ключи с применением reinstall); остальные берутся из файла setup.
type AZUpdateRequest struct {
	Commit string            `json:"commit,omitempty"`
	Values map[string]string `json:"values,omitempty"`
}

// AZRestoreRequest — восстановление из бэкапа по имени (AZBackup.Name).
type AZRestoreRequest struct {
	Backup string `json:"backup"`
}

// AZPreflight — проверки перед обновлением. OK == false — запуск будет
// отклонён; Reasons — причины по одной в строке.
type AZPreflight struct {
	OK      bool     `json:"ok"`
	Reasons []string `json:"reasons"`
	// Notes — как будет собрано окружение setup.sh (значения по умолчанию
	// для ключей, которых нет в setup).
	Notes []string `json:"notes,omitempty"`
}

// AZUpdateState — состояние последнего обновления и бэкапы.
func (c *HTTPClient) AZUpdateState(ctx context.Context) (AZUpdateState, error) {
	var v AZUpdateState
	return v, c.do(ctx, http.MethodGet, "/v1/antizapret/update", nil, &v)
}

// AZPreflight проверяет, можно ли обновлять сейчас, ничего не запуская.
func (c *HTTPClient) AZPreflight(ctx context.Context) (AZPreflight, error) {
	var v AZPreflight
	return v, c.do(ctx, http.MethodGet, "/v1/antizapret/update/preflight", nil, &v)
}

// AZUpdate запускает обновление: 202 и состояние; 409 — идёт другая задача
// или обновление; 422 — проверки не пройдены (причины в сообщении).
func (c *HTTPClient) AZUpdate(ctx context.Context, req AZUpdateRequest) (AZUpdateState, error) {
	var v AZUpdateState
	return v, c.do(ctx, http.MethodPost, "/v1/antizapret/update", req, &v)
}

// AZRetry повторяет прерванную установку (итог failed_late) с сохранённым
// бэкапом: тот же setup.sh и ответы, бэкап копируется в /root снова. 202 и
// состояние; 409 — идёт другая задача; 422 — повторять нечего или проверки не пройдены.
func (c *HTTPClient) AZRetry(ctx context.Context) (AZUpdateState, error) {
	var v AZUpdateState
	return v, c.do(ctx, http.MethodPost, "/v1/antizapret/update/retry", struct{}{}, &v)
}

// AZRestore восстанавливает конфигурацию и клиентов из бэкапа (client.sh 9);
// узел перезагрузится.
func (c *HTTPClient) AZRestore(ctx context.Context, backup string) (AZUpdateState, error) {
	var v AZUpdateState
	return v, c.do(ctx, http.MethodPost, "/v1/antizapret/restore", AZRestoreRequest{Backup: backup}, &v)
}
