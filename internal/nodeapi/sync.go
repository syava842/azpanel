package nodeapi

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Роли узла в группе синхронизации.
const (
	RolePrimary = "primary"
	RoleReplica = "replica"
)

// MaxSyncArchive — предел тела POST /v1/sync/apply.
const MaxSyncArchive = 256 << 20

// SyncEntry — файл набора синхронизации. Path — абсолютный путь на узле;
// у файла setup отпечаток и размер считаются без ключей WARP.
type SyncEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"` // права, восьмеричная запись: «0640»
}

// SyncManifest — ответ GET /v1/sync/manifest: файлы по возрастанию пути.
type SyncManifest struct {
	Files []SyncEntry `json:"files"`
}

// SyncRole — тело POST /v1/sync/role и ответ GET /v1/sync/role. Group — имя
// группы для сообщений реплики.
type SyncRole struct {
	Role  string `json:"role"`
	Group string `json:"group,omitempty"`
}

// SyncManifest — набор файлов узла с отпечатками.
func (c *HTTPClient) SyncManifest(ctx context.Context) (SyncManifest, error) {
	var v SyncManifest
	return v, c.do(ctx, http.MethodGet, "/v1/sync/manifest", nil, &v)
}

// SyncFile открывает файл набора потоком; закрыть читатель обязан вызывающий.
// Путь — только из манифеста.
func (c *HTTPClient) SyncFile(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/sync/file?path="+url.QueryEscape(path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
		var e ErrorBody
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return nil, &Error{Status: resp.StatusCode, Message: e.Error}
	}
	return resp.Body, nil
}

// SyncRemoveEntry — служебная запись tar: JSON-массив абсолютных путей,
// которые реплика должна удалить (WriteSyncRemove). Список строит панель по
// разнице манифестов основного и реплики; «всё, чего нет в архиве» агент
// не удаляет никогда.
const SyncRemoveEntry = ".azpanel-remove"

// SyncApplyOpts — параметры SyncApply.
type SyncApplyOpts struct {
	// Force разрешает удалять ключевые файлы (CA, index.txt, ключи WireGuard)
	// и больше половины набора за раз. Без него агент такой запрос отклоняет
	// кодом 422: за ним обычно стоит неполный манифест основного.
	Force bool
}

// SyncApply отправляет tar-архив с файлами набора (см. WriteSyncEntry) и,
// если нужно, список удаления (WriteSyncRemove). Агент проверяет пути и
// запускает задачу записи. Принимает только реплика.
func (c *HTTPClient) SyncApply(ctx context.Context, archive io.Reader, opts SyncApplyOpts) (Task, error) {
	path := "/v1/sync/apply"
	if opts.Force {
		path += "?force=1"
	}
	body, err := c.rawBody(ctx, http.MethodPost, path, "application/x-tar", archive)
	if err != nil {
		return Task{}, err
	}
	var t Task
	return t, json.Unmarshal(body, &t)
}

// WriteSyncRemove добавляет в tar список удаления; пустой список не пишется.
func WriteSyncRemove(tw *tar.Writer, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	norm := make([]string, len(paths))
	for i, p := range paths {
		norm[i] = strings.ReplaceAll(p, "\\", "/")
	}
	data, err := json.Marshal(norm)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: SyncRemoveEntry, Mode: 0o600, Size: int64(len(data))}); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

// SyncRemovals — файлы, которые есть на реплике, но которых нет на основном:
// по разнице двух манифестов. Путь setup агент не удаляет и такой список
// отклонит, поэтому вызывающий исключает его сам.
func SyncRemovals(primary, replica SyncManifest) []string {
	have := make(map[string]bool, len(primary.Files))
	for _, e := range primary.Files {
		have[e.Path] = true
	}
	var out []string
	for _, e := range replica.Files {
		if !have[e.Path] {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out
}

// SyncRole — роль узла.
func (c *HTTPClient) SyncRole(ctx context.Context) (SyncRole, error) {
	var v SyncRole
	return v, c.do(ctx, http.MethodGet, "/v1/sync/role", nil, &v)
}

// SetSyncRole назначает роль узла; хранится у агента в data/role.json.
func (c *HTTPClient) SetSyncRole(ctx context.Context, r SyncRole) error {
	return c.do(ctx, http.MethodPost, "/v1/sync/role", r, nil)
}

// WriteSyncEntry добавляет в tar файл набора: имя записи — путь на узле, права
// — из записи манифеста; size должен совпасть с числом байт в r.
func WriteSyncEntry(tw *tar.Writer, e SyncEntry, r io.Reader) error {
	mode, err := strconv.ParseUint(e.Mode, 8, 32)
	if err != nil {
		return fmt.Errorf("%s: права %q не восьмеричное число", e.Path, e.Mode)
	}
	hdr := &tar.Header{Typeflag: tar.TypeReg, Name: strings.ReplaceAll(e.Path, "\\", "/"), Mode: int64(mode), Size: e.Size}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	n, err := io.Copy(tw, r)
	if err != nil {
		return err
	}
	if n != e.Size {
		return errors.New(e.Path + ": размер файла не совпал с манифестом")
	}
	return nil
}
