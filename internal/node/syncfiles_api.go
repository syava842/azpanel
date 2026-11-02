package node

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/nodeapi"
)

// TaskSyncApply — запись набора синхронизации на реплике (вне песочницы).
const TaskSyncApply = "sync-apply"

func init() {
	DefaultTaskTimeouts[TaskSyncApply] = 900 * time.Second
}

// maxSyncReadWindow — сколько ждать загрузку архива до 256 МБ: общий
// ReadTimeout сервера (30 секунд) для неё мал.
const maxSyncReadWindow = 15 * time.Minute

// SyncService — набор синхронизации и роль узла.
type SyncService struct {
	Set       SyncSet
	Role      *RoleStore
	Self      string // бинарник azpanel для задачи sync-apply
	ParamsDir string // файлы параметров задач (0700)
	StageDir  string // куда кладётся принятый архив (0700), например data/sync
}

// RoleStore — роль узла в группе, data/role.json. Нет файла — основной.
type RoleStore struct {
	Path string
	mu   sync.Mutex
}

type roleFile struct {
	Role  string `json:"role"`
	Group string `json:"group,omitempty"`
}

// Get читает роль. Повреждённый файл — ошибка, а не молчаливый «основной»:
// реплика, принявшая себя за основной, начала бы расходиться с группой.
func (s *RoleStore) Get() (nodeapi.SyncRole, error) {
	if s == nil {
		return nodeapi.SyncRole{Role: nodeapi.RolePrimary}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nodeapi.SyncRole{Role: nodeapi.RolePrimary}, nil
	}
	if err != nil {
		return nodeapi.SyncRole{}, err
	}
	var f roleFile
	if err := json.Unmarshal(data, &f); err != nil || (f.Role != nodeapi.RolePrimary && f.Role != nodeapi.RoleReplica) {
		return nodeapi.SyncRole{}, fmt.Errorf("%s повреждён — исправьте или удалите файл", s.Path)
	}
	return nodeapi.SyncRole{Role: f.Role, Group: f.Group}, nil
}

// Set записывает роль атомарно.
func (s *RoleStore) Set(r nodeapi.SyncRole) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(roleFile{Role: r.Role, Group: r.Group})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.Path, data, 0o600)
}

func (a *API) registerSync(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/sync/manifest", a.syncManifest)
	mux.HandleFunc("GET /v1/sync/file", a.syncFile)
	mux.HandleFunc("POST /v1/sync/apply", a.syncApply)
	mux.HandleFunc("GET /v1/sync/role", a.syncGetRole)
	mux.HandleFunc("POST /v1/sync/role", a.syncSetRole)
}

func (a *API) syncReady(w http.ResponseWriter) bool {
	if a.Sync == nil {
		writeErr(w, http.StatusServiceUnavailable, "синхронизация не настроена")
		return false
	}
	return true
}

func (a *API) syncManifest(w http.ResponseWriter, r *http.Request) {
	if !a.syncReady(w) {
		return
	}
	files, err := a.Sync.Set.Manifest()
	if err != nil {
		a.fail(w, "манифест не собран", err)
		return
	}
	writeJSON(w, http.StatusOK, nodeapi.SyncManifest{Files: files})
}

func (a *API) syncFile(w http.ResponseWriter, r *http.Request) {
	if !a.syncReady(w) {
		return
	}
	p := filepath.FromSlash(r.URL.Query().Get("path"))
	rc, err := a.Sync.Set.Open(p)
	switch {
	case errors.Is(err, ErrNotInSet):
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, fs.ErrNotExist):
		writeErr(w, http.StatusNotFound, "файла нет")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	// Файл может быть крупным: общий WriteTimeout сервера на него не рассчитан.
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	io.Copy(w, rc)
}

func (a *API) syncGetRole(w http.ResponseWriter, r *http.Request) {
	if !a.syncReady(w) {
		return
	}
	role, err := a.Sync.Role.Get()
	if err != nil {
		a.fail(w, "роль не прочитана", err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (a *API) syncSetRole(w http.ResponseWriter, r *http.Request) {
	if !a.syncReady(w) {
		return
	}
	var req nodeapi.SyncRole
	if !decode(w, r, &req) {
		return
	}
	if req.Role != nodeapi.RolePrimary && req.Role != nodeapi.RoleReplica {
		writeErr(w, http.StatusBadRequest, "role — primary или replica")
		return
	}
	if len(req.Group) > 64 || strings.IndexFunc(req.Group, unicode.IsControl) >= 0 {
		writeErr(w, http.StatusBadRequest, "group — до 64 символов без управляющих")
		return
	}
	if req.Role == nodeapi.RolePrimary {
		req.Group = ""
	}
	if err := a.Sync.Role.Set(req); err != nil {
		a.fail(w, "роль не записана", err)
		return
	}
	a.Log.Info("роль узла изменена", "role", req.Role, "group", req.Group)
	writeJSON(w, http.StatusOK, req)
}

// syncApply принимает tar с файлами набора. Только реплика: на основном такой
// запрос — ошибка оператора, и он затёр бы источник правды. Пути проверяются
// здесь (400 до записи чего-либо), а запись идёт задачей sync-apply вне
// песочницы агента.
func (a *API) syncApply(w http.ResponseWriter, r *http.Request) {
	if !a.syncReady(w) {
		return
	}
	role, err := a.Sync.Role.Get()
	if err != nil {
		a.fail(w, "роль не прочитана", err)
		return
	}
	if role.Role != nodeapi.RoleReplica {
		writeErr(w, http.StatusConflict, "узел — основной: набор синхронизации пишется только на реплику")
		return
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(maxSyncReadWindow))
	rc.SetWriteDeadline(time.Now().Add(maxSyncReadWindow + time.Minute))

	stage, archive, err := a.stageArchive(r.Body)
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			writeErr(w, http.StatusRequestEntityTooLarge, "архив больше 256 МБ")
			return
		}
		a.fail(w, "архив не сохранён", err)
		return
	}
	f, err := os.Open(archive)
	if err != nil {
		os.RemoveAll(stage)
		a.fail(w, "архив не открыт", err)
		return
	}
	entries, verr := ValidateArchive(a.Sync.Set, f)
	f.Close()
	if verr == nil && len(entries) == 0 {
		verr = errors.New("архив пуст")
	}
	if verr != nil {
		os.RemoveAll(stage)
		writeErr(w, http.StatusBadRequest, verr.Error())
		return
	}
	prune := r.URL.Query().Get("prune") == "1"
	params, err := writeParamsFile(a.Sync.ParamsDir, SyncApplyParams{Set: a.Sync.Set, Archive: archive, Stage: stage, Prune: prune})
	if err != nil {
		os.RemoveAll(stage)
		a.fail(w, "параметры задачи не записаны", err)
		return
	}
	t, ok := a.launchExtTask(w, TaskSyncApply, []string{a.Sync.Self, "internal", "sync-apply", "--params", params}, params)
	if !ok {
		os.RemoveAll(stage)
		return
	}
	a.Log.Info("синхронизация принята", "files", len(entries), "prune", prune, "task", t.ID)
	writeJSON(w, http.StatusAccepted, t)
}

// stageArchive сохраняет тело запроса в новый каталог StageDir/<id>/archive.tar.
func (a *API) stageArchive(body io.Reader) (stage, archive string, err error) {
	var id [6]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", "", err
	}
	stage = filepath.Join(a.Sync.StageDir, hex.EncodeToString(id[:]))
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return "", "", err
	}
	archive = filepath.Join(stage, "archive.tar")
	f, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		os.RemoveAll(stage)
		return "", "", err
	}
	_, err = io.Copy(f, body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.RemoveAll(stage)
		return "", "", err
	}
	return stage, archive, nil
}

// replicaDenied — маршрут меняет клиентов, маршрутизацию или setup. Это можно
// только на основном; применение уже записанных списков (routing/apply),
// перезапуск, бэкап и обновления на реплике разрешены.
func replicaDenied(method, path string) bool {
	switch method {
	case http.MethodPost:
		switch {
		case path == "/v1/clients" || path == "/v1/clients/profiles/rebuild":
			return true
		case strings.HasPrefix(path, "/v1/clients/openvpn/") && strings.HasSuffix(path, "/renew"):
			return true
		case strings.HasPrefix(path, "/v1/routing/backups/") && strings.HasSuffix(path, "/restore"):
			return true
		}
	case http.MethodDelete:
		return strings.HasPrefix(path, "/v1/clients/")
	case http.MethodPut:
		switch {
		case path == "/v1/setup":
			return true
		case strings.HasPrefix(path, "/v1/clients/") && (strings.HasSuffix(path, "/limit") || strings.HasSuffix(path, "/blocked")):
			return true
		case strings.HasPrefix(path, "/v1/routing/files/"):
			return true
		}
	case http.MethodPatch:
		return strings.HasPrefix(path, "/v1/routing/files/")
	}
	return false
}

// roleGate отклоняет на реплике изменяющие маршруты кодом 409.
func (a *API) roleGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Sync != nil && replicaDenied(r.Method, r.URL.Path) {
			role, err := a.Sync.Role.Get()
			if err != nil {
				a.fail(w, "роль не прочитана", err)
				return
			}
			if role.Role == nodeapi.RoleReplica {
				name := "группы"
				if role.Group != "" {
					name = "группы «" + role.Group + "»"
				}
				writeErr(w, http.StatusConflict, "узел — реплика "+name+": клиенты, маршрутизация и setup меняются только на основном")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
