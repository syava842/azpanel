package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/update"
)

// TaskSelfUpdate — обновление самого azpanel. Идёт задачей systemd-run, чтобы
// пережить перезапуск агента, который сама же и делает.
const TaskSelfUpdate = "selfupdate"

// maxUpdateBody — предел тела POST /v1/update; для остальных маршрутов он
// остаётся прежним.
const maxUpdateBody = nodeapi.MaxUpdateBody

func init() {
	DefaultTaskTimeouts[TaskSelfUpdate] = 600 * time.Second
}

// UpdateService — самообновление агента. Подпись проверяет сам агент ключом,
// вшитым в бинарник; панели в этом он не верит.
type UpdateService struct {
	Root      string            // корень установки (/opt/azpanel)
	Pub       ed25519.PublicKey // ключ релизов; в тестах — тестовый
	Self      string            // путь к бинарнику azpanel, которым запускается задача
	ParamsDir string            // каталог файлов параметров задач (0700)
	StageDir  string            // куда складываются принятые файлы до задачи (0700)
	// Migrate — миграции конфига для предварительной проверки; nil — config.Migrate.
	Migrate func(data []byte, answers map[string]string) ([]byte, []config.Question, error)
}

func (a *API) registerUpdate(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/update", a.updatePost)
	mux.HandleFunc("GET /v1/update/result", a.updateResult)
}

// updateParams повторяет cmd/azpanel.selfUpdateParams (JSON-контракт режима
// `azpanel internal selfupdate`).
type updateParams struct {
	Name        string            `json:"name"`
	ArchivePath string            `json:"archive"`
	SumsPath    string            `json:"sums"`
	SigPath     string            `json:"sig"`
	Answers     map[string]string `json:"answers,omitempty"`
}

func (a *API) updateResult(w http.ResponseWriter, r *http.Request) {
	if a.Update == nil {
		writeErr(w, http.StatusServiceUnavailable, "обновление не настроено")
		return
	}
	res, err := update.ReadResult(a.Update.Root)
	if err != nil {
		a.fail(w, "итог обновления не прочитан", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]*update.Result{"result": res})
}

func (a *API) updatePost(w http.ResponseWriter, r *http.Request) {
	s := a.Update
	if s == nil {
		writeErr(w, http.StatusServiceUnavailable, "обновление не настроено")
		return
	}
	in, err := readUpdateForm(r)
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			writeErr(w, http.StatusRequestEntityTooLarge, "тело запроса больше 64 МБ")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	env := &update.Env{Root: s.Root, Version: a.Version, Pub: s.Pub, Migrate: s.Migrate}
	// Проверка до задачи: отказ по подписи или вопрос без ответа не должен
	// превращаться в упавшую задачу.
	if _, err := env.Preflight(in); err != nil {
		var qe *config.QuestionsError
		if errors.As(err, &qe) {
			body := nodeapi.ErrorBody{Error: err.Error()}
			for _, q := range qe.Questions {
				body.Questions = append(body.Questions, nodeapi.UpdateQuestion{Key: q.Key, Text: q.Text})
			}
			writeJSON(w, http.StatusConflict, body)
			return
		}
		a.Log.Warn("обновление отклонено", "err", err)
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	stage, err := stageUpdate(s.StageDir, in)
	if err != nil {
		a.fail(w, "файлы обновления не сохранены", err)
		return
	}
	cleanup := func() { os.RemoveAll(stage) }
	params, err := writeParamsFile(s.ParamsDir, updateParams{
		Name:        in.Name,
		ArchivePath: filepath.Join(stage, "archive"),
		SumsPath:    filepath.Join(stage, "sums"),
		SigPath:     filepath.Join(stage, "sig"),
		Answers:     in.Answers,
	})
	if err != nil {
		cleanup()
		a.fail(w, "параметры задачи не записаны", err)
		return
	}
	t, ok := a.launchExtTask(w, TaskSelfUpdate, []string{s.Self, "internal", "selfupdate", "--params", params}, params)
	if !ok {
		cleanup()
		return
	}
	writeJSON(w, http.StatusAccepted, t)
}

// readUpdateForm читает multipart-запрос по частям: архив нужен целиком, но
// без временных файлов на диске (агент в песочнице).
func readUpdateForm(r *http.Request) (update.Input, error) {
	var in update.Input
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/form-data" || params["boundary"] == "" {
		return in, errors.New("нужен multipart/form-data")
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	seen := map[string]bool{}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return in, wrapBody(err, "тело запроса не разобрано")
		}
		name := p.FormName()
		data, err := io.ReadAll(p)
		if err != nil {
			return in, wrapBody(err, "тело запроса не разобрано")
		}
		if seen[name] {
			return in, errors.New("часть " + name + " повторена")
		}
		seen[name] = true
		switch name {
		case nodeapi.UpdatePartName:
			in.Name = string(data)
		case nodeapi.UpdatePartArchive:
			in.Archive = data
		case nodeapi.UpdatePartSums:
			in.Sums = data
		case nodeapi.UpdatePartSig:
			in.Sig = data
		case nodeapi.UpdatePartAnswers:
			if err := json.Unmarshal(data, &in.Answers); err != nil {
				return in, errors.New("answers: нужен JSON-объект «ключ: ответ»")
			}
		default:
			return in, errors.New("неизвестная часть " + name)
		}
	}
	for _, n := range []string{nodeapi.UpdatePartName, nodeapi.UpdatePartArchive, nodeapi.UpdatePartSums, nodeapi.UpdatePartSig} {
		if !seen[n] {
			return in, errors.New("нет части " + n)
		}
	}
	return in, nil
}

// wrapBody оставляет *http.MaxBytesError узнаваемым для вызывающего.
func wrapBody(err error, msg string) error {
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return err
	}
	return errors.New(msg + ": " + err.Error())
}

// stageUpdate кладёт принятые файлы в новый каталог (0700); задача читает и
// удаляет их.
func stageUpdate(dir string, in update.Input) (string, error) {
	var id [6]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	stage := filepath.Join(dir, hex.EncodeToString(id[:]))
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return "", err
	}
	for name, data := range map[string][]byte{"archive": in.Archive, "sums": in.Sums, "sig": in.Sig} {
		if err := os.WriteFile(filepath.Join(stage, name), data, 0o600); err != nil {
			os.RemoveAll(stage)
			return "", err
		}
	}
	return stage, nil
}
