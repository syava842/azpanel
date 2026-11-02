// Package updateapi — HTTP-маршруты самообновления azpanel, общие для агента
// узла и агента прокси: POST /v1/update (принять подписанный релиз) и
// GET /v1/update/result (итог последнего обновления). Подпись проверяет сам
// агент ключом, вшитым в бинарник; панели в этом он не верит.
package updateapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/update"
)

// Params — JSON-контракт режима `azpanel internal selfupdate --params ФАЙЛ`
// (повторяет cmd/azpanel.selfUpdateParams).
type Params struct {
	Name        string            `json:"name"`
	ArchivePath string            `json:"archive"`
	SumsPath    string            `json:"sums"`
	SigPath     string            `json:"sig"`
	Answers     map[string]string `json:"answers,omitempty"`
}

// Service — самообновление агента.
type Service struct {
	Root      string            // корень установки (/opt/azpanel)
	Pub       ed25519.PublicKey // ключ релизов; в тестах — тестовый
	Self      string            // путь к бинарнику azpanel, которым запускается задача
	ParamsDir string            // каталог файлов параметров задач (0700)
	StageDir  string            // куда складываются принятые файлы до задачи (0700)
	// Exec запускает новый бинарник для предварительной миграции конфига; nil —
	// настоящий запуск.
	Exec    update.ExecFunc
	Version string // версия работающего агента
	Log     *slog.Logger
	// Launch запускает задачу selfupdate командой argv; файл params удаляется
	// им же при отказе. При отказе Launch сам отвечает ошибкой и возвращает
	// false; иначе — тело ответа 202.
	Launch func(w http.ResponseWriter, argv []string, params string) (body any, ok bool)
}

// Result — GET /v1/update/result.
func (s *Service) Result(w http.ResponseWriter, r *http.Request) {
	res, err := update.ReadResult(s.Root)
	if err != nil {
		s.fail(w, "итог обновления не прочитан", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]*update.Result{"result": res})
}

// Post — POST /v1/update.
func (s *Service) Post(w http.ResponseWriter, r *http.Request) {
	in, err := readForm(r)
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			writeErr(w, http.StatusRequestEntityTooLarge, "тело запроса больше 64 МБ")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	env := &update.Env{Root: s.Root, Version: s.Version, Pub: s.Pub, Exec: s.Exec, WorkDir: s.StageDir}
	// Проверка до задачи: отказ по подписи или вопрос без ответа не должен
	// превращаться в упавшую задачу. Миграцию конфига выполняет новый бинарник.
	if _, err := env.Preflight(r.Context(), in); err != nil {
		var qe *config.QuestionsError
		if errors.As(err, &qe) {
			body := nodeapi.ErrorBody{Error: err.Error()}
			for _, q := range qe.Questions {
				body.Questions = append(body.Questions, nodeapi.UpdateQuestion{Key: q.Key, Text: q.Text})
			}
			writeJSON(w, http.StatusConflict, body)
			return
		}
		s.log().Warn("обновление отклонено", "err", err)
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	stage, err := stageFiles(s.StageDir, in)
	if err != nil {
		s.fail(w, "файлы обновления не сохранены", err)
		return
	}
	params, err := WriteParams(s.ParamsDir, Params{
		Name:        in.Name,
		ArchivePath: filepath.Join(stage, "archive"),
		SumsPath:    filepath.Join(stage, "sums"),
		SigPath:     filepath.Join(stage, "sig"),
		Answers:     in.Answers,
	})
	if err != nil {
		os.RemoveAll(stage)
		s.fail(w, "параметры задачи не записаны", err)
		return
	}
	body, ok := s.Launch(w, []string{s.Self, "internal", "selfupdate", "--params", params}, params)
	if !ok {
		os.RemoveAll(stage)
		return
	}
	writeJSON(w, http.StatusAccepted, body)
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (s *Service) fail(w http.ResponseWriter, what string, err error) {
	s.log().Error(what, "err", err)
	writeErr(w, http.StatusInternalServerError, what+": "+err.Error())
}

// WriteParams кладёт параметры задачи в файл 0600 и возвращает путь. Задача
// читает файл и сразу удаляет его.
func WriteParams(dir string, v any) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "params-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return filepath.Clean(f.Name()), nil
}

// readForm читает multipart-запрос по частям: архив нужен целиком, но без
// временных файлов на диске (агент в песочнице).
func readForm(r *http.Request) (update.Input, error) {
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

// stageFiles кладёт принятые файлы в новый каталог (0700); задача читает и
// удаляет их.
func stageFiles(dir string, in update.Input) (string, error) {
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, nodeapi.ErrorBody{Error: msg})
}
