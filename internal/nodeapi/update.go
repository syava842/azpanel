package nodeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"

	"github.com/syava842/azpanel/internal/update"
)

// MaxUpdateBody — предел тела POST /v1/update (архив, суммы и подпись).
const MaxUpdateBody = 64 << 20

// Части multipart-запроса POST /v1/update.
const (
	UpdatePartName    = "name"    // имя архива, как в SHA256SUMS
	UpdatePartArchive = "archive" // tar.gz релиза
	UpdatePartSums    = "sums"    // SHA256SUMS
	UpdatePartSig     = "sig"     // SHA256SUMS.sig
	UpdatePartAnswers = "answers" // JSON {"ключ":"ответ"} на вопросы миграции
)

// UpdateQuestion — вопрос миграции конфига без ответа.
type UpdateQuestion struct {
	Key  string `json:"key"`
	Text string `json:"text"`
}

// UpdateRequest — релиз, который панель скачала и передаёт агенту. Подпись
// агент проверяет сам, вшитым ключом.
type UpdateRequest struct {
	Name    string
	Archive []byte
	Sums    []byte
	Sig     []byte
	Answers map[string]string
}

// UpdateResult — итог последнего обновления на узле (data/update/result.json).
type UpdateResult = update.Result

// Update передаёт агенту релиз. Отказ по подписи, версии или архитектуре —
// 422 с причиной, ничего не изменено; вопросы миграции без ответа — 409 и
// Error.Questions; принято — 202 и задача selfupdate (журнал и итог — по
// Tasks/Task, итог файла — UpdateResult).
func (c *HTTPClient) Update(ctx context.Context, req UpdateRequest) (Task, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField(UpdatePartName, req.Name); err != nil {
		return Task{}, err
	}
	for _, p := range []struct {
		part string
		data []byte
	}{{UpdatePartArchive, req.Archive}, {UpdatePartSums, req.Sums}, {UpdatePartSig, req.Sig}} {
		w, err := mw.CreateFormFile(p.part, p.part)
		if err != nil {
			return Task{}, err
		}
		if _, err := w.Write(p.data); err != nil {
			return Task{}, err
		}
	}
	if len(req.Answers) > 0 {
		b, err := json.Marshal(req.Answers)
		if err != nil {
			return Task{}, err
		}
		if err := mw.WriteField(UpdatePartAnswers, string(b)); err != nil {
			return Task{}, err
		}
	}
	if err := mw.Close(); err != nil {
		return Task{}, err
	}
	body, err := c.rawBody(ctx, http.MethodPost, "/v1/update", mw.FormDataContentType(), &buf)
	if err != nil {
		return Task{}, err
	}
	var t Task
	err = json.Unmarshal(body, &t)
	return t, err
}

// UpdateResult — итог последнего обновления; nil — обновлений не было.
func (c *HTTPClient) UpdateResult(ctx context.Context) (*UpdateResult, error) {
	var v struct {
		Result *UpdateResult `json:"result"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/update/result", nil, &v)
	return v.Result, err
}
