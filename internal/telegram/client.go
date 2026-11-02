package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL — боевой адрес Bot API.
const DefaultBaseURL = "https://api.telegram.org"

const (
	// LongPollSeconds — длительность long polling для getUpdates.
	LongPollSeconds = 50
	httpTimeout     = 60 * time.Second
	maxBackoff      = 60 * time.Second
	max429Retries   = 5
	// max429Wait — сколько всего можно ждать после ответов 429; дольше — отказ сразу.
	max429Wait = 5 * time.Minute
	// fileTimeout — предел одной отправки файла (бэкап до 50 МБ по медленному каналу).
	fileTimeout = 10 * time.Minute
)

// Client — клиент Bot API. Безопасен для параллельного использования.
type Client struct {
	token   string
	baseURL string
	http    *http.Client
	// fileHTTP — клиент для отправки файлов: без общего тайм-аута, предел задаёт контекст.
	fileHTTP *http.Client
	sleep    func(ctx context.Context, d time.Duration) error // подменяется в тестах
}

// New создаёт клиент; пустой baseURL означает https://api.telegram.org.
func New(token, baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		token:    token,
		baseURL:  strings.TrimRight(baseURL, "/"),
		http:     &http.Client{Timeout: httpTimeout},
		fileHTTP: &http.Client{},
		sleep:    sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// redactedError — ошибка с текстом без токена; исходная доступна через Unwrap
// (для errors.Is с context.Canceled), но её текст наружу не выводится.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

func (c *Client) redactStr(s string) string {
	if c.token == "" {
		return s
	}
	s = strings.ReplaceAll(s, c.token, "<токен>")
	return strings.ReplaceAll(s, url.PathEscape(c.token), "<токен>")
}

// redact вырезает токен из текста ошибки.
func (c *Client) redact(err error) error {
	if err == nil {
		return nil
	}
	var ae *APIError
	if errors.As(err, &ae) {
		return err // описание уже очищено при разборе
	}
	return &redactedError{msg: c.redactStr(err.Error()), err: err}
}

func (c *Client) endpoint(method string) string {
	return c.baseURL + "/bot" + c.token + "/" + method
}

type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// do выполняет запрос; при 429 ждёт retry_after и повторяет (до max429Retries раз).
func (c *Client) do(ctx context.Context, method, contentType string, body []byte) (json.RawMessage, error) {
	return c.doWith(ctx, c.http, method, contentType, body)
}

func (c *Client) doWith(ctx context.Context, hc *http.Client, method, contentType string, body []byte) (json.RawMessage, error) {
	var waited time.Duration
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(method), bytes.NewReader(body))
		if err != nil {
			return nil, c.redact(fmt.Errorf("запрос %s: %w", method, err))
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := hc.Do(req)
		if err != nil {
			// *url.Error содержит URL с токеном — берём только вложенную причину.
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			return nil, c.redact(fmt.Errorf("запрос %s: %w", method, err))
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if rerr != nil {
			return nil, c.redact(fmt.Errorf("чтение ответа %s: %w", method, rerr))
		}
		var ar apiResponse
		if err := json.Unmarshal(raw, &ar); err != nil {
			return nil, c.redact(fmt.Errorf("ответ %s (HTTP %d) не разобран: %w", method, resp.StatusCode, err))
		}
		if ar.OK {
			return ar.Result, nil
		}
		ae := &APIError{Code: ar.ErrorCode, Description: c.redactStr(ar.Description), RetryAfter: ar.Parameters.RetryAfter}
		if ae.Code == 0 {
			ae.Code = resp.StatusCode
		}
		if ae.Code == http.StatusTooManyRequests && attempt < max429Retries {
			wait := time.Duration(ae.RetryAfter) * time.Second
			if wait <= 0 {
				wait = time.Second
			}
			if waited+wait > max429Wait {
				return nil, ae // слишком долго: пусть решает вызывающий
			}
			waited += wait
			if err := c.sleep(ctx, wait); err != nil {
				return nil, c.redact(err)
			}
			continue
		}
		return nil, ae
	}
}

func (c *Client) callJSON(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return c.redact(fmt.Errorf("кодирование %s: %w", method, err))
	}
	res, err := c.do(ctx, method, "application/json", body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(res, out); err != nil {
		return c.redact(fmt.Errorf("результат %s: %w", method, err))
	}
	return nil
}

// backoff — пауза перед n-м повтором (n с нуля): 1, 2, 4 ... до 60 с.
func backoff(n int) time.Duration {
	if n >= 6 {
		return maxBackoff
	}
	d := time.Second << uint(n)
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

// GetUpdates — long polling. Сетевые сбои повторяются с нарастающей паузой
// до 60 с, пока не отменён ctx; ошибки Bot API возвращаются сразу.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeoutSec int) ([]Update, error) {
	params := map[string]any{
		"offset":          offset,
		"timeout":         timeoutSec,
		"allowed_updates": []string{"message", "callback_query"},
	}
	for n := 0; ; n++ {
		var ups []Update
		err := c.callJSON(ctx, "getUpdates", params, &ups)
		if err == nil {
			return ups, nil
		}
		if ctx.Err() != nil {
			return nil, c.redact(ctx.Err())
		}
		var ae *APIError
		if errors.As(err, &ae) {
			return nil, err
		}
		if serr := c.sleep(ctx, backoff(n)); serr != nil {
			return nil, c.redact(serr)
		}
	}
}

// NextOffset возвращает offset для следующего getUpdates.
func NextOffset(ups []Update, cur int64) int64 {
	for _, u := range ups {
		if u.UpdateID >= cur {
			cur = u.UpdateID + 1
		}
	}
	return cur
}

// GetMe возвращает данные бота (имя пользователя для ссылки привязки).
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	var u User
	if err := c.callJSON(ctx, "getMe", struct{}{}, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// SendMessage отправляет текст.
func (c *Client) SendMessage(ctx context.Context, p SendMessageParams) (*Message, error) {
	var m Message
	if err := c.callJSON(ctx, "sendMessage", p, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// EditMessageText меняет текст (и клавиатуру) отправленного сообщения.
func (c *Client) EditMessageText(ctx context.Context, p EditMessageTextParams) error {
	return c.callJSON(ctx, "editMessageText", p, nil)
}

// AnswerCallbackQuery закрывает «часики» на кнопке; text показывается всплывающим.
func (c *Client) AnswerCallbackQuery(ctx context.Context, id, text string, alert bool) error {
	return c.callJSON(ctx, "answerCallbackQuery", map[string]any{
		"callback_query_id": id, "text": text, "show_alert": alert,
	}, nil)
}

// SendDocument отправляет файл (multipart/form-data).
func (c *Client) SendDocument(ctx context.Context, chatID int64, filename string, r io.Reader, caption string) (*Message, error) {
	return c.sendFile(ctx, "sendDocument", "document", chatID, filename, r, caption)
}

// SendPhoto отправляет изображение (multipart/form-data).
func (c *Client) SendPhoto(ctx context.Context, chatID int64, filename string, r io.Reader, caption string) (*Message, error) {
	return c.sendFile(ctx, "sendPhoto", "photo", chatID, filename, r, caption)
}

func (c *Client) sendFile(ctx context.Context, method, field string, chatID int64, filename string, r io.Reader, caption string) (*Message, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	if caption != "" {
		_ = mw.WriteField("caption", caption)
	}
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		return nil, c.redact(fmt.Errorf("форма %s: %w", method, err))
	}
	if _, err := io.Copy(fw, r); err != nil {
		return nil, c.redact(fmt.Errorf("чтение файла для %s: %w", method, err))
	}
	if err := mw.Close(); err != nil {
		return nil, c.redact(fmt.Errorf("форма %s: %w", method, err))
	}
	fctx, cancel := context.WithTimeout(ctx, fileTimeout)
	defer cancel()
	res, err := c.doWith(fctx, c.fileHTTP, method, mw.FormDataContentType(), buf.Bytes())
	if err != nil {
		return nil, err
	}
	var m Message
	if err := json.Unmarshal(res, &m); err != nil {
		return nil, c.redact(fmt.Errorf("результат %s: %w", method, err))
	}
	return &m, nil
}
