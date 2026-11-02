package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "123456:SECRET-token"

func newTest(t *testing.T, h http.HandlerFunc) (*Client, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New(testToken, srv.URL)
	var sleeps []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return ctx.Err()
	}
	return c, &sleeps
}

func TestGetUpdatesParsesAndSendsOffset(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		io.WriteString(w, `{"ok":true,"result":[
{"update_id":10,"message":{"message_id":1,"from":{"id":7,"username":"u"},"chat":{"id":7,"type":"private"},"text":"/start abc"}},
{"update_id":11,"callback_query":{"id":"cb","from":{"id":7},"data":"x:1","message":{"message_id":2,"chat":{"id":7,"type":"private"}}}}]}`)
	})
	ups, err := c.GetUpdates(context.Background(), 10, 50)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot"+testToken+"/getUpdates" {
		t.Fatalf("путь: %s", gotPath)
	}
	if gotBody["offset"] != float64(10) || gotBody["timeout"] != float64(50) {
		t.Fatalf("тело: %v", gotBody)
	}
	if len(ups) != 2 || ups[0].Message.Text != "/start abc" || ups[0].Message.Chat.Type != "private" ||
		ups[1].CallbackQuery.Data != "x:1" || ups[1].CallbackQuery.Message.MessageID != 2 {
		t.Fatalf("разбор: %+v", ups)
	}
}

func TestOffsetGrows(t *testing.T) {
	var offsets []float64
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		offsets = append(offsets, b["offset"].(float64))
		io.WriteString(w, `{"ok":true,"result":[{"update_id":5},{"update_id":6}]}`)
	})
	ctx := context.Background()
	var off int64
	for i := 0; i < 2; i++ {
		ups, err := c.GetUpdates(ctx, off, 1)
		if err != nil {
			t.Fatal(err)
		}
		off = NextOffset(ups, off)
	}
	if off != 7 || offsets[0] != 0 || offsets[1] != 7 {
		t.Fatalf("offset %d, запросы %v", off, offsets)
	}
}

func TestRetryAfter429(t *testing.T) {
	n := 0
	c, sleeps := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(429)
			io.WriteString(w, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":3}}`)
			return
		}
		io.WriteString(w, `{"ok":true,"result":[]}`)
	})
	if _, err := c.GetUpdates(context.Background(), 0, 1); err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(*sleeps) != 1 || (*sleeps)[0] != 3*time.Second {
		t.Fatalf("запросов %d, паузы %v", n, *sleeps)
	}
}

func TestSendDocumentMultipart(t *testing.T) {
	var ct, chat, caption, fname, content string
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Error(err)
			return
		}
		chat = r.FormValue("chat_id")
		caption = r.FormValue("caption")
		f, h, err := r.FormFile("document")
		if err != nil {
			t.Error(err)
			return
		}
		fname = h.Filename
		b, _ := io.ReadAll(f)
		content = string(b)
		io.WriteString(w, `{"ok":true,"result":{"message_id":9,"chat":{"id":42,"type":"private"}}}`)
	})
	m, err := c.SendDocument(context.Background(), 42, "client.conf", strings.NewReader("[Interface]"), "конфиг")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "multipart/form-data") || chat != "42" || caption != "конфиг" ||
		fname != "client.conf" || content != "[Interface]" || m.MessageID != 9 {
		t.Fatalf("ct=%s chat=%s cap=%s f=%s c=%s m=%+v", ct, chat, caption, fname, content, m)
	}
}

func TestSendMessageJSON(t *testing.T) {
	var body map[string]any
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		io.WriteString(w, `{"ok":true,"result":{"message_id":3,"chat":{"id":5,"type":"private"}}}`)
	})
	kb := &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{{Text: "Да", CallbackData: "y"}}}}
	if _, err := c.SendMessage(context.Background(), SendMessageParams{ChatID: 5, Text: "привет", ReplyMarkup: kb}); err != nil {
		t.Fatal(err)
	}
	if body["text"] != "привет" || body["reply_markup"] == nil {
		t.Fatalf("тело: %v", body)
	}
}

func TestTokenRedactedOnNetworkFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // соединение будет отвергнуто
	c := New(testToken, url)
	c.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	_, err := c.GetMe(context.Background())
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("токен в ошибке: %v", err)
	}
}

func TestRedactStripsToken(t *testing.T) {
	c := New(testToken, "")
	err := c.redact(errors.New(`Post "https://api.telegram.org/bot` + testToken + `/getMe": EOF`))
	if strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "<токен>") {
		t.Fatalf("токен не вырезан: %v", err)
	}
}

func TestTokenRedactedInAPIError(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"ok":false,"error_code":401,"description":"bad `+testToken+`"}`)
	})
	_, err := c.GetMe(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != 401 || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("ошибка: %v", err)
	}
}

func TestGetUpdatesRetriesNetworkBackoff(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n <= 3 {
			// обрыв соединения без ответа
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		io.WriteString(w, `{"ok":true,"result":[]}`)
	}))
	defer srv.Close()
	c := New(testToken, srv.URL)
	var sleeps []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
	if _, err := c.GetUpdates(context.Background(), 0, 1); err != nil {
		t.Fatal(err)
	}
	if len(sleeps) != 3 || sleeps[0] >= sleeps[1] || sleeps[1] >= sleeps[2] {
		t.Fatalf("паузы не растут: %v", sleeps)
	}
	if backoff(20) != 60*time.Second {
		t.Fatalf("потолок паузы: %v", backoff(20))
	}
}

func TestGetUpdatesStopsOnContext(t *testing.T) {
	c := New(testToken, "http://127.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
	_, err := c.GetUpdates(ctx, 0, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидалась отмена: %v", err)
	}
}

func TestRetryAfterOverLimitFailsFast(t *testing.T) {
	n := 0
	c, sleeps := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(429)
		io.WriteString(w, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":3600}}`)
	})
	_, err := c.GetUpdates(context.Background(), 0, 1)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != 429 {
		t.Fatalf("ожидалась ошибка 429, получено %v", err)
	}
	if n != 1 || len(*sleeps) != 0 {
		t.Fatalf("при паузе дольше предела ждать нельзя: запросов %d, пауз %v", n, *sleeps)
	}
}

func TestRetryAfterTotalWaitBounded(t *testing.T) {
	n := 0
	c, sleeps := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(429)
		io.WriteString(w, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":200}}`)
	})
	c.sleep = func(ctx context.Context, d time.Duration) error { *sleeps = append(*sleeps, d); return nil }
	if _, err := c.GetUpdates(context.Background(), 0, 1); err == nil {
		t.Fatal("ожидалась ошибка 429")
	}
	var total time.Duration
	for _, d := range *sleeps {
		total += d
	}
	if total > max429Wait {
		t.Fatalf("суммарное ожидание %v больше предела %v", total, max429Wait)
	}
}

func TestSendDocumentUsesOwnTimeout(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true,"result":{"message_id":1,"chat":{"id":1,"type":"private"}}}`)
	})
	if c.fileHTTP == nil || c.fileHTTP.Timeout != 0 {
		t.Fatal("для файлов нужен клиент без общего тайм-аута")
	}
	if fileTimeout < 10*time.Minute {
		t.Fatalf("тайм-аут файла %v меньше 10 минут", fileTimeout)
	}
	if _, err := c.SendDocument(context.Background(), 1, "a.tar.gz", strings.NewReader("x"), ""); err != nil {
		t.Fatal(err)
	}
}
