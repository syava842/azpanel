package panel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

const runBotToken = "424242:SECRET-run-token"

// fakeBotAPI считает вызовы методов; getMe отвечает по режиму.
type fakeBotAPI struct {
	mu    sync.Mutex
	calls map[string]int
	getMe string // тело ответа getMe
}

func (f *fakeBotAPI) count(m string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[m]
}

func startFakeBotAPI(t *testing.T, getMe string) *fakeBotAPI {
	t.Helper()
	f := &fakeBotAPI{calls: map[string]int{}, getMe: getMe}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		f.mu.Lock()
		f.calls[m]++
		f.mu.Unlock()
		switch m {
		case "getMe":
			io.WriteString(w, f.getMe)
		case "getUpdates":
			time.Sleep(30 * time.Millisecond)
			io.WriteString(w, `{"ok":true,"result":[]}`)
		default:
			io.WriteString(w, `{"ok":true,"result":true}`)
		}
	}))
	t.Cleanup(srv.Close)
	old := telegramBaseURL
	telegramBaseURL = srv.URL
	t.Cleanup(func() { telegramBaseURL = old })
	return f
}

// runPanel запускает Run с агентом-заглушкой и возвращает адрес и остановку.
func runPanel(t *testing.T, cfg config.Config) (addr string, stop func() error) {
	t.Helper()
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/system":
			w.Write([]byte(`{"resources":{}}`))
		default:
			w.Write([]byte(`[]`))
		}
	}))
	t.Cleanup(agent.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	ln.Close()
	cfg.Panel.Listen = addr
	cfg.Panel.NodeURL = agent.URL
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, "test") }()
	for i := 0; i < 50; i++ {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return addr, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			return fmt.Errorf("Run не остановился")
		}
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

func panelLog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(paths.Log(), "panel.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func botSecrets(t *testing.T, withToken bool) {
	t.Helper()
	if err := secrets.Set(paths.SecretsFile(), secrets.NodeToken, strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	if withToken {
		if err := secrets.Set(paths.SecretsFile(), secrets.TelegramBotToken, runBotToken); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunStartsBotWithGetMe(t *testing.T) {
	runEnv(t)
	botSecrets(t, true)
	api := startFakeBotAPI(t, `{"ok":true,"result":{"id":1,"is_bot":true,"username":"runbot"}}`)
	cfg := config.Default()
	cfg.Telegram.Enabled = true
	_, stop := runPanel(t, cfg)
	waitFor(t, "getMe и getUpdates", func() bool { return api.count("getMe") >= 1 && api.count("getUpdates") >= 1 })
	if err := stop(); err != nil {
		t.Fatalf("Run после отмены: %v", err)
	}
	log := panelLog(t)
	if !strings.Contains(log, "Telegram-бот запущен") || !strings.Contains(log, "runbot") {
		t.Fatalf("нет записи о запуске бота: %s", log)
	}
	if strings.Contains(log, "SECRET-run-token") {
		t.Fatalf("токен в журнале панели: %s", log)
	}
}

func TestRunBotGetMeFailureLeavesPanelRunning(t *testing.T) {
	runEnv(t)
	botSecrets(t, true)
	// описание ошибки нарочно содержит токен: клиент обязан его вырезать
	api := startFakeBotAPI(t, `{"ok":false,"error_code":401,"description":"Unauthorized bot`+runBotToken+`"}`)
	oldBase := botRetryBase
	botRetryBase = 20 * time.Millisecond
	t.Cleanup(func() { botRetryBase = oldBase })
	cfg := config.Default()
	cfg.Telegram.Enabled = true
	addr, stop := runPanel(t, cfg)
	waitFor(t, "повтор getMe", func() bool { return api.count("getMe") >= 2 })
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("панель не работает без бота: %v", err)
	}
	resp.Body.Close()
	if api.count("getUpdates") != 0 {
		t.Fatal("опрос начат без успешного getMe")
	}
	if err := stop(); err != nil {
		t.Fatalf("Run после отмены: %v", err)
	}
	log := panelLog(t)
	if !strings.Contains(log, "бот не запущен") || !strings.Contains(log, "level=WARN") {
		t.Fatalf("нет предупреждения: %s", log)
	}
	if strings.Contains(log, "SECRET-run-token") || strings.Contains(log, "424242:") {
		t.Fatalf("токен в журнале панели: %s", log)
	}
}

func TestRunBotOffWithoutTokenOrFlag(t *testing.T) {
	runEnv(t)
	botSecrets(t, false)
	api := startFakeBotAPI(t, `{"ok":true,"result":{"id":1,"username":"runbot"}}`)
	cfg := config.Default()
	cfg.Telegram.Enabled = true // флаг есть, токена нет
	_, stop := runPanel(t, cfg)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(panelLog(t), "нет TELEGRAM_BOT_TOKEN") {
		t.Fatalf("нет предупреждения о токене: %s", panelLog(t))
	}
	if api.count("getMe") != 0 {
		t.Fatal("бот запущен без токена")
	}

	runEnv(t)
	botSecrets(t, true)
	cfg.Telegram.Enabled = false // токен есть, флага нет
	_, stop = runPanel(t, cfg)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if api.count("getMe") != 0 {
		t.Fatal("бот запущен при telegram.enabled = false")
	}
}
