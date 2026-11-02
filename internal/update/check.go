package update

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

// CheckInterval — как часто Checker спрашивает GitHub.
const CheckInterval = 6 * time.Hour

// ErrDisabled — проверка выключена: сборка dev или не задан токен GitHub.
var ErrDisabled = errors.New("проверка обновлений выключена: сборка dev или не задан GITHUB_TOKEN")

// IsDev — сборка без версии: обновлений не предлагает и не ставит.
func IsDev(version string) bool {
	_, err := ParseVersion(version)
	return err != nil
}

// Info — итог проверки обновлений.
type Info struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	Notes     string    `json:"notes,omitempty"` // описание релиза
	Checked   time.Time `json:"checked,omitempty"`
	Error     string    `json:"error,omitempty"` // последняя ошибка проверки, без токена
}

// Checker раз в CheckInterval сверяет версию с последним релизом. Панель
// создаёт его, запускает Run и показывает Last на странице «Обновление» и в
// шапке; OnAvailable вызывается один раз на версию (уведомление
// azpanel_update).
type Checker struct {
	Current string
	// Token отдаёт токен GitHub при каждой проверке (secrets.env читается
	// заново: владелец мог задать токен в настройках без перезапуска).
	Token func() string
	// Client строит клиент GitHub; nil — настоящий. Подменяется в тестах.
	Client      func(token string) *Client
	Interval    time.Duration
	Now         func() time.Time
	OnAvailable func(Info)
	Log         *slog.Logger

	mu       sync.Mutex
	last     Info
	notified string
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) logger() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Last — результат последней проверки (до первой — только Current).
func (c *Checker) Last() Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last.Current == "" {
		return Info{Current: c.Current}
	}
	return c.last
}

// Check спрашивает GitHub сейчас. dev-сборка и пустой токен — ErrDisabled
// без обращения к сети.
func (c *Checker) Check(ctx context.Context) (Info, error) {
	info := Info{Current: c.Current}
	token := ""
	if c.Token != nil {
		token = c.Token()
	}
	if IsDev(c.Current) || token == "" {
		c.store(info)
		return info, ErrDisabled
	}
	cl := &Client{Token: token}
	if c.Client != nil {
		cl = c.Client(token)
	}
	rel, err := cl.Latest(ctx)
	info.Checked = c.now()
	if err != nil {
		info.Error = Redact(err.Error(), token)
		// Прежний результат не затираем: сбой сети не отменяет найденное обновление.
		c.mu.Lock()
		prev := c.last
		c.mu.Unlock()
		if prev.Latest != "" {
			prev.Error, prev.Checked = info.Error, info.Checked
			info = prev
		}
		c.store(info)
		return info, errors.New(info.Error)
	}
	info.Latest, info.Notes = rel.Version(), rel.Body
	if newer, err := Newer(c.Current, info.Latest); err == nil && newer && !rel.Draft && !rel.Prerelease {
		info.Available = true
	}
	c.store(info)
	if info.Available {
		c.notify(info)
	}
	return info, nil
}

func (c *Checker) store(i Info) {
	c.mu.Lock()
	c.last = i
	c.mu.Unlock()
}

func (c *Checker) notify(i Info) {
	c.mu.Lock()
	seen := c.notified == i.Latest
	c.notified = i.Latest
	c.mu.Unlock()
	if !seen && c.OnAvailable != nil {
		c.OnAvailable(i)
	}
}

// Run проверяет сразу и затем каждые Interval, пока ctx не отменён.
func (c *Checker) Run(ctx context.Context) {
	every := c.Interval
	if every <= 0 {
		every = CheckInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := c.Check(ctx); err != nil && !errors.Is(err, ErrDisabled) {
			c.logger().Warn("проверка обновлений не удалась", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
