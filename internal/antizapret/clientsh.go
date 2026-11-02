package antizapret

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/limits"
)

// MaxCertDays — верхняя граница срока сертификата в client.sh.
const MaxCertDays = 3650

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ClientSh запускает /root/antizapret/client.sh — единственный способ, которым
// azpanel меняет клиентов AntiZapret. Вызовы идут по одному: client.sh
// правит общие файлы (PKI, конфиги WireGuard) без блокировок.
type ClientSh struct {
	Dir     string        // каталог AntiZapret, в нём client.sh и setup
	Timeout time.Duration // на один вызов
	// Run — запуск процесса; nil — настоящий client.sh. Подменяется в тестах.
	Run func(ctx context.Context, dir string, args ...string) ([]byte, error)
	mu  sync.Mutex
}

// AddOpenVPN — опция 1. Для существующего клиента client.sh не создаёт
// нового, а продлевает сертификат на days дней, поэтому создание и
// продление различает вызывающий.
func (c *ClientSh) AddOpenVPN(ctx context.Context, name string, days int) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	if days < 1 || days > MaxCertDays {
		return "", fmt.Errorf("срок сертификата %d дней, нужно 1..%d", days, MaxCertDays)
	}
	return c.run(ctx, "1", name, strconv.Itoa(days))
}

// DeleteOpenVPN — опция 2: отзыв сертификата, CRL, удаление профилей, kill сессий.
func (c *ClientSh) DeleteOpenVPN(ctx context.Context, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return c.run(ctx, "2", name)
}

// AddWireGuard — опция 4: пир в antizapret.conf и vpn.conf, профили WG и AmneziaWG.
func (c *ClientSh) AddWireGuard(ctx context.Context, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return c.run(ctx, "4", name)
}

// DeleteWireGuard — опция 5.
func (c *ClientSh) DeleteWireGuard(ctx context.Context, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return c.run(ctx, "5", name)
}

func checkName(name string) error {
	if !limits.ValidName(name) {
		return fmt.Errorf("недопустимое имя клиента %q: 1–32 символа a-z, A-Z, 0-9, _ и -", name)
	}
	return nil
}

// run: на неверном аргументе client.sh спрашивает через read в цикле и с
// пустым вводом не выходит никогда — поэтому аргументы проверены выше, а
// тайм-аут обрывает вызов в любом случае.
func (c *ClientSh) run(ctx context.Context, args ...string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	run := c.Run
	if run == nil {
		run = execClientSh
	}
	out, err := run(ctx, c.Dir, args...)
	text := tail(string(out), 20)
	what := "client.sh " + strings.Join(args, " ")
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return text, fmt.Errorf("%s не уложился в %s: %s", what, c.Timeout, text)
	case err != nil:
		return text, fmt.Errorf("%s: %w: %s", what, err, text)
	}
	return text, nil
}

func execClientSh(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "client.sh"), args...)
	cmd.Dir = dir
	cmd.Stdin = nil // /dev/null: read в client.sh сразу получит EOF
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// tail — последние n строк без цветовых кодов терминала.
func tail(s string, n int) string {
	s = ansiRe.ReplaceAllString(s, "")
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
