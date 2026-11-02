package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"
)

const cmdTimeout = 15 * time.Second

// run запускает команду с пределом времени; в ошибке — хвост её stderr.
func run(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 500 {
			msg = msg[len(msg)-500:]
		}
		if msg != "" {
			return "", fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return out.String(), nil
}

// ExecSave — `iptables-save -t nat`.
func ExecSave(ctx context.Context) (string, error) {
	return run(ctx, "", "iptables-save", "-t", "nat")
}

// ExecRestore подставляет таблицу nat целиком (-T nat: другие таблицы
// не затрагиваются, даже если в тексте они есть).
func ExecRestore(ctx context.Context, rules string) error {
	_, err := run(ctx, rules, "iptables-restore", "-w", "5", "-T", "nat")
	return err
}

// ExecPersist — сохранение, как в конце proxy.sh.
func ExecPersist(ctx context.Context) error {
	_, err := run(ctx, "", "netfilter-persistent", "save")
	return err
}

// ProcConntrack — таблица соединений ядра; нет файла (модуль не загружен
// или старое ядро) — `conntrack -L`.
func ProcConntrack(path string) func(ctx context.Context) (io.ReadCloser, error) {
	return func(ctx context.Context) (io.ReadCloser, error) {
		f, err := os.Open(path)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			return nil, err
		}
		out, cerr := run(ctx, "", "conntrack", "-L")
		if cerr != nil {
			return nil, fmt.Errorf("%s не читается (%v), conntrack -L тоже: %w", path, err, cerr)
		}
		return io.NopCloser(strings.NewReader(out)), nil
	}
}
