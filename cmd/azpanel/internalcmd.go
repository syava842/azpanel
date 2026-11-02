package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// internalMode — режим «azpanel internal <имя>»: его запускает задача агента
// через systemd-run, то есть вне песочницы агента и от root. Администратору
// эти режимы не нужны. Секреты приходят в файле параметров (0600), который
// читается и сразу удаляется, а не в аргументах.
type internalMode func(ctx context.Context, args []string, out io.Writer) error

// internalModes заполняют файлы internal_*.go: telemt-update, telemt-install,
// telemt-apply, warp-run, warp-install.
var internalModes = map[string]internalMode{}

func cmdInternal(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	mode, ok := internalModes[args[0]]
	if !ok {
		return errUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return mode(ctx, args[1:], out)
}

// readParams читает JSON из файла «--params ФАЙЛ» и удаляет файл: в нём могут
// быть секреты, а нужен он один раз.
func readParams(args []string, v any) error {
	if len(args) != 2 || args[0] != "--params" {
		return errUsage
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("файл параметров не прочитан: %w", err)
	}
	if err := os.Remove(args[1]); err != nil {
		return fmt.Errorf("файл параметров не удалён: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("параметры не разобраны: %w", err)
	}
	return nil
}
