package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/update"
)

// exitCodeError — режим просит завершить процесс с этим кодом без сообщения
// в stderr (всё, что нужно сказать, он уже вывел в stdout).
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("код выхода %d", e.code) }

func init() {
	// migrate-config --in ФАЙЛ --answers ФАЙЛ: миграция конфига кодом ЭТОГО
	// бинарника. Обновление запускает так распакованный новый бинарник: старый
	// не знает о цепочке миграций новой версии. Вывод: мигрированный TOML
	// (код 0) либо вопросы JSON (код 3, update.MigrateReply).
	internalModes["migrate-config"] = func(_ context.Context, args []string, out io.Writer) error {
		return runMigrateConfig(args, out)
	}
}

func runMigrateConfig(args []string, out io.Writer) error {
	if len(args) != 4 || args[0] != "--in" || args[2] != "--answers" {
		return errUsage
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("конфиг не прочитан: %w", err)
	}
	var answers map[string]string
	raw, err := os.ReadFile(args[3])
	if err != nil {
		return fmt.Errorf("файл ответов не прочитан: %w", err)
	}
	if err := json.Unmarshal(raw, &answers); err != nil {
		return fmt.Errorf("файл ответов: нужен JSON-объект «ключ: ответ»: %w", err)
	}
	res, _, err := config.Migrate(data, answers)
	var qe *config.QuestionsError
	if errors.As(err, &qe) {
		var reply update.MigrateReply
		for _, q := range qe.Questions {
			reply.Questions = append(reply.Questions, update.MigrateQuestion{Key: q.Key, Text: q.Text})
		}
		if err := json.NewEncoder(out).Encode(reply); err != nil {
			return err
		}
		return exitCodeError{code: update.MigrateExitQuestions}
	}
	if err != nil {
		return err
	}
	// Мигрированный конфиг обязан читаться этим же бинарником: иначе служба
	// не поднимется, и узнать об этом лучше до замены.
	if _, err := config.Parse(res); err != nil {
		return fmt.Errorf("мигрированный конфиг не проходит проверку: %w", err)
	}
	_, err = out.Write(res)
	return err
}
