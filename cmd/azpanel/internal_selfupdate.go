package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/syava842/azpanel/internal/update"
)

// selfUpdateParams — параметры задачи selfupdate: файлы, которые агент
// положил в каталог подготовки. Подпись агент проверил ещё при приёме, но
// шаг проверяет её заново: файлы лежали на диске.
type selfUpdateParams struct {
	Name        string            `json:"name"`
	ArchivePath string            `json:"archive"`
	SumsPath    string            `json:"sums"`
	SigPath     string            `json:"sig"`
	Answers     map[string]string `json:"answers,omitempty"`
}

func init() {
	// selfupdate --params ФАЙЛ: замена бинарника с бэкапом, проверкой и откатом
	internalModes["selfupdate"] = func(ctx context.Context, args []string, out io.Writer) error {
		var p selfUpdateParams
		if err := readParams(args, &p); err != nil {
			return err
		}
		in, err := loadUpdateInput(p)
		// Файлы нужны один раз и могут быть большими.
		for _, f := range []string{p.ArchivePath, p.SumsPath, p.SigPath} {
			os.Remove(f)
		}
		os.Remove(filepath.Dir(p.ArchivePath)) // каталог подготовки, если пуст
		if err != nil {
			return err
		}
		env, err := hostUpdateEnv(out)
		if err != nil {
			return err
		}
		_, err = env.Apply(ctx, in)
		return err
	}
}

func loadUpdateInput(p selfUpdateParams) (update.Input, error) {
	in := update.Input{Name: p.Name, Answers: p.Answers}
	var err error
	for _, f := range []struct {
		path string
		dst  *[]byte
	}{{p.ArchivePath, &in.Archive}, {p.SumsPath, &in.Sums}, {p.SigPath, &in.Sig}} {
		if *f.dst, err = os.ReadFile(f.path); err != nil {
			return in, fmt.Errorf("файл обновления не прочитан: %w", err)
		}
	}
	return in, nil
}
