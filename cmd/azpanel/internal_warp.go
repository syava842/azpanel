package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/syava842/azpanel/internal/warp"
)

func init() {
	// warp-run -- шаг [арг…] [-- шаг …]: команды warper по порядку, вывод без секретов
	internalModes["warp-run"] = func(ctx context.Context, args []string, out io.Writer) error {
		steps, err := splitSteps(args)
		if err != nil {
			return err
		}
		return (&warp.Warper{}).RunSteps(ctx, steps, out)
	}
	// warp-install --params ФАЙЛ: install.sh AZ-WARP под псевдотерминалом
	internalModes["warp-install"] = func(ctx context.Context, args []string, out io.Writer) error {
		var a warp.InstallAnswers
		if err := readParams(args, &a); err != nil {
			return err
		}
		return warp.Install(ctx, a, nil, os.TempDir(), out)
	}
}

// splitSteps делит «-- a b -- c» на команды warper [[a b] [c]].
func splitSteps(args []string) ([][]string, error) {
	var steps [][]string
	for _, a := range args {
		if a == "--" {
			steps = append(steps, nil)
			continue
		}
		if len(steps) == 0 {
			return nil, errors.New("команды warp-run начинаются с --")
		}
		steps[len(steps)-1] = append(steps[len(steps)-1], a)
	}
	for _, s := range steps {
		if len(s) == 0 {
			return nil, errors.New("пустая команда между --")
		}
	}
	if len(steps) == 0 {
		return nil, errors.New("нет команд для warper")
	}
	return steps, nil
}
