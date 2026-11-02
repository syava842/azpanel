package main

import (
	"context"
	"errors"
	"io"

	"github.com/syava842/azpanel/internal/telemt"
)

func init() {
	// telemt-update [--binary П] [--config П] [--unit И] [--force]
	internalModes["telemt-update"] = internalTelemtUpdate
	// telemt-install --params ФАЙЛ
	internalModes["telemt-install"] = func(ctx context.Context, args []string, out io.Writer) error {
		var p telemt.InstallParams
		if err := readParams(args, &p); err != nil {
			return err
		}
		env := telemt.NewEnv()
		env.Log = out
		return redactTelemtErr(env.Install(ctx, p))
	}
	// telemt-apply --params ФАЙЛ: правка пользователей и перезапуск с проверкой
	internalModes["telemt-apply"] = func(ctx context.Context, args []string, out io.Writer) error {
		var p telemt.ApplyParams
		if err := readParams(args, &p); err != nil {
			return err
		}
		env := telemt.NewEnv()
		env.Log = out
		return redactTelemtErr(env.Apply(ctx, p))
	}
}

// internalTelemtUpdate обновляет telemt. Пути и имя юнита можно задать —
// так проверяют обновление на втором экземпляре (временный юнит
// azpanel-telemt-test с копией конфига) раньше боевого.
func internalTelemtUpdate(ctx context.Context, args []string, out io.Writer) error {
	env := telemt.NewEnv()
	env.Log = out
	force := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--force" {
			force = true
			continue
		}
		if i+1 >= len(args) {
			return errUsage
		}
		switch args[i] {
		case "--binary":
			env.Binary = args[i+1]
		case "--config":
			env.Config = args[i+1]
		case "--unit":
			env.Unit = args[i+1]
		default:
			return errUsage
		}
		i++
	}
	return redactTelemtErr(env.Update(ctx, force))
}

// redactTelemtErr затирает секреты в тексте ошибки: stderr задачи — её журнал,
// который панель показывает целиком.
func redactTelemtErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(telemt.RedactSecrets(err.Error()))
}
