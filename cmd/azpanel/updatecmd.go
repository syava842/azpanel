package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/update"
)

// updateDeps — то, что тесты подменяют: клиент GitHub и окружение хоста.
type updateDeps struct {
	token  func() string
	client func(token string) *update.Client
	env    func(out io.Writer) (*update.Env, error)
}

func realUpdateDeps() updateDeps {
	return updateDeps{
		token: func() string {
			sec, _ := secrets.Load(paths.SecretsFile())
			return sec[update.TokenKey]
		},
		client: func(token string) *update.Client { return &update.Client{Token: token} },
		env:    hostUpdateEnv,
	}
}

// cmdUpdate — azpanel update [--check] [--yes]: сверка с последним релизом и
// установка с бэкапом и откатом. Вопросы миграции конфига задаются в консоли.
func cmdUpdate(args []string, in io.Reader, out io.Writer) error {
	return runUpdate(args, in, out, realUpdateDeps())
}

func runUpdate(args []string, in io.Reader, out io.Writer, d updateDeps) error {
	check, yes := false, false
	for _, a := range args {
		switch a {
		case "--check":
			check = true
		case "--yes":
			yes = true
		default:
			return errUsage
		}
	}
	if update.IsDev(version) {
		return errors.New("сборка dev обновлений не предлагает и не ставит")
	}
	token := d.token()
	if token == "" {
		return fmt.Errorf("не задан %s в %s: проверка обновлений выключена", update.TokenKey, paths.SecretsFile())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cl := d.client(token)
	rel, err := cl.Latest(ctx)
	if err != nil {
		return err
	}
	newer, err := update.Newer(version, rel.Version())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Установлена %s, последний релиз %s\n", version, rel.Version())
	if !newer {
		fmt.Fprintln(out, "Обновлений нет.")
		return nil
	}
	if strings.TrimSpace(rel.Body) != "" {
		fmt.Fprintf(out, "\nЧто нового:\n%s\n\n", strings.TrimSpace(rel.Body))
	}
	if check {
		fmt.Fprintln(out, "Есть обновление. Установить: azpanel update")
		return nil
	}
	rd := bufio.NewReader(in)
	if !yes {
		fmt.Fprintf(out, "Обновить до %s? [y/N] ", rel.Version())
		line, _ := rd.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" && a != "д" && a != "да" {
			fmt.Fprintln(out, "Отменено.")
			return nil
		}
	}
	fmt.Fprintln(out, "Скачиваю...")
	f, err := cl.Fetch(ctx, rel, runtime.GOARCH)
	if err != nil {
		return err
	}
	env, err := d.env(out)
	if err != nil {
		return err
	}
	input := update.Input{Name: f.Name, Archive: f.Archive, Sums: f.Sums, Sig: f.Sig, Answers: map[string]string{}}
	for {
		// Предварительная проверка ничего не меняет, поэтому вопросы можно
		// задавать сколько нужно.
		_, err := env.Preflight(input)
		var qe *config.QuestionsError
		if !errors.As(err, &qe) {
			if err != nil {
				return err
			}
			break
		}
		if yes {
			return fmt.Errorf("%w (запустите без --yes, чтобы ответить)", err)
		}
		for _, q := range qe.Questions {
			fmt.Fprintf(out, "%s\n%s: ", q.Text, q.Key)
			line, rerr := rd.ReadString('\n')
			input.Answers[q.Key] = strings.TrimSpace(line)
			if rerr != nil && strings.TrimSpace(line) == "" {
				return fmt.Errorf("ответ на %s не получен: обновление не начато", q.Key)
			}
		}
	}
	// Ctrl+C во время замены оставил бы систему наполовину обновлённой.
	res, err := env.Apply(context.WithoutCancel(ctx), input)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Обновлено: %s -> %s. Бэкап: %s\n", res.From, res.To, res.Backup)
	return nil
}
