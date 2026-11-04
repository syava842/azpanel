package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
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
	token := d.token() // пусто — анонимный запрос к публичному репозиторию
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
		_, err := env.Preflight(ctx, input)
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
	// Ctrl+C, обрыв SSH (SIGHUP) и SIGTERM во время замены оставили бы
	// систему наполовину обновлённой: с этого места сигналы игнорируются до
	// конца обновления или отката.
	protectFromSignals()
	res, err := env.Apply(context.WithoutCancel(ctx), input)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Обновлено: %s -> %s. Бэкап: %s\n", res.From, res.To, res.Backup)
	return nil
}

// protectFromSignals игнорирует SIGINT, SIGTERM, SIGHUP и SIGPIPE до конца
// процесса: CLI завершается сразу после замены. Вернуть их нельзя — Go после
// Ignore оставляет SIGHUP и SIGINT игнорируемыми навсегда (ни Reset, ни
// Notify с Stop этого не снимают; проверено на Linux). SIGPIPE: оборванный
// SSH закрывает stdout, и первая же запись в него убила бы процесс посреди
// отката.
//
// Выбор пути: можно было запускать Apply отдельной задачей systemd-run, как у
// агента, но тогда CLI превращается в наблюдателя за чужим процессом (файлы
// параметров, журнал, опрос итога) — вторая машина состояний ради случая,
// который закрывается игнорированием сигналов. Остаётся SIGKILL (его не
// перехватить) и потеря питания; от обоих спасает бэкап и ручной откат.
func protectFromSignals() {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE}
	signal.Ignore(sigs...)
}
