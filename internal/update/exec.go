package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/config"
)

// MigrateExitQuestions — код выхода `azpanel internal migrate-config`, когда
// миграции нужны ответы: вопросы лежат в stdout как JSON (MigrateReply).
const MigrateExitQuestions = 3

// MigrateQuestion — вопрос миграции конфига в JSON-ответе нового бинарника.
type MigrateQuestion struct {
	Key  string `json:"key"`
	Text string `json:"text"`
}

// MigrateReply — stdout `azpanel internal migrate-config` с кодом 3.
type MigrateReply struct {
	Questions []MigrateQuestion `json:"questions"`
}

// ExecResult — итог запуска файла: код выхода и вывод. Ненулевой код — не
// ошибка запуска, а данные для вызывающего.
type ExecResult struct {
	Stdout, Stderr []byte
	Code           int
}

// ExecFunc запускает исполняемый файл bin с аргументами. Ошибка — только если
// процесс не удалось запустить. В тестах подменяется «бинарниками» без ELF.
type ExecFunc func(ctx context.Context, bin string, args ...string) (ExecResult, error)

const execTimeout = 60 * time.Second

func runBinary(ctx context.Context, bin string, args ...string) (ExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := ExecResult{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.Code = ee.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

func (e *Env) exec() ExecFunc {
	if e.Exec != nil {
		return e.Exec
	}
	return runBinary
}

// workDir — где временно лежит распакованный новый бинарник для запуска.
func (e *Env) workDir() string {
	if e.WorkDir != "" {
		return e.WorkDir
	}
	return e.p("data", "update", "tmp")
}

// migrateWithBinary приводит конфиг к версии нового бинарника ЕГО же кодом:
// старый бинарник цепочки миграций новой версии не знает. Новый бинарник
// кладётся во временный каталог и запускается как `internal migrate-config`.
// Вопросы без ответа приходят как *config.QuestionsError.
func (e *Env) migrateWithBinary(ctx context.Context, bin, cfg []byte, answers map[string]string) ([]byte, error) {
	if err := os.MkdirAll(e.workDir(), 0o700); err != nil {
		return nil, fmt.Errorf("каталог для проверки нового бинарника: %w", err)
	}
	dir, err := os.MkdirTemp(e.workDir(), "migrate-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	exe := filepath.Join(dir, "azpanel")
	in, ans := filepath.Join(dir, "config.toml"), filepath.Join(dir, "answers.json")
	if answers == nil {
		answers = map[string]string{}
	}
	ansData, err := json.Marshal(answers)
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{exe, bin, 0o700}, {in, cfg, 0o600}, {ans, ansData, 0o600}} {
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			return nil, fmt.Errorf("файл для проверки нового бинарника: %w", err)
		}
	}
	res, err := e.exec()(ctx, exe, "internal", "migrate-config", "--in", in, "--answers", ans)
	if err != nil {
		return nil, fmt.Errorf("новый бинарник не запустился (проверьте, что каталог %s не смонтирован с noexec): %w", e.workDir(), err)
	}
	switch res.Code {
	case 0:
		if len(bytes.TrimSpace(res.Stdout)) == 0 {
			return nil, errors.New("новый бинарник вернул пустой конфиг")
		}
		return res.Stdout, nil
	case MigrateExitQuestions:
		var reply MigrateReply
		if err := json.Unmarshal(res.Stdout, &reply); err != nil || len(reply.Questions) == 0 {
			return nil, errors.New("новый бинарник задал вопросы в неразборчивом виде")
		}
		qe := &config.QuestionsError{}
		for _, q := range reply.Questions {
			qe.Questions = append(qe.Questions, config.Question{Key: q.Key, Text: q.Text})
		}
		return nil, qe
	default:
		msg := strings.TrimSpace(string(res.Stderr))
		if len(msg) > 500 {
			msg = msg[len(msg)-500:]
		}
		return nil, fmt.Errorf("миграция конфига новым бинарником: код %d: %s", res.Code, msg)
	}
}

// binaryVersionCheck — проверка «версия установленного бинарника — новая».
// Выручает на хосте без панели и агента: HTTP-проверок там нет, а молчаливый
// успех скрыл бы сломанный бинарник.
func (e *Env) binaryVersionCheck(ctx context.Context, newVer string) error {
	res, err := e.exec()(ctx, e.p("bin", "azpanel"), "version")
	if err != nil {
		return fmt.Errorf("azpanel version не запустился: %w", err)
	}
	if res.Code != 0 {
		return fmt.Errorf("azpanel version: код выхода %d", res.Code)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != newVer {
		return fmt.Errorf("azpanel version печатает %q, ждали %q", got, newVer)
	}
	return nil
}

// unitsActiveCheck — каждая служба хоста работает (systemctl is-active).
func (e *Env) unitsActiveCheck(ctx context.Context, _ string) error {
	sc := e.Systemctl
	if sc == nil {
		sc = runSystemctl
	}
	for _, u := range e.Units {
		if err := sc(ctx, "is-active", "--quiet", u); err != nil {
			return fmt.Errorf("служба %s не работает: %w", u, err)
		}
	}
	return nil
}
