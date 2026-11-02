package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// SelfUpdateUnit — временный юнит обновления. Имя одно на всех: пока юнит
// жив, второе обновление не запустится.
const SelfUpdateUnit = "azpanel-selfupdate"

// selfUpdateTimeout — предел юнита обновления (как у задачи агента узла).
const selfUpdateTimeout = 600

// SystemdRun запускает команду и возвращает код выхода и вывод; ошибка — если
// процесс не удалось запустить. В тестах подменяется.
type SystemdRun func(ctx context.Context, name string, args ...string) (code int, out []byte, err error)

func execRun(ctx context.Context, name string, args ...string) (int, []byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out, nil
	}
	return 0, out, err
}

// SelfUpdateLauncher запускает `azpanel internal selfupdate` отдельным юнитом
// systemd-run, вне песочницы агента: обновление перезапускает саму службу
// прокси и пишет в /opt/azpanel/bin. Итог — data/update/result.json
// (GET /v1/update/result), журнал — logPath. Подходит как Launch для
// updateapi.Service.
func SelfUpdateLauncher(run SystemdRun, logPath string, log *slog.Logger, now func() time.Time) func(w http.ResponseWriter, argv []string, params string) (any, bool) {
	if run == nil {
		run = execRun
	}
	if now == nil {
		now = time.Now
	}
	return func(w http.ResponseWriter, argv []string, params string) (any, bool) {
		fail := func(status int, msg string) (any, bool) {
			os.Remove(params) // в файле могут быть ответы миграции
			writeErr(w, status, msg)
			return nil, false
		}
		ctx := context.WithoutCancel(context.Background())
		// Уже идёт: is-active возвращает 0 только у работающего юнита.
		if code, _, err := run(ctx, "systemctl", "is-active", "--quiet", SelfUpdateUnit); err == nil && code == 0 {
			return fail(http.StatusConflict, "обновление уже идёт")
		}
		args := []string{
			"--unit=" + SelfUpdateUnit, "--collect", "--quiet",
			"--property=StandardOutput=append:" + logPath,
			"--property=StandardError=append:" + logPath,
			"--property=RuntimeMaxSec=" + strconv.Itoa(selfUpdateTimeout),
			"--",
		}
		code, out, err := run(ctx, "systemd-run", append(args, argv...)...)
		if err != nil {
			return fail(http.StatusInternalServerError, "обновление не запущено: "+err.Error())
		}
		if code != 0 {
			msg := strings.TrimSpace(string(out))
			if len(msg) > 300 {
				msg = msg[len(msg)-300:]
			}
			return fail(http.StatusInternalServerError, "systemd-run вернул код "+strconv.Itoa(code)+": "+msg)
		}
		return nodeapi.Task{ID: SelfUpdateUnit, Kind: "selfupdate", Started: now().UTC(), Log: logPath}, true
	}
}
