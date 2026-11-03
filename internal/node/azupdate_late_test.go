package node

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// lateFailure доводит обновление до failed_late: setup.sh напечатал начало
// установки и завершился с ошибкой (после остановки служб).
func lateFailure(t *testing.T, e *azEnv) nodeapi.AZUpdateState {
	t.Helper()
	e.ex.codes["azupdate"] = 1
	e.ex.output["azupdate"] = "== setup.sh ==\nInstallation, please wait...\nE: Unable to locate package x\n"
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{Values: map[string]string{"OPENVPN_PATCH": "3"}}); err != nil {
		t.Fatal(err)
	}
	st := e.waitStatus(nodeapi.AZStatusFailedLate)
	if e.u.Active() {
		t.Fatal("после провала состояние «идёт»")
	}
	return st
}

// Отказ после начала установки: узел без VPN — failed_late, действия «повторить»
// и «восстановить», новое обновление закрыто.
func TestAZLateFailureOffersRetryAndRestore(t *testing.T) {
	e := newAZ(t)
	st := lateFailure(t, e)
	if !strings.Contains(strings.Join(st.Reasons, "|"), "VPN на узле не работает") {
		t.Fatalf("причины: %v", st.Reasons)
	}
	if s := e.u.State(); s.CanRetry || s.CanRestore {
		t.Fatalf("бэкапа в каталоге ещё нет: %+v", s)
	}
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)
	s := e.u.State()
	if !s.CanRetry || !s.CanRestore || s.Status != nodeapi.AZStatusFailedLate {
		t.Fatalf("действия не предложены: %+v", s)
	}
	_, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{})
	var pre *PreflightError
	if !errors.As(err, &pre) || !strings.Contains(err.Error(), "failed_late") {
		t.Fatalf("новое обновление при failed_late: %v", err)
	}
}

// Повтор: тот же setup.sh и ответы, бэкап снова в /root, client.sh 8 не зовётся.
func TestAZRetryRunsSameSetupWithSavedBackup(t *testing.T) {
	e := newAZ(t)
	st := lateFailure(t, e)
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)

	e.ex.hold = make(chan struct{})
	got, err := e.u.Retry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != nodeapi.AZStatusRunning || got.Retries != 1 || got.Backup != st.Backup || got.Commit != st.Commit {
		t.Fatalf("%+v", got)
	}
	calls := waitCalls(e, "azretry")
	if len(calls) != 1 {
		t.Fatalf("вызовов повтора: %d", len(calls))
	}
	joined := strings.Join(calls[0], "\n")
	for _, want := range []string{
		"--setenv=OPENVPN_PATCH=3", "--setenv=HOME=/root",
		filepath.Join(e.rootDir, st.Backup), filepath.Join(e.backup, st.Backup),
		filepath.Join(e.data, "azupdate", "setup.sh"), filepath.Join(e.data, "azupdate", "stdin"),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("в вызове повтора нет %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, `client.sh" 8`) {
		t.Error("повтор не должен снимать новый бэкап: client.sh 8 снял бы копию с разрушенного узла")
	}
	in, _ := os.ReadFile(filepath.Join(e.data, "azupdate", "stdin"))
	if string(in) != "1380\nvpn.example.com\n\n" {
		t.Fatalf("ответы повтора: %q", in)
	}
	// Идёт — вторым повтором и новым обновлением не занять.
	if _, err := e.u.Retry(context.Background()); err == nil {
		t.Fatal("второй повтор принят")
	}

	// Узел перезагрузился, установка дошла до конца: итог ok, счётчик повторов виден.
	e.reboot()
	e.ex.release(t)
	e.u.Resume()
	done := e.waitStatus(nodeapi.AZStatusOK)
	if done.Retries != 1 || done.CanRetry {
		t.Fatalf("%+v", done)
	}
}

// Повтор, отказавший ещё на проверках setup.sh, не снимает failed_late: узел
// по-прежнему сломан прошлым заходом.
func TestAZRetryEarlyFailureStaysLate(t *testing.T) {
	e := newAZ(t)
	st := lateFailure(t, e)
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)
	e.ex.codes["azretry"] = 2
	e.ex.output["azretry"] = "Error: You need to reboot this server before installation!\n"
	if _, err := e.u.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := e.waitStatus(nodeapi.AZStatusFailedLate)
	if got.Retries != 1 || !strings.Contains(strings.Join(got.Reasons, "|"), "завершилась с кодом 2") {
		t.Fatalf("%+v", got)
	}
	if s := e.u.State(); !s.CanRetry || !s.CanRestore {
		t.Fatalf("действия пропали: %+v", s)
	}
}

func TestAZRetryRefusals(t *testing.T) {
	e := newAZ(t)
	var pre *PreflightError
	if _, err := e.u.Retry(context.Background()); !errors.As(err, &pre) {
		t.Fatalf("повторять нечего: %v", err)
	}
	st := lateFailure(t, e)
	// Бэкапа в каталоге нет.
	if _, err := e.u.Retry(context.Background()); !errors.As(err, &pre) || !strings.Contains(err.Error(), "бэкап") {
		t.Fatalf("без бэкапа: %v", err)
	}
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)
	// Серверу нужна перезагрузка: setup.sh откажется (код 2), повтор не запускается.
	e.exists["/var/run/reboot-required"] = true
	if _, err := e.u.Retry(context.Background()); !errors.As(err, &pre) || !strings.Contains(err.Error(), "перезагрузка") {
		t.Fatalf("reboot-required: %v", err)
	}
}

// Ранний отказ — только ошибка: ничего не тронуто, действий нет, новое
// обновление не закрыто.
func TestAZEarlyFailureHasNoActions(t *testing.T) {
	e := newAZ(t)
	e.ex.codes["azupdate"] = 3
	e.ex.output["azupdate"] = "Error: You need to run this as root!\n"
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	st := e.waitStatus(nodeapi.AZStatusFailed)
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)
	if s := e.u.State(); s.CanRestore || s.CanRetry {
		t.Fatalf("%+v", s)
	}
	if r := e.u.lateBlock(); r != "" {
		t.Fatalf("ранний отказ закрыл новое обновление: %s", r)
	}
	if p := e.u.Preflight(); !p.OK {
		t.Fatalf("после раннего отказа обновление должно быть доступно: %+v", p)
	}
}

// Установка прошла, проверка после перезагрузки нет: восстановить можно,
// повторять установку незачем.
func TestAZVerifyFailureOffersRestoreOnly(t *testing.T) {
	e := newAZ(t)
	e.setServices(azServices("kresd@1"))
	e.startAndReboot()
	st := e.waitStatus(nodeapi.AZStatusFailed)
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)
	if s := e.u.State(); !s.CanRestore || s.CanRetry {
		t.Fatalf("%+v", s)
	}
}

// Начало setup.sh в журнале ищется по всему файлу, а не по хвосту в 64 КБ.
func TestAZLateDetectedWhenMarkerFarFromTail(t *testing.T) {
	e := newAZ(t)
	e.ex.output["azupdate"] = "Installation, please wait...\n" + strings.Repeat("apt: Get:1 http://deb.debian.org/ x\n", 4000)
	e.ex.codes["azupdate"] = 100
	if _, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	e.waitStatus(nodeapi.AZStatusFailedLate)
}

// Коммит принимается только из истории main: архив по sha отдаёт и объекты форков.
func TestAZStartCommitMustBeInMain(t *testing.T) {
	e := newAZ(t)
	var pre *PreflightError
	for _, bad := range []string{azForkSHA, strings.Repeat("9", 40), "не sha"} {
		_, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{Commit: bad})
		if !errors.As(err, &pre) || !pre.BadRequest {
			t.Errorf("коммит %q: %v", bad, err)
		}
	}
	if e.u.Active() {
		t.Fatal("после отказа состояние «идёт»")
	}
	for _, good := range []string{azHead, azOldMain} {
		e2 := newAZ(t)
		e2.ex.hold = make(chan struct{})
		st, err := e2.u.Start(context.Background(), nodeapi.AZUpdateRequest{Commit: good})
		if err != nil || st.Commit != good {
			t.Errorf("коммит main %s: %+v %v", good[:7], st, err)
		}
		close(e2.ex.hold)
	}
}

// Скрипт upstream с другим набором вопросов не запускается: его вопрос остался бы без ответа.
func TestAZStartRefusesChangedSetupSh(t *testing.T) {
	e := newAZ(t)
	real := e.u.Download
	e.u.Download = func(ctx context.Context, sha, dest string) error {
		if err := real(ctx, sha, dest); err != nil {
			return err
		}
		data, _ := os.ReadFile(dest)
		mod := strings.Replace(string(data), `until [[ "$ROUTE_ALL" =~ (y|n) ]]`, `until [[ "$ROUTE_ALL" =~ (y|n|a) ]]`, 1)
		if mod == string(data) {
			t.Fatal("подмена вопроса не сработала")
		}
		return os.WriteFile(dest, []byte(mod), 0o700)
	}
	_, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{})
	var pre *PreflightError
	if !errors.As(err, &pre) || !strings.Contains(err.Error(), "setup.sh изменился, обновите azpanel") || !strings.Contains(err.Error(), "ROUTE_ALL") {
		t.Fatalf("%v", err)
	}
	if e.u.Active() || len(e.ex.callsFor("azupdate")) != 0 {
		t.Fatal("задача запущена несмотря на отказ")
	}
}

// Сеть идёт до замка операций: замок берётся только на запуск, и занятый замок — 409.
func TestAZStartTakesGateAfterNetwork(t *testing.T) {
	e := newAZ(t)
	downloaded := false
	real := e.u.Download
	e.u.Download = func(ctx context.Context, sha, dest string) error { downloaded = true; return real(ctx, sha, dest) }
	e.u.Gate = func() (func(), bool) {
		if !downloaded {
			t.Error("замок взят раньше, чем скачан setup.sh")
		}
		return nil, false
	}
	_, err := e.u.Start(context.Background(), nodeapi.AZUpdateRequest{})
	var pre *PreflightError
	if !errors.As(err, &pre) || !pre.Busy {
		t.Fatalf("занятый замок должен дать «занято»: %v", err)
	}
	if e.u.Active() {
		t.Fatal("состояние «идёт» при отказе")
	}
}

func TestAZRetryAPI(t *testing.T) {
	e := newAPI(t)
	az := newAZ(t)
	e.api.AZ = az.u
	e.api.AZVersion = az.u.Version
	e.api.Tasks = az.u.Tasks
	ctx := context.Background()
	if _, err := e.client.AZRetry(ctx); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("повтор без failed_late: %v", err)
	}
	if _, err := e.client.AZUpdate(ctx, nodeapi.AZUpdateRequest{Commit: azForkSHA}); status(err) != http.StatusBadRequest {
		t.Fatalf("чужой коммит: %v", err)
	}
	st := lateFailure(t, az)
	os.WriteFile(filepath.Join(az.backup, st.Backup), []byte("tgz"), 0o600)
	az.ex.hold = make(chan struct{})
	defer close(az.ex.hold)
	got, err := e.client.AZRetry(ctx)
	if err != nil || got.Status != nodeapi.AZStatusRunning || got.Retries != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

// waitCalls ждёт вызова подменного systemd-run: задача запускает его в
// горутине, и сразу после Start/Retry вызова может ещё не быть.
func waitCalls(e *azEnv, name string) [][]string {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c := e.ex.callsFor(name); len(c) > 0 {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// Повтор и восстановление тоже ждут замка операций над клиентами: client.sh
// пишет те же PKI и конфиги WireGuard.
func TestAZRetryAndRestoreTakeGate(t *testing.T) {
	busy := func() (func(), bool) { return nil, false }
	var pre *PreflightError

	e := newAZ(t)
	st := lateFailure(t, e)
	os.WriteFile(filepath.Join(e.backup, st.Backup), []byte("tgz"), 0o600)
	e.u.Gate = busy
	if _, err := e.u.Retry(context.Background()); !errors.As(err, &pre) || !pre.Busy {
		t.Fatalf("повтор при занятом замке: %v", err)
	}
	if got := e.u.State(); got.Status != nodeapi.AZStatusFailedLate {
		t.Fatalf("состояние после отказа повтора: %+v", got)
	}

	e = newAZ(t)
	name := "backup-azpanel-2026-11-02-101500.tar.gz"
	os.WriteFile(filepath.Join(e.backup, name), []byte("tgz"), 0o600)
	e.u.Gate = busy
	if _, err := e.u.Restore(context.Background(), name); !errors.As(err, &pre) || !pre.Busy {
		t.Fatalf("восстановление при занятом замке: %v", err)
	}
	if e.u.Active() {
		t.Fatal("состояние «идёт» при отказе")
	}
}
