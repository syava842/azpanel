//go:build linux

package warp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inst.sh")
	if err := os.WriteFile(p, []byte("#!/bin/bash\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func ptyDialog(log *bytes.Buffer, rules ...Rule) *Dialog {
	return &Dialog{Rules: rules, Log: log, Quiet: 50 * time.Millisecond, Unknown: time.Second, Stall: 20 * time.Second}
}

// Настоящий bash читает ответы с /dev/tty, как install.sh AZ-WARP.
func TestRunPTYAnswersTTYReads(t *testing.T) {
	script := writeScript(t, `
echo "старт"
read -r -p "Вопрос один? (Y/n): " a < /dev/tty
echo "a=[$a]"
read -r -s -p "Пароль: " b < /dev/tty; echo ""
echo "b=[$b]"
[ "$a" = "yes" ] && [ "$b" = "S3CRET" ] || exit 7
exit 0
`)
	var log bytes.Buffer
	d := ptyDialog(&log,
		Rule{Name: "one", Prompt: regexp.MustCompile(`Вопрос один\? \(Y/n\):\s*$`), Answer: fixed("yes")},
		Rule{Name: "pass", Prompt: regexp.MustCompile(`Пароль:\s*$`), Secret: true, Answer: fixed("S3CRET")},
	)
	d.Secrets = []string{"S3CRET"}
	if err := RunPTY(context.Background(), d, "/bin/bash", script); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if strings.Contains(log.String(), "S3CRET") {
		t.Fatalf("секрет в журнале:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "a=[yes]") {
		t.Fatalf("журнал:\n%s", log.String())
	}
}

func TestRunPTYUnknownPromptKillsInstaller(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "after")
	script := writeScript(t, `
read -r -p "Неожиданный вопрос? [y/N]: " a < /dev/tty
touch `+marker+`
`)
	var log bytes.Buffer
	err := RunPTY(context.Background(), ptyDialog(&log), "/bin/bash", script)
	if !errors.Is(err, ErrUnknownPrompt) {
		t.Fatalf("err=%v\n%s", err, log.String())
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("установщик продолжил работу после неизвестного вопроса")
	}
}

func TestRunPTYNonZeroExit(t *testing.T) {
	script := writeScript(t, "echo плохо\nexit 5\n")
	var log bytes.Buffer
	err := RunPTY(context.Background(), ptyDialog(&log), "/bin/bash", script)
	if err == nil || !strings.Contains(err.Error(), "кодом 5") {
		t.Fatalf("err=%v", err)
	}
}
