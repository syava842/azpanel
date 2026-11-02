package warp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// InstallerURL — установщик AZ-WARP (ветка main).
const InstallerURL = "https://raw.githubusercontent.com/Liafanx/AZ-WARP/main/install.sh"

const maxInstaller = 2 << 20

// FetchInstaller скачивает install.sh в dst (0700) и возвращает его SHA-256 для
// журнала. Файл обязан быть скриптом bash: страница ошибки вместо скрипта
// запускаться не должна.
func FetchInstaller(ctx context.Context, client *http.Client, url, dst string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	if url == "" {
		url = InstallerURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("install.sh не скачан: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("install.sh не скачан: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxInstaller+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxInstaller {
		return "", errors.New("install.sh больше 2 МБ — отказ")
	}
	if !strings.HasPrefix(string(data), "#!/bin/bash") {
		return "", errors.New("скачанный install.sh не похож на скрипт bash — отказ")
	}
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Install скачивает установщик и проводит его диалог под псевдотерминалом.
// Вывод установщика (без секретов) пишется в log.
func Install(ctx context.Context, a InstallAnswers, client *http.Client, workDir string, log io.Writer) error {
	if err := a.Validate(); err != nil {
		return err
	}
	script, err := os.CreateTemp(workDir, "az-warp-install-*.sh")
	if err != nil {
		return err
	}
	script.Close()
	defer os.Remove(script.Name())
	sum, err := FetchInstaller(ctx, client, "", script.Name())
	if err != nil {
		return err
	}
	fmt.Fprintf(log, "install.sh AZ-WARP скачан, sha256 %s\n", sum)
	return RunPTY(ctx, a.NewDialog(log), "/bin/bash", script.Name())
}
