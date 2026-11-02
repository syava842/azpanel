package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/update"
)

const (
	systemdDir = "/etc/systemd/system"
	nodeUnit   = "azpanel-node"
	panelUnit  = "azpanel-panel"
)

// hostUpdateEnv — окружение обновления на этом хосте: какие службы стоят,
// чем проверять живость, как снимать базу.
func hostUpdateEnv(out io.Writer) (*update.Env, error) {
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return nil, err
	}
	sec, err := secrets.Load(paths.SecretsFile())
	if err != nil {
		return nil, err
	}
	env := &update.Env{
		Root: paths.Root(), Version: version, Pub: update.ReleasePublicKey, Log: out,
		BackupDB: func(ctx context.Context, src, dst string) error {
			st, err := store.Open(src)
			if err != nil {
				return err
			}
			defer st.Close()
			return st.Backup(ctx, dst)
		},
	}
	hasPanel := unitInstalled(panelUnit)
	if unitInstalled(nodeUnit) {
		env.Units = append(env.Units, nodeUnit)
	}
	if hasPanel {
		env.Units = append(env.Units, panelUnit)
	}
	env.Checks = healthChecks(cfg, sec[secrets.NodeToken], hasPanel, env.Units)
	return env, nil
}

func unitInstalled(name string) bool {
	_, err := os.Stat(filepath.Join(systemdDir, name+".service"))
	return err == nil
}

// healthChecks: /healthz панели (если она на этом хосте) и /v1/info агента
// с новой версией.
func healthChecks(cfg config.Config, nodeToken string, hasPanel bool, units []string) []update.Check {
	var checks []update.Check
	hasNode := false
	for _, u := range units {
		hasNode = hasNode || u == nodeUnit
	}
	if hasPanel && cfg.Panel.Listen != "" {
		hc := &http.Client{Timeout: 3 * time.Second}
		url := "http://" + cfg.Panel.Listen + "/healthz"
		checks = append(checks, func(ctx context.Context, _ string) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := hc.Do(req)
			if err != nil {
				return fmt.Errorf("/healthz панели: %w", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("/healthz панели: ответ %d", resp.StatusCode)
			}
			return nil
		})
	}
	if hasNode && cfg.Node.APIListen != "" && nodeToken != "" {
		cl := nodeapi.New("http://"+cfg.Node.APIListen, nodeToken)
		cl.HTTP = &http.Client{Timeout: 3 * time.Second}
		checks = append(checks, func(ctx context.Context, newVersion string) error {
			info, err := cl.Info(ctx)
			if err != nil {
				return fmt.Errorf("/v1/info агента: %w", err)
			}
			if info.Version != newVersion {
				return fmt.Errorf("агент отвечает версией %q, ждали %q", info.Version, newVersion)
			}
			return nil
		})
	}
	return checks
}
