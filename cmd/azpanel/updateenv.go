package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/syava842/azpanel/internal/agenttls"
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
	proxyUnit  = "azpanel-proxy"
)

// tlsCertDir — каталог собственного сертификата агента (etc/tls); тесты
// подменяют.
var tlsCertDir = func() string { return filepath.Join(paths.Etc(), "tls") }

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
	for _, u := range []string{nodeUnit, panelUnit, proxyUnit} {
		if unitInstalled(u) {
			env.Units = append(env.Units, u)
		}
	}
	env.Checks = healthChecks(cfg, sec[secrets.NodeToken], env.Units)
	// Агент, доступный только по TLS, проверяется «вполсилы» (см. tlsInfoCheck):
	// версию установленного бинарника проверяем отдельно.
	env.VersionCheck = (cfg.Node.APIListen == "" && cfg.Node.ListenTLS != "" && contains(env.Units, nodeUnit)) ||
		(cfg.Proxy.Listen == "" && cfg.Proxy.ListenTLS != "" && contains(env.Units, proxyUnit))
	return env, nil
}

func unitInstalled(name string) bool {
	_, err := os.Stat(filepath.Join(systemdDir, name+".service"))
	return err == nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// healthChecks: /healthz панели (с префиксом panel.base_path), /v1/info агента
// узла и агента прокси с новой версией. Службы хоста — в units. Узел с одним
// только TLS проверяется через listen_tls с закреплением собственного
// сертификата.
func healthChecks(cfg config.Config, token string, units []string) []update.Check {
	var checks []update.Check
	if contains(units, panelUnit) && cfg.Panel.Listen != "" {
		checks = append(checks, panelHealthCheck(cfg.Panel.Listen, cfg.Panel.BasePath))
	}
	if contains(units, nodeUnit) && token != "" {
		if c := agentInfoCheck("агента", cfg.Node.APIListen, cfg.Node.ListenTLS, token); c != nil {
			checks = append(checks, c)
		}
	}
	if contains(units, proxyUnit) && token != "" {
		if c := agentInfoCheck("прокси-агента", cfg.Proxy.Listen, cfg.Proxy.ListenTLS, token); c != nil {
			checks = append(checks, c)
		}
	}
	return checks
}

// panelHealthCheck — GET /healthz панели. Панель за префиксом отвечает 404 на
// путь без него, поэтому префикс обязателен в адресе проверки.
func panelHealthCheck(listen, basePath string) update.Check {
	prefix := ""
	if t := strings.Trim(basePath, "/"); t != "" {
		prefix = "/" + t
	}
	url := "http://" + listen + prefix + "/healthz"
	hc := &http.Client{Timeout: 3 * time.Second}
	return func(ctx context.Context, _ string) error {
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
	}
}

// agentInfoCheck — /v1/info агента с новой версией по петлевому адресу, а если
// его нет — по listen_tls. Нет ни того ни другого — проверки нет (nil).
func agentInfoCheck(what, listen, listenTLS, token string) update.Check {
	switch {
	case listen != "":
		cl := nodeapi.New("http://"+listen, token)
		cl.HTTP = &http.Client{Timeout: 3 * time.Second}
		return infoCheck(what, cl)
	case listenTLS != "":
		return tlsInfoCheck(what, listenTLS, token)
	}
	return nil
}

func infoCheck(what string, cl *nodeapi.HTTPClient) update.Check {
	return func(ctx context.Context, newVersion string) error {
		info, err := cl.Info(ctx)
		if err != nil {
			return fmt.Errorf("/v1/info %s: %w", what, err)
		}
		if info.Version != newVersion {
			return fmt.Errorf("%s отвечает версией %q, ждали %q", what, info.Version, newVersion)
		}
		return nil
	}
}

// tlsInfoCheck проверяет агента, у которого есть только внешний TLS-порт:
// https с собственным сертификатом (отпечаток из etc/tls/node.crt). Белый
// список IP может не содержать адрес самого хоста: тогда агент закрывает
// соединение до рукопожатия, и версию по сети не проверить — порт при этом
// принимает соединения, что и засчитывается, а версию подтверждает проверка
// бинарника (Env.VersionCheck). Несовпадение отпечатка и отказ в соединении
// засчитываются как «не готов».
func tlsInfoCheck(what, listenTLS, token string) update.Check {
	return func(ctx context.Context, newVersion string) error {
		fp, err := agenttls.FingerprintFile(filepath.Join(tlsCertDir(), agenttls.CertFile))
		if err != nil {
			return fmt.Errorf("сертификат %s не прочитан: %w", what, err)
		}
		cl, err := nodeapi.NewPinned("https://"+selfDialAddr(listenTLS), token, fp)
		if err != nil {
			return err
		}
		cl.HTTP.Timeout = 3 * time.Second
		info, err := cl.Info(ctx)
		switch {
		case err == nil:
			if info.Version != newVersion {
				return fmt.Errorf("%s отвечает версией %q, ждали %q", what, info.Version, newVersion)
			}
			return nil
		case connDropped(err):
			// Порт принял соединение и закрыл его: адрес хоста вне allow_ips.
			return nil
		}
		return fmt.Errorf("/v1/info %s по TLS: %w", what, err)
	}
}

// selfDialAddr — адрес, по которому с этого хоста достать слушающий порт.
func selfDialAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// connDropped — сервер оборвал соединение до ответа (закрыто белым списком).
// Текст проверяется ради Windows, где ошибка сокета не сводится к errno
// пакета syscall.
func connDropped(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection was aborted") || strings.Contains(msg, "aborted by the software") ||
		strings.Contains(msg, "connection aborted")
}
