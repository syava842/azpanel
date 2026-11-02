package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/logx"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/sysinfo"
)

// Run — режим «azpanel proxy»: API агента прокси, пока не отменён ctx.
// Токен — NODE_TOKEN из secrets.env, как у агента узла.
func Run(ctx context.Context, cfg config.Config, version string) error {
	w, err := logx.Open(filepath.Join(paths.Log(), "proxy.log"), int64(cfg.Log.MaxSizeMB)<<20, cfg.Log.Keep)
	if err != nil {
		return err
	}
	defer w.Close()
	log := logx.New(w)

	sec, err := secrets.Load(paths.SecretsFile())
	if err != nil {
		return err
	}
	token := sec[secrets.NodeToken]
	if token == "" {
		return errors.New("в secrets.env нет NODE_TOKEN — его создаёт azpanel install")
	}
	if b, err := hex.DecodeString(token); err != nil || len(b) != 32 {
		return errors.New("NODE_TOKEN в secrets.env не 64 hex-символа — удалите строку и повторите azpanel install")
	}
	api := &API{
		Token: token, Version: version,
		Apply:     &Applier{Save: ExecSave, Restore: ExecRestore, Persist: ExecPersist, Log: log},
		Conntrack: ProcConntrack("/proc/net/nf_conntrack"),
		Sampler:   &sysinfo.Sampler{Proc: "/proc", DiskPath: "/"},
		Log:       log,
		Now:       time.Now,
	}
	lns, err := listen(cfg.Proxy, log)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Смена адреса — три команды iptables по 15 секунд, плюс откат.
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  time.Minute,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, len(lns))
	for _, ln := range lns {
		go func() { errc <- srv.Serve(ln) }()
	}
	log.Info("прокси-агент запущен", "listen", cfg.Proxy.Listen, "listen_tls", cfg.Proxy.ListenTLS, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
	log.Info("прокси-агент остановлен")
	return nil
}

// listen открывает порты агента прокси: петлевой и/или внешний по TLS с белым
// списком IP до рукопожатия (сертификат etc/tls/node.{crt,key}, как у узла).
func listen(p config.Proxy, log *slog.Logger) ([]net.Listener, error) {
	var lns []net.Listener
	if p.Listen != "" {
		ln, err := net.Listen("tcp", p.Listen)
		if err != nil {
			return nil, err
		}
		lns = append(lns, ln)
	}
	if p.ListenTLS != "" {
		allow, err := config.ParseAllowIPs(p.AllowIPs)
		if err == nil {
			var ln net.Listener
			var fp string
			ln, fp, err = agenttls.Listen(p.ListenTLS, filepath.Join(paths.Etc(), "tls"), allow, func(remote string) {
				log.Warn("TLS-порт: адрес вне белого списка закрыт до рукопожатия", "remote", remote)
			})
			if err == nil {
				lns = append(lns, ln)
				log.Info("TLS-порт прокси-агента открыт", "listen", p.ListenTLS, "fingerprint", agenttls.FormatFingerprint(fp))
			}
		}
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return nil, err
		}
	}
	return lns, nil
}
