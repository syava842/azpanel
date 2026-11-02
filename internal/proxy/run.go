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
	ln, err := net.Listen("tcp", cfg.Proxy.Listen)
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
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("прокси-агент запущен", "listen", cfg.Proxy.Listen, "version", version)
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
