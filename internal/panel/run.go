package panel

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/logx"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

// Run — режим «azpanel panel». Секреты (токен агента, хеш пароля) читаются
// один раз при старте; после azpanel panel passwd панель перезапускают.
func Run(ctx context.Context, cfg config.Config, version string) error {
	w, err := logx.Open(filepath.Join(paths.Log(), "panel.log"), int64(cfg.Log.MaxSizeMB)<<20, cfg.Log.Keep)
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
		return errors.New("нет NODE_TOKEN в secrets.env: переустановите узел")
	}
	user := sec[SecretAdminUser]
	if user == "" {
		user = "admin"
	}
	hash := sec[SecretAdminHash]
	if hash == "" {
		log.Warn("пароль администратора не задан — вход невозможен; задайте: azpanel panel passwd")
	}

	s := &Server{
		Node:      nodeapi.New(cfg.Panel.NodeURL, token),
		AdminUser: user,
		AdminHash: hash,
		Version:   version,
		Sessions:  NewSessions(time.Duration(cfg.Panel.SessionHours) * time.Hour),
		Limiter:   NewLimiter(),
		Log:       log,
	}
	ln, err := net.Listen("tcp", cfg.Panel.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Запрос к агенту может ждать мьютекс client.sh целый таймаут, поэтому 2×.
		WriteTimeout: 2*time.Duration(cfg.Node.ClientShTimeoutS)*time.Second + time.Minute,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Info("панель запущена", "listen", cfg.Panel.Listen, "user", user)

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(sctx)
	log.Info("панель остановлена")
	return err
}
