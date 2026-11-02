package panel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/logx"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
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

	st, err := store.Open(filepath.Join(paths.Data(), "azpanel.db"))
	if err != nil {
		return fmt.Errorf("база панели: %w", err)
	}
	defer st.Close()
	geo, err := OpenGeo(paths.Data())
	if err != nil {
		log.Warn("геоданные не открыты — работаем без города и провайдера", "err", err)
		geo = nil
	}
	defer geo.Close()

	node := nodeapi.New(cfg.Panel.NodeURL, token)
	col := &Collector{
		Node:        node,
		Store:       st,
		NodeID:      store.LocalNode,
		Every:       time.Duration(cfg.Panel.CollectSeconds) * time.Second,
		HistoryDays: cfg.Panel.HistoryDays,
		Log:         log,
	}
	// defer срабатывают в обратном порядке: сначала сборщик останавливается
	// и его ждут, и только потом закрываются геоданные и база.
	cctx, stopCollector := context.WithCancel(ctx)
	var colDone sync.WaitGroup
	colDone.Add(1)
	go func() { defer colDone.Done(); col.Run(cctx) }()
	defer func() { stopCollector(); colDone.Wait() }()

	s := &Server{
		Node:      node,
		Store:     st,
		NodeID:    store.LocalNode,
		Collector: col,
		Geo:       geo,
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
