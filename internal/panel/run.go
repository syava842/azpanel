package panel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/logx"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/update"
)

// Run — режим «azpanel panel». Секреты (токен агента, ключ данных) читаются
// один раз при старте. Хеш пароля из secrets.env нужен только для переноса
// администратора в базу, пока в ней нет ни одного пользователя.
func Run(ctx context.Context, cfg config.Config, version string) error {
	// stop — «перезапуск» из настроек: панель завершается, systemd поднимает её
	// заново (Restart=always).
	ctx, stop := context.WithCancel(ctx)
	defer stop()
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
	st, err := store.Open(filepath.Join(paths.Data(), "azpanel.db"))
	if err != nil {
		return fmt.Errorf("база панели: %w", err)
	}
	defer st.Close()
	dataKey, err := loadOrCreateDataKey(paths.SecretsFile(), sec, log)
	if err != nil {
		return err
	}
	if err := recoverDataKey(ctx, st, paths.SecretsFile(), sec, dataKey, log); err != nil {
		return err
	}
	if err := migrateAdmin(ctx, st, sec, time.Now(), log); err != nil {
		return err
	}
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
	tgToken := sec[secrets.TelegramBotToken]
	// Отложенное (бот, уведомления, проверка обновлений azpanel, сверка групп)
	// работает только при panel.experimental.
	exp := cfg.Panel.Experimental
	botOn := exp && cfg.Telegram.Enabled && tgToken != ""
	if botOn {
		col.Alerts = &cfg.Telegram
	} else if exp && cfg.Telegram.Enabled {
		log.Warn("telegram.enabled включён, но в secrets.env нет TELEGRAM_BOT_TOKEN — бот не запущен")
	}
	// Проверка обновлений azpanel раз в 6 часов. Токен GitHub читается из
	// secrets.env при каждой проверке; без него (и в сборке dev) проверка
	// выключена, страница «Обновление» объясняет причину.
	var s *Server
	checker := &update.Checker{
		Current: version,
		Token:   func() string { return s.UpdateToken() },
		Log:     log,
	}
	if botOn {
		checker.OnAvailable = func(i update.Info) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := notifyUpdateAvailable(ctx, st, &cfg.Telegram, time.Now(), i); err != nil {
				log.Warn("уведомление azpanel_update не поставлено в очередь", "err", err)
			}
		}
	}
	s = &Server{
		Node:      node,
		Svc:       node,
		Store:     st,
		NodeID:    store.LocalNode,
		Collector: col,
		Geo:       geo,
		Version:   version,
		Limiter:   NewLimiter(),
		Log:       log,

		SessionTTL:      time.Duration(cfg.Panel.SessionHours) * time.Hour,
		DataKey:         dataKey,
		RequireAdmin2FA: cfg.Panel.RequireAdmin2FA,
		ConfigFile:      paths.ConfigFile(),
		PublicURL:       cfg.Panel.PublicURL,
		BasePath:        cfg.Panel.BasePath,
		SecretsFile:     paths.SecretsFile(),
		Exit:            stop,
		Experimental:    exp,
		RestartNode: func(ctx context.Context) error {
			return restartNodeHTTP(ctx, cfg.Panel.NodeURL, token, sec[NodeFingerprintKey])
		},
		SyncNginx:  nginxSyncVia(node),
		CheckNginx: nginxCheckVia(node),
	}
	proxies, err := config.ParseTrustedProxies(cfg.Panel.TrustedProxies)
	if err != nil {
		return fmt.Errorf("panel.trusted_proxies: %w", err)
	}
	s.TrustedProxies = proxies
	if exp {
		s.Updates = checker
	}
	if err := s.SeedAllow(cfg.Panel.AllowIPs); err != nil {
		return fmt.Errorf("panel.allow_ips: %w", err)
	}
	// Перезапуск в середине таймера возврата не отменяет его: просроченное
	// изменение откатывается до того, как панель начнёт принимать запросы.
	s.CheckPending(ctx)
	ln, err := listen("tcp", cfg.Panel.Listen)
	if err != nil {
		return err
	}
	// Фоновые задачи стартуют только после занятия порта: при занятом порте
	// сборщик не должен успеть сделать проход (в нём срабатывают автоблокировки).
	// defer срабатывают в обратном порядке: сначала сборщик останавливается
	// и его ждут, и только потом закрываются геоданные и база.
	cctx, stopCollector := context.WithCancel(ctx)
	var colDone sync.WaitGroup
	colDone.Add(1)
	go func() { defer colDone.Done(); s.RunCollectors(cctx, col) }()
	colDone.Add(1)
	go func() { defer colDone.Done(); purgeSessionsLoop(cctx, st, purgeEvery, log) }()
	colDone.Add(1)
	go func() { defer colDone.Done(); s.PendingLoop(cctx, pendingCheckEvery) }()
	if botOn {
		s.startBot(cctx, &colDone, cfg, tgToken, node, log)
		// Уведомления об обновлениях: новые коммиты AntiZapret, итоги обновлений.
		wt := &Watcher{Node: node, Store: st, Alerts: &cfg.Telegram, Log: log}
		colDone.Add(1)
		go func() { defer colDone.Done(); wt.Run(cctx) }()
	}
	if exp {
		// Сверка групп синхронизации (после запуска бота: уведомления берут его настройки).
		colDone.Add(1)
		go func() { defer colDone.Done(); s.RunGroupWatch(cctx) }()
		if update.IsDev(version) {
			log.Info("проверка обновлений выключена: сборка без версии (dev)")
		} else if s.UpdateToken() == "" {
			log.Info("проверка обновлений выключена: нет " + update.TokenKey + " в secrets.env")
		}
		colDone.Add(1)
		go func() { defer colDone.Done(); checker.Run(cctx) }()
	}
	defer func() { stopCollector(); colDone.Wait() }()
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
	log.Info("панель запущена", "listen", cfg.Panel.Listen)

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

// nginxSnippetUpdater — то, чем панель просит агента переписать фрагмент nginx;
// *nodeapi.HTTPClient подходит. Сама панель в /etc/nginx не пишет: у неё нет прав.
type nginxSnippetUpdater interface {
	UpdateNginxSnippet(ctx context.Context, req nodeapi.NginxSnippetRequest) (nodeapi.NginxSnippetResult, error)
}

// nginxSyncVia — Server.SyncNginx через агента: он запускает задачу
// nginx-snippet (копия, nginx -t, откат, reload), её итог виден в «Задачах».
// done=false — фрагмента панели в nginx нет, ничего не запущено.
func nginxSyncVia(n nginxSnippetUpdater) func(basePath, listen string) (bool, error) {
	return func(basePath, listen string) (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, err := n.UpdateNginxSnippet(ctx, nodeapi.NginxSnippetRequest{BasePath: basePath, Upstream: listen})
		if err != nil {
			var ne *nodeapi.Error
			if errors.As(err, &ne) {
				return false, errors.New(ne.Message)
			}
			return false, err
		}
		return res.Done, nil
	}
}

// listen — занятие порта; в тестах подменяется.
var listen = net.Listen

const purgeEvery = time.Hour

// loadOrCreateDataKey: ключ шифрования секретов 2FA — 32 байта в hex в
// PANEL_DATA_KEY. Нет ключа — создаётся и записывается в secrets.env.
// Испорченный ключ — отказ запускаться: молча заменить его значит потерять
// все секреты 2FA.
func loadOrCreateDataKey(file string, sec map[string]string, log *slog.Logger) ([]byte, error) {
	if v := sec[SecretDataKey]; v != "" {
		key, err := hex.DecodeString(v)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("%s в secrets.env должен быть 64 шестнадцатеричными знаками (32 байта)", SecretDataKey)
		}
		return key, nil
	}
	v, err := secrets.NewToken()
	if err != nil {
		return nil, err
	}
	if err := secrets.Set(file, SecretDataKey, v); err != nil {
		return nil, fmt.Errorf("ключ данных не записан: %w", err)
	}
	log.Info("создан ключ шифрования секретов 2FA", "ключ", SecretDataKey)
	return hex.DecodeString(v)
}

// migrateAdmin: в базе нет ни одного пользователя, а в secrets.env есть хеш
// администратора — создаёт администратора с этим логином и хешем.
func migrateAdmin(ctx context.Context, st *store.Store, sec map[string]string, now time.Time, log *slog.Logger) error {
	us, err := st.Users(ctx)
	if err != nil {
		return fmt.Errorf("пользователи панели: %w", err)
	}
	if len(us) > 0 {
		return nil
	}
	hash := sec[SecretAdminHash]
	if hash == "" {
		log.Warn("в панели нет пользователей и пароль администратора не задан — вход невозможен; задайте: azpanel panel passwd")
		return nil
	}
	login := strings.ToLower(sec[SecretAdminUser])
	if login == "" {
		login = "admin"
	}
	if _, err := st.CreateUser(ctx, store.User{Login: login, Hash: hash, Role: store.RoleAdmin, Created: now.Unix()}); err != nil {
		return fmt.Errorf("перенос администратора: %w", err)
	}
	log.Info("перенесён администратор из secrets.env", "user", login)
	if err := st.Audit(ctx, store.AuditEntry{
		TS: now.Unix(), User: "система", Action: "user_migrate", Target: login,
		After: "перенесён администратор из secrets.env",
	}); err != nil {
		log.Warn("запись в журнал действий не удалась", "action", "user_migrate", "err", err)
	}
	return nil
}

// purgeSessionsLoop раз в every удаляет истёкшие сессии (и сразу при старте).
func purgeSessionsLoop(ctx context.Context, st *store.Store, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := st.PurgeExpiredSessions(ctx, time.Now().Unix()); err != nil && ctx.Err() == nil {
			log.Warn("истёкшие сессии не удалены", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// nginxCheckVia — Server.CheckNginx через агента: запрос с check=true ничего не
// запускает. Отказ — только явный 400 агента; недоступный агент проверку
// пропускает, чтобы не запирать настройки.
func nginxCheckVia(n nginxSnippetUpdater) func(basePath, listen string) error {
	return func(basePath, listen string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err := n.UpdateNginxSnippet(ctx, nodeapi.NginxSnippetRequest{BasePath: basePath, Upstream: listen, Check: true})
		var ne *nodeapi.Error
		if errors.As(err, &ne) && ne.Status == http.StatusBadRequest {
			return errors.New(ne.Message)
		}
		return nil
	}
}
