package node

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/logx"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/sysinfo"
	"github.com/syava842/azpanel/internal/telemt"
	"github.com/syava842/azpanel/internal/warp"
)

// hookCheckEvery — как часто проверять, что хук на месте: повторный
// setup.sh AntiZapret стирает /etc/openvpn/server целиком.
const hookCheckEvery = time.Minute

// Run — режим «azpanel node». ensureHook ставит хук в скрипты OpenVPN и
// сообщает, было ли изменение.
func Run(ctx context.Context, cfg config.Config, version string, ensureHook func() (bool, error)) error {
	maxBytes := int64(cfg.Log.MaxSizeMB) << 20
	nodeW, err := logx.Open(filepath.Join(paths.Log(), "node.log"), maxBytes, cfg.Log.Keep)
	if err != nil {
		return err
	}
	defer nodeW.Close()
	hookW, err := logx.Open(filepath.Join(paths.Log(), "hook.log"), maxBytes, cfg.Log.Keep)
	if err != nil {
		return err
	}
	defer hookW.Close()
	log := logx.New(nodeW)

	checkHook := func() {
		changed, err := ensureHook()
		switch {
		case err != nil:
			log.Error("хук лимита не установлен", "err", err)
		case changed:
			log.Info("хук лимита установлен в скрипты OpenVPN", "dir", cfg.Node.OpenVPNScriptsDir)
		}
	}
	checkHook()

	denials := NewDenials(maxDenials)
	tr := NewTracker()
	p := &Poller{
		Dir:     cfg.Node.OpenVPNSocketDir,
		Timeout: time.Duration(cfg.Node.QueryTimeoutMs) * time.Millisecond,
		Tracker: tr,
		Log:     log,
		Now:     time.Now,
		Query:   antizapret.QueryStatus,
	}
	p.PollOnce() // до первого ответа хуку счётчики должны быть заполнены

	sock := paths.NodeSocket()
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return err
	}
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	// Хук работает от nobody; кого пускать, решает PeerChecker.
	if err := os.Chmod(sock, 0o666); err != nil {
		log.Warn("права на сокет агента не выставлены — хук может не достучаться", "err", err)
	}
	srv := &Server{
		Tracker: tr,
		Limits:  limits.NewStore(paths.LimitsFile()),
		HookLog: logx.New(hookW),
		Denials: denials,
		Log:     log,
		Now:     time.Now,
		Peer:    PeerChecker(),
	}
	go p.Run(ctx, time.Duration(cfg.Node.PollSeconds)*time.Second)
	if cfg.Node.APIListen != "" {
		stop, err := startAPI(ctx, cfg, version, tr, denials, log, ensureHook)
		if err != nil {
			log.Error("API агента не запущен — панель узел не увидит, хук работает", "err", err)
		} else {
			defer stop()
		}
	}
	go func() {
		tk := time.NewTicker(hookCheckEvery)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				ln.Close()
				return
			case <-tk.C:
				checkHook()
			}
		}
	}()
	log.Info("агент запущен", "socket", sock, "openvpn", cfg.Node.OpenVPNSocketDir)
	err = srv.Serve(ln)
	log.Info("агент остановлен")
	return err
}

// startAPI запускает HTTP API для панели. Его сбой не трогает хук: лимиты
// и блокировки работают и без API. При остановке службы systemd гасит и
// дочерние процессы — client.sh, запущенный в эту секунду, оборвётся.
func startAPI(ctx context.Context, cfg config.Config, version string, tr *Tracker, denials *Denials, log *slog.Logger, ensureHook func() (bool, error)) (func(), error) {
	sec, err := secrets.Load(paths.SecretsFile())
	if err != nil {
		return nil, err
	}
	token := sec[secrets.NodeToken]
	if token == "" {
		return nil, errors.New("в secrets.env нет NODE_TOKEN — его создаёт azpanel install")
	}
	if b, err := hex.DecodeString(token); err != nil || len(b) != 32 {
		return nil, errors.New("NODE_TOKEN в secrets.env не 64 hex-символа — удалите строку и повторите azpanel install")
	}
	n := cfg.Node
	tasks := &Tasks{
		Dir: n.AntiZapretDir, LogDir: filepath.Join(paths.Log(), "tasks"),
		StatePath: filepath.Join(paths.Data(), "tasks.json"), Log: log, Now: time.Now, Ctx: ctx,
	}
	if err := tasks.Load(); err != nil {
		log.Error("список задач не прочитан — задачи начаты заново", "err", err)
	}
	go tasks.RunRotation(ctx)
	routing := &antizapret.Routing{
		ConfigDir: filepath.Join(n.AntiZapretDir, "config"),
		Backups:   &antizapret.Backups{Dir: filepath.Join(paths.Backup(), "antizapret")},
	}
	az := &AZUpdater{
		Tasks: tasks, Dir: n.AntiZapretDir, RootDir: filepath.Dir(n.AntiZapretDir),
		DataDir: paths.Data(), BackupDir: paths.Backup(), Record: antizapret.InstalledFile{Path: filepath.Join(paths.Data(), "antizapret.json")},
		Inventory:  antizapret.Inventory{PKI: n.EasyRSAPKI, WireGuardDir: n.WireGuardDir},
		EnsureHook: ensureHook, Log: log, Now: time.Now,
	}
	az.GitHub = &antizapret.GitHub{}
	az.Version = &antizapret.VersionService{GitHub: az.GitHub, Dir: n.AntiZapretDir, Record: az.Record}
	// Пока идёт doall, parse.sh переписывает config/*.txt (sed -i) и может
	// затереть правку; setup читают doall и restart. Во время обновления
	// AntiZapret не правится ничего.
	routing.Busy = anyBusy(busyDuring(tasks, TaskDoall), azBusy(az))
	api := &API{
		Tasks:   tasks,
		Routing: routing,
		AZ:      az, AZVersion: az.Version,
		Setup: &antizapret.SetupFile{
			Path:    filepath.Join(n.AntiZapretDir, "setup"),
			Backups: routing.Backups,
			Busy:    anyBusy(busyDuring(tasks, TaskDoall, TaskRestart), azBusy(az)),
		},
		Token: token, Version: version, Tracker: tr, LimitsPath: paths.LimitsFile(),
		Inventory:     antizapret.Inventory{PKI: n.EasyRSAPKI, WireGuardDir: n.WireGuardDir},
		ClientSh:      &antizapret.ClientSh{Dir: n.AntiZapretDir, Timeout: time.Duration(n.ClientShTimeoutS) * time.Second},
		AntiZapretDir: n.AntiZapretDir,
		SocketDir:     n.OpenVPNSocketDir,
		Sampler:       &sysinfo.Sampler{Proc: "/proc", DiskPath: "/"},
		Denials:       denials,
		WGShow:        antizapret.WGShow,
		Kill:          antizapret.KillClient,
		WGCmd:         ExecWGCmd,
		Log:           log,
		Now:           time.Now,
	}
	// telemt и WARP: чтение — агентом, изменения — задачами `azpanel internal …`
	// вне песочницы (пишут в /etc/telemt, /usr/local/bin, /root/warper).
	paramsDir := filepath.Join(paths.Data(), "params")
	api.Telemt = &TelemtService{Env: telemt.NewEnv(), Self: paths.Binary(), ParamsDir: paramsDir}
	api.Warp = &WarpService{Warper: &warp.Warper{}, Self: paths.Binary(), ParamsDir: paramsDir}
	api.Services = func(ctx context.Context) ([]sysinfo.Service, error) {
		// systemctl может зависнуть (например, при перегруженном dbus).
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		kresd, err := sysinfo.KresdUnits(ctx)
		if err != nil {
			return nil, err
		}
		return sysinfo.Services(ctx, sysinfo.ServiceUnits(kresd, api.WireGuardEnabled()))
	}
	az.Services = api.Services
	// Обновление, начатое до перезагрузки, получает итог здесь.
	if err := az.Load(); err != nil {
		log.Error("azupdate.json не прочитан", "err", err)
	}
	az.Resume()
	ln, err := net.Listen("tcp", n.APIListen)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Второй запрос ждёт мьютекс первого целый таймаут client.sh, поэтому 2×.
		WriteTimeout: 2*time.Duration(n.ClientShTimeoutS)*time.Second + time.Minute,
		IdleTimeout:  time.Minute,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go api.RunWGGuard(ctx, time.Duration(n.PollSeconds)*time.Second)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("API агента остановлен с ошибкой", "err", err)
		}
	}()
	log.Info("API агента запущен", "listen", n.APIListen)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}, nil
}
