package node

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/logx"
	"github.com/syava842/azpanel/internal/paths"
)

// hookCheckEvery — как часто проверять, что хук на месте: повторный
// setup.sh AntiZapret стирает /etc/openvpn/server целиком.
const hookCheckEvery = time.Minute

// Run — режим «azpanel node». ensureHook ставит хук в скрипты OpenVPN и
// сообщает, было ли изменение.
func Run(ctx context.Context, cfg config.Config, ensureHook func() (bool, error)) error {
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
		Log:     log,
		Now:     time.Now,
		Peer:    PeerChecker(),
	}
	go p.Run(ctx, time.Duration(cfg.Node.PollSeconds)*time.Second)
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
