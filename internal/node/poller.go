package node

import (
	"context"
	"log/slog"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

// silentWarnAfter — после стольких молчаливых опросов подряд экземпляр
// попадает в журнал. Одно-два молчания — штатно: экземпляр занят
// client-connect.
const silentWarnAfter = 3

type Poller struct {
	Dir     string
	Timeout time.Duration
	Tracker *Tracker
	Log     *slog.Logger
	Now     func() time.Time
	Query   func(sock string, timeout time.Duration) ([]antizapret.Session, error)
	fails   map[string]int
}

// PollOnce снимает состояние всех экземпляров. Не ответивший сохраняет
// прежний снимок.
func (p *Poller) PollOnce() {
	socks, err := antizapret.ListSockets(p.Dir)
	if err != nil {
		p.Log.Error("список сокетов OpenVPN не получен", "dir", p.Dir, "err", err)
		return
	}
	if p.fails == nil {
		p.fails = map[string]int{}
	}
	for _, sock := range socks {
		inst := antizapret.InstanceFromSocket(sock)
		taken := p.Now()
		sessions, err := p.Query(sock, p.Timeout)
		if err != nil {
			p.fails[inst]++
			if p.fails[inst] == silentWarnAfter {
				p.Log.Warn("экземпляр OpenVPN не отвечает", "instance", inst, "polls", p.fails[inst], "err", err)
			}
			continue
		}
		if p.fails[inst] >= silentWarnAfter {
			p.Log.Info("экземпляр OpenVPN снова отвечает", "instance", inst)
		}
		p.fails[inst] = 0
		p.Tracker.ApplySnapshot(inst, taken, sessions)
	}
}

func (p *Poller) Run(ctx context.Context, every time.Duration) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			p.PollOnce()
		}
	}
}
