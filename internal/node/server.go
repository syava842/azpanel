package node

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/limits"
)

// maxRequest — предел запроса хука: имя клиента — до 64 символов, адрес и
// экземпляр короткие.
const maxRequest = 4096

// Server отвечает хуку. Любая своя ошибка — «пускать»: из-за сбоя azpanel
// VPN отключаться не должен.
type Server struct {
	Tracker *Tracker
	Limits  *limits.Store
	HookLog *slog.Logger // hook.log: решения по подключениям
	Log     *slog.Logger // node.log: работа агента
	Now     func() time.Time
	Peer    func(net.Conn) error // nil — без проверки собеседника
}

func (s *Server) Handle(req agentproto.Request) agentproto.Response {
	k := Key{Instance: req.Instance, CN: req.CN, Addr: req.Addr}
	if (req.Op == agentproto.OpConnect || req.Op == agentproto.OpDisconnect) && !s.Tracker.Known(req.Instance) {
		// Нет снимка — событие не вычистит ни один опрос: не засчитываем.
		// Так же ведёт себя агент до первого ответа экземпляра.
		s.HookLog.Warn("неизвестный экземпляр, событие не учтено", "op", req.Op, "cn", req.CN, "instance", req.Instance)
		return agentproto.Response{Allow: true}
	}
	switch req.Op {
	case agentproto.OpConnect:
		e, err := s.Limits.Get(req.CN)
		if err != nil {
			// e — из последней прочитанной версии; не было её — без ограничений.
			s.HookLog.Error("limits.json не прочитан, действуют последние прочитанные лимиты", "cn", req.CN, "limit", e.Limit, "blocked", e.Blocked, "err", err)
		}
		if e.Blocked {
			s.HookLog.Warn("отказ: клиент заблокирован", "cn", req.CN, "instance", req.Instance, "addr", req.Addr)
			return agentproto.Response{Allow: false, Blocked: true}
		}
		ok, n := s.Tracker.Admit(k, s.Now(), e.Limit)
		if !ok {
			s.HookLog.Warn("отказ: лимит подключений", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", e.Limit)
			return agentproto.Response{Allow: false, Count: n, Limit: e.Limit}
		}
		s.HookLog.Info("подключение", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", e.Limit)
		return agentproto.Response{Allow: true, Count: n, Limit: e.Limit}
	case agentproto.OpDisconnect:
		s.Tracker.Disconnect(k, s.Now())
		s.HookLog.Info("отключение", "cn", req.CN, "instance", req.Instance, "addr", req.Addr)
		return agentproto.Response{Allow: true}
	case agentproto.OpList:
		return agentproto.Response{Allow: true, Counts: s.Tracker.Counts()}
	default:
		return agentproto.Response{Allow: true, Error: "неизвестная операция " + req.Op}
	}
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Временная ошибка (например, кончились дескрипторы) не должна
			// останавливать агента: без него хук пропускает всех.
			s.Log.Error("соединение с сокетом агента не принято", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.serveConn(c)
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if s.Peer != nil {
		if err := s.Peer(c); err != nil {
			s.Log.Warn("чужой процесс на сокете агента, отклонён", "err", err)
			return
		}
	}
	var req agentproto.Request
	if err := json.NewDecoder(io.LimitReader(c, maxRequest)).Decode(&req); err != nil {
		return
	}
	json.NewEncoder(c).Encode(s.Handle(req))
}
