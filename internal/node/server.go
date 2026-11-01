package node

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/limits"
)

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
		limit, err := s.Limits.Get(req.CN)
		if err != nil {
			s.HookLog.Error("лимиты не прочитаны, подключение пропущено без проверки", "cn", req.CN, "err", err)
			return agentproto.Response{Allow: true, Error: err.Error()}
		}
		ok, n := s.Tracker.Admit(k, s.Now(), limit)
		if !ok {
			s.HookLog.Warn("отказ: лимит подключений", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", limit)
			return agentproto.Response{Allow: false, Count: n, Limit: limit}
		}
		s.HookLog.Info("подключение", "cn", req.CN, "instance", req.Instance, "addr", req.Addr, "sessions", n, "limit", limit)
		return agentproto.Response{Allow: true, Count: n, Limit: limit}
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
			return err
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
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		return
	}
	json.NewEncoder(c).Encode(s.Handle(req))
}
