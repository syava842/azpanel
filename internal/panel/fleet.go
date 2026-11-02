package panel

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/store"
)

const fleetReconcile = 10 * time.Second

type fleetEntry struct {
	col    *Collector
	stamp  string
	cancel context.CancelFunc
}

// RunCollectors ведёт сборщики по всем узлам параллельно: локальный — local
// (он же Server.Collector), остальные заводятся и останавливаются вслед за
// записями узлов. Блокируется до отмены ctx и ждёт остановки всех.
func (s *Server) RunCollectors(ctx context.Context, local *Collector) {
	var wg sync.WaitGroup
	every := local.Every
	if every <= 0 {
		every = defaultEvery
	}
	loop := func(ctx context.Context, col *Collector, skip func(context.Context) bool) {
		defer wg.Done()
		for {
			if skip == nil || !skip(ctx) {
				_ = col.Tick(ctx) // ошибки шагов уже в журнале
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(every):
			}
		}
	}
	wg.Add(1)
	go loop(ctx, local, nil)

	fleet := map[int64]*fleetEntry{}
	stop := func(id int64) {
		if e := fleet[id]; e != nil {
			e.cancel()
			delete(fleet, id)
			s.hub.mu.Lock()
			delete(s.hub.cols, id)
			s.hub.mu.Unlock()
		}
	}
	for {
		if s.Store != nil {
			s.reconcileFleet(ctx, local, fleet, stop, func(ectx context.Context, e *fleetEntry, c *conn) {
				wg.Add(1)
				go loop(ectx, e.col, func(ctx context.Context) bool {
					info, err := s.infoOf(ctx, c)
					return err == nil && agentOutdated(info) // устаревшему агенту команды не шлём
				})
			})
		}
		select {
		case <-ctx.Done():
			for id := range fleet {
				stop(id)
			}
			wg.Wait()
			return
		case <-time.After(fleetReconcile):
		}
	}
}

func (s *Server) reconcileFleet(ctx context.Context, local *Collector, fleet map[int64]*fleetEntry, stop func(int64), start func(context.Context, *fleetEntry, *conn)) {
	recs, err := s.nodeRecs(ctx)
	if err != nil {
		return
	}
	want := map[int64]bool{}
	for _, rec := range recs {
		if rec.Kind != store.KindNode || rec.ID == store.LocalNode || !rec.Connected() {
			continue
		}
		want[rec.ID] = true
		stamp := rec.URL + "|" + rec.Fingerprint + "|" + rec.Token
		if e := fleet[rec.ID]; e != nil {
			if e.stamp == stamp {
				e.col.NodeName = rec.Name
				continue
			}
			stop(rec.ID)
		}
		c, err := s.connect(rec)
		if err != nil || c.node == nil {
			if local.Log != nil {
				local.Log.Warn("сборщик узла не запущен", "node", rec.Name, "err", err)
			}
			continue
		}
		col := &Collector{Node: c.node, Store: local.Store, NodeID: rec.ID, NodeName: rec.Name, Every: local.Every,
			HistoryDays: local.HistoryDays, Log: local.Log, Now: local.Now, Alerts: local.Alerts}
		ectx, cancel := context.WithCancel(ctx)
		e := &fleetEntry{col: col, stamp: stamp, cancel: cancel}
		fleet[rec.ID] = e
		s.hub.mu.Lock()
		if s.hub.cols == nil {
			s.hub.cols = map[int64]*Collector{}
		}
		s.hub.cols[rec.ID] = col
		s.hub.mu.Unlock()
		start(ectx, e, c)
	}
	for id := range fleet {
		if !want[id] {
			stop(id)
		}
	}
}

// collectorFor — сборщик узла: для частой смены адресов в «Сейчас».
func (s *Server) collectorFor(r *http.Request) *Collector {
	c := selected(r)
	if c == nil || c.rec.ID == store.LocalNode {
		return s.Collector
	}
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	return s.hub.cols[c.rec.ID]
}
