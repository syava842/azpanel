package store

import (
	"context"
	"database/sql"
)

// ResourcePoint — снимок ресурсов узла; TS — начало минуты или часа.
// NetRx и NetTx — счётчики интерфейса, а не приращения.
type ResourcePoint struct {
	TS        int64
	CPU       float64 // доля 0..1 или проценты — как у сборщика, хранилище не меняет
	Load1     float64
	MemUsed   int64
	MemTotal  int64
	DiskFree  int64
	DiskTotal int64
	NetRx     int64
	NetTx     int64
	Online    int
}

const resCols = `ts, cpu, load1, mem_used, mem_total, disk_free, disk_total, net_rx, net_tx, online`

// AddResource пишет точку минуты, в которую попал r.TS; повтор в ту же
// минуту заменяет прежнюю.
func (s *Store) AddResource(ctx context.Context, node int64, r ResourcePoint) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO resource_minute
		(node_id, `+resCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		node, minuteOf(r.TS), r.CPU, r.Load1, r.MemUsed, r.MemTotal, r.DiskFree, r.DiskTotal, r.NetRx, r.NetTx, r.Online)
	return err
}

// ResourceSeries — ряд за [from, to). Для Hour часы, ещё не свёрнутые,
// досчитываются из минут тем же способом, что и Rollup.
func (s *Store) ResourceSeries(ctx context.Context, node int64, from, to int64, step Step) ([]ResourcePoint, error) {
	var rows *sql.Rows
	var err error
	if step == Minute {
		rows, err = s.db.QueryContext(ctx, `SELECT `+resCols+` FROM resource_minute
			WHERE node_id = ? AND ts >= ? AND ts < ? ORDER BY ts`, node, from, to)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+resCols+` FROM resource_hour
				WHERE node_id = ? AND ts >= ? AND ts < ?
			UNION ALL
			SELECT `+resHourAgg+` FROM resource_minute m
				WHERE m.node_id = ? AND m.ts / 3600 * 3600 >= ? AND m.ts / 3600 * 3600 < ?
				AND NOT EXISTS (SELECT 1 FROM resource_hour h WHERE h.node_id = m.node_id AND h.ts = m.ts / 3600 * 3600)
				GROUP BY m.ts / 3600
			ORDER BY 1`, node, from, to, node, from, to)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResourcePoint{}
	for rows.Next() {
		var r ResourcePoint
		if err := rows.Scan(&r.TS, &r.CPU, &r.Load1, &r.MemUsed, &r.MemTotal, &r.DiskFree, &r.DiskTotal, &r.NetRx, &r.NetTx, &r.Online); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// resHourAgg — свёртка минут одного часа: среднее по значениям, максимум
// по счётчикам сети и числу онлайн.
const resHourAgg = `m.ts / 3600 * 3600, avg(m.cpu), avg(m.load1),
	CAST(round(avg(m.mem_used)) AS INTEGER), CAST(round(avg(m.mem_total)) AS INTEGER),
	CAST(round(avg(m.disk_free)) AS INTEGER), CAST(round(avg(m.disk_total)) AS INTEGER),
	max(m.net_rx), max(m.net_tx), max(m.online)`

const (
	// MinTrafficDays — сколько суток хранить часовой трафик независимо от
	// history_days: лимиты «неделя» и «месяц» считаются по нему, и усечение
	// истории не должно снимать блок посреди периода.
	MinTrafficDays = 35
	// AuditKeepDays — сколько суток хранить журнал действий.
	AuditKeepDays = 365
)

// Rollup сворачивает минуты законченных часов в часовые точки и удаляет
// старое: минуты — старше суток (целыми часами, чтобы повторный вызов не
// пересчитал час по неполным данным), часовые ресурсы — старше historyDays, часовой трафик — старше
// max(historyDays, MinTrafficDays), журнал действий — старше AuditKeepDays.
// Повторный вызов результат не меняет: час перезаписывается целиком.
func (s *Store) Rollup(ctx context.Context, now int64, historyDays int) error {
	cur := hourOf(now)
	minCut := hourOf(now - 86400)
	hourCut := now - int64(historyDays)*86400
	trafficCut := now - int64(max(historyDays, MinTrafficDays))*86400
	auditCut := now - AuditKeepDays*86400
	return s.tx(ctx, func(t *sql.Tx) error {
		stmts := []struct {
			q    string
			args []any
		}{
			{`INSERT OR REPLACE INTO traffic_hour (node_id, name, ts, rx, tx)
				SELECT node_id, name, ts / 3600 * 3600, sum(rx), sum(tx) FROM traffic_minute
				WHERE ts < ? GROUP BY node_id, name, ts / 3600`, []any{cur}},
			{`INSERT OR REPLACE INTO resource_hour (node_id, ` + resCols + `)
				SELECT m.node_id, ` + resHourAgg + ` FROM resource_minute m
				WHERE m.ts < ? GROUP BY m.node_id, m.ts / 3600`, []any{cur}},
			{`DELETE FROM traffic_minute WHERE ts < ?`, []any{minCut}},
			{`DELETE FROM resource_minute WHERE ts < ?`, []any{minCut}},
			{`DELETE FROM traffic_hour WHERE ts < ?`, []any{trafficCut}},
			{`DELETE FROM resource_hour WHERE ts < ?`, []any{hourCut}},
			{`DELETE FROM audit WHERE ts < ?`, []any{auditCut}},
		}
		for _, st := range stmts {
			if _, err := t.ExecContext(ctx, st.q, st.args...); err != nil {
				return err
			}
		}
		return nil
	})
}
