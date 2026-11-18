package store

import (
	"context"
	"database/sql"
)

// Step — шаг ряда: поминутные точки или часовые.
type Step int

const (
	Minute Step = iota
	Hour
)

// Bytes — байты в обе стороны: Rx принято сервером от клиента, Tx отправлено.
type Bytes struct{ Rx, Tx int64 }

// Point — точка ряда трафика; TS — начало минуты или часа, Unix UTC.
type Point struct{ TS, Rx, Tx int64 }

func minuteOf(ts int64) int64 { return ts - ts%60 }
func hourOf(ts int64) int64   { return ts - ts%3600 }

// AddTraffic прибавляет приращения к строкам минуты, в которую попал ts.
func (s *Store) AddTraffic(ctx context.Context, node int64, ts int64, rows map[string]Bytes) error {
	if len(rows) == 0 {
		return nil
	}
	return s.tx(ctx, func(t *sql.Tx) error {
		st, err := t.PrepareContext(ctx, `INSERT INTO traffic_minute (node_id, name, ts, rx, tx) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(node_id, name, ts) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx`)
		if err != nil {
			return err
		}
		defer st.Close()
		for name, b := range rows {
			if _, err := st.ExecContext(ctx, node, name, minuteOf(ts), b.Rx, b.Tx); err != nil {
				return err
			}
		}
		return nil
	})
}

// TrafficSeries — ряд клиента за [from, to). Для Hour часы, ещё не
// свёрнутые в traffic_hour, досчитываются из минут.
func (s *Store) TrafficSeries(ctx context.Context, node int64, name string, from, to int64, step Step) ([]Point, error) {
	var rows *sql.Rows
	var err error
	if step == Minute {
		rows, err = s.db.QueryContext(ctx, `SELECT ts, rx, tx FROM traffic_minute
			WHERE node_id = ? AND name = ? AND ts >= ? AND ts < ? ORDER BY ts`, node, name, from, to)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT ts, rx, tx FROM traffic_hour
				WHERE node_id = ? AND name = ? AND ts >= ? AND ts < ?
			UNION ALL
			SELECT m.ts / 3600 * 3600, sum(m.rx), sum(m.tx) FROM traffic_minute m
				WHERE m.node_id = ? AND m.name = ? AND m.ts / 3600 * 3600 >= ? AND m.ts / 3600 * 3600 < ?
				AND NOT EXISTS (SELECT 1 FROM traffic_hour h
					WHERE h.node_id = m.node_id AND h.name = m.name AND h.ts = m.ts / 3600 * 3600)
				GROUP BY m.ts / 3600
			ORDER BY 1`, node, name, from, to, node, name, from, to)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Point{}
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.TS, &p.Rx, &p.Tx); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TrafficTotals — суммы по клиентам за [from, to): часовые точки плюс минуты
// тех часов, что ещё не свёрнуты. Свёрнутый час считается один раз.
func (s *Store) TrafficTotals(ctx context.Context, node int64, from, to int64) (map[string]Bytes, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, sum(rx), sum(tx) FROM (
			SELECT name, rx, tx FROM traffic_hour WHERE node_id = ? AND ts >= ? AND ts < ?
			UNION ALL
			SELECT m.name, m.rx, m.tx FROM traffic_minute m
				WHERE m.node_id = ? AND m.ts >= ? AND m.ts < ?
				AND NOT EXISTS (SELECT 1 FROM traffic_hour h
					WHERE h.node_id = m.node_id AND h.name = m.name AND h.ts = m.ts / 3600 * 3600)
		) GROUP BY name`, node, from, to, node, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Bytes{}
	for rows.Next() {
		var n string
		var b Bytes
		if err := rows.Scan(&n, &b.Rx, &b.Tx); err != nil {
			return nil, err
		}
		out[n] = b
	}
	return out, rows.Err()
}

// DeleteTraffic стирает всю историю трафика имени: новый клиент с именем
// удалённого не наследует его байты в лимите.
func (s *Store) DeleteTraffic(ctx context.Context, node int64, name string) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		for _, tbl := range []string{"traffic_minute", "traffic_hour"} {
			if _, err := t.ExecContext(ctx, `DELETE FROM `+tbl+` WHERE node_id = ? AND name = ?`, node, name); err != nil {
				return err
			}
		}
		return nil
	})
}

// longCut — граница, до которой трафик берётся из суток, а не из часов:
// часы живут MinTrafficDays, берём с запасом.
func longCut(now int64) int64 { return now - now%86400 - int64(MinTrafficDays-5)*86400 }

// TrafficTotalsLong — как TrafficTotals, но для любого периода: старше
// longCut — из суточного трафика (DayTrafficDays), новее — из часов и минут.
func (s *Store) TrafficTotalsLong(ctx context.Context, node int64, from, to, now int64) (map[string]Bytes, error) {
	cut := longCut(now)
	if from >= cut {
		return s.TrafficTotals(ctx, node, from, to)
	}
	out, err := s.TrafficTotals(ctx, node, cut, to)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name, sum(rx), sum(tx) FROM traffic_day
		WHERE node_id = ? AND ts >= ? AND ts < ? GROUP BY name`, node, from-from%86400, min(cut, to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var b Bytes
		if err := rows.Scan(&n, &b.Rx, &b.Tx); err != nil {
			return nil, err
		}
		o := out[n]
		o.Rx += b.Rx
		o.Tx += b.Tx
		out[n] = o
	}
	return out, rows.Err()
}

// TrafficByDay — трафик по суткам UTC (начало суток → имя → байты) за
// [from, to): старше longCut — из суточной таблицы, новее — из часов и минут.
func (s *Store) TrafficByDay(ctx context.Context, node int64, from, to, now int64) (map[int64]map[string]Bytes, error) {
	cut := longCut(now)
	out := map[int64]map[string]Bytes{}
	add := func(day int64, name string, b Bytes) {
		m := out[day]
		if m == nil {
			m = map[string]Bytes{}
			out[day] = m
		}
		o := m[name]
		o.Rx += b.Rx
		o.Tx += b.Tx
		m[name] = o
	}
	scan := func(q string, args ...any) error {
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var day int64
			var n string
			var b Bytes
			if err := rows.Scan(&day, &n, &b.Rx, &b.Tx); err != nil {
				return err
			}
			add(day, n, b)
		}
		return rows.Err()
	}
	start := max(from, cut)
	if from < cut {
		if err := scan(`SELECT ts, name, rx, tx FROM traffic_day WHERE node_id = ? AND ts >= ? AND ts < ?`,
			node, from-from%86400, min(cut, to)); err != nil {
			return nil, err
		}
	}
	if start < to {
		err := scan(`SELECT ts / 86400 * 86400, name, sum(rx), sum(tx) FROM (
				SELECT name, ts, rx, tx FROM traffic_hour WHERE node_id = ? AND ts >= ? AND ts < ?
				UNION ALL
				SELECT m.name, m.ts, m.rx, m.tx FROM traffic_minute m
					WHERE m.node_id = ? AND m.ts >= ? AND m.ts < ?
					AND NOT EXISTS (SELECT 1 FROM traffic_hour h
						WHERE h.node_id = m.node_id AND h.name = m.name AND h.ts = m.ts / 3600 * 3600)
			) GROUP BY ts / 86400, name`, node, start, to, node, start, to)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
