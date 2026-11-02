package store

import (
	"context"
	"database/sql"
	"errors"
)

// Значения Card.AutoBlock и Card.TrafficPeriod.
const (
	AutoBlockExpired = "expired"
	AutoBlockTraffic = "traffic"

	PeriodDay   = "day"
	PeriodWeek  = "week"
	PeriodMonth = "month"
)

// Card — карточка клиента. AccessUntil nil — без срока; TrafficLimit 0 — без
// лимита. AutoBlock непуст, когда блокировку поставила панель. AutoSkip —
// отпечаток причины, которую админ снял вручную: по ней сборщик не блокирует,
// пока причина не изменится.
type Card struct {
	Node          int64
	Name          string
	Note          string
	AccessUntil   *int64
	TrafficLimit  int64
	TrafficPeriod string
	AutoBlock     string
	AutoSkip      string
}

func defaultCard(node int64, name string) Card {
	return Card{Node: node, Name: name, TrafficPeriod: PeriodMonth}
}

const cardCols = `node_id, name, note, access_until, traffic_limit, traffic_period, auto_block, auto_skip`

func scanCard(sc interface{ Scan(...any) error }) (Card, error) {
	var c Card
	var until sql.NullInt64
	if err := sc.Scan(&c.Node, &c.Name, &c.Note, &until, &c.TrafficLimit, &c.TrafficPeriod, &c.AutoBlock, &c.AutoSkip); err != nil {
		return Card{}, err
	}
	if until.Valid {
		v := until.Int64
		c.AccessUntil = &v
	}
	return c, nil
}

// Card — карточка клиента; нет строки — карточка по умолчанию, не ошибка.
func (s *Store) Card(ctx context.Context, node int64, name string) (Card, error) {
	c, err := scanCard(s.db.QueryRowContext(ctx, `SELECT `+cardCols+` FROM client_cards WHERE node_id = ? AND name = ?`, node, name))
	if errors.Is(err, sql.ErrNoRows) {
		return defaultCard(node, name), nil
	}
	return c, err
}

// SaveCard создаёт или заменяет карточку; владельца (owner_id) не трогает.
func (s *Store) SaveCard(ctx context.Context, c Card) error {
	if c.TrafficPeriod == "" {
		c.TrafficPeriod = PeriodMonth
	}
	var until any
	if c.AccessUntil != nil {
		until = *c.AccessUntil
	}
	// Upsert, а не REPLACE: замена строки стёрла бы owner_id.
	_, err := s.db.ExecContext(ctx, `INSERT INTO client_cards (`+cardCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id, name) DO UPDATE SET note = excluded.note, access_until = excluded.access_until,
		  traffic_limit = excluded.traffic_limit, traffic_period = excluded.traffic_period,
		  auto_block = excluded.auto_block, auto_skip = excluded.auto_skip`,
		c.Node, c.Name, c.Note, until, c.TrafficLimit, c.TrafficPeriod, c.AutoBlock, c.AutoSkip)
	return err
}

// SaveCardFields создаёт карточку или обновляет в ней note, access_until,
// traffic_limit и traffic_period, не трогая auto_block и auto_skip: правка из
// интерфейса не затирает пометку, которую в это же время ставит сборщик.
func (s *Store) SaveCardFields(ctx context.Context, c Card) error {
	if c.TrafficPeriod == "" {
		c.TrafficPeriod = PeriodMonth
	}
	var until any
	if c.AccessUntil != nil {
		until = *c.AccessUntil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO client_cards (node_id, name, note, access_until, traffic_limit, traffic_period)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id, name) DO UPDATE SET note = excluded.note, access_until = excluded.access_until,
		  traffic_limit = excluded.traffic_limit, traffic_period = excluded.traffic_period`,
		c.Node, c.Name, c.Note, until, c.TrafficLimit, c.TrafficPeriod)
	return err
}

// SetAutoBlock точечно меняет только auto_block и auto_skip существующей
// карточки, не трогая остальные поля: сборщик и ручная разблокировка не
// затирают правку карточки из интерфейса. Нет карточки — ничего не делает.
func (s *Store) SetAutoBlock(ctx context.Context, node int64, name, autoBlock, autoSkip string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE client_cards SET auto_block = ?, auto_skip = ? WHERE node_id = ? AND name = ?`,
		autoBlock, autoSkip, node, name)
	return err
}

// Cards — все карточки узла по имени клиента.
func (s *Store) Cards(ctx context.Context, node int64) (map[string]Card, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cardCols+` FROM client_cards WHERE node_id = ?`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Card{}
	for rows.Next() {
		c, err := scanCard(rows)
		if err != nil {
			return nil, err
		}
		out[c.Name] = c
	}
	return out, rows.Err()
}

func (s *Store) DeleteCard(ctx context.Context, node int64, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM client_cards WHERE node_id = ? AND name = ?`, node, name)
	return err
}
