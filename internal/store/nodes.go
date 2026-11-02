package store

import (
	"context"
	"database/sql"
	"errors"
)

// Виды записей таблицы nodes.
const (
	KindNode  = "node"  // агент узла AntiZapret
	KindProxy = "proxy" // прокси-агент (azpanel proxy)
)

// Роли узла в группе синхронизации (совпадают с nodeapi.Role*).
const (
	RolePrimary = "primary"
	RoleReplica = "replica"
)

// ErrNodeExists — узел или группа с таким именем уже есть.
var ErrNodeExists = errors.New("такое имя уже занято")

// ErrNodeLocal — локальный узел нельзя удалить.
var ErrNodeLocal = errors.New("локальный узел удалить нельзя")

// NodeRec — запись узла. URL и Fingerprint пусты, пока узел не подключён
// (ключ выдан, установка на узле ещё не сделана). Token — токен агента,
// зашифрованный ключом панели (base64); у локального узла пуст.
type NodeRec struct {
	ID          int64
	Name        string
	URL         string
	Kind        string
	Fingerprint string
	Token       string
	Role        string // primary | replica; пусто — узел вне группы
	GroupID     int64  // 0 — вне группы
	Created     int64
}

// Connected — узел подключён: известны адрес и отпечаток (или это локальный).
func (n NodeRec) Connected() bool { return n.ID == LocalNode || (n.URL != "" && n.Fingerprint != "") }

const nodeCols = `id, name, url, kind, fingerprint, token, role, coalesce(group_id, 0), created`

func scanNode(sc interface{ Scan(...any) error }) (NodeRec, error) {
	var n NodeRec
	err := sc.Scan(&n.ID, &n.Name, &n.URL, &n.Kind, &n.Fingerprint, &n.Token, &n.Role, &n.GroupID, &n.Created)
	return n, err
}

// Nodes — все записи (узлы и прокси-агенты) по возрастанию id.
func (s *Store) Nodes(ctx context.Context) ([]NodeRec, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeRec
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// NodeByID — запись узла; false — такого нет.
func (s *Store) NodeByID(ctx context.Context, id int64) (NodeRec, bool, error) {
	n, err := scanNode(s.db.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return NodeRec{}, false, nil
	}
	return n, err == nil, err
}

// AddNode добавляет узел и возвращает его id. Имя уникально.
func (s *Store) AddNode(ctx context.Context, n NodeRec) (int64, error) {
	if n.Kind == "" {
		n.Kind = KindNode
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO nodes (name, url, kind, fingerprint, token, role, group_id, created)
		VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, 0), ?)`, n.Name, n.URL, n.Kind, n.Fingerprint, n.Token, n.Role, n.GroupID, n.Created)
	if isUnique(err) {
		return 0, ErrNodeExists
	}
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetNodeConn записывает адрес и закреплённый отпечаток подключённого узла.
func (s *Store) SetNodeConn(ctx context.Context, id int64, url, fingerprint string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET url = ?, fingerprint = ? WHERE id = ?`, url, fingerprint, id)
	return err
}

// SetNodeGroup ставит узлу группу и роль; group 0 — вне группы (роль сбрасывается).
func (s *Store) SetNodeGroup(ctx context.Context, id, group int64, role string) error {
	if group == 0 {
		role = ""
	}
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET group_id = NULLIF(?, 0), role = ? WHERE id = ?`, group, role, id)
	return err
}

// SetNodeRoles меняет роли нескольких узлов одной транзакцией.
func (s *Store) SetNodeRoles(ctx context.Context, roles map[int64]string) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		for id, role := range roles {
			if _, err := t.ExecContext(ctx, `UPDATE nodes SET role = ? WHERE id = ?`, role, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteNode удаляет узел вместе с его карточками, историей и привязками.
// Локальный не удаляется.
func (s *Store) DeleteNode(ctx context.Context, id int64) error {
	if id == LocalNode {
		return ErrNodeLocal
	}
	return s.tx(ctx, func(t *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM client_cards WHERE node_id = ?`,
			`DELETE FROM traffic_minute WHERE node_id = ?`,
			`DELETE FROM traffic_hour WHERE node_id = ?`,
			`DELETE FROM resource_minute WHERE node_id = ?`,
			`DELETE FROM resource_hour WHERE node_id = ?`,
			`DELETE FROM client_kinds WHERE node_id = ?`,
			`DELETE FROM portal_links WHERE node_id = ?`,
			`DELETE FROM download_links WHERE node_id = ?`,
			`DELETE FROM nodes WHERE id = ?`,
		} {
			if _, err := t.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// Group — группа синхронизации: основной и реплики (роль хранится у узла).
type Group struct {
	ID      int64
	Name    string
	Domain  string // общий домен клиентских профилей; пусто — не задан
	Remotes string // JSON-массив адресов remote в .ovpn, по порядку
	// Failover — переключение прокси на реплику при отказе основного;
	// FailoverAfter — через сколько секунд недоступности.
	Failover      bool
	FailoverAfter int
	Created       int64
}

const groupCols = `id, name, domain, remotes, failover, failover_after, created`

func scanGroup(sc interface{ Scan(...any) error }) (Group, error) {
	var g Group
	var fo int
	err := sc.Scan(&g.ID, &g.Name, &g.Domain, &g.Remotes, &fo, &g.FailoverAfter, &g.Created)
	g.Failover = fo != 0
	return g, err
}

// Groups — все группы по возрастанию id.
func (s *Store) Groups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+groupCols+` FROM groups ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupByID — группа; false — такой нет.
func (s *Store) GroupByID(ctx context.Context, id int64) (Group, bool, error) {
	g, err := scanGroup(s.db.QueryRowContext(ctx, `SELECT `+groupCols+` FROM groups WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, false, nil
	}
	return g, err == nil, err
}

// AddGroup создаёт группу; primary — узел, который становится основным.
// Узел не должен состоять в другой группе.
func (s *Store) AddGroup(ctx context.Context, name string, primary int64, now int64) (int64, error) {
	var id int64
	err := s.tx(ctx, func(t *sql.Tx) error {
		var cur sql.NullInt64
		if err := t.QueryRowContext(ctx, `SELECT group_id FROM nodes WHERE id = ? AND kind = 'node'`, primary).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("узел не найден")
			}
			return err
		}
		if cur.Valid {
			return errors.New("узел уже состоит в группе")
		}
		res, err := t.ExecContext(ctx, `INSERT INTO groups (name, created) VALUES (?, ?)`, name, now)
		if isUnique(err) {
			return ErrNodeExists
		}
		if err != nil {
			return err
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `UPDATE nodes SET group_id = ?, role = 'primary' WHERE id = ?`, id, primary)
		return err
	})
	return id, err
}

// SetGroupAddrs записывает домен и список remote группы.
func (s *Store) SetGroupAddrs(ctx context.Context, id int64, domain, remotesJSON string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE groups SET domain = ?, remotes = ? WHERE id = ?`, domain, remotesJSON, id)
	return err
}

// SetGroupFailover включает или выключает переключение прокси при отказе.
func (s *Store) SetGroupFailover(ctx context.Context, id int64, on bool, afterSec int) error {
	v := 0
	if on {
		v = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE groups SET failover = ?, failover_after = ? WHERE id = ?`, v, afterSec, id)
	return err
}

// DeleteGroup удаляет группу; её узлы остаются вне групп, прокси —
// без привязки.
func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `UPDATE nodes SET group_id = NULL, role = '' WHERE group_id = ?`, id); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
		return err
	})
}
