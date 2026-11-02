package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ErrProxyExists — прокси с таким адресом уже записан.
var ErrProxyExists = errors.New("прокси с таким адресом уже есть")

// Proxy — российский VPS-прокси, чей адрес разрешён в allow-ips.txt.
type Proxy struct {
	ID      int64
	Name    string
	IP      string
	Note    string
	Created int64
	// AddedByPanel — строку в allow-ips.txt добавила панель; только такую
	// строку панель убирает при удалении прокси.
	AddedByPanel bool
}

const proxyCols = `id, name, ip, note, created, added_by_panel`

// Proxies — прокси по порядку добавления.
func (s *Store) Proxies(ctx context.Context) ([]Proxy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+proxyCols+` FROM proxies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Proxy{}
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProxyByID — прокси по номеру; ErrNotFound, если нет.
func (s *Store) ProxyByID(ctx context.Context, id int64) (Proxy, error) {
	p, err := scanProxy(s.db.QueryRowContext(ctx, `SELECT `+proxyCols+` FROM proxies WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Proxy{}, ErrNotFound
	}
	return p, err
}

// ProxyByIP — прокси по адресу; ErrNotFound, если нет.
func (s *Store) ProxyByIP(ctx context.Context, ip string) (Proxy, error) {
	p, err := scanProxy(s.db.QueryRowContext(ctx, `SELECT `+proxyCols+` FROM proxies WHERE ip = ?`, ip))
	if errors.Is(err, sql.ErrNoRows) {
		return Proxy{}, ErrNotFound
	}
	return p, err
}

// CreateProxy записывает прокси; занятый адрес — ErrProxyExists.
func (s *Store) CreateProxy(ctx context.Context, p Proxy) (Proxy, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO proxies (name, ip, note, created, added_by_panel) VALUES (?, ?, ?, ?, ?)`,
		p.Name, p.IP, p.Note, p.Created, p.AddedByPanel)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Proxy{}, ErrProxyExists
		}
		return Proxy{}, err
	}
	p.ID, err = res.LastInsertId()
	return p, err
}

// DeleteProxy удаляет прокси; ErrNotFound, если его нет.
func (s *Store) DeleteProxy(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM proxies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanProxy(r interface{ Scan(dest ...any) error }) (Proxy, error) {
	var p Proxy
	err := r.Scan(&p.ID, &p.Name, &p.IP, &p.Note, &p.Created, &p.AddedByPanel)
	return p, err
}
