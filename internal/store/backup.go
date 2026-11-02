package store

import (
	"context"
	"fmt"
	"os"
)

// Backup пишет согласованный снимок базы в path (VACUUM INTO): это не копия
// живого файла, поэтому WAL и параллельные записи не портят результат. Файл
// path не должен существовать; права снимка — 600.
func (s *Store) Backup(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("файл снимка %s уже есть", path)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		os.Remove(path)
		return fmt.Errorf("снимок базы: %w", err)
	}
	return os.Chmod(path, 0o600)
}
