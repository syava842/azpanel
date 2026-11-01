// Package limits — лимиты одновременных подключений, /opt/azpanel/data/limits.json.
package limits

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/fsutil"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ValidName — то же правило имени, что у client.sh AntiZapret.
func ValidName(name string) bool { return nameRe.MatchString(name) }

type file struct {
	Version int            `json:"version"`
	Limits  map[string]int `json:"limits"`
}

// Load читает лимиты; нет файла — пустая карта.
func Load(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: неизвестная версия %d", path, f.Version)
	}
	for name, n := range f.Limits {
		if !ValidName(name) {
			return nil, fmt.Errorf("%s: недопустимое имя клиента %q", path, name)
		}
		if n < 1 {
			return nil, fmt.Errorf("%s: лимит %s = %d, нужен 1 или больше", path, name, n)
		}
	}
	if f.Limits == nil {
		f.Limits = map[string]int{}
	}
	return f.Limits, nil
}

func Save(path string, m map[string]int) error {
	data, err := json.MarshalIndent(file{Version: 1, Limits: m}, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Store отдаёт лимиты и перечитывает файл, когда меняются его время или размер.
type Store struct {
	path string
	mu   sync.Mutex
	seen bool
	mod  time.Time
	size int64
	m    map[string]int
}

func NewStore(path string) *Store { return &Store{path: path, m: map[string]int{}} }

// Get — лимит клиента; 0 — без ограничения.
func (s *Store) Get(name string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.m, s.seen = map[string]int{}, false
	case err != nil:
		return 0, err
	case !s.seen || !st.ModTime().Equal(s.mod) || st.Size() != s.size:
		m, err := Load(s.path)
		if err != nil {
			return 0, err
		}
		s.m, s.mod, s.size, s.seen = m, st.ModTime(), st.Size(), true
	}
	return s.m[name], nil
}
