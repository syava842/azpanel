// Package limits — лимиты одновременных подключений, /opt/azpanel/data/limits.json.
package limits

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/fsutil"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ValidName — то же правило имени, что у client.sh AntiZapret.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Data — содержимое limits.json: лимит по клиенту (нет записи — без
// ограничения) и заблокированные клиенты.
type Data struct {
	Limits  map[string]int
	Blocked map[string]bool
}

func Empty() Data { return Data{Limits: map[string]int{}, Blocked: map[string]bool{}} }

// file — формат на диске. Версия 1 — только limits; версия 2 добавила
// blocked. Читаются обе, пишется 2.
type file struct {
	Version int            `json:"version"`
	Limits  map[string]int `json:"limits"`
	Blocked []string       `json:"blocked,omitempty"`
}

// Load читает лимиты; нет файла — пустые.
func Load(path string) (Data, error) {
	d := Empty()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return d, fmt.Errorf("%s: %w", path, err)
	}
	if f.Version != 1 && f.Version != 2 {
		return d, fmt.Errorf("%s: неизвестная версия %d", path, f.Version)
	}
	for name, n := range f.Limits {
		if !ValidName(name) {
			return Empty(), fmt.Errorf("%s: недопустимое имя клиента %q", path, name)
		}
		if n < 1 {
			return Empty(), fmt.Errorf("%s: лимит %s = %d, нужен 1 или больше", path, name, n)
		}
		d.Limits[name] = n
	}
	for _, name := range f.Blocked {
		if !ValidName(name) {
			return Empty(), fmt.Errorf("%s: недопустимое имя заблокированного клиента %q", path, name)
		}
		d.Blocked[name] = true
	}
	return d, nil
}

func Save(path string, d Data) error {
	f := file{Version: 2, Limits: d.Limits}
	if f.Limits == nil {
		f.Limits = map[string]int{}
	}
	for name, b := range d.Blocked {
		if b {
			f.Blocked = append(f.Blocked, name)
		}
	}
	sort.Strings(f.Blocked)
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Entry — что действует для одного клиента.
type Entry struct {
	Limit   int // 0 — без ограничения
	Blocked bool
}

// Store отдаёт лимиты и перечитывает файл, когда меняются его время или размер.
type Store struct {
	path string
	mu   sync.Mutex
	seen bool
	mod  time.Time
	size int64
	d    Data
}

func NewStore(path string) *Store { return &Store{path: path, d: Empty()} }

// Get — лимит и блокировка клиента. Если файл испорчен, вместе с ошибкой
// возвращается запись из последней прочитанной версии: одна кривая правка
// не должна снимать лимиты и блокировки у всех.
func (s *Store) Get(name string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.d, s.seen = Empty(), false
	case err != nil:
		return s.entry(name), err
	case !s.seen || !st.ModTime().Equal(s.mod) || st.Size() != s.size:
		d, err := Load(s.path)
		if err != nil {
			return s.entry(name), err
		}
		s.d, s.mod, s.size, s.seen = d, st.ModTime(), st.Size(), true
	}
	return s.entry(name), nil
}

func (s *Store) entry(name string) Entry {
	return Entry{Limit: s.d.Limits[name], Blocked: s.d.Blocked[name]}
}
