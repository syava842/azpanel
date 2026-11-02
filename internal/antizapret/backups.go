package antizapret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// KeepBackups — сколько последних копий хранится на файл.
const KeepBackups = 20

// stampLayout — метка копии: UTC, миллисекунды; строки сортируются как время.
const stampLayout = "20060102T150405.000Z"

var stampRe = regexp.MustCompile(`^\d{8}T\d{6}\.\d{3}Z$`)

// ErrBadStamp — метка копии не того вида.
var ErrBadStamp = errors.New("неверная метка копии")

// BackupInfo — одна копия файла.
type BackupInfo struct {
	Stamp string
	Bytes int64
}

// Backups — копии файлов перед записью: <Dir>/<имя>.<UTC-время>.
// Хранится KeepBackups последних на каждое имя.
type Backups struct {
	Dir string
	Now func() time.Time // nil — time.Now
}

func (b *Backups) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

// Save кладёт data в новую копию файла name и вытесняет лишние старые.
// Возвращает метку копии.
func (b *Backups) Save(name string, data []byte) (string, error) {
	if err := os.MkdirAll(b.Dir, 0o750); err != nil {
		return "", err
	}
	at := b.now()
	// Порядок копий — порядок создания: метка не меньше уже существующих,
	// даже если часы ушли назад (NTP). Права 0600: в копиях бывают секреты
	// (ключи WARP в setup).
	if list, err := b.List(name); err == nil && len(list) > 0 {
		if last, err := time.Parse(stampLayout, list[0].Stamp); err == nil && !at.After(last) {
			at = last.Add(time.Millisecond)
		}
	}
	for i := 0; i < 1000; i++ {
		stamp := at.Format(stampLayout)
		f, err := os.OpenFile(filepath.Join(b.Dir, name+"."+stamp), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			at = at.Add(time.Millisecond) // две записи в одну миллисекунду
			continue
		}
		if err != nil {
			return "", err
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(f.Name())
			return "", werr
		}
		b.prune(name)
		return stamp, nil
	}
	return "", fmt.Errorf("не удалось подобрать свободную метку копии для %s", name)
}

func (b *Backups) prune(name string) {
	list, err := b.List(name)
	if err != nil || len(list) <= KeepBackups {
		return
	}
	for _, old := range list[KeepBackups:] { // список — от новых к старым
		os.Remove(filepath.Join(b.Dir, name+"."+old.Stamp))
	}
}

// List — копии файла name, новые сверху.
func (b *Backups) List(name string) ([]BackupInfo, error) {
	entries, err := os.ReadDir(b.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return []BackupInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []BackupInfo{}
	for _, e := range entries {
		stamp, ok := strings.CutPrefix(e.Name(), name+".")
		if !ok || e.IsDir() || !stampRe.MatchString(stamp) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{Stamp: stamp, Bytes: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stamp > out[j].Stamp })
	return out, nil
}

// Read читает копию. Метка проверяется по шаблону: путь из запроса не
// собирается.
func (b *Backups) Read(name, stamp string) ([]byte, error) {
	if !stampRe.MatchString(stamp) {
		return nil, ErrBadStamp
	}
	return os.ReadFile(filepath.Join(b.Dir, name+"."+stamp))
}
