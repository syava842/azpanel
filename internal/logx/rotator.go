// Package logx — журналы azpanel в /opt/azpanel/log с ротацией по размеру.
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// Rotator пишет в файл и при превышении размера сдвигает его:
// file → file.1 → … → file.<keep>, самый старый удаляется.
type Rotator struct {
	mu   sync.Mutex
	path string
	max  int64
	keep int
	f    *os.File
	size int64
}

func Open(path string, maxBytes int64, keep int) (*Rotator, error) {
	r := &Rotator{path: path, max: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotator) open() error {
	// 600: в журналах имена и адреса клиентов, а nobody на AntiZapret — в
	// группе root.
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	f.Chmod(0o600) // файл мог остаться от прежней версии с другими правами
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil { // прошлая ротация не смогла открыть файл — пробуем снова
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *Rotator) rotate() error {
	r.f.Close()
	r.f = nil
	os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	os.Rename(r.path, r.path+".1")
	return r.open()
}

func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}

// New — текстовый slog поверх любого писателя.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}
