package antizapret

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/syava842/azpanel/internal/fsutil"
)

const (
	hookBegin        = "# azpanel begin"
	hookEnd          = "# azpanel end"
	connectScript    = "custom-client-connect.sh"
	disconnectScript = "custom-client-disconnect.sh"
	backupSuffix     = ".bak-azpanel"
)

// ConnectBlock: код 3 — отказ по лимиту; любой другой код (нет бинарника —
// 127, падение — 2) подключение не останавливает.
func ConnectBlock(bin string) string {
	return hookBegin + "\n" + bin + " hook connect; [ $? -ne 3 ] || exit 1\n" + hookEnd + "\n"
}

func DisconnectBlock(bin string) string {
	return hookBegin + "\n" + bin + " hook disconnect\n" + hookEnd + "\n"
}

// Strip убирает блок azpanel, остальное оставляет как было.
func Strip(content string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.SplitAfter(content, "\n") {
		t := strings.TrimRight(line, "\r\n")
		switch {
		case t == hookBegin:
			in = true
		case in && t == hookEnd:
			in = false
		case !in:
			b.WriteString(line)
		}
	}
	return b.String()
}

// Insert ставит блок сразу после shebang, заменяя прежний блок azpanel.
func Insert(content, block string) string {
	c := Strip(content)
	switch {
	case c == "":
		return "#!/bin/bash\n" + block + "\nexit 0\n"
	case strings.HasPrefix(c, "#!"):
		i := strings.IndexByte(c, '\n')
		if i < 0 {
			return c + "\n" + block
		}
		return c[:i+1] + block + c[i+1:]
	default:
		return block + c
	}
}

// HookFiles — хук в custom-client-connect.sh и custom-client-disconnect.sh.
// Эти файлы AntiZapret оставляет для своих правок и вызывает из
// client-connect.sh и client-disconnect.sh.
type HookFiles struct {
	ScriptsDir string
	Binary     string
}

type hookFile struct{ path, block string }

func (h HookFiles) files() []hookFile {
	return []hookFile{
		{filepath.Join(h.ScriptsDir, connectScript), ConnectBlock(h.Binary)},
		{filepath.Join(h.ScriptsDir, disconnectScript), DisconnectBlock(h.Binary)},
	}
}

// Ensure ставит блоки, если их нет или они устарели. Перед первой правкой
// файла сохраняет копию .bak-azpanel.
func (h HookFiles) Ensure() (bool, error) {
	if _, err := os.Stat(h.ScriptsDir); err != nil {
		return false, err
	}
	changed := false
	for _, f := range h.files() {
		old, err := os.ReadFile(f.path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return changed, err
		}
		updated := Insert(string(old), f.block)
		if updated == string(old) {
			continue
		}
		if err == nil {
			bak := f.path + backupSuffix
			if _, e := os.Stat(bak); errors.Is(e, fs.ErrNotExist) {
				if e := fsutil.WriteFileAtomic(bak, old, 0o755); e != nil {
					return changed, e
				}
			}
		}
		if err := fsutil.WriteFileAtomic(f.path, []byte(updated), 0o755); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// Installed — оба блока стоят в актуальном виде.
func (h HookFiles) Installed() (bool, error) {
	for _, f := range h.files() {
		b, err := os.ReadFile(f.path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if Insert(string(b), f.block) != string(b) {
			return false, nil
		}
	}
	return true, nil
}

// Remove убирает блоки; копии .bak-azpanel остаются.
func (h HookFiles) Remove() error {
	for _, f := range h.files() {
		b, err := os.ReadFile(f.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if s := Strip(string(b)); s != string(b) {
			if err := fsutil.WriteFileAtomic(f.path, []byte(s), 0o755); err != nil {
				return err
			}
		}
	}
	return nil
}
