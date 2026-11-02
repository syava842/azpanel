// Package secrets — /opt/azpanel/etc/secrets.env: строки KEY=VALUE, права 600.
// Значения не попадают ни в ошибки, ни в журналы.
package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/syava842/azpanel/internal/fsutil"
)

// NodeToken — токен, которым панель подписывает запросы к агенту.
const NodeToken = "NODE_TOKEN"

var keyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Load читает файл; нет файла — пустая карта. Пустые строки и строки с #
// пропускаются.
func Load(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !keyRe.MatchString(k) {
			// Саму строку не печатать: в ней может быть секрет.
			return nil, fmt.Errorf("%s:%d: ожидается KEY=VALUE", path, i+1)
		}
		out[k] = v
	}
	return out, nil
}

// Set меняет или добавляет один ключ, остальные сохраняет. Комментарии
// файла при этом не сохраняются: файл пишет только azpanel.
func Set(path, key, value string) error {
	return SetMany(path, map[string]string{key: value})
}

// SetMany меняет или добавляет несколько ключей одной атомарной записью:
// записаны либо все, либо ни один. При ошибке проверки ключей и значений
// файл не трогается.
func SetMany(path string, kv map[string]string) error {
	for key, value := range kv {
		if !keyRe.MatchString(key) {
			return fmt.Errorf("недопустимое имя ключа %q", key)
		}
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("значение секрета не может содержать перевод строки")
		}
	}
	m, err := Load(path)
	if err != nil {
		return err
	}
	for k, v := range kv {
		m[k] = v
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, m[k])
	}
	return fsutil.WriteFileAtomic(path, []byte(b.String()), 0o600)
}

// NewToken — 32 случайных байта в hex.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
