package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
)

// SyncSet — набор файлов, одинаковых на всех серверах группы (спецификация,
// «Синхронизация серверов»). Пути — из конфига агента; любой путь вне набора
// не читается и не пишется, симлинки не разворачиваются.
type SyncSet struct {
	AntiZapretDir string `json:"antizapret_dir"` // setup, config/*.txt, client/**, banned_clients
	EasyRSADir    string `json:"easyrsa_dir"`    // /etc/openvpn/easyrsa3 целиком, включая pki/crl.pem
	WireGuardDir  string `json:"wireguard_dir"`  // antizapret.conf, vpn.conf, key
	AmneziaWGDir  string `json:"amneziawg_dir"`  // то же для AmneziaWG; пусто — пропускается
	KnotDir       string `json:"knot_dir"`       // custom*.lua
	LimitsPath    string `json:"limits_path"`    // limits.json
}

// NewSyncSet строит набор по конфигу агента: каталог easyrsa3 — родитель PKI.
func NewSyncSet(n config.Node, limitsPath string) SyncSet {
	return SyncSet{
		AntiZapretDir: n.AntiZapretDir,
		EasyRSADir:    filepath.Dir(n.EasyRSAPKI),
		WireGuardDir:  n.WireGuardDir,
		AmneziaWGDir:  n.AmneziaWGDir,
		KnotDir:       n.KnotResolverDir,
		LimitsPath:    limitsPath,
	}
}

// Файлы ключей WG и AmneziaWG в каталоге интерфейсов.
var wgSetFiles = []string{"antizapret.conf", "vpn.conf", "key"}

// kind — к какой части набора относится файл (нужен, чтобы решить, какие
// службы перезапускать, и как читать файл).
type syncKind int

const (
	kindEasyRSA syncKind = iota + 1
	kindWireGuard
	kindAmnezia
	kindProfile
	kindRouting
	kindKnot
	kindSetup
	kindLimits
	kindBanned
)

// classify сообщает, входит ли путь в набор, и возвращает вид файла и корень,
// ниже которого ни один компонент пути не должен быть симлинком.
func (s SyncSet) classify(p string) (kind syncKind, root string, ok bool) {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return 0, "", false
	}
	base, dir := filepath.Base(p), filepath.Dir(p)
	switch {
	case s.EasyRSADir != "" && under(s.EasyRSADir, p):
		return kindEasyRSA, s.EasyRSADir, true
	case s.WireGuardDir != "" && dir == s.WireGuardDir && contains(wgSetFiles, base):
		return kindWireGuard, s.WireGuardDir, true
	case s.AmneziaWGDir != "" && dir == s.AmneziaWGDir && contains(wgSetFiles, base):
		return kindAmnezia, s.AmneziaWGDir, true
	case s.AntiZapretDir != "" && under(filepath.Join(s.AntiZapretDir, "client"), p):
		return kindProfile, filepath.Join(s.AntiZapretDir, "client"), true
	case s.AntiZapretDir != "" && dir == filepath.Join(s.AntiZapretDir, "config") && matches("*.txt", base):
		return kindRouting, filepath.Join(s.AntiZapretDir, "config"), true
	case s.KnotDir != "" && dir == s.KnotDir && matches("custom*.lua", base):
		return kindKnot, s.KnotDir, true
	case s.AntiZapretDir != "" && p == filepath.Join(s.AntiZapretDir, "setup"):
		return kindSetup, s.AntiZapretDir, true
	case s.AntiZapretDir != "" && p == filepath.Join(s.AntiZapretDir, "banned_clients"):
		return kindBanned, s.AntiZapretDir, true
	case s.LimitsPath != "" && p == s.LimitsPath:
		return kindLimits, filepath.Dir(s.LimitsPath), true
	}
	return 0, "", false
}

// Contains — путь входит в набор.
func (s SyncSet) Contains(p string) bool {
	_, _, ok := s.classify(p)
	return ok
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func matches(pattern, name string) bool {
	ok, _ := filepath.Match(pattern, name)
	return ok
}

// under — p лежит строго внутри dir.
func under(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// noSymlinks проверяет, что ни один компонент p ниже root не симлинк. Нет
// какого-то компонента — не ошибка (файл ещё не создан).
func noSymlinks(root, p string) error {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("путь вне корня набора")
	}
	// Сам корень набора тоже не должен быть ссылкой: запись ушла бы туда,
	// куда она указывает.
	if fi, err := os.Lstat(root); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s — символическая ссылка, корень набора синхронизации ею быть не может", root)
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s — символическая ссылка, в наборе синхронизации их нет", cur)
		}
	}
	return nil
}

// Manifest — файлы набора, которые есть на диске, по возрастанию пути.
// Симлинки и не-обычные файлы пропускаются; нет файла (например, banned_clients)
// или каталога — тоже. У setup отпечаток и размер считаются без ключей WARP.
func (s SyncSet) Manifest() ([]nodeapi.SyncEntry, error) {
	var paths []string
	walk := func(root string) error {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.Type().IsRegular() {
				paths = append(paths, p)
			}
			return nil
		})
		return err
	}
	if s.EasyRSADir != "" {
		if err := walk(s.EasyRSADir); err != nil {
			return nil, err
		}
	}
	dirs := []string{s.WireGuardDir, s.AmneziaWGDir, s.KnotDir}
	files := []string{s.LimitsPath}
	if s.AntiZapretDir != "" {
		if err := walk(filepath.Join(s.AntiZapretDir, "client")); err != nil {
			return nil, err
		}
		dirs = append(dirs, filepath.Join(s.AntiZapretDir, "config"))
		files = append(files, filepath.Join(s.AntiZapretDir, "setup"), filepath.Join(s.AntiZapretDir, "banned_clients"))
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type().IsRegular() {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, f := range files {
		if f == "" {
			continue
		}
		if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() {
			paths = append(paths, f)
		}
	}
	sort.Strings(paths)
	out := make([]nodeapi.SyncEntry, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		kind, root, ok := s.classify(p)
		if !ok || seen[p] || noSymlinks(root, p) != nil {
			continue
		}
		seen[p] = true
		e, err := entryOf(p, kind)
		if errors.Is(err, fs.ErrNotExist) {
			continue // исчез между обходом и чтением
		}
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func entryOf(p string, kind syncKind) (nodeapi.SyncEntry, error) {
	f, err := os.Open(p)
	if err != nil {
		return nodeapi.SyncEntry{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nodeapi.SyncEntry{}, err
	}
	h := sha256.New()
	size := fi.Size()
	if kind == kindSetup {
		data, err := io.ReadAll(io.LimitReader(f, maxSetupSize+1))
		if err != nil {
			return nodeapi.SyncEntry{}, err
		}
		if len(data) > maxSetupSize {
			return nodeapi.SyncEntry{}, errors.New("setup больше 1 МБ")
		}
		data = StripWarpAccount(data)
		h.Write(data)
		size = int64(len(data))
	} else if _, err := io.Copy(h, f); err != nil {
		return nodeapi.SyncEntry{}, err
	}
	return nodeapi.SyncEntry{
		Path: filepath.ToSlash(p), SHA256: hex.EncodeToString(h.Sum(nil)), Size: size,
		Mode: fmt.Sprintf("%04o", fi.Mode().Perm()),
	}, nil
}

// ErrNotInSet — путь вне набора синхронизации (ответ 400).
var ErrNotInSet = errors.New("путь не входит в набор синхронизации")

// Open открывает файл набора для чтения. У setup содержимое без ключей WARP.
func (s SyncSet) Open(p string) (io.ReadCloser, error) {
	kind, root, ok := s.classify(p)
	if !ok {
		return nil, ErrNotInSet
	}
	if err := noSymlinks(root, p); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	if kind == kindSetup {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(StripWarpAccount(data))), nil
	}
	return os.Open(p)
}

// maxSetupSize — предел файла setup: настоящий — десятки строк.
const maxSetupSize = 1 << 20

// IsWarpAccountKey — ключ setup с данными аккаунта WARP (у каждого сервера свои):
// …WARP…_PRIVATE_KEY, _PUBLIC_KEY, _ENDPOINT, _ADDRESS. Настройки вроде
// ANTIZAPRET_WARP, WARP_MTU, DNS_WARP — общие и синхронизируются.
func IsWarpAccountKey(key string) bool {
	if !strings.Contains(key, "WARP") {
		return false
	}
	for _, suf := range []string{"_PRIVATE_KEY", "_PUBLIC_KEY", "_ENDPOINT", "_ADDRESS"} {
		if strings.HasSuffix(key, suf) {
			return true
		}
	}
	return false
}

func setupLineKey(line string) (string, bool) {
	k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
	if !ok || k == "" || strings.HasPrefix(k, "#") {
		return "", false
	}
	return strings.TrimSpace(k), true
}

// StripWarpAccount убирает из setup строки аккаунта WARP.
func StripWarpAccount(data []byte) []byte {
	var out bytes.Buffer
	for _, line := range splitKeepEOL(data) {
		if k, ok := setupLineKey(line); ok && IsWarpAccountKey(k) {
			continue
		}
		out.WriteString(line)
	}
	return out.Bytes()
}

// MergeSetup — setup реплики после синхронизации: всё из присланного, кроме
// строк аккаунта WARP, которые остаются свои (локальные).
func MergeSetup(incoming, local []byte) []byte {
	out := StripWarpAccount(incoming)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	for _, line := range splitKeepEOL(local) {
		if k, ok := setupLineKey(line); ok && IsWarpAccountKey(k) {
			if !strings.HasSuffix(line, "\n") {
				line += "\n"
			}
			out = append(out, line...)
		}
	}
	return out
}

func splitKeepEOL(data []byte) []string {
	var lines []string
	s := string(data)
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			lines = append(lines, s)
			break
		}
		lines = append(lines, s[:i+1])
		s = s[i+1:]
	}
	return lines
}
