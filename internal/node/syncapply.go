package node

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/syava842/azpanel/internal/sysinfo"
)

// SyncApplyParams — параметры задачи sync-apply (`azpanel internal sync-apply
// --params ФАЙЛ`). Задача идёт вне песочницы агента: пишет в /etc/openvpn,
// /etc/wireguard, /etc/knot-resolver и /root/antizapret.
type SyncApplyParams struct {
	Set     SyncSet `json:"set"`
	Archive string  `json:"archive"` // tar, уже проверенный агентом
	Stage   string  `json:"stage"`   // каталог архива: удаляется по окончании
	Prune   bool    `json:"prune"`   // удалить файлы набора, которых нет в архиве
}

// SyncEnv — внешний мир задачи; в тестах подменяется.
type SyncEnv struct {
	// Run выполняет команду и возвращает вывод; nil — настоящий запуск.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	Out io.Writer
}

func (e *SyncEnv) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if e.Run != nil {
		return e.Run(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (e *SyncEnv) logf(format string, a ...any) {
	if e.Out != nil {
		fmt.Fprintf(e.Out, format+"\n", a...)
	}
}

// archiveEntry — проверенная запись архива.
type archiveEntry struct {
	path string
	mode os.FileMode
	size int64
}

// ValidateArchive читает tar от начала до конца и проверяет каждую запись:
// обычный файл, путь чистый, абсолютный и входит в набор, без повторов, без
// симлинков по пути. Ничего не пишет на диск. Ошибка — ErrNotInSet или текст о
// том, какая запись не подошла; вызывающий отвечает 400.
func ValidateArchive(set SyncSet, r io.Reader) ([]archiveEntry, error) {
	tr := tar.NewReader(r)
	var out []archiveEntry
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("архив не разобран: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s: в архиве допустимы только обычные файлы", h.Name)
		}
		p := filepath.FromSlash(h.Name)
		kind, root, ok := set.classify(p)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNotInSet, h.Name)
		}
		if seen[p] {
			return nil, fmt.Errorf("%s: файл повторён в архиве", h.Name)
		}
		seen[p] = true
		if err := noSymlinks(root, p); err != nil {
			return nil, fmt.Errorf("%s: %w", h.Name, err)
		}
		if kind == kindSetup && h.Size > maxSetupSize {
			return nil, errors.New("setup больше 1 МБ")
		}
		out = append(out, archiveEntry{path: p, mode: os.FileMode(h.Mode).Perm(), size: h.Size})
	}
}

// RunSyncApply — тело задачи sync-apply: повторная проверка архива, запись
// файлов набора атомарно с правами из архива, удаление лишнего (Prune),
// перезапуск затронутых служб. Ошибка записи не прячется за перезапуском: итог
// — ненулевой код задачи. Каталог Stage удаляется всегда.
func RunSyncApply(ctx context.Context, p SyncApplyParams, env *SyncEnv) error {
	if p.Stage != "" {
		defer os.RemoveAll(p.Stage)
	}
	f, err := os.Open(p.Archive)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := ValidateArchive(p.Set, f)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if p.Prune && len(entries) == 0 {
		return errors.New("пустой архив с удалением лишнего: набор был бы стёрт")
	}
	env.logf("в архиве файлов: %d", len(entries))

	var changed []string
	var failed []string
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		path := filepath.FromSlash(h.Name)
		did, werr := writeSyncFile(p.Set, path, os.FileMode(h.Mode).Perm(), tr)
		switch {
		case werr != nil:
			env.logf("ОШИБКА %s: %v", path, werr)
			failed = append(failed, path)
		case did:
			changed = append(changed, path)
			env.logf("записан %s", path)
		}
	}
	if p.Prune {
		removed, perr := pruneSyncFiles(p.Set, entries, env)
		changed = append(changed, removed...)
		if perr != nil {
			failed = append(failed, perr.Error())
		}
	}
	env.logf("изменено файлов: %d", len(changed))
	units := append(p.Set.unitsToRestart(changed), env.kresdIf(ctx, p.Set, changed)...)
	for _, u := range units {
		out, err := env.run(ctx, "systemctl", "try-restart", u)
		if err != nil {
			env.logf("ОШИБКА перезапуска %s: %v %s", u, err, strings.TrimSpace(string(out)))
			failed = append(failed, "перезапуск "+u)
			continue
		}
		env.logf("перезапущен %s", u)
	}
	if len(failed) > 0 {
		return fmt.Errorf("синхронизация закончилась с ошибками (%d): %s", len(failed), strings.Join(failed, "; "))
	}
	return nil
}

// kresdIf — экземпляры kresd@*, если менялись custom*.lua.
func (e *SyncEnv) kresdIf(ctx context.Context, set SyncSet, changed []string) []string {
	for _, p := range changed {
		if k, _, _ := set.classify(p); k == kindKnot {
			out, err := e.run(ctx, "systemctl", "list-units", "--plain", "--no-legend", "--all", "kresd@*")
			if err != nil {
				e.logf("ОШИБКА списка kresd: %v", err)
				return nil
			}
			return sysinfo.ParseListUnits(string(out))
		}
	}
	return nil
}

// unitsToRestart — службы OpenVPN и WireGuard, которым нужен перезапуск после
// смены файлов. Добавление клиента меняет pki/issued и index.txt, но OpenVPN
// читает их при каждом подключении, поэтому перезапуск (он обрывает все
// сессии) — только при смене CA, DH и ключей самих серверов; WireGuard — при
// смене конфига своего интерфейса.
func (s SyncSet) unitsToRestart(changed []string) []string {
	var units []string
	add := func(u string) {
		if !contains(units, u) {
			units = append(units, u)
		}
	}
	for _, p := range changed {
		kind, _, _ := s.classify(p)
		switch kind {
		case kindEasyRSA:
			rel, _ := filepath.Rel(s.EasyRSADir, p)
			rel = filepath.ToSlash(rel)
			base := filepath.Base(rel)
			serverCert := (strings.HasPrefix(rel, "pki/issued/") || strings.HasPrefix(rel, "pki/private/")) && strings.Contains(base, "server")
			if rel == "pki/ca.crt" || rel == "pki/dh.pem" || serverCert {
				for _, u := range []string{"antizapret-udp", "antizapret-tcp", "vpn-udp", "vpn-tcp"} {
					add("openvpn-server@" + u)
				}
			}
		case kindWireGuard, kindAmnezia:
			prefix := "wg-quick@"
			if kind == kindAmnezia {
				prefix = "awg-quick@"
			}
			switch filepath.Base(p) {
			case "antizapret.conf":
				add(prefix + "antizapret")
			case "vpn.conf":
				add(prefix + "vpn")
			case "key":
				add(prefix + "antizapret")
				add(prefix + "vpn")
			}
		}
	}
	return units
}

// writeSyncFile пишет один файл набора. Содержимое совпало с текущим — файл не
// переписывается (права, если разошлись, поправляются), и результат false.
// setup дополняется строками WARP самой реплики.
func writeSyncFile(set SyncSet, path string, mode os.FileMode, r io.Reader) (bool, error) {
	kind, root, ok := set.classify(path)
	if !ok {
		return false, ErrNotInSet
	}
	if err := noSymlinks(root, path); err != nil {
		return false, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirModeFor(set, path)); err != nil {
		return false, err
	}
	if kind == kindSetup {
		return writeSetup(path, mode, r)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".sync-*")
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), r); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if cur, ok := fileSum(path); ok && cur == hex.EncodeToString(h.Sum(nil)) {
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() != mode {
			return true, os.Chmod(path, mode)
		}
		return false, nil
	}
	if err := os.Chmod(name, mode); err != nil {
		return false, err
	}
	return true, os.Rename(name, path)
}

func writeSetup(path string, mode os.FileMode, r io.Reader) (bool, error) {
	in, err := io.ReadAll(io.LimitReader(r, maxSetupSize+1))
	if err != nil {
		return false, err
	}
	local, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	merged := MergeSetup(in, local)
	if bytes.Equal(merged, local) {
		return false, nil
	}
	// Права и владелец прежнего setup сохраняются; нет файла — права из архива.
	if err == nil {
		if fi, serr := os.Stat(path); serr == nil {
			mode = fi.Mode().Perm()
		}
	}
	return true, writeFileAtomicMode(path, merged, mode)
}

func writeFileAtomicMode(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".sync-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func fileSum(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// dirModeFor — права каталога, который приходится создать: закрытые ключи
// EasyRSA — 0700, остальное — 0755.
func dirModeFor(set SyncSet, path string) os.FileMode {
	if set.EasyRSADir != "" && under(set.EasyRSADir, path) && strings.Contains(filepath.ToSlash(path), "/private/") {
		return 0o700
	}
	return 0o755
}

// pruneSyncFiles удаляет файлы набора, которых нет в архиве. setup не удаляется
// никогда. Возвращает удалённые пути.
func pruneSyncFiles(set SyncSet, keep []archiveEntry, env *SyncEnv) ([]string, error) {
	have := map[string]bool{}
	for _, e := range keep {
		have[e.path] = true
	}
	cur, err := set.Manifest()
	if err != nil {
		return nil, err
	}
	var removed, failed []string
	for _, e := range cur {
		p := filepath.FromSlash(e.Path)
		if have[p] {
			continue
		}
		if k, _, _ := set.classify(p); k == kindSetup {
			continue
		}
		if err := os.Remove(p); err != nil {
			env.logf("ОШИБКА удаления %s: %v", p, err)
			failed = append(failed, p)
			continue
		}
		env.logf("удалён %s", p)
		removed = append(removed, p)
	}
	if len(failed) > 0 {
		return removed, fmt.Errorf("не удалены: %s", strings.Join(failed, ", "))
	}
	return removed, nil
}
