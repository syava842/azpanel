package node

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/sysinfo"
)

// SyncApplyParams — параметры задачи sync-apply (`azpanel internal sync-apply
// --params ФАЙЛ`). Задача идёт вне песочницы агента: пишет в /etc/openvpn,
// /etc/wireguard, /etc/knot-resolver и /root/antizapret.
type SyncApplyParams struct {
	Set     SyncSet `json:"set"`
	Archive string  `json:"archive"` // tar, уже проверенный агентом
	Stage   string  `json:"stage"`   // каталог архива: удаляется по окончании
	Force   bool    `json:"force"`   // разрешить удаление ключевых файлов и больше половины набора
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

// SyncArchive — разобранный и проверенный архив: файлы для записи и пути к
// удалению (служебная запись nodeapi.SyncRemoveEntry).
type SyncArchive struct {
	Entries []archiveEntry
	Remove  []string
}

// maxRemoveList — предел служебной записи со списком удаления.
const maxRemoveList = 8 << 20

// ValidateArchive читает tar и возвращает файлы для записи; список удаления
// проверяется, но не возвращается (см. ParseArchive).
func ValidateArchive(set SyncSet, r io.Reader) ([]archiveEntry, error) {
	a, err := ParseArchive(set, r)
	return a.Entries, err
}

// ParseArchive читает tar от начала до конца и проверяет каждую запись:
// обычный файл, путь чистый, абсолютный и входит в набор, без повторов, без
// симлинков по пути. Служебная запись nodeapi.SyncRemoveEntry — список путей
// к удалению; к нему те же требования, setup удалять нельзя. Ничего не пишет
// на диск. Ошибка — ErrNotInSet или текст о том, какая запись не подошла;
// вызывающий отвечает 400.
func ParseArchive(set SyncSet, r io.Reader) (SyncArchive, error) {
	tr := tar.NewReader(r)
	var out SyncArchive
	seen := map[string]bool{}
	haveRemove := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return SyncArchive{}, fmt.Errorf("архив не разобран: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return SyncArchive{}, fmt.Errorf("%s: в архиве допустимы только обычные файлы", h.Name)
		}
		if h.Name == nodeapi.SyncRemoveEntry {
			if haveRemove {
				return SyncArchive{}, errors.New("список удаления повторён в архиве")
			}
			haveRemove = true
			if out.Remove, err = readRemoveList(set, tr); err != nil {
				return SyncArchive{}, err
			}
			continue
		}
		p := filepath.FromSlash(h.Name)
		kind, root, ok := set.classify(p)
		if !ok {
			return SyncArchive{}, fmt.Errorf("%w: %s", ErrNotInSet, h.Name)
		}
		if seen[p] {
			return SyncArchive{}, fmt.Errorf("%s: файл повторён в архиве", h.Name)
		}
		seen[p] = true
		if err := noSymlinks(root, p); err != nil {
			return SyncArchive{}, fmt.Errorf("%s: %w", h.Name, err)
		}
		if kind == kindSetup && h.Size > maxSetupSize {
			return SyncArchive{}, errors.New("setup больше 1 МБ")
		}
		out.Entries = append(out.Entries, archiveEntry{path: p, mode: os.FileMode(h.Mode).Perm(), size: h.Size})
	}
	for _, p := range out.Remove {
		if seen[p] {
			return SyncArchive{}, fmt.Errorf("%s: файл и в архиве, и в списке удаления", p)
		}
	}
	return out, nil
}

func readRemoveList(set SyncSet, r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRemoveList+1))
	if err != nil {
		return nil, fmt.Errorf("список удаления не прочитан: %w", err)
	}
	if len(data) > maxRemoveList {
		return nil, errors.New("список удаления больше 8 МБ")
	}
	var raw []string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("список удаления: нужен JSON-массив путей")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, n := range raw {
		p := filepath.FromSlash(n)
		kind, root, ok := set.classify(p)
		if !ok {
			return nil, fmt.Errorf("удаление: %w: %s", ErrNotInSet, n)
		}
		if kind == kindSetup {
			return nil, fmt.Errorf("удаление: %s — setup не удаляется", n)
		}
		if seen[p] {
			return nil, fmt.Errorf("удаление: %s повторён", n)
		}
		seen[p] = true
		if err := noSymlinks(root, p); err != nil {
			return nil, fmt.Errorf("удаление: %s: %w", n, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// ErrRemovalRefused — удаление отклонено защитой (нужен force).
var ErrRemovalRefused = errors.New("удаление отклонено")

// CheckRemoval решает, можно ли выполнять список удаления. Без force
// отклоняются: удаление ключевых файлов (CA, index.txt, ключи сервера,
// ключи и конфиги WireGuard) и удаление более половины набора (от десяти
// файлов) — признаки неполного манифеста основного, а не воли оператора.
// Пустой архив без списка удаления — тоже отказ.
func CheckRemoval(set SyncSet, a SyncArchive, force bool) error {
	if len(a.Entries) == 0 && len(a.Remove) == 0 {
		return errors.New("архив пуст")
	}
	if len(a.Remove) == 0 || force {
		return nil
	}
	var crit []string
	for _, p := range a.Remove {
		if criticalSyncFile(set, p) {
			crit = append(crit, p)
		}
	}
	if len(crit) > 0 {
		return fmt.Errorf("%w: в списке ключевые файлы (%s) — без force не удаляются", ErrRemovalRefused, strings.Join(crit, ", "))
	}
	cur, err := set.Manifest()
	if err != nil {
		return err
	}
	if n := len(a.Remove); n >= 10 && n*2 > len(cur) {
		return fmt.Errorf("%w: удаляется %d файлов из %d — без force так много не удаляют (манифест основного неполон?)", ErrRemovalRefused, n, len(cur))
	}
	return nil
}

// criticalSyncFile — файлы, потеря которых ломает PKI или туннели реплики.
func criticalSyncFile(set SyncSet, p string) bool {
	kind, _, ok := set.classify(p)
	if !ok {
		return false
	}
	switch kind {
	case kindWireGuard, kindAmnezia:
		return true
	case kindEasyRSA:
		rel, _ := filepath.Rel(set.EasyRSADir, p)
		rel = filepath.ToSlash(rel)
		switch rel {
		case "pki/ca.crt", "pki/private/ca.key", "pki/index.txt", "pki/serial", "pki/dh.pem", "pki/crl.pem":
			return true
		}
		return (strings.HasPrefix(rel, "pki/issued/") || strings.HasPrefix(rel, "pki/private/")) && strings.Contains(filepath.Base(rel), "server")
	}
	return false
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
	arch, err := ParseArchive(p.Set, f)
	if err != nil {
		return err
	}
	if err := CheckRemoval(p.Set, arch, p.Force); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	env.logf("в архиве файлов: %d, к удалению: %d", len(arch.Entries), len(arch.Remove))

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
		if h.Name == nodeapi.SyncRemoveEntry {
			continue
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
	if len(arch.Remove) > 0 {
		removed, rerr := removeSyncFiles(p.Set, arch.Remove, env)
		changed = append(changed, removed...)
		if rerr != nil {
			failed = append(failed, rerr.Error())
		}
	}
	env.logf("изменено файлов: %d", len(changed))
	for _, n := range p.Set.needsApply(changed) {
		env.logf("НУЖНО ПРИМЕНИТЬ: %s", n)
	}
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
	var local os.FileMode
	hasLocal := false
	if fi, err := os.Stat(path); err == nil {
		local, hasLocal = fi.Mode().Perm(), true
	}
	mode = safeMode(kind, path, mode, local, hasLocal)
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
		// Содержимое то же: права, если разошлись, поправляются, но это не
		// изменение — перезапускать службы из-за них нельзя.
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() != mode {
			return false, os.Chmod(path, mode)
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

// safeMode ограничивает права файла из архива: панель основного не должна
// решать, что файл на реплике доступен на запись всем или исполняется.
// Группа и остальные не пишут; секреты (ключи PKI, ключи и конфиги
// WireGuard, setup с ключами WARP) — не шире 0640; прочее — не шире 0644.
// Исполняемость сохраняется только у *.sh и у файла, который уже исполняем
// на реплике (например, easyrsa), и только если она есть в архиве.
func safeMode(kind syncKind, path string, mode, local os.FileMode, hasLocal bool) os.FileMode {
	m := mode.Perm() &^ 0o022
	exec := m&0o111 != 0 && (matches("*.sh", filepath.Base(path)) || (hasLocal && local&0o111 != 0))
	if !exec {
		m &^= 0o111
	}
	if syncSecret(kind, path) {
		m &= 0o640
	}
	return m
}

// syncSecret — файл с секретом: читать его группе можно, остальным нельзя.
func syncSecret(kind syncKind, path string) bool {
	switch kind {
	case kindWireGuard, kindAmnezia, kindSetup:
		return true
	case kindEasyRSA:
		return strings.Contains(filepath.ToSlash(path), "/private/") || strings.HasSuffix(path, ".key")
	}
	return false
}

// dirModeFor — права каталога, который приходится создать: закрытые ключи
// EasyRSA — 0700, остальное — 0755.
func dirModeFor(set SyncSet, path string) os.FileMode {
	if set.EasyRSADir != "" && under(set.EasyRSADir, path) && strings.Contains(filepath.ToSlash(path), "/private/") {
		return 0o700
	}
	return 0o755
}

// removeSyncFiles удаляет файлы из списка удаления, и только их. Каждый путь
// проверяется заново: он по-прежнему входит в набор, не симлинк и обычный
// файл. Нет файла — не ошибка (реплика уже расходится с основным). Возвращает
// удалённые пути.
func removeSyncFiles(set SyncSet, remove []string, env *SyncEnv) ([]string, error) {
	var removed, failed []string
	for _, p := range remove {
		_, root, ok := set.classify(p)
		if !ok {
			failed = append(failed, p)
			continue
		}
		if err := noSymlinks(root, p); err != nil {
			env.logf("ОШИБКА удаления %s: %v", p, err)
			failed = append(failed, p)
			continue
		}
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !fi.Mode().IsRegular() {
			env.logf("ОШИБКА удаления %s: не обычный файл", p)
			failed = append(failed, p)
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

// needsApply — что изменилось такого, что одной записью файлов не
// вступает в силу: списки маршрутизации и setup начинают действовать после
// doall и перезапуска AntiZapret, которые запускает панель (маршрут
// routing/apply), а не эта задача.
func (s SyncSet) needsApply(changed []string) []string {
	var out []string
	routing, setup := false, false
	for _, p := range changed {
		switch k, _, _ := s.classify(p); k {
		case kindRouting:
			routing = true
		case kindSetup:
			setup = true
		}
	}
	if routing {
		out = append(out, "списки config/*.txt изменены — выполните «Применить маршрутизацию» (doall)")
	}
	if setup {
		out = append(out, "setup изменён — выполните «Применить маршрутизацию» и перезапуск AntiZapret")
	}
	return out
}
