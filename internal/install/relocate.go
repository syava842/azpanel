package install

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/paths"
)

// RelocateOptions — перенос установки из прежнего каталога (/opt/azpanel) в
// новый (/root/azpanel). Все пути явные: в тестах подменяются целиком.
type RelocateOptions struct {
	From, To   string // каталоги установки
	UnitDir    string // /etc/systemd/system
	ScriptsDir string // скрипты OpenVPN с хуком; пусто или нет каталога — хук не трогается
	LinkPath   string // /usr/local/bin/azpanel
	HookBinary string // копия программы для хука; пусто — хук зовёт сам бинарник
	// NginxGlobs — где искать конфиги nginx с прежним путём (сертификат в
	// etc/tls при своём порте); пусто — nginx не трогается.
	NginxGlobs []string
	Out        io.Writer
	Run        func(name string, args ...string) error
	// Wait ждёт ответа агента после запуска; nil — не ждать.
	Wait func() error
}

// LegacyRelocation — перенос прежней установки /opt/azpanel в /root/azpanel
// на настоящей системе. scriptsDir — каталог скриптов OpenVPN из конфига.
func LegacyRelocation(scriptsDir string) RelocateOptions {
	d := Defaults()
	return RelocateOptions{
		From: paths.LegacyRoot, To: paths.DefaultRoot,
		UnitDir: d.UnitDir, ScriptsDir: scriptsDir,
		LinkPath: paths.CommandLink(), HookBinary: paths.DefaultHookBinary,
		NginxGlobs: []string{"/etc/nginx/sites-available/*", "/etc/nginx/snippets/*", "/etc/nginx/conf.d/*"},
		Out:        d.Out, Run: d.Run, Wait: d.Wait,
	}
}

// Relocate переносит установку: останавливает службы, перемещает каталог,
// правит пути в настройках, переписывает юниты, копию для хука, хук и ссылку
// команды, запускает службы. При сбое после перемещения возвращает всё на
// место и запускает службы из прежнего каталога.
func Relocate(o RelocateOptions) error {
	if _, err := os.Stat(filepath.Join(o.From, "etc")); err != nil {
		return fmt.Errorf("в %s установки нет: переносить нечего", o.From)
	}
	if _, err := os.Lstat(o.To); err == nil {
		return fmt.Errorf("%s уже существует: перенос остановлен, ничего не изменено", o.To)
	}
	if err := os.MkdirAll(filepath.Dir(o.To), 0o700); err != nil {
		return err
	}
	type unit struct {
		name, svc string
		build     func(bin string) string
		old       []byte
	}
	fromSlash, toSlash := filepath.ToSlash(o.From), filepath.ToSlash(o.To)
	hookDir := ""
	if o.HookBinary != "" {
		hookDir = filepath.ToSlash(filepath.Dir(o.HookBinary))
	}
	all := []unit{
		{name: nodeUnitName, svc: "azpanel-node", build: func(bin string) string { return nodeUnit(bin, toSlash, hookDir) }},
		{name: panelUnitName, svc: "azpanel-panel", build: func(bin string) string { return panelUnit(bin, toSlash) }},
		{name: proxyUnitName, svc: "azpanel-proxy", build: func(bin string) string { return proxyUnit(bin, toSlash) }},
	}
	var units []unit
	for _, u := range all {
		data, err := os.ReadFile(filepath.Join(o.UnitDir, u.name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		u.old = data
		units = append(units, u)
	}
	hasNode := len(units) > 0 && units[0].name == nodeUnitName

	fmt.Fprintf(o.Out, "Перенос %s -> %s\n", o.From, o.To)
	for i := len(units) - 1; i >= 0; i-- { // панель раньше агента
		if err := o.Run("systemctl", "stop", units[i].svc); err != nil {
			return fmt.Errorf("служба %s не остановлена, ничего не перенесено: %w", units[i].svc, err)
		}
	}
	start := func() error {
		if err := o.Run("systemctl", "daemon-reload"); err != nil {
			return err
		}
		for _, u := range units {
			if err := o.Run("systemctl", "start", u.svc); err != nil {
				return err
			}
			if u.name == nodeUnitName && o.Wait != nil {
				if err := o.Wait(); err != nil {
					return fmt.Errorf("агент не ответил: %w", err)
				}
			}
		}
		return nil
	}

	if err := moveDir(o.From, o.To, o.Run); err != nil {
		if serr := start(); serr != nil {
			return fmt.Errorf("каталог не перемещён: %w; службы не запущены: %v", err, serr)
		}
		return fmt.Errorf("каталог не перемещён, службы запущены из %s: %w", o.From, err)
	}
	bin := toSlash + "/bin/azpanel"
	oldBin := filepath.Join(o.From, "bin", "azpanel")
	nginxOld := map[string][]byte{} // прежнее содержимое изменённых конфигов nginx
	apply := func() error {
		if err := replaceInFiles(o.To, fromSlash, toSlash); err != nil {
			return fmt.Errorf("пути в настройках: %w", err)
		}
		if err := replaceInNginx(o.NginxGlobs, fromSlash, toSlash, nginxOld); err != nil {
			return fmt.Errorf("конфиги nginx: %w", err)
		}
		if len(nginxOld) > 0 {
			if err := o.Run("nginx", "-t"); err != nil {
				return fmt.Errorf("nginx -t после правки путей: %w", err)
			}
			if err := o.Run("systemctl", "reload", "nginx"); err != nil {
				return fmt.Errorf("nginx не перечитал конфиг: %w", err)
			}
		}
		for _, u := range units {
			if err := fsutil.WriteFileAtomic(filepath.Join(o.UnitDir, u.name), []byte(u.build(bin)), 0o644); err != nil {
				return err
			}
		}
		hookBin := filepath.Join(o.To, "bin", "azpanel")
		if o.HookBinary != "" {
			if err := syncFile(hookBin, o.HookBinary); err != nil {
				return fmt.Errorf("копия программы для хука: %w", err)
			}
			hookBin = o.HookBinary
		}
		if hasNode && o.ScriptsDir != "" {
			if _, err := os.Stat(o.ScriptsDir); err == nil {
				if _, err := (antizapret.HookFiles{ScriptsDir: o.ScriptsDir, Binary: filepath.ToSlash(hookBin)}).Ensure(); err != nil {
					return fmt.Errorf("хук: %w", err)
				}
			}
		}
		return nil
	}
	if err := apply(); err != nil {
		// Назад: прежние юниты, каталог на старое место, прежний хук.
		var undo []error
		for _, u := range units {
			undo = append(undo, fsutil.WriteFileAtomic(filepath.Join(o.UnitDir, u.name), u.old, 0o644))
		}
		undo = append(undo, replaceInFiles(o.To, toSlash, fromSlash)) // пути в настройках — обратно
		undo = append(undo, moveDir(o.To, o.From, o.Run))
		for p, data := range nginxOld {
			undo = append(undo, fsutil.WriteFileAtomic(p, data, 0o644))
		}
		if len(nginxOld) > 0 {
			undo = append(undo, o.Run("systemctl", "reload", "nginx"))
		}
		if hasNode && o.ScriptsDir != "" {
			if _, serr := os.Stat(o.ScriptsDir); serr == nil {
				_, herr := (antizapret.HookFiles{ScriptsDir: o.ScriptsDir, Binary: filepath.ToSlash(oldBin)}).Ensure()
				undo = append(undo, herr)
			}
		}
		undo = append(undo, start())
		if uerr := errors.Join(undo...); uerr != nil {
			return fmt.Errorf("перенос не удался: %w; ВОЗВРАТ НЕ УДАЛСЯ: %v", err, uerr)
		}
		return fmt.Errorf("перенос не удался, всё возвращено в %s: %w", o.From, err)
	}
	relinkCommand(o.LinkPath, oldBin, filepath.Join(o.To, "bin", "azpanel"), o.Out)
	if err := start(); err != nil {
		return fmt.Errorf("каталог перенесён в %s, но службы не запустились: %w (журнал: %s)", o.To, err, filepath.Join(o.To, "log"))
	}
	fmt.Fprintf(o.Out, "Готово: azpanel теперь в %s\n", o.To)
	return nil
}

// moveDir перемещает каталог; между разными файловыми системами — через mv.
func moveDir(from, to string, run func(name string, args ...string) error) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	return run("mv", from, to)
}

// replaceInFiles меняет прежний путь установки на новый в текстовых файлах,
// где он мог быть записан: настройки, ответы мастера, состояние задач.
// Права файлов сохраняются; файлы без прежнего пути не переписываются.
func replaceInFiles(root, from, to string) error {
	files := []string{filepath.Join(root, "etc", "config.toml"), filepath.Join(root, "etc", "install.env")}
	more, err := filepath.Glob(filepath.Join(root, "data", "*.json"))
	if err != nil {
		return err
	}
	for _, p := range append(files, more...) {
		info, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !bytes.Contains(data, []byte(from)) {
			continue
		}
		if err := fsutil.WriteFileAtomic(p, bytes.ReplaceAll(data, []byte(from), []byte(to)), info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// replaceInNginx меняет прежний путь в конфигах nginx и запоминает прежнее
// содержимое изменённых файлов в old.
func replaceInNginx(globs []string, from, to string, old map[string][]byte) error {
	for _, g := range globs {
		list, err := filepath.Glob(g)
		if err != nil {
			return err
		}
		for _, p := range list {
			info, err := os.Lstat(p)
			if err != nil || !info.Mode().IsRegular() {
				continue // ссылки sites-enabled ведут на те же файлы sites-available
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if !bytes.Contains(data, []byte(from)) {
				continue
			}
			if err := fsutil.WriteFileAtomic(p, bytes.ReplaceAll(data, []byte(from), []byte(to)), info.Mode().Perm()); err != nil {
				return err
			}
			old[p] = data
		}
	}
	return nil
}

// relinkCommand переводит ссылку команды azpanel на новый бинарник. Чужой
// файл на её месте не трогает.
func relinkCommand(link, oldTarget, newTarget string, out io.Writer) {
	if link == "" {
		return
	}
	cur, err := os.Readlink(link)
	switch {
	case err == nil && cur == newTarget:
		return
	case err == nil && filepath.ToSlash(cur) == filepath.ToSlash(oldTarget):
		if os.Remove(link) != nil {
			fmt.Fprintf(out, "ссылка %s не обновлена: команда доступна как %s\n", link, newTarget)
			return
		}
	default:
		if _, lerr := os.Lstat(link); lerr == nil {
			fmt.Fprintf(out, "%s занят чужим файлом: команда доступна как %s\n", link, newTarget)
			return
		}
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err == nil {
		err = os.Symlink(newTarget, link)
		if err == nil {
			return
		}
	}
	fmt.Fprintf(out, "ссылка %s не создана: команда доступна как %s\n", link, newTarget)
}
