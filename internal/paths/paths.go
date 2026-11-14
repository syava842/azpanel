// Package paths — раскладка azpanel на сервере.
package paths

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultRoot — каталог установки: рядом с /root/antizapret, как у
	// остальных сервисов вокруг AntiZapret.
	DefaultRoot = "/root/azpanel"
	// LegacyRoot — каталог версий до 0.1.2. Пока сервер не перенесён
	// (azpanel relocate), программа работает из него.
	LegacyRoot = "/opt/azpanel"
	// hookDir — копия программы для хука OpenVPN: он работает от nobody, а
	// /root закрыт всем, кроме root.
	hookDir = "/usr/local/lib/azpanel"
	// DefaultHookBinary — та самая копия при установке в DefaultRoot.
	DefaultHookBinary = hookDir + "/azpanel"
)

// isDir подменяется в тестах.
var isDir = func(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// Root — корень установки. AZPANEL_ROOT переопределяет его (для тестов).
// Без него: /root/azpanel; если его нет, а старый /opt/azpanel есть — старый.
func Root() string {
	if r := os.Getenv("AZPANEL_ROOT"); r != "" {
		return r
	}
	if !isDir(filepath.Join(DefaultRoot, "etc")) && isDir(filepath.Join(LegacyRoot, "etc")) {
		return LegacyRoot
	}
	return DefaultRoot
}

// Legacy — установка ещё в прежнем каталоге /opt/azpanel.
func Legacy() bool { return os.Getenv("AZPANEL_ROOT") == "" && Root() == LegacyRoot }

// underRootHome — каталог внутри /root: туда не попасть никому, кроме root.
func underRootHome(p string) bool { return p == "/root" || strings.HasPrefix(p, "/root/") }

// HookBinary — программа, которую вызывает хук OpenVPN. При установке в
// /root это отдельная копия в /usr/local/lib/azpanel (её обновляет агент при
// запуске); иначе — сам бинарник.
func HookBinary() string {
	// Под AZPANEL_ROOT (тесты) системный каталог не трогаем никогда.
	if os.Getenv("AZPANEL_ROOT") == "" && underRootHome(filepath.ToSlash(Root())) {
		return DefaultHookBinary
	}
	return Binary()
}

// HookDir — каталог копии для хука; пусто — копия не нужна.
func HookDir() string {
	if HookBinary() == Binary() {
		return ""
	}
	return hookDir
}

func Bin() string    { return filepath.Join(Root(), "bin") }
func Etc() string    { return filepath.Join(Root(), "etc") }
func Log() string    { return filepath.Join(Root(), "log") }
func Data() string   { return filepath.Join(Root(), "data") }
func Backup() string { return filepath.Join(Root(), "backup") }

// Подкаталоги backup/: каждый вид бэкапа лежит отдельно. Всё, что связано с
// AntiZapret (в копиях setup — ключи WARP), остаётся внутри
// backup/antizapret: этот каталог закрыт службе панели (InaccessiblePaths),
// и файл службы на уже установленных серверах при обновлении не меняется.
const (
	BackupSelfDir = "azpanel" // перед обновлением самой панели: update-*.tar.gz
	backupAZDir   = "antizapret"
)

func BackupSelf() string { return filepath.Join(Backup(), BackupSelfDir) }

// BackupAntiZapret — полные архивы AntiZapret: перед его обновлением и перед
// удалением панели.
func BackupAntiZapret() string { return filepath.Join(Backup(), backupAZDir, "archives") }

// BackupLists — прежние версии списков маршрутизации и setup.
func BackupLists() string { return filepath.Join(Backup(), backupAZDir, "lists") }

// BackupNginx — прежние версии конфигов nginx.
func BackupNginx() string { return filepath.Join(Backup(), "nginx") }

// MigrateBackupLayout раскладывает бэкапы версий до 0.1.2 по подкаталогам:
// раньше update-*.tar.gz и backup-azpanel-*.tar.gz лежали прямо в backup/, а
// копии списков — вперемешку с архивами в backup/antizapret. Файл, который
// уже есть на новом месте, не затирается. Повторный вызов ничего не делает.
//
// update-*.tar.gz моложе часа не трогается: это бэкап идущего обновления, и
// прежняя версия, которая его написала, при сбое проверки откатится по
// старому пути. Такой файл переедет при следующем запуске.
func MigrateBackupLayout() error {
	root := Backup()
	if _, err := os.Stat(root); err != nil {
		return nil // установки ещё нет
	}
	settled := func(dir, name string) bool {
		info, err := os.Stat(filepath.Join(dir, name))
		return err == nil && time.Since(info.ModTime()) > time.Hour
	}
	move := func(fromDir, toDir string, match func(name string) bool) error {
		entries, err := os.ReadDir(fromDir)
		if err != nil {
			return nil
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || !match(e.Name()) {
				continue
			}
			if err := os.MkdirAll(toDir, 0o700); err != nil {
				return err
			}
			dst := filepath.Join(toDir, e.Name())
			if _, err := os.Lstat(dst); err == nil {
				continue
			}
			if err := os.Rename(filepath.Join(fromDir, e.Name()), dst); err != nil {
				return err
			}
		}
		return nil
	}
	isArchive := func(n string) bool { return strings.HasSuffix(n, ".tar.gz") }
	prefixed := func(prefix string) func(string) bool {
		return func(n string) bool { return strings.HasPrefix(n, prefix) && isArchive(n) }
	}
	isUpdate := prefixed("update-")
	if err := move(root, BackupSelf(), func(n string) bool { return isUpdate(n) && settled(root, n) }); err != nil {
		return err
	}
	if err := move(root, BackupAntiZapret(), prefixed("backup-azpanel-")); err != nil {
		return err
	}
	// Файлы прямо в backup/antizapret: архивы — в archives, копии списков — в lists.
	az := filepath.Join(root, backupAZDir)
	if err := move(az, BackupAntiZapret(), isArchive); err != nil {
		return err
	}
	return move(az, BackupLists(), func(n string) bool { return !isArchive(n) })
}

func Binary() string      { return filepath.Join(Bin(), "azpanel") }
func ConfigFile() string  { return filepath.Join(Etc(), "config.toml") }
func SecretsFile() string { return filepath.Join(Etc(), "secrets.env") }
func LimitsFile() string  { return filepath.Join(Data(), "limits.json") }

// CommandLink — ссылка на бинарник в PATH, чтобы команда azpanel работала
// без полного пути.
func CommandLink() string {
	if os.Getenv("AZPANEL_ROOT") != "" {
		return filepath.Join(Root(), "usr-local-bin", "azpanel")
	}
	return "/usr/local/bin/azpanel"
}

// NodeSocket — сокет агента. Путь не настраивается: хук работает от nobody,
// config.toml ему не прочитать.
func NodeSocket() string {
	if os.Getenv("AZPANEL_ROOT") != "" {
		return filepath.Join(Root(), "run", "node.sock")
	}
	return "/run/azpanel/node.sock"
}
