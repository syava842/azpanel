// Package paths — раскладка azpanel на сервере.
package paths

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Root — корень установки. AZPANEL_ROOT переопределяет его (для тестов).
func Root() string {
	if r := os.Getenv("AZPANEL_ROOT"); r != "" {
		return r
	}
	return "/opt/azpanel"
}

func Bin() string    { return filepath.Join(Root(), "bin") }
func Etc() string    { return filepath.Join(Root(), "etc") }
func Log() string    { return filepath.Join(Root(), "log") }
func Data() string   { return filepath.Join(Root(), "data") }
func Backup() string { return filepath.Join(Root(), "backup") }

// Подкаталоги backup/: каждый вид бэкапа лежит отдельно.
const (
	BackupSelfDir       = "azpanel"    // перед обновлением самой панели: update-*.tar.gz
	BackupAntiZapretDir = "antizapret" // полные архивы AntiZapret: перед его обновлением и перед удалением панели
	BackupListsDir      = "lists"      // прежние версии списков маршрутизации и setup
	BackupNginxDir      = "nginx"      // прежние версии конфигов nginx
)

func BackupSelf() string       { return filepath.Join(Backup(), BackupSelfDir) }
func BackupAntiZapret() string { return filepath.Join(Backup(), BackupAntiZapretDir) }
func BackupLists() string      { return filepath.Join(Backup(), BackupListsDir) }
func BackupNginx() string      { return filepath.Join(Backup(), BackupNginxDir) }

// MigrateBackupLayout раскладывает бэкапы версий до 0.1.2 по подкаталогам:
// раньше update-*.tar.gz и backup-azpanel-*.tar.gz лежали прямо в backup/, а
// копии списков — вместе с архивами в backup/antizapret. Файл, который уже
// есть на новом месте, не затирается. Повторный вызов ничего не делает.
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
	archive := func(prefix string) func(string) bool {
		return func(n string) bool { return strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ".tar.gz") }
	}
	isUpdate := archive("update-")
	if err := move(root, BackupSelf(), func(n string) bool { return isUpdate(n) && settled(root, n) }); err != nil {
		return err
	}
	if err := move(root, BackupAntiZapret(), archive("backup-azpanel-")); err != nil {
		return err
	}
	// В backup/antizapret остаются только архивы; всё прочее — копии списков.
	return move(BackupAntiZapret(), BackupLists(), func(n string) bool { return !strings.HasSuffix(n, ".tar.gz") })
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
