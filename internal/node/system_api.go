package node

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// Виды задач бота: перезагрузка сервера и бэкап client.sh 8.
const (
	TaskReboot = "reboot"
	TaskBackup = "backup"
)

// DefaultBackupDir — куда client.sh 8 кладёт архив:
// /root/antizapret/backup-<IP>.tar.gz (сверено по client.sh).
const DefaultBackupDir = "/root/antizapret"

// backupNameRe — имя файла бэкапа: backup*.tar.gz без разделителей пути.
var backupNameRe = regexp.MustCompile(`^backup[A-Za-z0-9._()-]*\.tar\.gz$`)

func init() {
	DefaultTaskTimeouts[TaskReboot] = 120 * time.Second
	DefaultTaskTimeouts[TaskBackup] = 600 * time.Second
}

func (a *API) rebootServer(w http.ResponseWriter, r *http.Request) {
	// Под ops: перезагрузка не должна прервать создание или удаление клиента.
	a.startTask(w, TaskReboot, []string{"systemctl", "reboot"}, true)
}

func (a *API) createBackup(w http.ResponseWriter, r *http.Request) {
	a.startTask(w, TaskBackup, []string{filepath.Join(a.AntiZapretDir, "client.sh"), "8"}, true)
}

func (a *API) backupDir() string {
	if a.BackupDir != "" {
		return a.BackupDir
	}
	// client.sh кладёт архив в свой каталог — тот же, откуда запускается.
	if a.AntiZapretDir != "" {
		return a.AntiZapretDir
	}
	return DefaultBackupDir
}

// backupFiles — обычные файлы backup*.tar.gz каталога, новые первыми.
// Ссылки и каталоги пропускаются.
func (a *API) backupFiles() ([]nodeapi.Backup, error) {
	ents, err := os.ReadDir(a.backupDir())
	if errors.Is(err, os.ErrNotExist) {
		return []nodeapi.Backup{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []nodeapi.Backup{}
	for _, e := range ents {
		if !backupNameRe.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, nodeapi.Backup{Name: e.Name(), Size: fi.Size(), Modified: fi.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Modified.Equal(out[j].Modified) {
			return out[i].Modified.After(out[j].Modified)
		}
		return out[i].Name > out[j].Name
	})
	return out, nil
}

func (a *API) listBackups(w http.ResponseWriter, r *http.Request) {
	list, err := a.backupFiles()
	if err != nil {
		a.fail(w, "каталог бэкапов не прочитан", err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// getBackup отдаёт файл бэкапа. Имя берётся только из списка каталога:
// путь из запроса не собирается.
func (a *API) getBackup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !backupNameRe.MatchString(name) {
		writeErr(w, http.StatusNotFound, "бэкап не найден")
		return
	}
	list, err := a.backupFiles()
	if err != nil {
		a.fail(w, "каталог бэкапов не прочитан", err)
		return
	}
	for _, b := range list {
		if b.Name != name {
			continue
		}
		f, err := openRegular(filepath.Join(a.backupDir(), b.Name))
		if err != nil {
			a.fail(w, "бэкап не открыт", err)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/gzip")
		io.Copy(w, f)
		a.Log.Info("бэкап выдан", "file", b.Name)
		return
	}
	writeErr(w, http.StatusNotFound, "бэкап не найден")
}

// openRegular открывает только обычный файл: ссылка, подставленная между
// проверкой списка и открытием, отвергается (сверяются Lstat до и Stat после).
func openRegular(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("не обычный файл")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, errors.New("файл подменён")
	}
	return f, nil
}
