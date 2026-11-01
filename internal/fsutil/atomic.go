// Package fsutil — работа с файлами, общая для всех режимов.
package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic пишет файл через временный рядом и rename: читатель видит
// либо прежнее содержимое, либо новое целиком.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // после rename файла под этим именем уже нет
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
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // на Windows каталог не синхронизируется — ошибка не важна
		d.Close()
	}
	return nil
}
