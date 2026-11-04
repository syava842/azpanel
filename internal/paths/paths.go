// Package paths — раскладка azpanel на сервере.
package paths

import (
	"os"
	"path/filepath"
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
