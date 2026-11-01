// Package config — /opt/azpanel/etc/config.toml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/syava842/azpanel/internal/fsutil"
)

// CurrentVersion — версия структуры конфига, которую знает этот бинарник.
const CurrentVersion = 1

type Config struct {
	ConfigVersion int  `toml:"config_version"`
	Node          Node `toml:"node"`
	Log           Log  `toml:"log"`
}

type Node struct {
	OpenVPNSocketDir  string `toml:"openvpn_socket_dir"`
	OpenVPNScriptsDir string `toml:"openvpn_scripts_dir"`
	PollSeconds       int    `toml:"poll_seconds"`
	QueryTimeoutMs    int    `toml:"query_timeout_ms"`
}

type Log struct {
	MaxSizeMB int `toml:"max_size_mb"`
	Keep      int `toml:"keep"`
}

func Default() Config {
	return Config{
		ConfigVersion: CurrentVersion,
		Node: Node{
			OpenVPNSocketDir:  "/run/openvpn-server",
			OpenVPNScriptsDir: "/etc/openvpn/server/scripts",
			PollSeconds:       5,
			QueryTimeoutMs:    1000,
		},
		Log: Log{MaxSizeMB: 10, Keep: 5},
	}
}

// Load читает конфиг поверх умолчаний; нет файла — умолчания. При ошибке
// вместе с ней возвращаются умолчания.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return Default(), err
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	if c.ConfigVersion > CurrentVersion {
		return Default(), fmt.Errorf("%s: config_version %d новее, чем знает эта версия azpanel (%d)", path, c.ConfigVersion, CurrentVersion)
	}
	if c.ConfigVersion < 1 {
		c.ConfigVersion = CurrentVersion
	}
	if err := c.Validate(); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c Config) Validate() error {
	switch {
	case c.Node.OpenVPNSocketDir == "":
		return errors.New("node.openvpn_socket_dir пуст")
	case c.Node.OpenVPNScriptsDir == "":
		return errors.New("node.openvpn_scripts_dir пуст")
	case c.Node.PollSeconds < 1 || c.Node.PollSeconds > 60:
		return fmt.Errorf("node.poll_seconds = %d, нужно 1..60", c.Node.PollSeconds)
	case c.Node.QueryTimeoutMs < 100 || c.Node.QueryTimeoutMs > 5000:
		return fmt.Errorf("node.query_timeout_ms = %d, нужно 100..5000", c.Node.QueryTimeoutMs)
	case c.Log.MaxSizeMB < 1 || c.Log.MaxSizeMB > 1000:
		return fmt.Errorf("log.max_size_mb = %d, нужно 1..1000", c.Log.MaxSizeMB)
	case c.Log.Keep < 1 || c.Log.Keep > 100:
		return fmt.Errorf("log.keep = %d, нужно 1..100", c.Log.Keep)
	}
	return nil
}

func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, buf.Bytes(), 0o600)
}
