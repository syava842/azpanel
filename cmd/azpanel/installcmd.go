package main

import (
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/paths"
)

func installOptions(args []string) (install.Options, error) {
	o := install.Defaults()
	if cfg, err := config.Load(paths.ConfigFile()); err == nil {
		o.ScriptsDir = cfg.Node.OpenVPNScriptsDir
	}
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			o.Yes = true
		case "--panel":
			o.Panel = true
		case "--purge":
			o.Purge = true
		default:
			return o, errUsage
		}
	}
	return o, nil
}

func runInstall(args []string) error {
	o, err := installOptions(args)
	if err != nil {
		return err
	}
	return install.InstallNode(o)
}

func runUninstall(args []string) error {
	o, err := installOptions(args)
	if err != nil {
		return err
	}
	return install.Uninstall(o)
}
