package antizapret

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Listen — на чём слушает экземпляр OpenVPN: протокол (udp, tcp) и порт из
// строк «proto» и «port» его конфига.
type Listen struct {
	Proto string
	Port  int
}

// InstanceListen читает <confDir>/<instance>.conf. Нет файла или строк —
// протокол по имени экземпляра (…-udp, …-tcp), порт 0.
func InstanceListen(confDir, instance string) Listen {
	var l Listen
	if f, err := os.Open(filepath.Join(confDir, instance+".conf")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "proto":
				l.Proto = strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(fields[1], "-server"), "-client"), "46")
			case "port":
				l.Port, _ = strconv.Atoi(fields[1])
			}
		}
		f.Close()
	}
	if l.Proto == "" {
		switch {
		case strings.HasSuffix(instance, "-udp"):
			l.Proto = "udp"
		case strings.HasSuffix(instance, "-tcp"):
			l.Proto = "tcp"
		}
	}
	return l
}
