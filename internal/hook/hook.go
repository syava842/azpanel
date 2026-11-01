// Package hook — «azpanel hook connect|disconnect», вызывается из скриптов
// OpenVPN от nobody. Файлов не пишет: решения записывает агент.
package hook

import (
	"fmt"
	"io"
	"net"
	"path"
	"strings"

	"github.com/syava842/azpanel/internal/agentproto"
	"github.com/syava842/azpanel/internal/antizapret"
)

// ExitDeny — единственный код, по которому скрипт отказывает в подключении.
const ExitDeny = 3

type Caller func(agentproto.Request) (agentproto.Response, error)

// Run возвращает код выхода процесса. Отказ — только по явному ответу
// агента; любая ошибка — 0.
func Run(op string, env func(string) string, call Caller, stderr io.Writer) int {
	cn := env("common_name")
	if cn == "" {
		return 0
	}
	req := agentproto.Request{
		CN:       cn,
		Instance: strings.TrimSuffix(path.Base(env("config")), ".conf"),
		Addr:     antizapret.NormalizeAddr(net.JoinHostPort(env("trusted_ip"), env("trusted_port"))),
	}
	switch op {
	case "connect":
		req.Op = agentproto.OpConnect
	case "disconnect":
		req.Op = agentproto.OpDisconnect
	default:
		fmt.Fprintf(stderr, "azpanel hook: неизвестная операция %q\n", op)
		return 0
	}
	resp, err := call(req)
	if err != nil {
		fmt.Fprintf(stderr, "azpanel hook: агент недоступен (%v), лимит для %s не проверен\n", err, cn)
		return 0
	}
	if req.Op == agentproto.OpConnect && !resp.Allow {
		fmt.Fprintf(stderr, "azpanel hook: отказ %s — подключений %d из %d\n", cn, resp.Count, resp.Limit)
		return ExitDeny
	}
	return 0
}
