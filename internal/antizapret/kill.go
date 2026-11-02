package antizapret

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/limits"
)

var killedRe = regexp.MustCompile(`(\d+) client\(s\) killed`)

// KillClient отключает все сессии клиента в одном экземпляре OpenVPN
// командой управляющего интерфейса «kill <имя>» и возвращает их число.
// Клиента в экземпляре нет — 0 без ошибки.
func KillClient(sockPath, name string, timeout time.Duration) (int, error) {
	// Имя уходит в командную строку интерфейса: перевод строки в нём дал
	// бы вторую, чужую команду.
	if !limits.ValidName(name) {
		return 0, fmt.Errorf("недопустимое имя клиента %q", name)
	}
	deadline := time.Now().Add(timeout)
	conn, err := (&net.Dialer{Deadline: deadline}).Dial("unix", sockPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(conn, "kill "+name+"\n"); err != nil {
		return 0, err
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SUCCESS:"):
			io.WriteString(conn, "quit\n")
			if m := killedRe.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				return n, nil
			}
			return 1, nil
		case strings.HasPrefix(line, "ERROR:"):
			io.WriteString(conn, "quit\n")
			if strings.Contains(line, "not found") {
				return 0, nil
			}
			return 0, fmt.Errorf("%s: %s", sockPath, line)
		}
		if err != nil {
			return 0, fmt.Errorf("%s: нет ответа на kill: %w", sockPath, err)
		}
	}
}
