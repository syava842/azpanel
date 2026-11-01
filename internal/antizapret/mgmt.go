// Package antizapret — работа с файлами, скриптами и службами AntiZapret.
package antizapret

import (
	"bufio"
	"errors"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Session — одна строка CLIENT_LIST ответа на «status 3».
type Session struct {
	Instance       string
	CommonName     string
	RealAddr       string
	BytesRx        int64
	BytesTx        int64
	ConnectedSince time.Time
}

var ErrIncomplete = errors.New("ответ status оборван до END")

// protoPrefix — протокол перед адресом в Real Address: udp4:, tcp4-server: …
var protoPrefix = regexp.MustCompile(`^(udp|tcp)[46]?(-server|-client)?:`)

// NormalizeAddr приводит адрес клиента к виду ip:port, как в trusted_ip и
// trusted_port хука: OpenVPN пишет перед адресом протокол или метку
// семейства, а IPv4 — в виде ::ffff:a.b.c.d.
func NormalizeAddr(a string) string {
	a = protoPrefix.ReplaceAllString(a, "")
	a = strings.TrimPrefix(a, "[AF_INET6]")
	a = strings.TrimPrefix(a, "[AF_INET]")
	return strings.TrimPrefix(a, "::ffff:")
}

// ParseStatus3 разбирает ответ управляющего интерфейса на «status 3»
// (поля через табуляцию) до строки END.
func ParseStatus3(instance string, r io.Reader) ([]Session, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []Session
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "END" {
			return out, nil
		}
		if strings.HasPrefix(line, ">") {
			continue // приветствие и асинхронные уведомления
		}
		f := strings.Split(line, "\t")
		if len(f) < 9 || f[0] != "CLIENT_LIST" || f[1] == "UNDEF" {
			continue // UNDEF — рукопожатие ещё не закончено
		}
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		since, _ := strconv.ParseInt(f[8], 10, 64)
		out = append(out, Session{
			Instance:       instance,
			CommonName:     f[1],
			RealAddr:       NormalizeAddr(f[2]),
			BytesRx:        rx,
			BytesTx:        tx,
			ConnectedSince: time.Unix(since, 0),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, ErrIncomplete
}

// QueryStatus спрашивает «status 3» у одного экземпляра. Управляющий
// интерфейс обслуживает одного собеседника за раз, поэтому соединение
// держится не дольше timeout.
func QueryStatus(sockPath string, timeout time.Duration) ([]Session, error) {
	conn, err := net.DialTimeout("unix", sockPath, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, "status 3\n"); err != nil {
		return nil, err
	}
	s, err := ParseStatus3(InstanceFromSocket(sockPath), conn)
	io.WriteString(conn, "quit\n")
	return s, err
}

// InstanceFromSocket: /run/openvpn-server/antizapret-udp.sock → antizapret-udp.
func InstanceFromSocket(p string) string {
	return strings.TrimSuffix(filepath.Base(p), ".sock")
}

func ListSockets(dir string) ([]string, error) {
	return filepath.Glob(filepath.Join(dir, "*.sock"))
}
