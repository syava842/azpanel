//go:build linux

package node

import (
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"syscall"
)

// PeerChecker пускает к сокету агента только root и nobody — под nobody
// OpenVPN AntiZapret выполняет скрипты.
func PeerChecker() func(net.Conn) error {
	allowed := map[uint32]bool{0: true}
	if u, err := user.Lookup("nobody"); err == nil {
		if id, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			allowed[uint32(id)] = true
		}
	}
	return func(c net.Conn) error {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return errors.New("не unix-сокет")
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return err
		}
		var cred *syscall.Ucred
		var cerr error
		if err := raw.Control(func(fd uintptr) {
			cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		}); err != nil {
			return err
		}
		if cerr != nil {
			return cerr
		}
		if !allowed[cred.Uid] {
			return fmt.Errorf("uid %d, pid %d", cred.Uid, cred.Pid)
		}
		return nil
	}
}
