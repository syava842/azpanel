//go:build !linux

package node

import "net"

// PeerChecker вне linux не проверяет: агент работает только на linux,
// здесь — для тестов на машине разработчика.
func PeerChecker() func(net.Conn) error { return nil }
