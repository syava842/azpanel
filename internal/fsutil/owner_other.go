//go:build !linux

package fsutil

import "os"

// copyOwner вне Linux ничего не делает: владельцы файлов AntiZapret — забота
// Linux-узла.
func copyOwner(os.FileInfo, string) error { return nil }
