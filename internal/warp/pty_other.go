//go:build !linux

package warp

import (
	"context"
	"errors"
)

// RunPTY работает только на Linux: установщик AZ-WARP ставится на узел.
func RunPTY(ctx context.Context, d *Dialog, name string, args ...string) error {
	return errors.New("установка AZ-WARP поддерживается только на Linux")
}
