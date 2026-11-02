//go:build !linux

package update

import (
	"context"
	"errors"
)

func runSystemctl(context.Context, ...string) error {
	return errors.New("systemctl есть только в Linux")
}
