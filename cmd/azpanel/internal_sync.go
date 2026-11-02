package main

import (
	"context"
	"io"

	"github.com/syava842/azpanel/internal/node"
)

func init() {
	// sync-apply --params ФАЙЛ: запись набора синхронизации на реплике и перезапуск служб
	internalModes["sync-apply"] = func(ctx context.Context, args []string, out io.Writer) error {
		var p node.SyncApplyParams
		if err := readParams(args, &p); err != nil {
			return err
		}
		return node.RunSyncApply(ctx, p, &node.SyncEnv{Out: out})
	}
}
