package node

import (
	"context"
	"net/http"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// Пока идёт обновление AntiZapret, задачи telemt и WARP не стартуют: setup.sh
// переписывает службы, а чужая задача заняла бы очередь и сбила порядок.
func TestAZActiveBlocksTelemtTasks(t *testing.T) {
	e := newTelemtEnv(t, true)
	az := newAZ(t)
	e.api.AZ = az.u
	az.ex.hold = make(chan struct{})
	defer close(az.ex.hold)
	if _, err := az.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := e.client.TelemtUpdate(ctx); status(err) != http.StatusConflict {
		t.Fatalf("telemt update во время обновления AntiZapret: %v", err)
	}
	if _, err := e.client.TelemtRestart(ctx); status(err) != http.StatusConflict {
		t.Fatalf("telemt restart: %v", err)
	}
	if _, err := e.client.TelemtAddUser(ctx, nodeapi.TelemtAddUser{Name: "bob"}); status(err) != http.StatusConflict {
		t.Fatalf("telemt add user: %v", err)
	}
	if got := e.paramsFiles(t); len(got) != 0 {
		t.Fatalf("файлы параметров остались после отказа: %v", got)
	}
}

func TestAZActiveBlocksWarpTasks(t *testing.T) {
	e := newWarpEnv(t, true)
	az := newAZ(t)
	e.api.AZ = az.u
	az.ex.hold = make(chan struct{})
	defer close(az.ex.hold)
	if _, err := az.u.Start(context.Background(), nodeapi.AZUpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := e.client.WarpSync(ctx); status(err) != http.StatusConflict {
		t.Fatalf("warp sync во время обновления AntiZapret: %v", err)
	}
	if _, err := e.client.WarpUpdate(ctx); status(err) != http.StatusConflict {
		t.Fatalf("warp update: %v", err)
	}
	if _, err := e.client.EditWarpDomains(ctx, nodeapi.WarpEdit{Ops: []nodeapi.WarpOp{{Op: "add", Arg: "example.org"}}}); status(err) != http.StatusConflict {
		t.Fatalf("warp domains: %v", err)
	}
}
