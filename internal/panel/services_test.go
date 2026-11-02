package panel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// svcNode — поддельный агент для страниц сервисов: Node берётся у fakeNode,
// каждый метод ServiceNode — из поля-функции (нет поля — ошибка errNotSet).
// Вызовы записываются в Calls.
type svcNode struct {
	*fakeNode
	Calls              []string
	AZVersionFn        func(ctx context.Context) (nodeapi.AZVersion, error)
	AZUpdateStateFn    func(ctx context.Context) (nodeapi.AZUpdateState, error)
	AZPreflightFn      func(ctx context.Context) (nodeapi.AZPreflight, error)
	AZUpdateFn         func(ctx context.Context, req nodeapi.AZUpdateRequest) (nodeapi.AZUpdateState, error)
	AZRestoreFn        func(ctx context.Context, backup string) (nodeapi.AZUpdateState, error)
	TelemtStatusFn     func(ctx context.Context) (nodeapi.TelemtStatus, error)
	TelemtReleaseFn    func(ctx context.Context) (nodeapi.TelemtRelease, error)
	TelemtPreflightFn  func(ctx context.Context, port int) (nodeapi.TelemtPreflight, error)
	TelemtAddUserFn    func(ctx context.Context, req nodeapi.TelemtAddUser) (nodeapi.TelemtUserResult, error)
	TelemtRemoveUserFn func(ctx context.Context, name string) (nodeapi.TelemtUserResult, error)
	TelemtLinkFn       func(ctx context.Context, name, server string) (nodeapi.TelemtLink, error)
	TelemtRestartFn    func(ctx context.Context) (nodeapi.Task, error)
	TelemtUpdateFn     func(ctx context.Context) (nodeapi.Task, error)
	InstallTelemtFn    func(ctx context.Context, p nodeapi.TelemtInstall) (nodeapi.Task, error)
	WarpFn             func(ctx context.Context) (nodeapi.Warp, error)
	WarpDomainsFn      func(ctx context.Context) (nodeapi.WarpList, error)
	WarpIPsFn          func(ctx context.Context) (nodeapi.WarpList, error)
	EditWarpDomainsFn  func(ctx context.Context, e nodeapi.WarpEdit) (nodeapi.Task, error)
	EditWarpIPsFn      func(ctx context.Context, e nodeapi.WarpEdit) (nodeapi.Task, error)
	WarpSyncFn         func(ctx context.Context) (nodeapi.Task, error)
	WarpUpdateFn       func(ctx context.Context) (nodeapi.Task, error)
	InstallWarpFn      func(ctx context.Context, a nodeapi.WarpInstallAnswers) (nodeapi.Task, error)
	UpdateFn           func(ctx context.Context, req nodeapi.UpdateRequest) (nodeapi.Task, error)
	UpdateResultFn     func(ctx context.Context) (*nodeapi.UpdateResult, error)
}

func (f *svcNode) AZVersion(ctx context.Context) (nodeapi.AZVersion, error) {
	f.Calls = append(f.Calls, "AZVersion")
	if f.AZVersionFn == nil {
		var z nodeapi.AZVersion
		return z, errNotSet
	}
	return f.AZVersionFn(ctx)
}
func (f *svcNode) AZUpdateState(ctx context.Context) (nodeapi.AZUpdateState, error) {
	f.Calls = append(f.Calls, "AZUpdateState")
	if f.AZUpdateStateFn == nil {
		var z nodeapi.AZUpdateState
		return z, errNotSet
	}
	return f.AZUpdateStateFn(ctx)
}
func (f *svcNode) AZPreflight(ctx context.Context) (nodeapi.AZPreflight, error) {
	f.Calls = append(f.Calls, "AZPreflight")
	if f.AZPreflightFn == nil {
		var z nodeapi.AZPreflight
		return z, errNotSet
	}
	return f.AZPreflightFn(ctx)
}
func (f *svcNode) AZUpdate(ctx context.Context, req nodeapi.AZUpdateRequest) (nodeapi.AZUpdateState, error) {
	f.Calls = append(f.Calls, "AZUpdate")
	if f.AZUpdateFn == nil {
		var z nodeapi.AZUpdateState
		return z, errNotSet
	}
	return f.AZUpdateFn(ctx, req)
}
func (f *svcNode) AZRestore(ctx context.Context, backup string) (nodeapi.AZUpdateState, error) {
	f.Calls = append(f.Calls, "AZRestore")
	if f.AZRestoreFn == nil {
		var z nodeapi.AZUpdateState
		return z, errNotSet
	}
	return f.AZRestoreFn(ctx, backup)
}
func (f *svcNode) TelemtStatus(ctx context.Context) (nodeapi.TelemtStatus, error) {
	f.Calls = append(f.Calls, "TelemtStatus")
	if f.TelemtStatusFn == nil {
		var z nodeapi.TelemtStatus
		return z, errNotSet
	}
	return f.TelemtStatusFn(ctx)
}
func (f *svcNode) TelemtRelease(ctx context.Context) (nodeapi.TelemtRelease, error) {
	f.Calls = append(f.Calls, "TelemtRelease")
	if f.TelemtReleaseFn == nil {
		var z nodeapi.TelemtRelease
		return z, errNotSet
	}
	return f.TelemtReleaseFn(ctx)
}
func (f *svcNode) TelemtPreflight(ctx context.Context, port int) (nodeapi.TelemtPreflight, error) {
	f.Calls = append(f.Calls, "TelemtPreflight")
	if f.TelemtPreflightFn == nil {
		var z nodeapi.TelemtPreflight
		return z, errNotSet
	}
	return f.TelemtPreflightFn(ctx, port)
}
func (f *svcNode) TelemtAddUser(ctx context.Context, req nodeapi.TelemtAddUser) (nodeapi.TelemtUserResult, error) {
	f.Calls = append(f.Calls, "TelemtAddUser")
	if f.TelemtAddUserFn == nil {
		var z nodeapi.TelemtUserResult
		return z, errNotSet
	}
	return f.TelemtAddUserFn(ctx, req)
}
func (f *svcNode) TelemtRemoveUser(ctx context.Context, name string) (nodeapi.TelemtUserResult, error) {
	f.Calls = append(f.Calls, "TelemtRemoveUser")
	if f.TelemtRemoveUserFn == nil {
		var z nodeapi.TelemtUserResult
		return z, errNotSet
	}
	return f.TelemtRemoveUserFn(ctx, name)
}
func (f *svcNode) TelemtLink(ctx context.Context, name, server string) (nodeapi.TelemtLink, error) {
	f.Calls = append(f.Calls, "TelemtLink")
	if f.TelemtLinkFn == nil {
		var z nodeapi.TelemtLink
		return z, errNotSet
	}
	return f.TelemtLinkFn(ctx, name, server)
}
func (f *svcNode) TelemtRestart(ctx context.Context) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "TelemtRestart")
	if f.TelemtRestartFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.TelemtRestartFn(ctx)
}
func (f *svcNode) TelemtUpdate(ctx context.Context) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "TelemtUpdate")
	if f.TelemtUpdateFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.TelemtUpdateFn(ctx)
}
func (f *svcNode) InstallTelemt(ctx context.Context, p nodeapi.TelemtInstall) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "InstallTelemt")
	if f.InstallTelemtFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.InstallTelemtFn(ctx, p)
}
func (f *svcNode) Warp(ctx context.Context) (nodeapi.Warp, error) {
	f.Calls = append(f.Calls, "Warp")
	if f.WarpFn == nil {
		var z nodeapi.Warp
		return z, errNotSet
	}
	return f.WarpFn(ctx)
}
func (f *svcNode) WarpDomains(ctx context.Context) (nodeapi.WarpList, error) {
	f.Calls = append(f.Calls, "WarpDomains")
	if f.WarpDomainsFn == nil {
		var z nodeapi.WarpList
		return z, errNotSet
	}
	return f.WarpDomainsFn(ctx)
}
func (f *svcNode) WarpIPs(ctx context.Context) (nodeapi.WarpList, error) {
	f.Calls = append(f.Calls, "WarpIPs")
	if f.WarpIPsFn == nil {
		var z nodeapi.WarpList
		return z, errNotSet
	}
	return f.WarpIPsFn(ctx)
}
func (f *svcNode) EditWarpDomains(ctx context.Context, e nodeapi.WarpEdit) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "EditWarpDomains")
	if f.EditWarpDomainsFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.EditWarpDomainsFn(ctx, e)
}
func (f *svcNode) EditWarpIPs(ctx context.Context, e nodeapi.WarpEdit) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "EditWarpIPs")
	if f.EditWarpIPsFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.EditWarpIPsFn(ctx, e)
}
func (f *svcNode) WarpSync(ctx context.Context) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "WarpSync")
	if f.WarpSyncFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.WarpSyncFn(ctx)
}
func (f *svcNode) WarpUpdate(ctx context.Context) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "WarpUpdate")
	if f.WarpUpdateFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.WarpUpdateFn(ctx)
}
func (f *svcNode) InstallWarp(ctx context.Context, a nodeapi.WarpInstallAnswers) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "InstallWarp")
	if f.InstallWarpFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.InstallWarpFn(ctx, a)
}
func (f *svcNode) Update(ctx context.Context, req nodeapi.UpdateRequest) (nodeapi.Task, error) {
	f.Calls = append(f.Calls, "Update")
	if f.UpdateFn == nil {
		var z nodeapi.Task
		return z, errNotSet
	}
	return f.UpdateFn(ctx, req)
}
func (f *svcNode) UpdateResult(ctx context.Context) (*nodeapi.UpdateResult, error) {
	if f.UpdateResultFn == nil {
		return nil, errNotSet
	}
	return f.UpdateResultFn(ctx)
}

var _ ServiceNode = (*svcNode)(nil)

// svcEnv — окружение с администратором и узлом сервисов.
func svcEnv(t *testing.T) (*testEnv, *svcNode, *http.Cookie, string) {
	t.Helper()
	e := newEnv(t, adminHash(t))
	n := &svcNode{fakeNode: e.node}
	e.srv.Svc = n
	c, s := e.sessionCookie(t)
	return e, n, c, s.CSRF
}

func (n *svcNode) called(name string) int {
	c := 0
	for _, x := range n.Calls {
		if x == name {
			c++
		}
	}
	return c
}

// errNotSetNet — ошибка связи (не ответ агента): узел перезагружается.
var errNotSetNet = errors.New("connection refused")

var _ = errors.New
var _ = httptest.NewRecorder
var _ = url.Values{}
var _ = strings.Contains
