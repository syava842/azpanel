package panel

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// ServiceNode — то, что страницы «Обновление AntiZapret», «telemt», «WARP» и
// «Обновление azpanel» берут у агента. *nodeapi.HTTPClient подходит. Отдельный
// интерфейс, а не часть Node: узел без этих методов (заглушка в тестах)
// получает честное «не поддерживается».
type ServiceNode interface {
	// Обновление AntiZapret.
	AZVersion(ctx context.Context) (nodeapi.AZVersion, error)
	AZUpdateState(ctx context.Context) (nodeapi.AZUpdateState, error)
	AZPreflight(ctx context.Context) (nodeapi.AZPreflight, error)
	AZUpdate(ctx context.Context, req nodeapi.AZUpdateRequest) (nodeapi.AZUpdateState, error)
	AZRestore(ctx context.Context, backup string) (nodeapi.AZUpdateState, error)
	AZRetry(ctx context.Context) (nodeapi.AZUpdateState, error)

	// telemt.
	TelemtStatus(ctx context.Context) (nodeapi.TelemtStatus, error)
	TelemtRelease(ctx context.Context) (nodeapi.TelemtRelease, error)
	TelemtPreflight(ctx context.Context, port int) (nodeapi.TelemtPreflight, error)
	TelemtAddUser(ctx context.Context, req nodeapi.TelemtAddUser) (nodeapi.TelemtUserResult, error)
	TelemtRemoveUser(ctx context.Context, name string) (nodeapi.TelemtUserResult, error)
	TelemtLink(ctx context.Context, name, server string) (nodeapi.TelemtLink, error)
	TelemtRestart(ctx context.Context) (nodeapi.Task, error)
	TelemtUpdate(ctx context.Context) (nodeapi.Task, error)
	InstallTelemt(ctx context.Context, p nodeapi.TelemtInstall) (nodeapi.Task, error)

	// WARP.
	Warp(ctx context.Context) (nodeapi.Warp, error)
	WarpDomains(ctx context.Context) (nodeapi.WarpList, error)
	WarpIPs(ctx context.Context) (nodeapi.WarpList, error)
	EditWarpDomains(ctx context.Context, e nodeapi.WarpEdit) (nodeapi.Task, error)
	EditWarpIPs(ctx context.Context, e nodeapi.WarpEdit) (nodeapi.Task, error)
	WarpSync(ctx context.Context) (nodeapi.Task, error)
	WarpUpdate(ctx context.Context) (nodeapi.Task, error)
	InstallWarp(ctx context.Context, a nodeapi.WarpInstallAnswers) (nodeapi.Task, error)

	// Самообновление azpanel.
	Update(ctx context.Context, req nodeapi.UpdateRequest) (nodeapi.Task, error)
	UpdateResult(ctx context.Context) (*nodeapi.UpdateResult, error)
}

var _ ServiceNode = (*nodeapi.HTTPClient)(nil)

// svc возвращает узел с методами сервисов; нет — страница с ошибкой 501.
func (s *Server) svc(w http.ResponseWriter, r *http.Request) (ServiceNode, bool) {
	if n := s.serviceFor(r); n != nil {
		return n, true
	}
	s.errorPage(w, r, http.StatusNotImplemented, "этот агент не поддерживает управление сервисами")
	return nil, false
}

func (s *Server) serviceNode() ServiceNode {
	if s.Svc != nil {
		return s.Svc
	}
	n, _ := s.Node.(ServiceNode)
	return n
}

// svcErr: как agentErr, но 422 («проверки не пройдены») остаётся 422.
func (s *Server) svcErr(err error) (int, string) {
	var ne *nodeapi.Error
	if errors.As(err, &ne) && ne.Status == http.StatusUnprocessableEntity {
		return http.StatusUnprocessableEntity, ne.Message
	}
	return s.agentErr(err)
}

// isNetErr — агент не ответил вовсе (не ошибка с кодом): узел перезагружается
// или недоступен.
func isNetErr(err error) bool {
	var ne *nodeapi.Error
	return err != nil && !errors.As(err, &ne)
}

// formConfirmed — флажок подтверждения опасного действия.
func formConfirmed(r *http.Request) bool { return r.PostForm.Get("confirm") == "1" }

// taskStarted записывает запуск задачи в журналы и ведёт на её страницу.
func (s *Server) taskStarted(w http.ResponseWriter, r *http.Request, op, target, detail string, t nodeapi.Task) {
	s.Log.Info("действие", "user", s.user(r), "op", op, "target", target, "task", t.ID)
	s.audit(r, op, target, "", strings.TrimSpace(detail+" задача "+t.ID))
	if t.ID == "" {
		s.redirect(w, r, "/tasks", http.StatusSeeOther)
		return
	}
	s.redirect(w, r, taskHref(t.ID), http.StatusSeeOther)
}

// serviceRefused — отказ агента: журнал и страница с ошибкой.
func (s *Server) serviceRefused(w http.ResponseWriter, r *http.Request, op, target string, err error) {
	s.Log.Warn("действие", "user", s.user(r), "op", op, "target", target, "err", err)
	st, tx := s.svcErr(err)
	s.auditRefused(r, op, target, st, tx)
	s.errorPage(w, r, st, tx)
}

// serviceFor — сервисные методы выбранного узла; без выбора — узел панели.
func (s *Server) serviceFor(r *http.Request) ServiceNode {
	if c := selected(r); c != nil {
		return c.svc
	}
	return s.serviceNode()
}
