package panel

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/store"
)

const (
	pendingAllowIPs   = "panel.allow_ips" // ключ опасной настройки
	accessConfirmTTL  = 2 * time.Minute   // сколько ждём подтверждения
	pendingCheckEvery = 5 * time.Second   // как часто проверяются сроки
)

// accessState — состояние белого списка и таймера; заводится один раз.
type accessState struct {
	once sync.Once
	mu   sync.Mutex // сохранение, подтверждение и возврат — по очереди
	list []string   // действующий список в виде записей
}

func (s *Server) initAccess() {
	s.access.once.Do(func() {
		if s.Allow == nil {
			s.Allow = NewAllowList(nil)
		}
		if s.Pending == nil && s.Store != nil {
			s.Pending = &PendingStore{Store: s.Store, Now: s.now}
		}
		if s.Pending != nil {
			if s.Pending.Apply == nil {
				s.Pending.Apply = map[string]func(string) error{}
			}
			s.Pending.Apply[pendingAllowIPs] = func(v string) error { return s.restoreAllow(splitList(v)) }
			s.Pending.Apply[pendingSettings] = s.restoreSettings
		}
	})
}

// splitList: записи через запятую, точку с запятой или любые пробелы.
func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
}

// writeAllowFile пишет список в config.toml.
func (s *Server) writeAllowFile(list []string) error {
	if s.NoConfigFile {
		return nil
	}
	file := s.ConfigFile
	if file == "" {
		file = paths.ConfigFile()
	}
	cfg, err := config.Load(file)
	if err != nil {
		return err
	}
	cfg.Panel.AllowIPs = list
	return config.Save(file, cfg)
}

// applyAllow ставит новый список в работу и в config.toml. Файл пишется
// первым: не записался — работа не меняется. Вызывается под access.mu.
func (s *Server) applyAllow(list []string) error {
	nets, err := config.ParseAllowIPs(list)
	if err != nil {
		return err
	}
	if err := s.writeAllowFile(list); err != nil {
		return err
	}
	s.Allow.Set(nets)
	s.access.list = list
	return nil
}

// restoreAllow возвращает прежний список. Порядок обратный applyAllow: сначала
// в работу, потом в файл. Иначе неисправный config.toml оставил бы в работе
// новый (возможно, запирающий) список бессрочно. Ошибка файла возвращается,
// запись ожидания остаётся, и следующая проверка повторит запись; в память
// список к тому времени уже поставлен. Вызывается под access.mu.
func (s *Server) restoreAllow(list []string) error {
	nets, err := config.ParseAllowIPs(list)
	if err != nil {
		return err
	}
	s.Allow.Set(nets)
	s.access.list = list
	return s.writeAllowFile(list)
}

// CurrentAllow — записи действующего белого списка.
func (s *Server) CurrentAllow() []string {
	s.initAccess()
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	return append([]string(nil), s.access.list...)
}

// SeedAllow задаёт начальный список (из конфига) при старте.
func (s *Server) SeedAllow(list []string) error {
	s.initAccess()
	nets, err := config.ParseAllowIPs(list)
	if err != nil {
		return err
	}
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	s.Allow.Set(nets)
	s.access.list = append([]string(nil), list...)
	return nil
}

// CheckPending возвращает прежние значения опасных настроек, чей срок
// подтверждения вышел. Зовётся при старте (перезапуск в середине таймера
// не отменяет возврат) и циклом PendingLoop.
func (s *Server) CheckPending(ctx context.Context) {
	s.initAccess()
	if s.Pending == nil {
		return
	}
	s.access.mu.Lock()
	done, err := s.Pending.Expire(ctx)
	s.access.mu.Unlock()
	if err != nil {
		s.Log.Error("возврат опасной настройки не выполнен", "err", err)
	}
	for _, x := range done {
		s.Log.Warn("изменение не подтверждено — возвращено прежнее значение", "key", x.Key)
		if s.Store == nil {
			continue
		}
		if err := s.Store.Audit(ctx, store.AuditEntry{
			TS: s.now().Unix(), User: "система", Action: "setting_revert", Target: x.Key,
			Before: x.New, After: x.Old,
		}); err != nil {
			s.Log.Warn("запись в журнал действий не удалась", "action", "setting_revert", "err", err)
		}
	}
}

// PendingLoop проверяет сроки, пока не отменён ctx.
func (s *Server) PendingLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.CheckPending(ctx)
		}
	}
}

type accessPending struct {
	New      string
	Deadline string
	Left     int
}

func (s *Server) renderAccess(w http.ResponseWriter, r *http.Request, status int, data map[string]any) {
	d := map[string]any{"Remote": s.remoteHost(r), "Ips": strings.Join(s.access.list, "\n")}
	if s.Pending != nil {
		if x, ok, err := s.Pending.Get(r.Context(), pendingAllowIPs); err == nil && ok {
			left := int(x.Deadline - s.now().Unix())
			if left < 0 {
				left = 0
			}
			d["Pending"] = accessPending{
				New:      strings.Join(splitList(x.New), ", "),
				Deadline: time.Unix(x.Deadline, 0).Local().Format("15:04:05"),
				Left:     left,
			}
		}
	}
	for k, v := range data {
		d[k] = v
	}
	s.render(w, r, status, "settings_access", d)
}

func (s *Server) accessPage(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	s.renderAccess(w, r, http.StatusOK, nil)
}

// accessSave: новое значение действует сразу и пишется в config.toml;
// через 2 минуты без подтверждения возвращается прежнее. Список, который
// не пускает текущий адрес, сохраняется только со вторым подтверждением.
func (s *Server) accessSave(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	if s.Pending == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	text := r.PostForm.Get("ips")
	list := splitList(text)
	nets, err := config.ParseAllowIPs(list)
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	if err != nil {
		s.renderAccess(w, r, http.StatusBadRequest, map[string]any{"Error": "белый список: " + err.Error(), "Ips": text})
		return
	}
	if _, ok, _ := s.Pending.Get(r.Context(), pendingAllowIPs); ok {
		s.renderAccess(w, r, http.StatusConflict, map[string]any{
			"Error": "предыдущее изменение ещё не подтверждено: подтвердите его или дождитесь возврата", "Ips": text,
		})
		return
	}
	old := s.access.list
	if strings.Join(old, ",") == strings.Join(list, ",") {
		s.renderAccess(w, r, http.StatusOK, map[string]any{"Notice": "список не изменился"})
		return
	}
	if !allowsIn(nets, s.remoteHost(r)) && r.PostForm.Get("lockout") != "1" {
		s.renderAccess(w, r, http.StatusOK, map[string]any{
			"Warn": true, "Ips": text,
			"Error": "Новый список не включает ваш адрес " + s.remoteHost(r) +
				": после применения панель станет недоступна отсюда, подтвердить изменение будет нельзя, " +
				"и через 2 минуты прежний список вернётся сам.",
		})
		return
	}
	if _, err := s.Pending.Begin(r.Context(), pendingAllowIPs, strings.Join(old, ","), strings.Join(list, ","), accessConfirmTTL); err != nil {
		s.Log.Error("ожидание подтверждения не записано", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	if err := s.applyAllow(list); err != nil {
		s.Store.ClearMeta(r.Context(), pendingMetaPrefix+pendingAllowIPs)
		s.Log.Error("белый список не применён", "err", err)
		s.renderAccess(w, r, http.StatusInternalServerError, map[string]any{"Error": "не удалось применить список: " + err.Error(), "Ips": text})
		return
	}
	s.audit(r, "access_set", pendingAllowIPs, strings.Join(old, ", "), strings.Join(list, ", "))
	s.renderAccess(w, r, http.StatusOK, map[string]any{"Notice": "список применён; подтвердите в течение 2 минут, иначе вернётся прежний"})
}

func (s *Server) accessConfirm(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	if s.Pending == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	x, _, _ := s.Pending.Get(r.Context(), pendingAllowIPs)
	if err := s.Pending.Confirm(r.Context(), pendingAllowIPs); err != nil {
		s.renderAccess(w, r, http.StatusConflict, map[string]any{"Error": err.Error()})
		return
	}
	s.audit(r, "access_confirm", pendingAllowIPs, "", strings.Join(splitList(x.New), ", "))
	s.renderAccess(w, r, http.StatusOK, map[string]any{"Notice": "изменение подтверждено"})
}
