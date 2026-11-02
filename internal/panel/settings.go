package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

const (
	// pendingSettings — ключ таймера возврата для опасных полей config.toml:
	// значением хранится JSON-карта «путь поля → прежний текст».
	pendingSettings = "settings.dangerous"
	draftTTL        = 15 * time.Minute // сколько живёт проверенный, но не применённый набор
	defaultExitWait = time.Second      // пауза между ответом «перезапуск…» и завершением
)

// settingsState — замок на «прочитать — поправить — записать» config.toml и
// secrets.env и черновики, ждущие подтверждения.
type settingsState struct {
	mu     sync.Mutex
	dmu    sync.Mutex
	drafts map[string]*settingsDraft
}

// settingsDraft — проверенный набор изменений: из формы или из импорта.
// Секреты импорта лежат только в памяти и только до подтверждения.
type settingsDraft struct {
	user    string // IDHash сессии: чужой черновик применить нельзя
	source  string
	old     config.Config
	cfg     config.Config
	secrets map[string]string
	exp     time.Time
}

func (s *Server) configPath() (string, error) {
	if s.NoConfigFile {
		return "", errors.New("файл настроек не используется")
	}
	if s.ConfigFile != "" {
		return s.ConfigFile, nil
	}
	return paths.ConfigFile(), nil
}

func (s *Server) secretsPath() string {
	if s.SecretsFile != "" {
		return s.SecretsFile
	}
	return paths.SecretsFile()
}

func (s *Server) loadConfig() (config.Config, error) {
	file, err := s.configPath()
	if err != nil {
		return config.Config{}, err
	}
	return config.Load(file)
}

// exitSoon завершает процесс через поле-функцию Exit; systemd поднимает
// панель заново (Restart=always). Пауза нужна, чтобы браузер успел получить
// страницу «перезапуск…».
func (s *Server) exitSoon() {
	if s.Exit == nil {
		s.Log.Warn("перезапуск панели не настроен — перезапустите службу вручную")
		return
	}
	d := s.ExitDelay
	if d <= 0 {
		d = defaultExitWait
	}
	time.AfterFunc(d, s.Exit)
}

// --- черновики ---

func (s *Server) putDraft(r *http.Request, d *settingsDraft) (string, error) {
	id, err := randomHex()
	if err != nil {
		return "", err
	}
	sess, _ := session(r)
	d.user, d.exp = sess.IDHash, s.now().Add(draftTTL)
	s.settings.dmu.Lock()
	defer s.settings.dmu.Unlock()
	if s.settings.drafts == nil {
		s.settings.drafts = map[string]*settingsDraft{}
	}
	for k, x := range s.settings.drafts {
		if s.now().After(x.exp) {
			delete(s.settings.drafts, k)
		}
	}
	s.settings.drafts[id] = d
	return id, nil
}

// takeDraft достаёт и сразу снимает черновик: применить его можно один раз.
func (s *Server) takeDraft(r *http.Request, id string) *settingsDraft {
	sess, _ := session(r)
	s.settings.dmu.Lock()
	defer s.settings.dmu.Unlock()
	d := s.settings.drafts[id]
	if d == nil || d.user != sess.IDHash || s.now().After(d.exp) {
		return nil
	}
	delete(s.settings.drafts, id)
	return d
}

// --- страница ---

type optView struct {
	Value string
	On    bool
}

type fieldView struct {
	Path, Name, Title, Hint, Kind, ApplyText, Value, Page, Err string
	Checked                                                    bool
	Opts                                                       []optView
}

type sectionView struct {
	Title  string
	Fields []fieldView
}

var settingsApplyTexts = map[config.Apply]string{
	config.ApplyNow:          "действует сразу",
	config.ApplyRestartPanel: "после перезапуска панели (панель перезапустится сама)",
	config.ApplyRestartNode:  "после перезапуска агента узла (агент перезапустится сам)",
	config.ApplyForeign:      "читает другой сервис — перезапустите его вручную",
	config.ApplyDangerous:    "опасная: панель перезапустится, на подтверждение дадим 2 минуты, иначе вернётся прежнее значение",
}

// buildSections строит поля формы по описаниям. raw — введённый текст (при
// ошибке показывается он, а не сохранённое значение), errs — ошибки по путям.
func buildSections(cfg config.Config, raw, errs map[string]string) []sectionView {
	var out []sectionView
	for _, sec := range config.Sections {
		sv := sectionView{Title: sec.Title}
		for _, f := range config.Fields() {
			if f.Section != sec.Key || f.Kind == config.KindReadonly {
				continue
			}
			val, typed := raw[f.Path]
			if !typed {
				val = config.Get(cfg, f.Path)
			}
			fv := fieldView{
				Path: f.Path, Name: "f:" + f.Path, Title: f.Title, Hint: f.Hint, Kind: string(f.Kind),
				ApplyText: settingsApplyTexts[f.Apply], Value: val, Page: f.Page, Err: errs[f.Path],
				Checked: val == "true" || val == "on",
			}
			if f.Kind == config.KindChoice || f.Kind == config.KindMulti {
				chosen := config.SplitList(val)
				for _, c := range f.Choices {
					fv.Opts = append(fv.Opts, optView{Value: c, On: hasString(chosen, c)})
				}
			}
			sv.Fields = append(sv.Fields, fv)
		}
		out = append(out, sv)
	}
	return out
}

func hasString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

type secretView struct {
	Key, Title, Note, Mask string
	Replace, Delete, Regen bool
	WarnRegen              string
	Set                    bool
}

var knownSecrets = []secretView{
	{Key: secrets.NodeToken, Title: "Токен агента", Note: "Общий секрет панели и агента.", Regen: true,
		WarnRegen: "Новый токен потребует перезапуска агента и панели: перезапущу оба. Пока они поднимаются, панель на несколько секунд потеряет связь с агентом."},
	{Key: SecretDataKey, Title: "Ключ шифрования 2FA", Note: "Шифрует секреты двухфакторной проверки в базе.", Regen: true,
		WarnRegen: "Секреты 2FA в базе будут перешифрованы новым ключом; панель перезапустится. Старый ключ после этого нигде не хранится."},
	{Key: secrets.TelegramBotToken, Title: "Токен Telegram-бота", Note: "Нужен, чтобы бот работал; после замены панель перезапустится.", Replace: true, Delete: true},
}

// maskSecret — «задан, заканчивается на …abcd»; короткие значения хвоста не
// показывают.
func maskSecret(v string) string {
	switch {
	case v == "":
		return "не задан"
	case utf8.RuneCountInString(v) < 12:
		return "задан"
	}
	r := []rune(v)
	return "задан, заканчивается на …" + string(r[len(r)-4:])
}

func (s *Server) secretViews() ([]secretView, error) {
	cur, err := secrets.Load(s.secretsPath())
	if err != nil {
		return nil, err
	}
	var out []secretView
	seen := map[string]bool{}
	for _, k := range knownSecrets {
		k.Mask, k.Set = maskSecret(cur[k.Key]), cur[k.Key] != ""
		out = append(out, k)
		seen[k.Key] = true
	}
	var extra []string
	for k := range cur {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, secretView{Key: k, Title: k, Note: "Служебный ключ; здесь не меняется.", Mask: maskSecret(cur[k]), Set: true})
	}
	return out, nil
}

type settingsPending struct {
	Deadline string
	Left     int
	Fields   string
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, status int, cfg config.Config, data map[string]any) {
	raw, _ := data["Raw"].(map[string]string)
	errs, _ := data["Errs"].(map[string]string)
	d := map[string]any{"Sections": buildSections(cfg, raw, errs)}
	if sv, err := s.secretViews(); err != nil {
		d["Error"] = "secrets.env не прочитан: " + err.Error()
	} else {
		d["Secrets"] = sv
	}
	if s.Pending != nil {
		if x, ok, err := s.Pending.Get(r.Context(), pendingSettings); err == nil && ok {
			var m map[string]string
			_ = json.Unmarshal([]byte(x.Old), &m)
			var names []string
			for p := range m {
				if f, ok := config.FieldByPath(p); ok {
					names = append(names, f.Title)
				}
			}
			sort.Strings(names)
			left := int(x.Deadline - s.now().Unix())
			if left < 0 {
				left = 0
			}
			d["Pending"] = settingsPending{Deadline: time.Unix(x.Deadline, 0).Local().Format("15:04:05"), Left: left, Fields: strings.Join(names, ", ")}
		}
	}
	for k, v := range data {
		d[k] = v
	}
	s.render(w, r, status, "settings", d)
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	cfg, err := s.loadConfig()
	if err != nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "настройки недоступны: "+err.Error())
		return
	}
	s.renderSettings(w, r, http.StatusOK, cfg, nil)
}

// --- сохранение из формы ---

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	s.settings.mu.Lock()
	defer s.settings.mu.Unlock()
	cur, err := s.loadConfig()
	if err != nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "настройки недоступны: "+err.Error())
		return
	}
	cand := cur
	raw, errs := map[string]string{}, map[string]string{}
	for _, f := range config.Fields() {
		if f.Kind == config.KindReadonly || f.Page != "" {
			continue
		}
		name := "f:" + f.Path
		var text string
		switch f.Kind {
		case config.KindBool:
			text = "false"
			if r.PostForm.Get(name) != "" {
				text = "true"
			}
		case config.KindMulti:
			text = strings.Join(r.PostForm[name], "\n")
		default:
			if !r.PostForm.Has(name) {
				continue
			}
			text = r.PostForm.Get(name)
		}
		raw[f.Path] = text
		if err := config.Set(&cand, f.Path, text); err != nil {
			errs[f.Path] = err.Error()
		}
	}
	if len(errs) == 0 {
		if err := cand.Validate(); err != nil {
			if f, ok := config.ErrorField(err); ok && f.Page == "" {
				errs[f.Path] = err.Error()
			} else {
				s.renderSettings(w, r, http.StatusBadRequest, cur, map[string]any{"Error": err.Error(), "Raw": raw})
				return
			}
		}
	}
	if len(errs) > 0 {
		s.renderSettings(w, r, http.StatusBadRequest, cur, map[string]any{"Raw": raw, "Errs": errs, "Error": "Есть неверные значения — исправьте отмеченные поля; ничего не сохранено."})
		return
	}
	s.previewDraft(w, r, &settingsDraft{source: "форма настроек", old: cur, cfg: cand}, cur)
}

type changeView struct {
	Title, Path, Old, New, ApplyText string
	Dangerous                        bool
}

// previewDraft показывает «было → стало» и способ применения и ждёт
// подтверждения.
func (s *Server) previewDraft(w http.ResponseWriter, r *http.Request, d *settingsDraft, cur config.Config) {
	changes := config.Diff(d.old, d.cfg)
	if len(changes) == 0 && len(d.secrets) == 0 {
		s.renderSettings(w, r, http.StatusOK, cur, map[string]any{"Notice": "ничего не изменилось"})
		return
	}
	id, err := s.putDraft(r, d)
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	var views []changeView
	var notes []string
	var needNode, needPanel, dangerous bool
	for _, c := range changes {
		views = append(views, changeView{
			Title: c.Field.Title, Path: c.Field.Path, Old: shortList(c.Old), New: shortList(c.New),
			ApplyText: settingsApplyTexts[c.Field.Apply], Dangerous: c.Field.Apply == config.ApplyDangerous,
		})
		switch c.Field.Apply {
		case config.ApplyRestartNode:
			needNode = true
		case config.ApplyRestartPanel:
			needPanel = true
		case config.ApplyDangerous:
			needPanel, dangerous = true, true
		case config.ApplyForeign:
			notes = append(notes, "«"+c.Field.Title+"»: читает другой сервис, перезапустите его вручную.")
		}
	}
	var keys []string
	for k := range d.secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		needPanel = true
	}
	if !allowsIn(mustAllow(d.cfg.Panel.AllowIPs), s.remoteHost(r)) {
		notes = append(notes, "Новый белый список не включает ваш адрес "+s.remoteHost(r)+": после перезапуска отсюда панель не откроется, подтвердить будет нельзя, и через 2 минуты прежнее значение вернётся само.")
	}
	s.render(w, r, http.StatusOK, "settings_preview", map[string]any{
		"Draft": id, "Source": d.source, "Changes": views, "SecretKeys": keys, "Notes": notes,
		"NeedNode": needNode, "NeedPanel": needPanel, "Dangerous": dangerous,
	})
}

func mustAllow(list []string) []netip.Prefix {
	nets, err := config.ParseAllowIPs(list)
	if err != nil {
		return nil
	}
	return nets
}

// shortList: список в одну строку для таблицы «было → стало».
func shortList(v string) string {
	if v == "" {
		return "—"
	}
	return strings.ReplaceAll(v, "\n", ", ")
}

// --- применение ---

func dangerousSnapshot(cfg config.Config, changes []config.Change) string {
	m := map[string]string{}
	for _, c := range changes {
		if c.Field.Apply == config.ApplyDangerous {
			m[c.Field.Path] = config.Get(cfg, c.Field.Path)
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (s *Server) settingsApply(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	d := s.takeDraft(r, r.PostForm.Get("draft"))
	s.settings.mu.Lock()
	defer s.settings.mu.Unlock()
	cur, err := s.loadConfig()
	if err != nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "настройки недоступны: "+err.Error())
		return
	}
	if d == nil {
		s.renderSettings(w, r, http.StatusConflict, cur, map[string]any{"Error": "Проверенный набор изменений устарел или уже применён: введите значения заново."})
		return
	}
	if !reflect.DeepEqual(cur, d.old) {
		s.renderSettings(w, r, http.StatusConflict, cur, map[string]any{"Error": "Настройки изменились после проверки: введите значения заново."})
		return
	}
	changes := config.Diff(cur, d.cfg)
	var needNode, needPanel bool
	var dangerous []config.Change
	for _, c := range changes {
		switch c.Field.Apply {
		case config.ApplyRestartNode:
			needNode = true
		case config.ApplyRestartPanel:
			needPanel = true
		case config.ApplyDangerous:
			needPanel = true
			dangerous = append(dangerous, c)
		}
	}
	if len(dangerous) > 0 {
		if s.Pending == nil {
			s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна: таймер возврата не работает")
			return
		}
		if _, ok, _ := s.Pending.Get(r.Context(), pendingSettings); ok {
			s.renderSettings(w, r, http.StatusConflict, cur, map[string]any{"Error": "Предыдущее опасное изменение ещё не подтверждено: подтвердите его или дождитесь возврата."})
			return
		}
	}
	// Секреты первыми: они могут не примениться (агент не перезапустился),
	// и тогда config.toml остаётся прежним.
	var notes []string
	if len(d.secrets) > 0 {
		if err := s.applySecrets(r.Context(), d.secrets); err != nil {
			s.renderSettings(w, r, http.StatusBadGateway, cur, map[string]any{"Error": "Секреты не применены, настройки не тронуты: " + err.Error()})
			return
		}
		needPanel = true
		s.auditSecrets(r, "secret_import", d.secrets)
	}
	if len(dangerous) > 0 {
		old, new := dangerousSnapshot(cur, dangerous), dangerousSnapshot(d.cfg, dangerous)
		if _, err := s.Pending.Begin(r.Context(), pendingSettings, old, new, accessConfirmTTL); err != nil {
			s.Log.Error("ожидание подтверждения не записано", "err", err)
			s.errorPage(w, r, http.StatusInternalServerError, "внутренняя ошибка")
			return
		}
	}
	file, _ := s.configPath()
	if len(changes) > 0 {
		if err := config.Save(file, d.cfg); err != nil {
			if len(dangerous) > 0 {
				s.Store.ClearMeta(r.Context(), pendingMetaPrefix+pendingSettings)
			}
			s.Log.Error("config.toml не записан", "err", err)
			s.renderSettings(w, r, http.StatusInternalServerError, cur, map[string]any{"Error": "Не удалось записать config.toml: " + err.Error()})
			return
		}
	}
	for _, c := range changes {
		s.audit(r, "setting_set", c.Field.Path, c.Old, c.New)
	}
	if needNode {
		switch {
		case s.RestartNode == nil:
			notes = append(notes, "перезапуск агента не настроен — перезапустите azpanel-node вручную")
		default:
			if err := s.RestartNode(r.Context()); err != nil {
				notes = append(notes, "агент не перезапущен ("+err.Error()+") — перезапустите azpanel-node вручную")
			}
		}
	}
	for _, c := range changes {
		if c.Field.Apply == config.ApplyForeign {
			notes = append(notes, "«"+c.Field.Title+"»: перезапустите читающий её сервис вручную")
		}
	}
	if needPanel {
		s.exitSoon()
		s.renderRestart(w, r, d.cfg, len(dangerous) > 0, notes)
		return
	}
	notes = append([]string{"Сохранено."}, notes...)
	s.renderSettings(w, r, http.StatusOK, d.cfg, map[string]any{"Notice": strings.Join(notes, " ")})
}

// renderRestart — страница «перезапуск…»: обновляется сама и через несколько
// секунд открывает настройки (по новому префиксу, если он поменялся).
func (s *Server) renderRestart(w http.ResponseWriter, r *http.Request, cfg config.Config, dangerous bool, notes []string) {
	s.render(w, r, http.StatusOK, "settings_restart", map[string]any{"Base": cfg.Panel.BasePath, "Dangerous": dangerous, "Notes": notes, "Wait": 6})
}

// settingsConfirm подтверждает опасные изменения, применённые с таймером.
func (s *Server) settingsConfirm(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	if s.Pending == nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "база панели недоступна")
		return
	}
	cur, err := s.loadConfig()
	if err != nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "настройки недоступны: "+err.Error())
		return
	}
	x, _, _ := s.Pending.Get(r.Context(), pendingSettings)
	if err := s.Pending.Confirm(r.Context(), pendingSettings); err != nil {
		s.renderSettings(w, r, http.StatusConflict, cur, map[string]any{"Error": err.Error()})
		return
	}
	s.audit(r, "setting_confirm", pendingSettings, "", x.New)
	s.renderSettings(w, r, http.StatusOK, cur, map[string]any{"Notice": "изменение подтверждено"})
}

// restoreSettings возвращает прежние значения опасных полей, когда время
// подтверждения вышло, и перезапускает панель, чтобы вернуть их в работу.
func (s *Server) restoreSettings(value string) error {
	var m map[string]string
	if err := json.Unmarshal([]byte(value), &m); err != nil {
		return fmt.Errorf("запись возврата испорчена: %w", err)
	}
	s.settings.mu.Lock()
	defer s.settings.mu.Unlock()
	file, err := s.configPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load(file)
	if err != nil {
		return err
	}
	for p, text := range m {
		if err := config.Set(&cfg, p, text); err != nil {
			return err
		}
	}
	if err := config.Save(file, cfg); err != nil {
		return err
	}
	s.exitSoon()
	return nil
}

// auditSecrets пишет в журнал имена ключей, без значений.
func (s *Server) auditSecrets(r *http.Request, action string, kv map[string]string) {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s.audit(r, action, k, "", "значение скрыто")
	}
}
