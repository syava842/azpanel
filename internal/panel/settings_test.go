package panel

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
)

const (
	oldNodeToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	botToken     = "123456789:AAH-secret-token-value-XYZ"
)

// setEnv — окружение страницы настроек: config.toml и secrets.env во
// временном каталоге, перезапуски записываются.
type setEnv struct {
	*accessEnv
	secFile   string
	exited    chan struct{}
	nodeCalls int
	nodeErr   error
	cookie    *http.Cookie
	sess      Session
}

func newSetEnv(t *testing.T) *setEnv {
	t.Helper()
	e := &setEnv{accessEnv: newAccessEnv(t), exited: make(chan struct{}, 8)}
	e.secFile = filepath.Join(t.TempDir(), "secrets.env")
	if err := secrets.SetMany(e.secFile, map[string]string{
		secrets.NodeToken: oldNodeToken, secrets.TelegramBotToken: botToken, "PANEL_DATA_KEY": strings.Repeat("ab", 32),
	}); err != nil {
		t.Fatal(err)
	}
	e.srv.SecretsFile = e.secFile
	e.srv.DataKey, _ = hex.DecodeString(strings.Repeat("ab", 32))
	e.srv.ExitDelay = time.Millisecond
	e.srv.Exit = func() { e.exited <- struct{}{} }
	e.srv.RestartNode = func(context.Context) error { e.nodeCalls++; return e.nodeErr }
	return e
}

// post — POST администратора из одной и той же сессии: черновик привязан к ней.
func (e *setEnv) post(t *testing.T, path, from string, f url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if e.cookie == nil {
		e.cookie, e.sess = e.sessionCookie(t)
	}
	f.Set("csrf", e.sess.CSRF)
	req := postForm(path, f)
	req.AddCookie(e.cookie)
	req.RemoteAddr = from + ":4000"
	return e.do(req)
}

func (e *setEnv) wasExit() bool {
	select {
	case <-e.exited:
		return true
	case <-time.After(300 * time.Millisecond):
		return false
	}
}

func (e *setEnv) cfg(t *testing.T) config.Config {
	t.Helper()
	c, err := config.Load(e.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *setEnv) cfgBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(e.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// form собирает полную форму настроек из сохранённых значений плюс правки.
func (e *setEnv) form(t *testing.T, edits map[string]string) url.Values {
	t.Helper()
	cur := e.cfg(t)
	v := url.Values{}
	for _, f := range config.Fields() {
		if f.Kind == config.KindReadonly || f.Page != "" {
			continue
		}
		val := config.Get(cur, f.Path)
		if x, ok := edits[f.Path]; ok {
			val = x
		}
		switch f.Kind {
		case config.KindBool:
			if val == "true" {
				v.Set("f:"+f.Path, "1")
			}
		case config.KindMulti:
			for _, x := range config.SplitList(val) {
				v.Add("f:"+f.Path, x)
			}
		default:
			v.Set("f:"+f.Path, val)
		}
	}
	return v
}

var draftRe = regexp.MustCompile(`name="draft" value="([0-9a-f]+)"`)

// save шлёт форму; при успешной проверке возвращает номер черновика.
func (e *setEnv) save(t *testing.T, edits map[string]string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	rec := e.post(t, "/settings", "10.0.0.1", e.form(t, edits))
	m := draftRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		return rec, ""
	}
	return rec, m[1]
}

func (e *setEnv) apply(t *testing.T, draft string) *httptest.ResponseRecorder {
	t.Helper()
	return e.post(t, "/settings/apply", "10.0.0.1", url.Values{"draft": {draft}})
}

func (e *setEnv) auditActions(t *testing.T) []string {
	t.Helper()
	rows, _, err := e.st.AuditList(context.Background(), 100, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Action+" "+r.Target+" "+r.Before+" "+r.After)
	}
	return out
}

func TestSettingsAdminOnly(t *testing.T) {
	e := newSetEnv(t)
	u, err := e.st.CreateUser(context.Background(), store.User{Login: "bob", Hash: "x", Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := e.sessionFor(t, u, false)
	for _, p := range []string{"/settings", "/settings/export"} {
		if rec := e.get(p, "10.0.0.1", c); rec.Code != 403 {
			t.Errorf("GET %s у пользователя: %d", p, rec.Code)
		}
	}
	if rec := e.get("/settings", "10.0.0.1", nil); rec.Code != 303 {
		t.Errorf("без входа: %d", rec.Code)
	}
}

// Сторож формы: каждое редактируемое поле Config есть на странице.
func TestSettingsPageShowsEveryField(t *testing.T) {
	e := newSetEnv(t)
	c, _ := e.sessionCookie(t)
	rec := e.get("/settings", "10.0.0.1", c)
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	body := rec.Body.String()
	for _, f := range config.Fields() {
		if f.Kind == config.KindReadonly || f.Page != "" {
			continue
		}
		if !strings.Contains(body, `name="f:`+f.Path+`"`) {
			t.Errorf("на странице нет поля %s", f.Path)
		}
	}
}

func TestSettingsSecretsMasked(t *testing.T) {
	e := newSetEnv(t)
	c, _ := e.sessionCookie(t)
	body := e.get("/settings", "10.0.0.1", c).Body.String()
	for _, secret := range []string{oldNodeToken, botToken, strings.Repeat("ab", 32)} {
		if strings.Contains(body, secret) {
			t.Fatalf("секрет показан целиком: %s", secret)
		}
	}
	if !strings.Contains(body, "заканчивается на …"+botToken[len(botToken)-4:]) {
		t.Errorf("нет маски токена бота:\n%s", body)
	}
	if maskSecret("") != "не задан" || maskSecret("короткий") != "задан" {
		t.Error("маска пустого и короткого значения")
	}
}

func TestSettingsInvalidValueRefused(t *testing.T) {
	e := newSetEnv(t)
	before := e.cfgBytes(t)
	for name, edits := range map[string]map[string]string{
		"не число":      {"node.poll_seconds": "abc"},
		"вне диапазона": {"node.poll_seconds": "0"},
		"префикс":       {"panel.base_path": "azpanel"},
		"прокси":        {"panel.trusted_proxies": "не-адрес"},
		"время":         {"telegram.summary_at": "25:99"},
	} {
		rec, draft := e.save(t, edits)
		if rec.Code != 400 || draft != "" {
			t.Errorf("%s: код %d, черновик %q", name, rec.Code, draft)
		}
		if !strings.Contains(rec.Body.String(), `class="error"`) {
			t.Errorf("%s: нет сообщения об ошибке", name)
		}
	}
	// Ошибка видна у самого поля.
	rec, _ := e.save(t, map[string]string{"node.poll_seconds": "0"})
	if !regexp.MustCompile(`(?s)name="f:node.poll_seconds".*?<div class="error">node.poll_seconds = 0`).MatchString(rec.Body.String()) {
		t.Errorf("ошибка не у поля:\n%s", rec.Body)
	}
	if !bytes.Equal(before, e.cfgBytes(t)) {
		t.Fatal("config.toml тронут")
	}
	if e.wasExit() || e.nodeCalls != 0 {
		t.Fatal("перезапуск при отказе")
	}
}

func TestSettingsNoChanges(t *testing.T) {
	e := newSetEnv(t)
	rec, draft := e.save(t, nil)
	if rec.Code != 200 || draft != "" || !strings.Contains(rec.Body.String(), "ничего не изменилось") {
		t.Fatalf("%d %q", rec.Code, draft)
	}
}

func TestSettingsPreviewThenApplyRestartsPanel(t *testing.T) {
	e := newSetEnv(t)
	before := e.cfgBytes(t)
	rec, draft := e.save(t, map[string]string{"panel.history_days": "7"})
	if rec.Code != 200 || draft == "" {
		t.Fatalf("%d\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<td>30</td><td>7</td>") || !strings.Contains(body, "после перезапуска панели") {
		t.Errorf("нет «было → стало» и способа применения:\n%s", body)
	}
	if !bytes.Equal(before, e.cfgBytes(t)) {
		t.Fatal("до подтверждения файл изменён")
	}
	rec = e.apply(t, draft)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("после применения должна быть страница перезапуска: %d\n%s", rec.Code, rec.Body)
	}
	if e.cfg(t).Panel.HistoryDays != 7 {
		t.Fatal("значение не записано")
	}
	if !e.wasExit() {
		t.Fatal("панель не завершила процесс")
	}
	if e.nodeCalls != 0 {
		t.Fatal("агент перезапущен зря")
	}
	var found bool
	for _, a := range e.auditActions(t) {
		if strings.HasPrefix(a, "setting_set panel.history_days 30 7") {
			found = true
		}
	}
	if !found {
		t.Errorf("нет записи в журнале: %v", e.auditActions(t))
	}
	// Повторное применение того же черновика — отказ.
	if rec := e.apply(t, draft); rec.Code != 409 {
		t.Fatalf("повтор: %d", rec.Code)
	}
}

func TestSettingsDraftBelongsToSession(t *testing.T) {
	e := newSetEnv(t)
	_, draft := e.save(t, map[string]string{"panel.history_days": "7"})
	// Другая сессия того же администратора чужой черновик не применит.
	c, sess := e.sessionCookie(t)
	req := postForm("/settings/apply", url.Values{"csrf": {sess.CSRF}, "draft": {draft}})
	req.AddCookie(c)
	req.RemoteAddr = "10.0.0.1:1"
	if rec := e.do(req); rec.Code != 409 {
		t.Fatalf("чужой черновик: %d", rec.Code)
	}
	if e.cfg(t).Panel.HistoryDays == 7 {
		t.Fatal("значение записано")
	}
}

func TestSettingsConfigChangedMeanwhile(t *testing.T) {
	e := newSetEnv(t)
	_, draft := e.save(t, map[string]string{"panel.history_days": "7"})
	c := e.cfg(t)
	c.Log.Keep = 9
	if err := config.Save(e.cfgFile, c); err != nil {
		t.Fatal(err)
	}
	if rec := e.apply(t, draft); rec.Code != 409 {
		t.Fatalf("%d", rec.Code)
	}
	if e.cfg(t).Panel.HistoryDays == 7 {
		t.Fatal("применено поверх чужой правки")
	}
}

func TestSettingsRestartNodeFields(t *testing.T) {
	e := newSetEnv(t)
	_, draft := e.save(t, map[string]string{"node.poll_seconds": "10"})
	rec := e.apply(t, draft)
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	if e.nodeCalls != 1 {
		t.Fatalf("агент перезапущен %d раз", e.nodeCalls)
	}
	if e.wasExit() {
		t.Fatal("панель перезапущена, хотя менялся только агент")
	}
	if e.cfg(t).Node.PollSeconds != 10 {
		t.Fatal("значение не записано")
	}
	// Агент не перезапустился: файл сохранён, оператор предупреждён.
	e.nodeErr = errors.New("агент недоступен")
	_, draft = e.save(t, map[string]string{"node.poll_seconds": "11"})
	rec = e.apply(t, draft)
	if !strings.Contains(rec.Body.String(), "агент не перезапущен") || e.cfg(t).Node.PollSeconds != 11 {
		t.Fatalf("%s", rec.Body)
	}
}

func TestSettingsDangerousTimerConfirmAndRevert(t *testing.T) {
	e := newSetEnv(t)
	_, draft := e.save(t, map[string]string{"panel.base_path": "/azpanel/", "panel.trusted_proxies": "10.0.0.0/8"})
	if draft == "" {
		t.Fatal("нет черновика")
	}
	rec := e.apply(t, draft)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "/azpanel/settings") {
		t.Fatalf("страница перезапуска должна вести на новый префикс: %d\n%s", rec.Code, rec.Body)
	}
	if !e.wasExit() {
		t.Fatal("панель не перезапущена")
	}
	c := e.cfg(t)
	if c.Panel.BasePath != "/azpanel/" || strings.Join(c.Panel.TrustedProxies, ",") != "10.0.0.0/8" {
		t.Fatalf("не записано: %+v", c.Panel)
	}
	x, ok, _ := e.srv.Pending.Get(context.Background(), pendingSettings)
	if !ok || x.Deadline != e.now.Add(accessConfirmTTL).Unix() {
		t.Fatalf("таймер: %+v %v", x, ok)
	}
	// Подтверждение снимает таймер, значения остаются.
	e.now = e.now.Add(30 * time.Second)
	rec = e.post(t, "/settings/confirm", "10.0.0.1", url.Values{})
	if rec.Code != 200 {
		t.Fatalf("подтверждение: %d\n%s", rec.Code, rec.Body)
	}
	e.srv.CheckPending(context.Background())
	if e.cfg(t).Panel.BasePath != "/azpanel/" {
		t.Fatal("подтверждённое значение откатилось")
	}

	// Без подтверждения по истечении срока возвращается прежнее и панель перезапускается.
	_, draft = e.save(t, map[string]string{"panel.base_path": ""})
	e.apply(t, draft)
	e.wasExit()
	e.now = e.now.Add(accessConfirmTTL + time.Second)
	e.srv.CheckPending(context.Background())
	if e.cfg(t).Panel.BasePath != "/azpanel/" {
		t.Fatalf("прежнее значение не возвращено: %q", e.cfg(t).Panel.BasePath)
	}
	if !e.wasExit() {
		t.Fatal("после возврата панель должна перезапуститься")
	}
	// Второе опасное изменение при неподтверждённом первом — отказ.
	_, d1 := e.save(t, map[string]string{"panel.base_path": "/x/"})
	e.apply(t, d1)
	_, d2 := e.save(t, map[string]string{"panel.base_path": "/y/"})
	if rec := e.apply(t, d2); rec.Code != 409 {
		t.Fatalf("второе опасное изменение: %d", rec.Code)
	}
}

func TestSettingsSecretsReplaceDelete(t *testing.T) {
	e := newSetEnv(t)
	newTok := "654321:BBB-new-token-value-1234"
	rec := e.post(t, "/settings/secrets", "10.0.0.1", url.Values{"key": {secrets.TelegramBotToken}, "action": {"replace"}, "value": {newTok}})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), newTok) {
		t.Fatalf("%d, значение в ответе: %v", rec.Code, strings.Contains(rec.Body.String(), newTok))
	}
	m, _ := secrets.Load(e.secFile)
	if m[secrets.TelegramBotToken] != newTok || m[secrets.NodeToken] != oldNodeToken {
		t.Fatalf("%v", m)
	}
	if !e.wasExit() {
		t.Fatal("после замены токена бота панель должна перезапуститься")
	}
	for _, a := range e.auditActions(t) {
		if strings.Contains(a, newTok) || strings.Contains(a, botToken) {
			t.Fatalf("значение секрета в журнале: %s", a)
		}
	}
	rec = e.post(t, "/settings/secrets", "10.0.0.1", url.Values{"key": {secrets.TelegramBotToken}, "action": {"delete"}})
	m, _ = secrets.Load(e.secFile)
	if rec.Code != 200 || m[secrets.TelegramBotToken] != "" {
		t.Fatalf("не удалён: %d %v", rec.Code, m)
	}
	// Пробел внутри значения и чужие ключи — отказ.
	for _, f := range []url.Values{
		{"key": {secrets.TelegramBotToken}, "action": {"replace"}, "value": {"a b"}},
		{"key": {secrets.NodeToken}, "action": {"replace"}, "value": {"x"}},
		{"key": {secrets.NodeToken}, "action": {"delete"}},
		{"key": {"PANEL_ADMIN_HASH"}, "action": {"delete"}},
	} {
		if rec := e.post(t, "/settings/secrets", "10.0.0.1", f); rec.Code != 400 {
			t.Errorf("%v: %d", f, rec.Code)
		}
	}
}

func TestSettingsRegenNodeToken(t *testing.T) {
	e := newSetEnv(t)
	f := url.Values{"key": {secrets.NodeToken}, "action": {"regen"}}
	if rec := e.post(t, "/settings/secrets", "10.0.0.1", f); rec.Code != 400 {
		t.Fatalf("без подтверждения: %d", rec.Code)
	}
	if m, _ := secrets.Load(e.secFile); m[secrets.NodeToken] != oldNodeToken || e.nodeCalls != 0 {
		t.Fatal("токен изменён без подтверждения")
	}
	// Агент не отвечает — токен не меняется.
	e.nodeErr = errors.New("нет связи")
	f.Set("confirm", "1")
	if rec := e.post(t, "/settings/secrets", "10.0.0.1", f); rec.Code != 502 {
		t.Fatalf("агент недоступен: %d", rec.Code)
	}
	if m, _ := secrets.Load(e.secFile); m[secrets.NodeToken] != oldNodeToken {
		t.Fatal("токен изменён, хотя агент не перезапущен")
	}
	e.nodeErr = nil
	rec := e.post(t, "/settings/secrets", "10.0.0.1", f)
	m, _ := secrets.Load(e.secFile)
	if rec.Code != 200 || m[secrets.NodeToken] == oldNodeToken || len(m[secrets.NodeToken]) != 64 {
		t.Fatalf("%d %q", rec.Code, m[secrets.NodeToken])
	}
	if e.nodeCalls != 2 || !e.wasExit() {
		t.Fatalf("нужно перезапустить и агента, и панель: агент %d", e.nodeCalls)
	}
	if strings.Contains(rec.Body.String(), m[secrets.NodeToken]) {
		t.Fatal("новый токен показан")
	}
}

func TestSettingsRegenDataKeyReencryptsTOTP(t *testing.T) {
	e := newSetEnv(t)
	secret := []byte("12345678901234567890")
	sealed, err := Seal(e.srv.DataKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetTOTP(context.Background(), e.admin.ID, sealed, 5); err != nil {
		t.Fatal(err)
	}
	rec := e.post(t, "/settings/secrets", "10.0.0.1", url.Values{"key": {SecretDataKey}, "action": {"regen"}, "confirm": {"1"}})
	m, _ := secrets.Load(e.secFile)
	if rec.Code != 200 || m[SecretDataKey] == strings.Repeat("ab", 32) {
		t.Fatalf("%d %q", rec.Code, m[SecretDataKey])
	}
	newKey, _ := hex.DecodeString(m[SecretDataKey])
	u, err := e.st.UserByID(context.Background(), e.admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(newKey, u.TOTPSecret)
	if err != nil || !bytes.Equal(got, secret) || u.TOTPLastStep != 5 {
		t.Fatalf("секрет 2FA не перешифрован: %v", err)
	}
	if !e.wasExit() {
		t.Fatal("панель не перезапущена")
	}
}

func TestSettingsExport(t *testing.T) {
	e := newSetEnv(t)
	rec := e.post(t, "/settings/export", "10.0.0.1", url.Values{})
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "config.toml") {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if strings.Contains(rec.Body.String(), oldNodeToken) || !strings.Contains(rec.Body.String(), "poll_seconds") {
		t.Fatalf("экспорт без секретов:\n%s", rec.Body)
	}
	e.now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	rec = e.post(t, "/settings/export", "10.0.0.1", url.Values{"with_secrets": {"1"}})
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "azpanel-settings-2026-11-02.tar") {
		t.Fatalf("имя файла: %v", rec.Header())
	}
	files := map[string]string{}
	tr := tar.NewReader(rec.Body)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = string(b)
	}
	if len(files) != 2 || !strings.Contains(files["config.toml"], "poll_seconds") || !strings.Contains(files["secrets.env"], "NODE_TOKEN="+oldNodeToken) {
		t.Fatalf("состав архива: %v", files)
	}
	if got := e.auditActions(t); len(got) != 2 {
		t.Fatalf("экспорт должен попасть в журнал: %v", got)
	}
}

func (e *setEnv) upload(t *testing.T, name string, data []byte, withSecrets bool) *httptest.ResponseRecorder {
	t.Helper()
	if e.cookie == nil {
		e.cookie, e.sess = e.sessionCookie(t)
	}
	c, sess := e.cookie, e.sess
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("csrf", sess.CSRF)
	if withSecrets {
		mw.WriteField("with_secrets", "1")
	}
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(data)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/settings/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(c)
	req.RemoteAddr = "10.0.0.1:1"
	return e.do(req)
}

func importTar(t *testing.T, cfg config.Config, sec map[string]string) []byte {
	t.Helper()
	cb, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range map[string][]byte{"config.toml": cb, "secrets.env": secrets.Marshal(sec)} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))})
		tw.Write(data)
	}
	tw.Close()
	return buf.Bytes()
}

func TestSettingsImportToml(t *testing.T) {
	e := newSetEnv(t)
	c := e.cfg(t)
	c.Panel.HistoryDays = 12
	data, _ := config.Marshal(c)
	secBefore, _ := os.ReadFile(e.secFile)
	rec := e.upload(t, "config.toml", data, false)
	m := draftRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil || !strings.Contains(rec.Body.String(), "<td>30</td><td>12</td>") {
		t.Fatalf("%d\n%s", rec.Code, rec.Body)
	}
	if e.cfg(t).Panel.HistoryDays != 30 {
		t.Fatal("до подтверждения применено")
	}
	if rec := e.apply(t, m[1]); rec.Code != 200 || e.cfg(t).Panel.HistoryDays != 12 {
		t.Fatalf("%d", rec.Code)
	}
	if secAfter, _ := os.ReadFile(e.secFile); !bytes.Equal(secBefore, secAfter) {
		t.Fatal("secrets.env изменён импортом config.toml")
	}
}

func TestSettingsImportSecretsOnlyWithFlag(t *testing.T) {
	e := newSetEnv(t)
	c := e.cfg(t)
	c.Panel.HistoryDays = 12
	newTok := strings.Repeat("cd", 32)
	data := importTar(t, c, map[string]string{secrets.NodeToken: newTok, secrets.TelegramBotToken: "1:imported-bot-token-9999"})
	secBefore, _ := os.ReadFile(e.secFile)

	// Без флажка секреты из архива не берутся.
	rec := e.upload(t, "x.tar", data, false)
	m := draftRe.FindStringSubmatch(rec.Body.String())
	if m == nil || strings.Contains(rec.Body.String(), "Секреты, которые будут заменены") {
		t.Fatalf("секреты предложены без флажка:\n%s", rec.Body)
	}
	e.apply(t, m[1])
	if secAfter, _ := os.ReadFile(e.secFile); !bytes.Equal(secBefore, secAfter) {
		t.Fatal("secrets.env изменён без флажка")
	}

	// С флажком — предпросмотр называет ключи без значений, применение меняет файл и перезапускает.
	c.Panel.HistoryDays = 13
	data = importTar(t, c, map[string]string{secrets.NodeToken: newTok, secrets.TelegramBotToken: "1:imported-bot-token-9999"})
	rec = e.upload(t, "x.tar", data, true)
	m = draftRe.FindStringSubmatch(rec.Body.String())
	body := rec.Body.String()
	if m == nil || !strings.Contains(body, "NODE_TOKEN") || strings.Contains(body, newTok) || strings.Contains(body, "imported-bot-token") {
		t.Fatalf("предпросмотр секретов:\n%s", body)
	}
	if rec := e.apply(t, m[1]); rec.Code != 200 {
		t.Fatalf("%d\n%s", rec.Code, rec.Body)
	}
	sec, _ := secrets.Load(e.secFile)
	if sec[secrets.NodeToken] != newTok || sec[secrets.TelegramBotToken] != "1:imported-bot-token-9999" {
		t.Fatalf("секреты не применены: %v", sec)
	}
	if e.nodeCalls != 1 {
		t.Fatalf("смена NODE_TOKEN должна перезапустить агента: %d", e.nodeCalls)
	}
	if !e.wasExit() {
		t.Fatal("панель не перезапущена")
	}
	for _, a := range e.auditActions(t) {
		if strings.Contains(a, newTok) || strings.Contains(a, "imported-bot-token") {
			t.Fatalf("значение секрета в журнале: %s", a)
		}
	}
}

func TestSettingsImportRejectsBadFile(t *testing.T) {
	e := newSetEnv(t)
	before := e.cfgBytes(t)
	bad := e.cfg(t)
	bad.Node.PollSeconds = 500
	badToml := []byte("[node]\npoll_seconds = 500\n")
	_ = bad
	for name, data := range map[string][]byte{
		"неверное значение": badToml,
		"не toml":           []byte("это не toml ===="),
		"пустой":            nil,
	} {
		rec := e.upload(t, "config.toml", data, false)
		if rec.Code != 400 || draftRe.MatchString(rec.Body.String()) {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if !bytes.Equal(before, e.cfgBytes(t)) {
		t.Fatal("config.toml тронут")
	}
}

func TestRestartNodeHTTP(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	if err := restartNodeHTTP(context.Background(), srv.URL+"/", "TOKEN", ""); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer TOKEN" || gotPath != "/v1/system/restart" || gotMethod != "POST" {
		t.Fatalf("%q %q %q", gotAuth, gotPath, gotMethod)
	}
	srv2 := httptest.NewServer(http.NotFoundHandler())
	defer srv2.Close()
	if err := restartNodeHTTP(context.Background(), srv2.URL, "T", ""); err == nil || !strings.Contains(err.Error(), "обновите агент") {
		t.Fatalf("404: %v", err)
	}
	if err := restartNodeHTTP(context.Background(), "http://127.0.0.1:1", "T", ""); err == nil {
		t.Fatal("недоступный агент не вернул ошибку")
	}
}

// Агент по https: перезапуск идёт через клиент с закреплённым отпечатком (M11).
func TestRestartNodeHTTPSPinned(t *testing.T) {
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	good := hex.EncodeToString(sum[:])
	if err := restartNodeHTTP(context.Background(), srv.URL, "T", good); err != nil || hits != 1 {
		t.Fatalf("верный отпечаток: %v, запросов %d", err, hits)
	}
	bad := strings.Repeat("00", 32)
	if err := restartNodeHTTP(context.Background(), srv.URL, "T", bad); err == nil || hits != 1 {
		t.Fatalf("чужой отпечаток должен давать отказ без запроса: %v, запросов %d", err, hits)
	}
	if err := restartNodeHTTP(context.Background(), srv.URL, "T", ""); err == nil || hits != 1 {
		t.Fatalf("https без отпечатка: %v, запросов %d", err, hits)
	}
}

// Смена ключа данных: файл заменён целиком, временного файла нет, ключ в
// памяти новый (I4).
func TestSettingsRegenDataKeyLeavesNoTempFile(t *testing.T) {
	e := newSetEnv(t)
	oldKey := append([]byte(nil), e.srv.DataKey...)
	e.post(t, "/settings/secrets", "10.0.0.1", url.Values{"key": {SecretDataKey}, "action": {"regen"}, "confirm": {"1"}})
	if _, err := os.Stat(e.secFile + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secrets.env.new остался: %v", err)
	}
	m, _ := secrets.Load(e.secFile)
	got, _ := hex.DecodeString(m[SecretDataKey])
	if !bytes.Equal(e.srv.DataKey, got) || bytes.Equal(e.srv.DataKey, oldKey) {
		t.Fatal("ключ в памяти не совпал с файлом")
	}
	if m[secrets.NodeToken] != oldNodeToken {
		t.Fatal("прочие секреты потеряны")
	}
}

// Сбой замены secrets.env в середине смены ключа: база откатывается, файл и
// ключ в памяти прежние, 2FA остаётся читаемой.
func TestSettingsRegenDataKeyFailureKeepsEverything(t *testing.T) {
	e := newSetEnv(t)
	secret := []byte("12345678901234567890")
	sealed, _ := Seal(e.srv.DataKey, secret)
	if err := e.st.SetTOTP(context.Background(), e.admin.ID, sealed, 5); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(e.secFile)
	oldKey := append([]byte(nil), e.srv.DataKey...)
	e.srv.settings.rename = func(string, string) error { return errors.New("диск отказал") }
	rec := e.post(t, "/settings/secrets", "10.0.0.1", url.Values{"key": {SecretDataKey}, "action": {"regen"}, "confirm": {"1"}})
	if rec.Code == 200 && strings.Contains(rec.Body.String(), "перезапуск") {
		t.Fatalf("сбой принят за успех:\n%s", rec.Body)
	}
	after, _ := os.ReadFile(e.secFile)
	if !bytes.Equal(before, after) || !bytes.Equal(oldKey, e.srv.DataKey) {
		t.Fatal("secrets.env или ключ в памяти изменились")
	}
	if _, err := os.Stat(e.secFile + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("временный файл остался")
	}
	u, _ := e.st.UserByID(context.Background(), e.admin.ID)
	got, err := Open(oldKey, u.TOTPSecret)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("секрет 2FA не читается прежним ключом: %v", err)
	}
	if e.wasExit() {
		t.Fatal("панель перезапущена после сбоя")
	}
}

// Предпросмотр: адрес считается по новому списку прокси (M2).
func TestSettingsPreviewProxyWarnings(t *testing.T) {
	e := newSetEnv(t)
	e.srv.TrustedProxies = mustAllow([]string{"10.0.0.1"})
	rec, draft := e.save(t, map[string]string{"panel.trusted_proxies": "192.0.2.0/24"})
	if draft == "" || !strings.Contains(rec.Body.String(), "исчезает из доверенных") {
		t.Fatalf("нет предупреждения о выбывшем прокси:\n%s", rec.Body)
	}
	rec, draft = e.save(t, map[string]string{"panel.trusted_proxies": "0.0.0.0/0"})
	if draft == "" || !strings.Contains(rec.Body.String(), "слишком широка") {
		t.Fatalf("нет предупреждения о широкой сети:\n%s", rec.Body)
	}
}

// Смена listen/base_path обновляет фрагмент nginx в том же применении; возврат
// по таймеру возвращает и фрагмент (M4).
func TestSettingsDangerousSyncsNginxAndRestores(t *testing.T) {
	e := newSetEnv(t)
	type call struct{ base, listen string }
	var calls []call
	e.srv.SyncNginx = func(base, listen string) (bool, error) {
		calls = append(calls, call{base, listen})
		return true, nil
	}
	_, draft := e.save(t, map[string]string{"panel.base_path": "/azpanel/"})
	rec := e.apply(t, draft)
	if rec.Code != 200 || len(calls) != 1 || calls[0].base != "/azpanel/" {
		t.Fatalf("фрагмент не обновлён: %d %v", rec.Code, calls)
	}
	if !strings.Contains(rec.Body.String(), "Фрагмент nginx переписывается") {
		t.Fatalf("страница не сообщает об обновлении:\n%s", rec.Body)
	}
	e.wasExit()
	e.now = e.now.Add(accessConfirmTTL + time.Second)
	e.srv.CheckPending(context.Background())
	if len(calls) != 2 || calls[1].base != "" {
		t.Fatalf("возврат не вернул фрагмент: %v", calls)
	}
	// Не опасное поле nginx не трогает.
	calls = nil
	_, draft = e.save(t, map[string]string{"panel.history_days": "30"})
	e.apply(t, draft)
	if len(calls) != 0 {
		t.Fatalf("лишнее обновление nginx: %v", calls)
	}
	// Сбой правки nginx — замечание на странице, изменение остаётся.
	e.srv.SyncNginx = func(string, string) (bool, error) { return true, errors.New("нет прав") }
	_, draft = e.save(t, map[string]string{"panel.base_path": "/x/"})
	rec = e.apply(t, draft)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "не обновлён") || e.cfg(t).Panel.BasePath != "/x/" {
		t.Fatalf("%d\n%s", rec.Code, rec.Body)
	}
}

// Отказ из-за неподтверждённого опасного изменения не теряет черновик (M12).
func TestSettingsPendingConflictKeepsDraft(t *testing.T) {
	e := newSetEnv(t)
	_, draft := e.save(t, map[string]string{"panel.base_path": "/azpanel/"})
	if _, err := e.srv.Pending.Begin(context.Background(), pendingSettings, "{}", "{}", accessConfirmTTL); err != nil {
		t.Fatal(err)
	}
	if rec := e.apply(t, draft); rec.Code != 409 {
		t.Fatalf("ожидался отказ: %d", rec.Code)
	}
	if err := e.srv.Pending.Confirm(context.Background(), pendingSettings); err != nil {
		t.Fatal(err)
	}
	if rec := e.apply(t, draft); rec.Code != 200 {
		t.Fatalf("черновик потерян после отказа: %d\n%s", rec.Code, rec.Body)
	}
}

// Портал не обходится путём с «..» (M5).
func TestAllowGateCleansPath(t *testing.T) {
	if got := cleanURLPath("/p/../clients"); got != "/clients" {
		t.Fatal(got)
	}
	if got := cleanURLPath("/p/abc/"); got != "/p/abc/" {
		t.Fatal(got)
	}
	if got := cleanURLPath("//dl/../x"); got != "/x" {
		t.Fatal(got)
	}
}

// Агент отказал во фрагменте (пустой префикс в чужом server-блоке): настройка
// не записана, nginx не тронут, введённое не потеряно.
func TestSettingsNginxCheckRefusalKeepsConfig(t *testing.T) {
	e := newSetEnv(t)
	synced := false
	e.srv.SyncNginx = func(string, string) (bool, error) { synced = true; return true, nil }
	e.srv.CheckNginx = func(base, listen string) error {
		if base == "" {
			return errors.New("панель заняла бы весь сайт")
		}
		return nil
	}
	_, draft := e.save(t, map[string]string{"panel.base_path": "/azpanel/"})
	if rec := e.apply(t, draft); rec.Code != 200 {
		t.Fatalf("непустой префикс: %d", rec.Code)
	}
	e.wasExit()
	if err := e.srv.Pending.Confirm(context.Background(), pendingSettings); err != nil {
		t.Fatal(err)
	}
	synced = false
	_, draft = e.save(t, map[string]string{"panel.base_path": ""})
	rec := e.apply(t, draft)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "весь сайт") {
		t.Fatalf("%d\n%s", rec.Code, rec.Body)
	}
	if e.cfg(t).Panel.BasePath != "/azpanel/" || synced {
		t.Fatalf("настройка тронута: %q, nginx: %v", e.cfg(t).Panel.BasePath, synced)
	}
	if rec := e.apply(t, draft); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("черновик потерян: %d", rec.Code)
	}
}
