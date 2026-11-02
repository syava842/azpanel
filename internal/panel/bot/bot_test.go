package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/telegram"
)

const testToken = "123456:SECRET-token"

// --- поддельный Bot API ---

type tgCall struct {
	Method string
	Body   map[string]any
	File   string // имя файла в multipart
	Data   []byte
}

type fakeTG struct {
	mu       sync.Mutex
	calls    []tgCall
	fail     bool   // отвечать ошибкой на отправку
	failCode int    // код ошибки Bot API; 0 — 403
	failChat int64  // не ноль: отказ только для sendMessage в этот чат
	failOnly string // не пусто: отказ только для этого метода (например, sendDocument)
	srv      *httptest.Server
}

func newFakeTG(t *testing.T) *fakeTG {
	t.Helper()
	f := &fakeTG{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		call := tgCall{Method: method, Body: map[string]any{}}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			if err := r.ParseMultipartForm(64 << 20); err == nil {
				for k, v := range r.MultipartForm.Value {
					call.Body[k] = v[0]
				}
				for _, fhs := range r.MultipartForm.File {
					call.File = fhs[0].Filename
					fh, _ := fhs[0].Open()
					call.Data, _ = io.ReadAll(fh)
					fh.Close()
				}
			}
		} else {
			json.NewDecoder(r.Body).Decode(&call.Body)
		}
		f.mu.Lock()
		f.calls = append(f.calls, call)
		fail, code := f.fail && method != "answerCallbackQuery", f.failCode
		if f.failOnly != "" {
			fail = f.failOnly == method
		}
		if f.failChat != 0 {
			fail = fail || (method == "sendMessage" && fmt.Sprint(call.Body["chat_id"]) == fmt.Sprint(f.failChat))
		}
		f.mu.Unlock()
		if fail {
			if code == 0 {
				code = 403
			}
			fmt.Fprintf(w, `{"ok":false,"error_code":%d,"description":"Forbidden: bot was blocked by the user"}`, code)
			return
		}
		switch method {
		case "getMe":
			io.WriteString(w, `{"ok":true,"result":{"id":1,"is_bot":true,"username":"testbot"}}`)
		case "sendMessage", "sendDocument", "sendPhoto":
			io.WriteString(w, `{"ok":true,"result":{"message_id":7,"chat":{"id":1,"type":"private"}}}`)
		default:
			io.WriteString(w, `{"ok":true,"result":true}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTG) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

func (f *fakeTG) of(method string) []tgCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []tgCall
	for _, c := range f.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// texts — тексты всех отправленных и изменённых сообщений.
func (f *fakeTG) texts() []string {
	var out []string
	for _, m := range []string{"sendMessage", "editMessageText"} {
		for _, c := range f.of(m) {
			out = append(out, fmt.Sprint(c.Body["text"]))
		}
	}
	return out
}

// buttons — данные всех кнопок последнего сообщения с клавиатурой.
func (f *fakeTG) buttons() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		rm, ok := f.calls[i].Body["reply_markup"].(map[string]any)
		if !ok {
			continue
		}
		var out []string
		for _, r := range rm["inline_keyboard"].([]any) {
			for _, b := range r.([]any) {
				m := b.(map[string]any)
				out = append(out, fmt.Sprint(m["text"])+"|"+fmt.Sprint(m["callback_data"]))
			}
		}
		return out
	}
	return nil
}

func hasButton(btns []string, sub string) bool {
	for _, b := range btns {
		if strings.Contains(b, sub) {
			return true
		}
	}
	return false
}

// dataOf возвращает callback_data кнопки, чей текст содержит sub.
func dataOf(t *testing.T, btns []string, sub string) string {
	t.Helper()
	for _, b := range btns {
		if strings.Contains(b, sub) {
			return b[strings.LastIndex(b, "|")+1:]
		}
	}
	t.Fatalf("кнопки %q среди %v нет", sub, btns)
	return ""
}

// --- поддельные агент и действия панели ---

type fakeNode struct {
	mu       sync.Mutex
	clients  []nodeapi.Client
	sessions []nodeapi.Session
	profiles map[string][]nodeapi.Profile
	renewed  []string
	limits   []string
	rebooted int
	system   nodeapi.System
	// clientsErr — ошибка, которую вернёт Clients (сетевой сбой)
	clientsErr error
	// backupGate — если задан, CreateBackup ждёт закрытия канала
	backupGate chan struct{}
	// бэкап
	backupTask  nodeapi.Task
	taskPolls   int
	backupFiles []nodeapi.Backup
	backupData  map[string]string
	taskExit    int
	backupCalls int
}

func (n *fakeNode) Info(context.Context) (nodeapi.Info, error) {
	return nodeapi.Info{Hostname: "host1", Version: "v-test"}, nil
}
func (n *fakeNode) Clients(context.Context) ([]nodeapi.Client, error) {
	if n.clientsErr != nil {
		return nil, n.clientsErr
	}
	return n.clients, nil
}
func (n *fakeNode) Sessions(context.Context) ([]nodeapi.Session, error) {
	return n.sessions, nil
}
func (n *fakeNode) System(context.Context) (nodeapi.System, error) { return n.system, nil }
func (n *fakeNode) Profiles(_ context.Context, name string) ([]nodeapi.Profile, error) {
	return n.profiles[name], nil
}
func (n *fakeNode) Profile(_ context.Context, name string, p nodeapi.Profile) ([]byte, error) {
	return []byte("PROFILE:" + name + ":" + p.File), nil
}
func (n *fakeNode) Renew(_ context.Context, name string, days int) (nodeapi.Result, error) {
	n.renewed = append(n.renewed, fmt.Sprintf("%s %d", name, days))
	return nodeapi.Result{}, nil
}
func (n *fakeNode) SetLimit(_ context.Context, name string, limit int) error {
	n.limits = append(n.limits, fmt.Sprintf("%s %d", name, limit))
	return nil
}
func (n *fakeNode) Reboot(context.Context) (nodeapi.Task, error) {
	n.rebooted++
	return nodeapi.Task{ID: "aaaaaaaaaaaa", Kind: "reboot"}, nil
}
func (n *fakeNode) CreateBackup(context.Context) (nodeapi.Task, error) {
	if n.backupGate != nil {
		<-n.backupGate
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.backupCalls++
	n.backupTask = nodeapi.Task{ID: "bbbbbbbbbbbb", Kind: "backup", Started: time.Now()}
	return n.backupTask, nil
}
func (n *fakeNode) Task(_ context.Context, id string) (nodeapi.TaskDetail, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.taskPolls++
	d := nodeapi.TaskDetail{Task: n.backupTask}
	if n.taskPolls >= 2 {
		now := time.Now()
		code := n.taskExit
		d.Finished, d.ExitCode = &now, &code
	}
	return d, nil
}
func (n *fakeNode) Backups(context.Context) ([]nodeapi.Backup, error) {
	return n.backupFiles, nil
}
func (n *fakeNode) Backup(_ context.Context, name string) (io.ReadCloser, error) {
	d, ok := n.backupData[name]
	if !ok {
		return nil, &nodeapi.Error{Status: 404, Message: "бэкап не найден"}
	}
	return io.NopCloser(strings.NewReader(d)), nil
}

type fakeBack struct {
	mu       sync.Mutex
	now      func() time.Time
	tries    map[string][]int64 // ключ -> моменты попыток
	lockedAt map[string]int64
	blocked  []string
	deleted  []string
	created  []string
	redeems  []string
	goodCode string
	users    int
	st       *store.Store
}

func (f *fakeBack) Redeem(_ context.Context, c nodeapi.Client, owner *int64, code string) (Extend, error) {
	f.redeems = append(f.redeems, c.Name+" "+code)
	if code == "BLOCK" {
		return Extend{}, ErrBlocked
	}
	if code != f.goodCode {
		return Extend{}, store.ErrCodeInvalid
	}
	return Extend{Before: 1_800_000_000, After: 1_802_592_000, Days: 30}, nil
}
func (f *fakeBack) Block(_ context.Context, c nodeapi.Client, blocked bool) (int, error) {
	f.blocked = append(f.blocked, fmt.Sprintf("%s %v", c.Name, blocked))
	return 2, nil
}
func (f *fakeBack) Delete(_ context.Context, c nodeapi.Client, kind string) error {
	f.deleted = append(f.deleted, c.Name+" "+kind)
	return nil
}
func (f *fakeBack) Create(_ context.Context, name, kind string, days int) error {
	f.created = append(f.created, fmt.Sprintf("%s %s %d", name, kind, days))
	return nil
}
func (f *fakeBack) NewUser(ctx context.Context, login string) (store.User, error) {
	f.users++
	return f.st.CreateUser(ctx, store.User{Login: login, Hash: "x", Role: store.RoleUser, Created: 1})
}
func (f *fakeBack) QR(data []byte) ([]byte, bool) { return append([]byte("PNG:"), data...), true }

// Попытки — те же правила, что у панели: пять неверных за час закрывают ввод на час.
func (f *fakeBack) OpenAttempt(_ context.Context, userID int64) (AttemptTicket, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fmt.Sprintf("code:user:%d", userID)
	ts := f.now().Unix()
	if f.tries == nil {
		f.tries, f.lockedAt = map[string][]int64{}, map[string]int64{}
	}
	if at, ok := f.lockedAt[key]; ok && ts-at < 3600 {
		return AttemptTicket{}, time.Duration(at+3600-ts) * time.Second, nil
	}
	n := 0
	for _, x := range f.tries[key] {
		if ts-x < 3600 {
			n++
		}
	}
	if n >= 5 {
		return AttemptTicket{}, time.Hour, nil
	}
	f.tries[key] = append(f.tries[key], ts)
	return AttemptTicket{Key: key, TS: ts}, 0, nil
}
func (f *fakeBack) RefundAttempt(_ context.Context, t AttemptTicket) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, x := range f.tries[t.Key] {
		if x == t.TS {
			f.tries[t.Key] = append(f.tries[t.Key][:i], f.tries[t.Key][i+1:]...)
			return
		}
	}
}
func (f *fakeBack) FailAttempt(_ context.Context, t AttemptTicket) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, x := range f.tries[t.Key] {
		if f.now().Unix()-x < 3600 {
			n++
		}
	}
	if n >= 5 {
		f.lockedAt[t.Key] = f.now().Unix()
	}
	return max(5-n, 0)
}

// --- стенд ---

type env struct {
	t    *testing.T
	b    *Bot
	tg   *fakeTG
	node *fakeNode
	back *fakeBack
	st   *store.Store
	now  time.Time
	logs *bytes.Buffer
}

const (
	adminTG = int64(1001)
	userTG  = int64(2002)
)

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, tg: newFakeTG(t), now: time.Unix(1_800_000_000, 0), logs: &bytes.Buffer{}}
	e.node = &fakeNode{
		clients: []nodeapi.Client{
			{Name: "alice", OpenVPN: true, WireGuard: true},
			{Name: "bob", OpenVPN: true},
		},
		profiles: map[string][]nodeapi.Profile{
			"alice": {{Kind: "openvpn", Variant: "antizapret", File: "a.ovpn"}, {Kind: "wireguard", Variant: "antizapret", File: "a.conf"}},
			"bob":   {{Kind: "openvpn", Variant: "vpn", File: "b.ovpn"}},
		},
		backupData: map[string]string{},
	}
	e.back = &fakeBack{goodCode: "GOOD", st: st, now: func() time.Time { return e.now }}
	c := telegram.New(testToken, e.tg.srv.URL)
	e.b = &Bot{
		TG: c, Node: e.node, Store: st, Back: e.back, NodeID: store.LocalNode,
		Cfg: config.Default().Telegram,
		Log: slog.New(slog.NewTextHandler(e.logs, nil)), Now: func() time.Time { return e.now },
		BackupDir: filepath.Join(t.TempDir(), "backup"), PollEvery: time.Millisecond, Sync: true,
	}
	return e
}

// user создаёт пользователя; tg != 0 привязывает Telegram.
func (e *env) user(login, role string, tg int64) store.User {
	e.t.Helper()
	u, err := e.st.CreateUser(context.Background(), store.User{Login: login, Hash: "x", Role: role, Created: 1})
	if err != nil {
		e.t.Fatal(err)
	}
	if tg != 0 {
		if err := e.st.SetTelegramID(context.Background(), u.ID, tg); err != nil {
			e.t.Fatal(err)
		}
	}
	return u
}

func (e *env) msg(from int64, text string) {
	e.t.Helper()
	e.msgIn(from, "private", text)
}

func (e *env) msgIn(from int64, chatType, text string) {
	e.t.Helper()
	e.b.HandleUpdate(context.Background(), telegram.Update{UpdateID: 1, Message: &telegram.Message{
		MessageID: 5, From: &telegram.User{ID: from, FirstName: "Имя", Username: "nick"},
		Chat: telegram.Chat{ID: from, Type: chatType}, Text: text,
	}})
}

func (e *env) press(from int64, data string) {
	e.t.Helper()
	e.pressIn(from, "private", data)
}

func (e *env) pressIn(from int64, chatType, data string) {
	e.t.Helper()
	e.b.HandleUpdate(context.Background(), telegram.Update{UpdateID: 2, CallbackQuery: &telegram.CallbackQuery{
		ID: "cbid", From: telegram.User{ID: from}, Data: data,
		Message: &telegram.Message{MessageID: 9, Chat: telegram.Chat{ID: from, Type: chatType}},
	}})
}

func (e *env) toast() string {
	calls := e.tg.of("answerCallbackQuery")
	if len(calls) == 0 {
		return ""
	}
	return fmt.Sprint(calls[len(calls)-1].Body["text"])
}

// --- привязка ---

func TestLinkByCodeBindsOnce(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, 0)
	code, err := e.st.CreateLinkCode(context.Background(), u.ID, e.now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	e.msg(userTG, "/start "+code)
	got, err := e.st.UserByTelegramID(context.Background(), userTG)
	if err != nil || got.ID != u.ID {
		t.Fatalf("привязка не сработала: %+v, %v", got, err)
	}
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "Готово") {
		t.Fatalf("нет подтверждения: %q", txt)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "tg_link")
	if len(list) != 1 || list[0].IP != "tg:2002" || list[0].User != "ivan" {
		t.Fatalf("журнал: %+v", list)
	}
	// тот же код другим Telegram — отказ
	e.tg.reset()
	e.msg(3003, "/start "+code)
	if _, err := e.st.UserByTelegramID(context.Background(), 3003); err == nil {
		t.Fatal("код сработал дважды")
	}
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "недействителен") {
		t.Fatalf("нет отказа: %q", txt)
	}
}

func TestLinkExpiredCodeRefused(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, 0)
	code, _ := e.st.CreateLinkCode(context.Background(), u.ID, e.now.Unix())
	e.now = e.now.Add(11 * time.Minute)
	e.msg(userTG, "/start "+code)
	if _, err := e.st.UserByTelegramID(context.Background(), userTG); err == nil {
		t.Fatal("просроченный код принят")
	}
}

func TestStrangerClosedIsSilent(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "closed"
	e.msg(9, "привет")
	e.msg(9, "/start")
	e.press(9, "l:0")
	for _, m := range []string{"sendMessage", "editMessageText", "sendDocument"} {
		if n := len(e.tg.of(m)); n != 0 {
			t.Fatalf("%s: %d вызовов у непривязанного в closed", m, n)
		}
	}
}

func TestStrangerRequestNotifiesAdminsOnce(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	e.msg(9, "привет")
	reqs, _ := e.st.TelegramRequests(context.Background())
	if len(reqs) != 1 || reqs[0].ID != 9 || reqs[0].Username != "nick" {
		t.Fatalf("заявка: %+v", reqs)
	}
	var toAdmin, toStranger int
	for _, c := range e.tg.of("sendMessage") {
		switch fmt.Sprint(c.Body["chat_id"]) {
		case "1001":
			toAdmin++
		case "9":
			toStranger++
		}
	}
	if toAdmin != 1 || toStranger != 1 {
		t.Fatalf("администратору %d, заявителю %d", toAdmin, toStranger)
	}
	btns := e.tg.buttons()
	for _, w := range []string{"Одобрить", "Отклонить", "Заблокировать ID"} {
		if !hasButton(btns, w) {
			t.Fatalf("нет кнопки %q: %v", w, btns)
		}
	}
	e.tg.reset()
	e.msg(9, "ещё раз")
	for _, c := range e.tg.of("sendMessage") {
		if fmt.Sprint(c.Body["chat_id"]) == "1001" {
			t.Fatal("администратора уведомили повторно")
		}
	}
}

func TestApproveRequestBindsExistingUser(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	ivan := e.user("ivan", store.RoleUser, 0)
	e.msg(9, "привет")
	e.press(adminTG, "ra:9")
	btns := e.tg.buttons()
	if !hasButton(btns, "ivan") || hasButton(btns, "root") {
		t.Fatalf("список для привязки: %v", btns)
	}
	e.press(adminTG, dataOf(t, btns, "ivan"))
	got, err := e.st.UserByTelegramID(context.Background(), 9)
	if err != nil || got.ID != ivan.ID {
		t.Fatalf("не привязан: %+v %v", got, err)
	}
	if reqs, _ := e.st.TelegramRequests(context.Background()); len(reqs) != 0 {
		t.Fatalf("заявка осталась: %+v", reqs)
	}
}

func TestApproveRequestCreatesUserAndBan(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	e.msg(9, "привет")
	e.press(adminTG, "rc:9")
	got, err := e.st.UserByTelegramID(context.Background(), 9)
	if err != nil || got.Login != "nick" || got.Role != store.RoleUser {
		t.Fatalf("новый пользователь: %+v %v", got, err)
	}
	e.msg(10, "привет")
	e.press(adminTG, "rx:10")
	e.tg.reset()
	e.msg(10, "привет")
	if len(e.tg.of("sendMessage")) != 0 {
		t.Fatal("заблокированному ID ответили")
	}
}

func TestBannedIsAlwaysSilent(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("ivan", store.RoleUser, userTG)
	e.st.BanTelegram(context.Background(), userTG, 1)
	e.msg(userTG, "/start")
	e.press(userTG, "l:0")
	if len(e.tg.of("sendMessage"))+len(e.tg.of("editMessageText")) != 0 {
		t.Fatal("заблокированный получил ответ")
	}
}

func TestGroupChatsIgnored(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	for _, ct := range []string{"group", "supergroup", "channel"} {
		e.msgIn(adminTG, ct, "/start")
		e.pressIn(adminTG, ct, "z")
	}
	if n := len(e.tg.of("sendMessage")) + len(e.tg.of("editMessageText")); n != 0 {
		t.Fatalf("групповой чат получил %d ответов", n)
	}
}

// --- права ---

func TestUserSeesOnlyOwnClientsAndNoAdminButtons(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, userTG)
	e.st.SetOwner(context.Background(), store.LocalNode, "alice", &u.ID)

	e.msg(userTG, "/menu")
	if btns := e.tg.buttons(); hasButton(btns, "Перезагрузка") || hasButton(btns, "Создать") || hasButton(btns, "Бэкап") || !hasButton(btns, "Ввести код") {
		t.Fatalf("меню пользователя: %v", btns)
	}
	e.press(userTG, "l:0")
	btns := e.tg.buttons()
	if !hasButton(btns, "alice") || hasButton(btns, "bob") {
		t.Fatalf("список: %v", btns)
	}
	// чужая карточка недоступна
	e.tg.reset()
	e.press(userTG, "c:bob")
	if len(e.tg.of("editMessageText")) != 0 || e.toast() != textGone {
		t.Fatalf("чужая карточка: toast %q", e.toast())
	}
	e.press(userTG, "p:bob")
	e.press(userTG, "f:0:bob")
	if len(e.tg.of("sendDocument")) != 0 {
		t.Fatal("чужой профиль выдан")
	}
	// своя карточка без кнопок администратора
	e.press(userTG, "c:alice")
	btns = e.tg.buttons()
	if hasButton(btns, "Удалить") || hasButton(btns, "Заблокировать") || hasButton(btns, "+30") {
		t.Fatalf("кнопки администратора у пользователя: %v", btns)
	}
	// прямой вызов административных операций
	for _, d := range []string{"b:1:alice", "d:alice", "e:30:alice", "i:1:alice", "z", "u", "n", "s", "ra:9"} {
		e.press(userTG, d)
		if e.toast() != textNoRights {
			t.Fatalf("%s: toast %q", d, e.toast())
		}
	}
	if len(e.back.blocked)+len(e.back.deleted)+len(e.node.renewed)+len(e.node.limits)+e.node.rebooted != 0 || e.node.backupCalls != 0 {
		t.Fatal("административное действие выполнено пользователем")
	}
}

func TestProfilesFilteredByClientKinds(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, userTG)
	e.st.SetOwner(context.Background(), store.LocalNode, "alice", &u.ID)
	e.user("root", store.RoleAdmin, adminTG)
	e.st.SetClientKinds(context.Background(), store.LocalNode, "alice", []string{"wireguard"})

	e.press(userTG, "p:alice")
	btns := e.tg.buttons()
	if hasButton(btns, "openvpn/") || !hasButton(btns, "wireguard/") {
		t.Fatalf("профили пользователя: %v", btns)
	}
	e.press(adminTG, "p:alice")
	if btns := e.tg.buttons(); !hasButton(btns, "openvpn/") || !hasButton(btns, "wireguard/") {
		t.Fatalf("профили администратора: %v", btns)
	}
	// у пользователя индекс 0 — это wireguard
	e.tg.reset()
	e.press(userTG, "f:0:alice")
	docs := e.tg.of("sendDocument")
	if len(docs) != 1 || docs[0].File != "a.conf" || string(docs[0].Data) != "PROFILE:alice:a.conf" {
		t.Fatalf("документ: %+v", docs)
	}
	e.press(userTG, "q:0:alice")
	ph := e.tg.of("sendPhoto")
	if len(ph) != 1 || !strings.HasPrefix(string(ph[0].Data), "PNG:") {
		t.Fatalf("QR: %+v", ph)
	}
	// QR у OpenVPN нет, даже администратору
	e.press(adminTG, "q:0:alice")
	if len(e.tg.of("sendPhoto")) != 1 {
		t.Fatal("QR выдан для OpenVPN")
	}
}

// --- опасные действия ---

func TestDeleteNeedsConfirmationAndExpires(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.press(adminTG, "d:bob")
	if len(e.back.deleted) != 0 {
		t.Fatal("удалено без подтверждения")
	}
	tok := dataOf(t, e.tg.buttons(), "Да, удалить")
	e.press(adminTG, tok)
	if len(e.back.deleted) != 1 || e.back.deleted[0] != "bob openvpn" {
		t.Fatalf("удаление: %v", e.back.deleted)
	}
	// повтор того же подтверждения не работает
	e.press(adminTG, tok)
	if len(e.back.deleted) != 1 {
		t.Fatal("подтверждение сработало дважды")
	}
	// истечение через 60 с
	e.press(adminTG, "d:bob")
	tok = dataOf(t, e.tg.buttons(), "Да, удалить")
	e.now = e.now.Add(61 * time.Second)
	e.press(adminTG, tok)
	if len(e.back.deleted) != 1 {
		t.Fatalf("просроченное подтверждение сработало: %v", e.back.deleted)
	}
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "истекло") {
		t.Fatalf("нет сообщения об истечении: %q", txt)
	}
	// до 60 с работает
	e.press(adminTG, "d:bob")
	tok = dataOf(t, e.tg.buttons(), "Да, удалить")
	e.now = e.now.Add(59 * time.Second)
	e.press(adminTG, tok)
	if len(e.back.deleted) != 2 {
		t.Fatalf("подтверждение в срок не сработало: %v", e.back.deleted)
	}
}

func TestConfirmIsBoundToAskingAdmin(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.user("root2", store.RoleAdmin, 1002)
	e.press(adminTG, "z")
	tok := dataOf(t, e.tg.buttons(), "Да, перезагрузить")
	e.press(1002, tok)
	if e.node.rebooted != 0 {
		t.Fatal("чужое подтверждение сработало")
	}
	e.press(adminTG, "z")
	tok = dataOf(t, e.tg.buttons(), "Да, перезагрузить")
	e.press(adminTG, tok)
	if e.node.rebooted != 1 {
		t.Fatalf("перезагрузок %d", e.node.rebooted)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "reboot")
	if len(list) != 1 || list[0].IP != "tg:1001" {
		t.Fatalf("журнал: %+v", list)
	}
}

func TestAdminClientActionsAreAudited(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.press(adminTG, "b:1:alice")
	e.press(adminTG, "e:90:alice")
	e.press(adminTG, "i:3:alice")
	if len(e.back.blocked) != 1 || e.back.blocked[0] != "alice true" ||
		len(e.node.renewed) != 1 || e.node.renewed[0] != "alice 90" ||
		len(e.node.limits) != 1 || e.node.limits[0] != "alice 3" {
		t.Fatalf("действия: %v %v %v", e.back.blocked, e.node.renewed, e.node.limits)
	}
	list, total, _ := e.st.AuditList(context.Background(), 20, 0, "")
	if total != 3 {
		t.Fatalf("записей журнала %d: %+v", total, list)
	}
	for _, en := range list {
		if en.User != "root" || en.IP != "tg:1001" {
			t.Fatalf("запись: %+v", en)
		}
	}
}

func TestCreateClientDialog(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.press(adminTG, "n")
	e.msg(adminTG, "плохое имя!")
	if len(e.back.created) != 0 {
		t.Fatal("создан клиент с плохим именем")
	}
	e.msg(adminTG, "carol")
	e.press(adminTG, "t:openvpn")
	e.press(adminTG, "g:90")
	if len(e.back.created) != 1 || e.back.created[0] != "carol openvpn 90" {
		t.Fatalf("создание: %v", e.back.created)
	}
}

// --- ввод кода ---

func TestCodeEntryExtendsAndLimitsAttempts(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, userTG)
	e.st.SetOwner(context.Background(), store.LocalNode, "alice", &u.ID)

	e.press(userTG, "k")
	for i := 0; i < 5; i++ {
		e.msg(userTG, "WRONG")
	}
	if len(e.back.redeems) != 5 {
		t.Fatalf("попыток %d", len(e.back.redeems))
	}
	// шестая, даже верная, не доходит до гашения
	e.press(userTG, "k")
	e.msg(userTG, "GOOD")
	if len(e.back.redeems) != 5 {
		t.Fatalf("после лимита код проверялся: %v", e.back.redeems)
	}
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "закрыт на час") {
		t.Fatalf("нет сообщения о закрытии: %q", txt)
	}
	// через час окно очищается
	e.now = e.now.Add(61 * time.Minute)
	e.press(userTG, "k")
	e.msg(userTG, "GOOD")
	if len(e.back.redeems) != 6 {
		t.Fatalf("код не проверен после часа: %v", e.back.redeems)
	}
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "продлён на 30 дн.") {
		t.Fatalf("нет сообщения о продлении: %q", txt)
	}
	list, _, _ := e.st.AuditList(context.Background(), 10, 0, "redeem")
	if len(list) != 1 || list[0].Target != "alice" || list[0].IP != "tg:2002" {
		t.Fatalf("журнал: %+v", list)
	}
}

func TestCodeAttemptsAreCountedPerTelegramID(t *testing.T) {
	e := newEnv(t)
	u1 := e.user("ivan", store.RoleUser, userTG)
	u2 := e.user("petr", store.RoleUser, 3003)
	e.st.SetOwner(context.Background(), store.LocalNode, "alice", &u1.ID)
	e.st.SetOwner(context.Background(), store.LocalNode, "bob", &u2.ID)
	e.press(userTG, "k")
	for i := 0; i < 5; i++ {
		e.msg(userTG, "WRONG")
	}
	e.press(3003, "k")
	e.msg(3003, "GOOD")
	if last := e.back.redeems[len(e.back.redeems)-1]; last != "bob GOOD" {
		t.Fatalf("второй пользователь заблокирован чужими попытками: %v", e.back.redeems)
	}
}

// --- бэкап ---

func TestBackupButtonSendsFileAndKeeps14(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.node.backupFiles = []nodeapi.Backup{
		{Name: "backup-new.tar.gz", Size: 4, Modified: time.Now()},
		{Name: "backup-old.tar.gz", Size: 3, Modified: time.Now().Add(-48 * time.Hour)},
	}
	e.node.backupData["backup-new.tar.gz"] = "DATA"
	// 15 прежних копий: останется 14 с новой
	os.MkdirAll(e.b.BackupDir, 0o750)
	for i := 0; i < 15; i++ {
		os.WriteFile(filepath.Join(e.b.BackupDir, fmt.Sprintf("tgbackup-202001%02dT000000Z.tar.gz", i+1)), []byte("x"), 0o600)
	}
	e.press(adminTG, "u")
	docs := e.tg.of("sendDocument")
	if len(docs) != 1 || string(docs[0].Data) != "DATA" || !strings.HasPrefix(docs[0].File, "tgbackup-") {
		t.Fatalf("документ бэкапа: %+v", docs)
	}
	ents, _ := os.ReadDir(e.b.BackupDir)
	if len(ents) != 14 {
		t.Fatalf("в каталоге %d копий", len(ents))
	}
	if e.node.backupCalls != 1 {
		t.Fatalf("задач бэкапа %d", e.node.backupCalls)
	}
}

func TestBackupFailureReported(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.node.taskExit = 1
	e.press(adminTG, "u")
	if len(e.tg.of("sendDocument")) != 0 {
		t.Fatal("файл отправлен при сбое задачи")
	}
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "Бэкап не создан") {
		t.Fatalf("нет сообщения о сбое: %q", txt)
	}
}

// --- журнал ---

func TestTokenNeverInLogs(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	// Bot API перестаёт отвечать: ошибки идут в журнал бота.
	e.tg.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.b.HandleUpdate(ctx, telegram.Update{Message: &telegram.Message{
		From: &telegram.User{ID: adminTG}, Chat: telegram.Chat{ID: adminTG, Type: "private"}, Text: "/menu",
	}})
	if e.logs.Len() == 0 {
		t.Fatal("ошибка отправки не записана в журнал")
	}
	if strings.Contains(e.logs.String(), "SECRET-token") || strings.Contains(e.logs.String(), "123456:") {
		t.Fatalf("токен в журнале: %s", e.logs.String())
	}
	if err := e.b.Init(ctx); err == nil || strings.Contains(err.Error(), "SECRET-token") {
		t.Fatalf("ошибка Init: %v", err)
	}
}

func TestNodeScreenAndCardForAdmin(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.node.sessions = []nodeapi.Session{{Name: "alice", Kind: "openvpn"}}
	e.press(adminTG, "s")
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "host1") || !strings.Contains(txt, "Сессий онлайн: 1") {
		t.Fatalf("узел: %q", txt)
	}
	e.press(adminTG, "l:0")
	if !hasButton(e.tg.buttons(), "● alice") {
		t.Fatalf("онлайн не отмечен: %v", e.tg.buttons())
	}
	e.msg(adminTG, "bo")
	if !hasButton(e.tg.buttons(), "bob") || hasButton(e.tg.buttons(), "alice") {
		t.Fatalf("поиск: %v", e.tg.buttons())
	}
	e.press(adminTG, "c:bob")
	b := e.tg.buttons()
	for _, w := range []string{"Заблокировать", "Удалить", "+30 дн.", "Лимит: 1", "Снять"} {
		if !hasButton(b, w) {
			t.Fatalf("нет кнопки %q: %v", w, b)
		}
	}
}

func TestCodeForManuallyBlockedClientKeepsCode(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, userTG)
	e.st.SetOwner(context.Background(), store.LocalNode, "alice", &u.ID)
	e.press(userTG, "k")
	e.msg(userTG, "BLOCK")
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "код не потрачен") {
		t.Fatalf("нет объяснения: %q", txt)
	}
	// попытка не засчитана: пять неверных кодов после этого всё ещё доступны
	e.press(userTG, "k")
	for i := 0; i < 5; i++ {
		e.msg(userTG, "WRONG")
	}
	if len(e.back.redeems) != 6 {
		t.Fatalf("попытки: %v", e.back.redeems)
	}
}
