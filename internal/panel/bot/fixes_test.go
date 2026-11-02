package bot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
	"github.com/syava842/azpanel/internal/telegram"
)

// --- I1: одобрение заявки ---

func TestApproveListHidesUnboundAdmin(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	adm2 := e.user("admin2", store.RoleAdmin, 0) // администратор без привязки
	ivan := e.user("ivan", store.RoleUser, 0)
	e.msg(9, "привет")
	e.press(adminTG, "ra:9")
	btns := e.tg.buttons()
	if hasButton(btns, "admin2") || !hasButton(btns, "ivan") {
		t.Fatalf("в списке должен быть только обычный пользователь: %v", btns)
	}
	// прямое нажатие на администратора отклоняется
	e.press(adminTG, fmt.Sprintf("rb:9:%d", adm2.ID))
	if _, err := e.st.UserByTelegramID(context.Background(), 9); err == nil {
		t.Fatal("Telegram привязан к администратору через бота")
	}
	if got, _ := e.st.UserByID(context.Background(), adm2.ID); got.TelegramID != nil {
		t.Fatal("у администратора появилась привязка")
	}
	if !strings.Contains(e.toast(), "нельзя") {
		t.Fatalf("нет отказа: %q", e.toast())
	}
	_ = ivan
}

func TestApproveDoesNotOverwriteExistingBinding(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	ivan := e.user("ivan", store.RoleUser, 0)
	e.msg(9, "привет")
	e.press(adminTG, "ra:9")
	btn := dataOf(t, e.tg.buttons(), "ivan") // список открыт, пока Иван не привязан
	if err := e.st.SetTelegramID(context.Background(), ivan.ID, userTG); err != nil {
		t.Fatal(err)
	}
	e.press(adminTG, btn)
	got, _ := e.st.UserByID(context.Background(), ivan.ID)
	if got.TelegramID == nil || *got.TelegramID != userTG {
		t.Fatalf("чужая привязка затёрта: %+v", got.TelegramID)
	}
	if _, err := e.st.UserByTelegramID(context.Background(), 9); err == nil {
		t.Fatal("заявитель привязан")
	}
}

// --- I2: получатели бэкапа ---

func TestScheduledBackupOnlyToActiveAdminsAndConfirmedGroups(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.BackupEveryDays = 1
	e.b.Cfg.BackupChats = []int64{555, 556, -100, -200}
	e.user("owner", store.RoleAdmin, 555)
	fired := e.user("fired", store.RoleAdmin, 556)
	e.user("root", store.RoleAdmin, adminTG)
	if err := e.st.SetRole(context.Background(), fired.ID, store.RoleUser); err != nil { // разжалован
		t.Fatal(err)
	}
	if err := e.st.SetMeta(context.Background(), BackupGroupsKey, "-200"); err != nil {
		t.Fatal(err)
	}
	e.node.backupFiles = []nodeapi.Backup{{Name: "backup-x.tar.gz", Size: 4, Modified: time.Now().Add(time.Hour)}}
	e.node.backupData["backup-x.tar.gz"] = "DATA"
	e.b.scheduleTick(context.Background(), time.Unix(1_800_000_000, 0))

	got := map[string]bool{}
	for _, c := range e.tg.of("sendDocument") {
		got[fmt.Sprint(c.Body["chat_id"])] = true
	}
	if len(got) != 2 || !got["555"] || !got["-200"] {
		t.Fatalf("файл ушёл в %v, ожидались 555 и -200", got)
	}
	// администраторы узнают об отказе текстом, без файла
	if txt := strings.Join(e.sentTo(), "|"); !strings.Contains(txt, "1001:") || !strings.Contains(txt, "не отправлен в чаты") {
		t.Fatalf("администраторов не предупредили: %q", txt)
	}
	if !strings.Contains(e.logs.String(), "level=WARN") {
		t.Fatal("отказ не записан в журнал")
	}
}

func TestScheduledBackupNoRecipientsMakesNoBackup(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.BackupEveryDays = 1
	e.b.Cfg.BackupChats = []int64{-100} // группа не подтверждена
	e.b.scheduleTick(context.Background(), time.Unix(1_800_000_000, 0))
	if e.node.backupCalls != 0 || len(e.tg.of("sendDocument")) != 0 {
		t.Fatalf("бэкап сделан без получателей: задач %d", e.node.backupCalls)
	}
}

func TestScheduledBackupDeliveryFailureIsReportedAndRetried(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.BackupEveryDays = 1
	e.b.Cfg.BackupChats = []int64{555}
	e.user("owner", store.RoleAdmin, 555)
	e.node.backupFiles = []nodeapi.Backup{{Name: "backup-x.tar.gz", Size: 4, Modified: time.Now().Add(time.Hour)}}
	e.node.backupData["backup-x.tar.gz"] = "DATA"
	e.tg.mu.Lock()
	e.tg.failOnly, e.tg.failCode = "sendDocument", 500
	e.tg.mu.Unlock()
	e.b.scheduleTick(context.Background(), time.Unix(1_800_000_000, 0))
	if txt := strings.Join(e.sentTo(), "|"); !strings.Contains(txt, "не отправлен") {
		t.Fatalf("о сбое отправки файла чат не уведомлён: %q", txt)
	}
	if _, found, _ := e.st.Meta(context.Background(), backupLastKey); found {
		t.Fatal("недоставленный бэкап отмечен как сделанный")
	}
}

func TestBackupDoesNotBlockSchedule(t *testing.T) {
	e := newEnv(t)
	e.b.Sync = false
	e.b.Cfg.BackupEveryDays = 1
	e.b.Cfg.BackupChats = []int64{555}
	e.user("owner", store.RoleAdmin, 555)
	e.node.backupGate = make(chan struct{})
	done := make(chan struct{})
	go func() {
		e.b.scheduleTick(context.Background(), time.Unix(1_800_000_000, 0))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("расписание ждёт бэкап")
	}
	close(e.node.backupGate)
	e.b.tasks.Wait()
}

// --- I3 (бот): привязка сообщает администраторам; отключённый не привязывается ---

func TestLinkNotifiesOtherAdmins(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	u := e.user("ivan", store.RoleUser, 0)
	code, _ := e.st.CreateLinkCode(context.Background(), u.ID, e.now.Unix())
	e.msg(userTG, "/start "+code)
	found := false
	for _, s := range e.sentTo() {
		if strings.HasPrefix(s, "1001:") && strings.Contains(s, "ivan") && strings.Contains(s, "2002") {
			found = true
		}
	}
	if !found {
		t.Fatalf("администратору не сообщили о привязке: %v", e.sentTo())
	}
}

func TestLinkRefusedForDisabledUser(t *testing.T) { // M14
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, 0)
	code, _ := e.st.CreateLinkCode(context.Background(), u.ID, e.now.Unix())
	if err := e.st.SetDisabled(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}
	e.msg(userTG, "/start "+code)
	if _, err := e.st.UserByTelegramID(context.Background(), userTG); err == nil {
		t.Fatal("отключённая учётная запись привязана")
	}
	if txt := strings.Join(e.tg.texts(), "|"); strings.Contains(txt, "Готово") {
		t.Fatalf("сказано «Готово»: %q", txt)
	}
}

func TestLinkAttemptsLimitedPerTelegramID(t *testing.T) { // M17
	e := newEnv(t)
	for i := 0; i < linkMax; i++ {
		e.msg(9, fmt.Sprintf("/start bad%d", i))
	}
	e.tg.reset()
	e.msg(9, "/start bad-next")
	if len(e.tg.of("sendMessage")) != 0 {
		t.Fatal("после предела попыток бот продолжает отвечать")
	}
}

// --- M2: заявки ---

func TestRequestFloodCapped(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	for i := 0; i < maxRequests+5; i++ {
		e.msg(int64(100+i), "привет")
	}
	reqs, _ := e.st.TelegramRequests(context.Background())
	if len(reqs) != maxRequests {
		t.Fatalf("заявок %d, предел %d", len(reqs), maxRequests)
	}
}

func TestRequesterAnsweredOnlyOnce(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	e.msg(9, "привет")
	e.msg(9, "ещё")
	e.msg(9, "и ещё")
	n := 0
	for _, c := range e.tg.of("sendMessage") {
		if fmt.Sprint(c.Body["chat_id"]) == "9" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("заявителю ответили %d раз", n)
	}
}

func TestRejectedRequestStaysQuietForADay(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "request"
	e.user("root", store.RoleAdmin, adminTG)
	e.msg(9, "привет")
	e.press(adminTG, "rd:9")
	e.tg.reset()
	e.msg(9, "ну пожалуйста")
	if len(e.tg.of("sendMessage")) != 0 {
		t.Fatal("отклонённый ID снова породил заявку")
	}
	e.now = e.now.Add(25 * time.Hour)
	e.msg(9, "ещё раз")
	if reqs, _ := e.st.TelegramRequests(context.Background()); len(reqs) != 1 {
		t.Fatalf("через сутки заявка должна подаваться: %+v", reqs)
	}
}

// --- M3, M4: очередь ---

func TestDeliveryFailCountSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.enqueue(KindNodeDown, nil, "узел")
	e.failSend(true, 500)
	for i := 0; i < 5; i++ {
		e.b.DeliverOutbox(context.Background())
	}
	// перезапуск панели: бот новый, база прежняя
	fresh := &Bot{TG: e.b.TG, Node: e.b.Node, Store: e.b.Store, Back: e.b.Back, Cfg: e.b.Cfg, NodeID: e.b.NodeID, Log: e.b.Log, Now: e.b.Now, Sync: true}
	for i := 0; i < 4; i++ {
		fresh.DeliverOutbox(context.Background())
		if e.pending() != 1 {
			t.Fatalf("проход %d после перезапуска: запись отброшена раньше десяти неудач", i+6)
		}
	}
	fresh.DeliverOutbox(context.Background())
	if e.pending() != 0 {
		t.Fatal("счётчик неудач не пережил перезапуск")
	}
}

type failUsers struct{ Store }

func (failUsers) Users(context.Context) ([]store.User, error) {
	return nil, errors.New("база недоступна")
}

func TestDeliveryKeptWhenRecipientsUnreadable(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.enqueue(KindNodeDown, nil, "узел")
	good := e.b.Store
	e.b.Store = failUsers{good}
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 1 {
		t.Fatal("запись пропала при сбое чтения получателей")
	}
	e.b.Store = good
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 0 || len(e.sentTo()) != 1 {
		t.Fatalf("после восстановления: в очереди %d, отправлено %v", e.pending(), e.sentTo())
	}
}

func TestFirstStartSkipsStaleOutbox(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	ctx := context.Background()
	if _, err := e.st.Enqueue(ctx, KindNodeDown, nil, NoticeJSON("старое"), e.now.Add(-72*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	e.enqueue(KindNodeDown, nil, "свежее")
	e.b.DeliverOutbox(ctx)
	got := strings.Join(e.sentTo(), "|")
	if strings.Contains(got, "старое") || !strings.Contains(got, "свежее") {
		t.Fatalf("при первом запуске: %q", got)
	}
	if e.pending() != 0 {
		t.Fatal("устаревшая запись осталась в очереди")
	}
	// отметка стоит: позднее такие записи не отбрасываются
	e.tg.reset()
	if _, err := e.st.Enqueue(ctx, KindNodeDown, nil, NoticeJSON("давнее, но после запуска"), e.now.Add(-72*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	e.b.mu.Lock()
	e.b.outboxOK = false
	e.b.mu.Unlock()
	e.b.DeliverOutbox(ctx)
	if !strings.Contains(strings.Join(e.sentTo(), "|"), "давнее") {
		t.Fatal("отсечка действует не только при первом запуске")
	}
}

// --- M6: ресурсы из снимка сборщика ---

func TestNodeScreenUsesCollectorSnapshot(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.press(adminTG, "s")
	if txt := strings.Join(e.tg.texts(), "|"); strings.Contains(txt, "ЦП") {
		t.Fatalf("ресурсы показаны без снимка: %q", txt)
	}
	e.b.LastSystem = func() (nodeapi.System, bool) {
		var s nodeapi.System
		s.Resources.CPUPercent = 77
		return s, true
	}
	e.tg.reset()
	e.press(adminTG, "s")
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "ЦП 77%") {
		t.Fatalf("снимок сборщика не показан: %q", txt)
	}
}

// --- M10: долгие действия ---

func TestLongActionAnswersCallbackFirst(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.press(adminTG, "z")
	tok := dataOf(t, e.tg.buttons(), "Да, перезагрузить")
	e.tg.reset()
	e.press(adminTG, tok)
	e.tg.mu.Lock()
	defer e.tg.mu.Unlock()
	ans, act := -1, -1
	for i, c := range e.tg.calls {
		switch c.Method {
		case "answerCallbackQuery":
			if ans < 0 {
				ans = i
			}
		case "editMessageText", "sendMessage":
			if act < 0 {
				act = i
			}
		}
	}
	if ans < 0 || act < 0 || ans > act {
		t.Fatalf("кнопке нужно отвечать до долгого действия: ответ %d, итог %d", ans, act)
	}
	if e.node.rebooted != 1 {
		t.Fatal("перезагрузка не выполнена")
	}
}

func TestLongActionRunsInBackground(t *testing.T) {
	e := newEnv(t)
	e.b.Sync = false
	e.user("root", store.RoleAdmin, adminTG)
	e.press(adminTG, "z")
	tok := dataOf(t, e.tg.buttons(), "Да, перезагрузить")
	e.press(adminTG, tok)
	e.b.tasks.Wait()
	if e.node.rebooted != 1 {
		t.Fatalf("перезагрузок %d", e.node.rebooted)
	}
}

func TestLongActionFailureGoesToChat(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.node.clientsErr = errors.New("dial tcp 10.0.0.5:8443: connection refused")
	e.press(adminTG, "e:30:alice")
	if got := e.toast(); got != "" {
		t.Fatalf("всплывашка у долгого действия: %q", got)
	}
	txt := strings.Join(e.tg.texts(), "|")
	if !strings.Contains(txt, "временно недоступен") {
		t.Fatalf("итог не пришёл сообщением: %q", txt)
	}
}

// --- M12 ---

func TestPollPauseGrowsAndCaps(t *testing.T) {
	if pollPause(1) != 5*time.Second || pollPause(2) <= pollPause(1) || pollPause(50) != pollPauseMax {
		t.Fatalf("паузы: %v %v %v", pollPause(1), pollPause(2), pollPause(50))
	}
	now := time.Unix(1_800_000_000, 0)
	if !pollShouldLog(1, time.Time{}, now) {
		t.Fatal("первая ошибка серии не пишется")
	}
	if pollShouldLog(2, now, now.Add(time.Minute)) {
		t.Fatal("повтор через минуту пишется")
	}
	if !pollShouldLog(40, now, now.Add(pollLogEvery)) {
		t.Fatal("раз в pollLogEvery писать нужно")
	}
}

// --- M1: счётчик кодов общий по пользователю, а не по Telegram ID ---

func TestCodeAttemptsSharedByPanelUser(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, userTG)
	e.st.SetOwner(context.Background(), store.LocalNode, "alice", &u.ID)
	// пять неверных кодов уже сделаны в вебе тем же пользователем
	for i := 0; i < 5; i++ {
		tk, _, _ := e.back.OpenAttempt(context.Background(), u.ID)
		e.back.FailAttempt(context.Background(), tk)
	}
	e.press(userTG, "k")
	e.msg(userTG, "GOOD")
	if len(e.back.redeems) != 0 {
		t.Fatalf("бот погасил код, хотя ввод закрыт общим счётчиком: %v", e.back.redeems)
	}
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "закрыт") {
		t.Fatalf("нет сообщения о закрытии: %q", txt)
	}
}

// --- M16 ---

func TestAgentErrorDetailsNotShown(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, userTG)
	e.st.SetOwner(context.Background(), store.LocalNode, "alice", &u.ID)
	e.node.clientsErr = errors.New("Get \"http://10.0.0.5:8443/v1/clients\": dial tcp 10.0.0.5:8443: connect: connection refused")
	e.press(userTG, "l:0")
	for _, s := range e.tg.texts() {
		if strings.Contains(s, "10.0.0.5") || strings.Contains(s, "8443") {
			t.Fatalf("адрес агента показан пользователю: %q", s)
		}
	}
	if !strings.Contains(e.logs.String(), "10.0.0.5") {
		t.Fatal("подробности ошибки должны остаться в журнале")
	}
}

// --- M17: отключённые и разжалованные ---

func TestDisabledUserGetsNothingButNotice(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivan", store.RoleUser, userTG)
	e.st.SetDisabled(context.Background(), u.ID, true)
	e.msg(userTG, "/menu")
	if txt := strings.Join(e.tg.texts(), "|"); !strings.Contains(txt, "отключена") || hasButton(e.tg.buttons(), "Мои клиенты") {
		t.Fatalf("сообщение отключённому: %q, кнопки %v", txt, e.tg.buttons())
	}
	e.tg.reset()
	e.press(userTG, "l:0")
	if e.toast() != "Нет доступа." || len(e.tg.of("editMessageText"))+len(e.tg.of("sendMessage")) != 0 {
		t.Fatalf("кнопка отключённого: toast %q", e.toast())
	}
}

func TestDemotedAdminCannotUseConfirmation(t *testing.T) {
	e := newEnv(t)
	adm := e.user("root", store.RoleAdmin, adminTG)
	e.press(adminTG, "z")
	tok := dataOf(t, e.tg.buttons(), "Да, перезагрузить")
	if err := e.st.SetRole(context.Background(), adm.ID, store.RoleUser); err != nil {
		t.Fatal(err)
	}
	e.tg.reset()
	e.press(adminTG, tok)
	if e.node.rebooted != 0 {
		t.Fatal("разжалованный выполнил перезагрузку по старому подтверждению")
	}
	if !strings.Contains(strings.Join(e.tg.texts(), "|"), textNoRights) {
		t.Fatalf("нет отказа: %v", e.tg.texts())
	}
}

func TestStrangerClosedCallbackHasNoToast(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.Strangers = "closed"
	e.press(9, "z")
	for _, c := range e.tg.of("answerCallbackQuery") {
		if c.Body["text"] != "" && c.Body["text"] != nil {
			t.Fatalf("незнакомцу показан текст: %v", c.Body["text"])
		}
	}
}

func TestBotSendsNoUpdatesFromBotsOrGroupsToBackend(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.b.HandleUpdate(context.Background(), telegram.Update{Message: &telegram.Message{
		From: &telegram.User{ID: adminTG, IsBot: true}, Chat: telegram.Chat{ID: adminTG, Type: "private"}, Text: "/menu",
	}})
	if len(e.tg.of("sendMessage")) != 0 {
		t.Fatal("бот ответил боту")
	}
}
