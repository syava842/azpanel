package bot

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/store"
)

func (e *env) enqueue(kind string, uid *int64, text string) int64 {
	e.t.Helper()
	id, err := e.st.Enqueue(context.Background(), kind, uid, NoticeJSON(text), e.now.Unix())
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) pending() int {
	items, err := e.st.Pending(context.Background(), 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(items)
}

// sentTo — чаты и тексты отправленных сообщений (в порядке отправки).
func (e *env) sentTo() []string {
	var out []string
	for _, c := range e.tg.of("sendMessage") {
		out = append(out, fmt.Sprint(c.Body["chat_id"])+":"+fmt.Sprint(c.Body["text"]))
	}
	return out
}

func (e *env) failSend(on bool, code int) {
	e.tg.mu.Lock()
	e.tg.fail, e.tg.failCode = on, code
	e.tg.mu.Unlock()
}

func TestEveryKindIsDeliveredToAdminsAndChats(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.user("ivan", store.RoleUser, userTG) // обычный пользователь системных уведомлений не получает
	e.b.Cfg.NotifyChats = []int64{-100500}
	for _, k := range config.TelegramNotifyKinds {
		if k == KindAccessExpiring {
			continue
		}
		e.enqueue(k, nil, "текст "+k)
	}
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 0 {
		t.Fatalf("осталось в очереди: %d", e.pending())
	}
	got := strings.Join(e.sentTo(), "\n")
	for _, k := range config.TelegramNotifyKinds {
		if k == KindAccessExpiring {
			continue
		}
		for _, chat := range []string{"1001", "-100500"} {
			if !strings.Contains(got, chat+":текст "+k) {
				t.Fatalf("вид %s не дошёл в %s:\n%s", k, chat, got)
			}
		}
	}
	if strings.Contains(got, "2002:") {
		t.Fatal("обычный пользователь получил системное уведомление")
	}
}

func TestAccessExpiringGoesToOwnerOnly(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	ivan := e.user("ivan", store.RoleUser, userTG)
	nobody := e.user("nobody", store.RoleUser, 0)
	until := e.now.Add(72 * time.Hour).Unix()
	payload := fmt.Sprintf(`{"until":%d,"days":3,"clients":["alice","bob"]}`, until)
	e.st.Enqueue(context.Background(), KindAccessExpiring, &ivan.ID, payload, e.now.Unix())
	e.st.Enqueue(context.Background(), KindAccessExpiring, &nobody.ID, payload, e.now.Unix())
	e.b.DeliverOutbox(context.Background())
	got := e.sentTo()
	if len(got) != 1 || !strings.HasPrefix(got[0], "2002:") || !strings.Contains(got[0], "через 3 дн.") || !strings.Contains(got[0], "alice, bob") {
		t.Fatalf("напоминание владельцу: %v", got)
	}
	if e.pending() != 0 {
		t.Fatal("запись без привязанного владельца не помечена")
	}
}

func TestDisabledKindIsMarkedWithoutSending(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.b.Cfg.Notify = []string{KindNodeDown}
	e.enqueue(KindReboot, nil, "перезагрузка")
	e.enqueue(KindNodeDown, nil, "узел")
	e.b.DeliverOutbox(context.Background())
	got := e.sentTo()
	if len(got) != 1 || !strings.Contains(got[0], "узел") {
		t.Fatalf("отправлено: %v", got)
	}
	if e.pending() != 0 {
		t.Fatal("выключенный вид остался в очереди")
	}
}

func TestDeliveryRetriesAfterError(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.b.Cfg.NotifyChats = []int64{-100500}
	e.enqueue(KindNodeDown, nil, "узел")
	e.failSend(true, 500)
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 1 {
		t.Fatal("запись помечена при ошибке доставки")
	}
	e.failSend(false, 0)
	e.tg.reset()
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 0 || len(e.sentTo()) != 2 {
		t.Fatalf("повтор: в очереди %d, отправлено %v", e.pending(), e.sentTo())
	}
}

func TestDeliveryDoesNotDuplicateToDeliveredChats(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.b.Cfg.NotifyChats = []int64{-100500}
	e.enqueue(KindNodeDown, nil, "узел")
	// Отказ только для группы: администратору уходит сразу.
	e.tg.mu.Lock()
	e.tg.failChat, e.tg.failCode = -100500, 500
	e.tg.mu.Unlock()
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 1 || len(e.tg.of("sendMessage")) != 2 {
		t.Fatalf("первый проход: в очереди %d, вызовов %d", e.pending(), len(e.tg.of("sendMessage")))
	}
	e.tg.mu.Lock()
	e.tg.failChat = 0
	e.tg.mu.Unlock()
	e.tg.reset()
	e.b.DeliverOutbox(context.Background())
	got := e.sentTo()
	if len(got) != 1 || !strings.HasPrefix(got[0], "-100500:") || e.pending() != 0 {
		t.Fatalf("повтор должен дойти только до группы: %v, в очереди %d", got, e.pending())
	}
}

func TestDeliveryGivesUpAfterTenFailures(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.enqueue(KindNodeDown, nil, "узел")
	e.failSend(true, 500)
	for i := 1; i <= 9; i++ {
		e.b.DeliverOutbox(context.Background())
		if e.pending() != 1 {
			t.Fatalf("проход %d: запись отброшена рано", i)
		}
	}
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 0 {
		t.Fatal("после десяти неудач запись осталась")
	}
	if !strings.Contains(e.logs.String(), "level=ERROR") || strings.Contains(e.logs.String(), "SECRET-token") {
		t.Fatalf("журнал: %s", e.logs.String())
	}
}

func TestBlockedChatIsNotRetried(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.enqueue(KindNodeDown, nil, "узел")
	e.failSend(true, 403) // бот заблокирован: повтор не поможет
	e.b.DeliverOutbox(context.Background())
	if e.pending() != 0 {
		t.Fatal("403 ведёт к бесконечным повторам")
	}
}

// --- расписание ---

func TestSummaryAtConfiguredMinuteOnce(t *testing.T) {
	e := newEnv(t)
	e.user("root", store.RoleAdmin, adminTG)
	e.b.Cfg.SummaryAt = "09:00"
	e.node.sessions = []nodeapi.Session{{Name: "alice"}, {Name: "alice"}, {Name: "bob"}}
	day := time.Date(2026, 11, 4, 8, 59, 0, 0, time.UTC)
	e.st.AddTraffic(context.Background(), store.LocalNode, day.Add(-2*time.Hour).Unix(),
		map[string]store.Bytes{"alice": {Rx: 5 << 20, Tx: 5 << 20}, "bob": {Rx: 1 << 20}})
	ctx := context.Background()

	e.b.scheduleTick(ctx, day) // 08:59: рано
	if len(e.sentTo()) != 0 {
		t.Fatal("сводка до времени")
	}
	e.b.scheduleTick(ctx, day.Add(time.Minute)) // 09:00
	got := e.sentTo()
	if len(got) != 1 || !strings.HasPrefix(got[0], "1001:Сводка") || !strings.Contains(got[0], "клиентов 2, сессий 3") ||
		!strings.Contains(got[0], "1. alice: 10.0 МБ") || !strings.Contains(got[0], "2. bob: 1.0 МБ") {
		t.Fatalf("сводка: %v", got)
	}
	e.b.scheduleTick(ctx, day.Add(2*time.Minute)) // тот же день
	e.b.scheduleTick(ctx, day.Add(5*time.Hour))   // позже окна
	if len(e.sentTo()) != 1 {
		t.Fatalf("повтор сводки: %v", e.sentTo())
	}
	e.b.scheduleTick(ctx, day.Add(24*time.Hour+time.Minute)) // следующие сутки
	if len(e.sentTo()) != 2 {
		t.Fatalf("сводка на следующие сутки: %v", e.sentTo())
	}
	// выключена пустым временем
	e.b.Cfg.SummaryAt = ""
	e.b.scheduleTick(ctx, day.Add(48*time.Hour+time.Minute))
	if len(e.sentTo()) != 2 {
		t.Fatal("сводка при пустом summary_at")
	}
}

func (e *env) resetTask() {
	e.node.mu.Lock()
	e.node.taskPolls = 0
	e.node.mu.Unlock()
}

func TestScheduledBackupEveryNDays(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.BackupEveryDays = 2
	e.b.Cfg.BackupChats = []int64{555}
	e.node.backupFiles = []nodeapi.Backup{{Name: "backup-x.tar.gz", Size: 4, Modified: time.Now().Add(time.Hour)}}
	e.node.backupData["backup-x.tar.gz"] = "DATA"
	ctx := context.Background()
	start := time.Unix(1_800_000_000, 0)

	docs := func() int { return len(e.tg.of("sendDocument")) }
	e.b.scheduleTick(ctx, start)
	if docs() != 1 || fmt.Sprint(e.tg.of("sendDocument")[0].Body["chat_id"]) != "555" {
		t.Fatalf("первый бэкап: %d", docs())
	}
	e.resetTask()
	e.b.scheduleTick(ctx, start.Add(25*time.Hour))
	if docs() != 1 {
		t.Fatal("бэкап раньше срока")
	}
	e.b.scheduleTick(ctx, start.Add(49*time.Hour))
	if docs() != 2 {
		t.Fatalf("бэкап через двое суток: %d", docs())
	}
	// выключен нулём
	e.b.Cfg.BackupEveryDays = 0
	e.b.scheduleTick(ctx, start.Add(200*time.Hour))
	if docs() != 2 {
		t.Fatal("бэкап при backup_every_days = 0")
	}
}

func TestScheduledBackupFailureRetriedNoSoonerThanAnHour(t *testing.T) {
	e := newEnv(t)
	e.b.Cfg.BackupEveryDays = 1
	e.b.Cfg.BackupChats = []int64{555}
	e.node.taskExit = 1
	ctx := context.Background()
	start := time.Unix(1_800_000_000, 0)
	e.b.scheduleTick(ctx, start)
	e.b.scheduleTick(ctx, start.Add(10*time.Minute))
	if e.node.backupCalls != 1 {
		t.Fatalf("повтор раньше часа: задач %d", e.node.backupCalls)
	}
	if txt := strings.Join(e.sentTo(), "|"); !strings.Contains(txt, "по расписанию не создан") {
		t.Fatalf("нет сообщения о сбое: %q", txt)
	}
	e.resetTask()
	e.b.scheduleTick(ctx, start.Add(61*time.Minute))
	if e.node.backupCalls != 2 {
		t.Fatalf("повтор через час не случился: %d", e.node.backupCalls)
	}
}
