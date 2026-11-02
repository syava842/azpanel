package bot

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	keepBackups   = 14 // копий в BackupDir
	backupPrefix  = "tgbackup-"
	backupSuffix  = ".tar.gz"
	backupTimeout = 11 * time.Minute // client.sh 8 ограничен 600 с на стороне агента
	taskSlack     = 10 * time.Second // допуск часов агента и панели при выборе файла
)

// backupFile — полученный от агента бэкап.
type backupFile struct {
	path, name string
	size       int64
	cleanup    func()
}

// BackupGroupsKey — ключ meta: через запятую chat ID групп из backup_chats,
// которым владелец явно разрешил получать бэкап (подтверждается в вебе).
const BackupGroupsKey = "tg_backup_groups"

// spawn запускает f в фоне; с Sync (тесты) — сразу. Паника не должна
// останавливать панель.
func (b *Bot) spawn(f func()) {
	run := func() {
		defer func() {
			if r := recover(); r != nil {
				b.log().Error("бот: сбой фонового действия", "panic", fmt.Sprint(r))
			}
		}()
		f()
	}
	if b.Sync {
		run()
		return
	}
	b.tasks.Add(1)
	go func() {
		defer b.tasks.Done()
		run()
	}()
}

// ParseChatList разбирает список chat ID через запятую; мусор пропускается.
func ParseChatList(v string) []int64 {
	var out []int64
	for _, p := range strings.Split(v, ",") {
		if n, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil && n != 0 {
			out = append(out, n)
		}
	}
	return out
}

// FormatChatList — обратное к ParseChatList.
func FormatChatList(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, n := range ids {
		parts = append(parts, strconv.FormatInt(n, 10))
	}
	return strings.Join(parts, ",")
}

// BackupRecipients отбирает из backup_chats тех, кому бэкап можно отправить.
// Бэкап содержит ключи всех клиентов, поэтому: личный чат — только если это
// привязанный действующий администратор (роль читается в момент отправки),
// групповой — только если владелец подтвердил его в вебе. Остальные — отказ.
func (b *Bot) BackupRecipients(ctx context.Context) (ok, rejected []int64, err error) {
	admins, err := b.adminsErr(ctx)
	if err != nil {
		return nil, nil, err
	}
	var groups []int64
	if v, found, merr := b.Store.Meta(ctx, BackupGroupsKey); merr != nil {
		return nil, nil, merr
	} else if found {
		groups = ParseChatList(v)
	}
	for _, chat := range b.Cfg.BackupChats {
		allowed := false
		if chat > 0 {
			for _, a := range admins {
				if *a.TelegramID == chat {
					allowed = true
				}
			}
		} else {
			allowed = slices.Contains(groups, chat)
		}
		if allowed {
			ok = append(ok, chat)
		} else {
			rejected = append(rejected, chat)
		}
	}
	return ok, rejected, nil
}

// startBackup — кнопка «Бэкап»: client.sh 8 задачей агента, файл — в чат.
func (b *Bot) startBackup(ctx context.Context, a actor) string {
	if !b.backupMu.TryLock() {
		return "Бэкап уже идёт."
	}
	b.audit(ctx, a, "backup", "сервер", "", "запуск из Telegram")
	b.spawn(func() {
		defer b.backupMu.Unlock()
		bf, err := b.makeBackup(ctx)
		if err != nil {
			b.log().Warn("бот: бэкап не создан", "err", err)
			b.send(ctx, a.chat, "Бэкап не создан: "+err.Error(), nil)
			return
		}
		defer bf.cleanup()
		if err := b.sendBackup(ctx, a.chat, bf); err != nil {
			b.send(ctx, a.chat, "Бэкап создан, но не отправлен: "+err.Error(), nil)
		}
	})
	return "Бэкап запущен, это займёт несколько минут."
}

func (b *Bot) pollEvery() time.Duration {
	if b.PollEvery > 0 {
		return b.PollEvery
	}
	return 3 * time.Second
}

// makeBackup запускает client.sh 8, ждёт задачу и забирает файл у агента.
func (b *Bot) makeBackup(ctx context.Context) (*backupFile, error) {
	task, err := b.Node.CreateBackup(ctx)
	if err != nil {
		return nil, fmt.Errorf("задача не запущена: %s", b.agentErr(err))
	}
	deadline := time.Now().Add(backupTimeout)
	var done bool
	for !done {
		d, err := b.Node.Task(ctx, task.ID)
		if err != nil {
			return nil, fmt.Errorf("состояние задачи не получено: %s", b.agentErr(err))
		}
		switch {
		case d.Finished == nil:
		case d.TimedOut:
			return nil, fmt.Errorf("задача остановлена по пределу времени")
		case d.Interrupted:
			return nil, fmt.Errorf("задача прервана: агент перезапускался")
		case d.ExitCode == nil || *d.ExitCode != 0:
			code := -1
			if d.ExitCode != nil {
				code = *d.ExitCode
			}
			return nil, fmt.Errorf("client.sh 8 завершился с кодом %d", code)
		default:
			done = true
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("задача не закончилась за %s", backupTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(b.pollEvery()):
		}
	}
	files, err := b.Node.Backups(ctx)
	if err != nil {
		return nil, fmt.Errorf("список бэкапов не получен: %s", b.agentErr(err))
	}
	var src string
	for _, f := range files { // новые первыми
		if !f.Modified.Before(task.Started.Add(-taskSlack)) {
			src = f.Name
			break
		}
	}
	if src == "" {
		return nil, fmt.Errorf("файл бэкапа после задачи не найден")
	}
	rc, err := b.Node.Backup(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("файл бэкапа не получен: %s", b.agentErr(err))
	}
	defer rc.Close()
	return b.saveBackup(rc)
}

// saveBackup пишет поток в BackupDir (и оставляет там) либо во временный файл.
func (b *Bot) saveBackup(r io.Reader) (*backupFile, error) {
	name := backupPrefix + b.now().UTC().Format("20060102T150405Z") + backupSuffix
	var f *os.File
	var err error
	bf := &backupFile{name: name, cleanup: func() {}}
	if b.BackupDir != "" {
		if err = os.MkdirAll(b.BackupDir, 0o750); err != nil {
			return nil, err
		}
		f, err = os.CreateTemp(b.BackupDir, ".tgbackup-*.part")
	} else {
		f, err = os.CreateTemp("", "azpanel-backup-*")
	}
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return nil, fmt.Errorf("файл бэкапа не записан: %w", err)
	}
	bf.size = n
	if b.BackupDir != "" {
		bf.path = filepath.Join(b.BackupDir, name)
		if err := os.Rename(f.Name(), bf.path); err != nil {
			os.Remove(f.Name())
			return nil, err
		}
		b.pruneBackups()
	} else {
		bf.path = f.Name()
		bf.cleanup = func() { os.Remove(bf.path) }
	}
	return bf, nil
}

// pruneBackups оставляет в BackupDir keepBackups последних копий.
func (b *Bot) pruneBackups() {
	ents, err := os.ReadDir(b.BackupDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), backupPrefix) && strings.HasSuffix(e.Name(), backupSuffix) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names))) // метка времени в имени: новые первыми
	for _, n := range names[min(len(names), keepBackups):] {
		if err := os.Remove(filepath.Join(b.BackupDir, n)); err != nil {
			b.log().Warn("бот: старая копия бэкапа не удалена", "file", n, "err", err)
		}
	}
}

// sendBackup отправляет файл в чат; слишком большой остаётся на сервере
// (об этом пишется текстом, и это не ошибка). Ошибка — файл не дошёл.
func (b *Bot) sendBackup(ctx context.Context, chat int64, bf *backupFile) error {
	if bf.size > telegramLimit {
		where := "на сервере панели"
		if b.BackupDir == "" {
			where = "только у агента"
		}
		b.send(ctx, chat, fmt.Sprintf("Бэкап готов (%s), но больше предела Telegram в 50 МБ. Файл %s.", humanBytes(uint64(bf.size)), where), nil)
		return nil
	}
	f, err := os.Open(bf.path)
	if err != nil {
		b.log().Warn("бот: файл бэкапа не открыт", "err", err)
		return fmt.Errorf("файл бэкапа не открыт")
	}
	defer f.Close()
	caption := fmt.Sprintf("Бэкап %s, %s", b.now().UTC().Format("2006-01-02 15:04 UTC"), humanBytes(uint64(bf.size)))
	if _, err := b.TG.SendDocument(ctx, chat, bf.name, f, caption); err != nil {
		b.log().Warn("бот: бэкап не отправлен", "chat", chat, "err", err)
		return fmt.Errorf("Telegram не принял файл")
	}
	return nil
}
