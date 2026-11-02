package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/syava842/azpanel/internal/panel"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/store"
)

// consoleUser — под каким именем действия консоли попадают в журнал.
const consoleUser = "root (консоль)"

const (
	resetPasswordLen = 16
	// Без похожих знаков (0/O, 1/l/I): пароль читают с экрана и вводят руками.
	resetLetters = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
	resetDigits  = "23456789"
)

// cmdUser — «azpanel user reset <логин>» и «azpanel user list».
func cmdUser(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errUsage
		}
		st, err := openPanelStore()
		if err != nil {
			return err
		}
		defer st.Close()
		return userList(context.Background(), st, out)
	case "reset":
		if len(args) != 2 {
			return errUsage
		}
		st, err := openPanelStore()
		if err != nil {
			return err
		}
		defer st.Close()
		pw, err := userReset(context.Background(), st, args[1], "", time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Новый пароль пользователя %s: %s\n", strings.ToLower(strings.TrimSpace(args[1])), pw)
		fmt.Fprintln(out, "При первом входе панель потребует сменить его; двухфакторная проверка выключена, все сессии завершены.")
		return nil
	}
	return errUsage
}

// panelDBPath — база панели. Команды не создают её сами: нет файла — панель
// не установлена или стоит в другом месте.
func panelDBPath() string { return filepath.Join(paths.Data(), "azpanel.db") }

func openPanelStore() (*store.Store, error) {
	p := panelDBPath()
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("база панели не найдена (%s): запускайте от root на сервере панели", p)
	}
	st, err := store.Open(p)
	if err != nil {
		return nil, fmt.Errorf("база панели: %w", err)
	}
	return st, nil
}

// newResetPassword — случайный пароль: буквы и цифры, обязательно и те и другие.
func newResetPassword() (string, error) {
	const all = resetLetters + resetDigits
	pick := func(set string) (byte, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return 0, err
		}
		return set[n.Int64()], nil
	}
	b := make([]byte, resetPasswordLen)
	for i := range b {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		b[i] = c
	}
	// Гарантируем по одному знаку каждого вида в случайных местах.
	for _, set := range []string{resetLetters, resetDigits} {
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		pos, err := rand.Int(rand.Reader, big.NewInt(resetPasswordLen))
		if err != nil {
			return "", err
		}
		b[pos.Int64()] = c
	}
	// Вторая вставка могла затереть первую; проверяем и повторяем.
	s := string(b)
	if !strings.ContainsAny(s, resetLetters) || !strings.ContainsAny(s, resetDigits) {
		return newResetPassword()
	}
	return s, nil
}

// userReset: новый пароль (pw пуст — случайный, он и возвращается),
// must_change=1, 2FA выключена, резервные коды удалены, все сессии
// завершены, запись в журнале от «root (консоль)».
func userReset(ctx context.Context, st *store.Store, login, pw string, now time.Time) (string, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	u, err := st.UserByLogin(ctx, login)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("пользователь %q не найден", login)
	}
	if err != nil {
		return "", err
	}
	if pw == "" {
		if pw, err = newResetPassword(); err != nil {
			return "", err
		}
	}
	hash, err := panel.HashPassword(pw)
	if err != nil {
		return "", err
	}
	if err := resetUser(ctx, st, u, hash, true, now); err != nil {
		return "", err
	}
	return pw, nil
}

// resetUser применяет сброс с готовым хешем. mustChange — потребовать смену
// пароля при входе (для пароля, который человек задал сам, не нужно).
func resetUser(ctx context.Context, st *store.Store, u store.User, hash string, mustChange bool, now time.Time) error {
	had2FA := len(u.TOTPSecret) > 0
	// Точечные записи: процесс консоли не должен затирать чужие поля строки.
	if err := st.SetPassword(ctx, u.ID, hash, mustChange); err != nil {
		return err
	}
	if err := st.SetTOTP(ctx, u.ID, nil, 0); err != nil {
		return err
	}
	if err := st.SetBackupCodes(ctx, u.ID, nil); err != nil {
		return err
	}
	if err := st.DeleteUserSessions(ctx, u.ID, ""); err != nil {
		return err
	}
	after := "пароль сброшен, сессии завершены"
	if had2FA {
		after += ", 2FA выключена"
	}
	return st.Audit(ctx, store.AuditEntry{
		TS: now.Unix(), User: consoleUser, Action: "user_reset", Target: u.Login, After: after,
	})
}

// userList печатает таблицу пользователей.
func userList(ctx context.Context, st *store.Store, out io.Writer) error {
	us, err := st.Users(ctx)
	if err != nil {
		return err
	}
	if len(us) == 0 {
		fmt.Fprintln(out, "Пользователей нет.")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ЛОГИН\tРОЛЬ\tСОСТОЯНИЕ\t2FA\tСМЕНА ПАРОЛЯ")
	for _, u := range us {
		role := "пользователь"
		if u.Role == store.RoleAdmin {
			role = "администратор"
		}
		state := "активен"
		if u.Disabled {
			state = "отключён"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Login, role, state, yesNo(len(u.TOTPSecret) > 0), yesNo(u.MustChange))
	}
	return tw.Flush()
}

func yesNo(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}

// resetFirstAdmin — часть «azpanel panel passwd» для обратной совместимости:
// если в базе уже есть пользователи, пароль получает указанный (--user) или
// первый администратор, а не только secrets.env. Второе значение — чьему
// паролю это применилось (пусто — в базе никого нет и файла тоже).
func resetFirstAdmin(ctx context.Context, login, hash string, now time.Time) (string, error) {
	if _, err := os.Stat(panelDBPath()); err != nil {
		return "", nil
	}
	st, err := openPanelStore()
	if err != nil {
		return "", err
	}
	defer st.Close()
	us, err := st.Users(ctx)
	if err != nil {
		return "", err
	}
	var target *store.User
	login = strings.ToLower(strings.TrimSpace(login))
	for i := range us {
		u := &us[i]
		if login != "" {
			if u.Login == login {
				target = u
			}
			continue
		}
		if u.Role == store.RoleAdmin && (target == nil || u.ID < target.ID) {
			target = u
		}
	}
	if target == nil {
		if len(us) == 0 {
			return "", nil // база пуста: пароль подхватит перенос при запуске панели
		}
		// Пользователи есть, а цели нет: перенос при перезапуске не сработает,
		// и сообщать «перезапустите панель» было бы неправдой.
		if login != "" {
			return "", fmt.Errorf("пользователя %q нет в базе панели: пароль не применён", login)
		}
		return "", errors.New("в базе панели нет администратора: пароль не применён")
	}
	if err := resetUser(ctx, st, *target, hash, false, now); err != nil {
		return "", err
	}
	return target.Login, nil
}
