package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/store"
)

// console — ввод и вывод интерактивных команд. В тестах подменяется целиком.
type console struct {
	in  *bufio.Reader
	out io.Writer
	// secret читает строку без эха; nil — stdin не терминал, строка берётся из in.
	secret func() (string, error)
	// sub запускает подкоманду azpanel (doctor, update) и возвращает её код.
	sub func(args ...string) int
	// systemctl — перезапуск служб.
	systemctl func(args ...string) error
}

func realConsole() *console {
	c := &console{
		in: bufio.NewReader(os.Stdin), out: os.Stdout,
		sub: func(args ...string) int { return run(args) },
		systemctl: func(args ...string) error {
			cmd := exec.Command("systemctl", args...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			return cmd.Run()
		},
	}
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		c.secret = func() (string, error) {
			b, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stdout)
			return string(b), err
		}
	}
	return c
}

func (c *console) printf(format string, a ...any) { fmt.Fprintf(c.out, format, a...) }

// ask печатает вопрос и читает строку; пустой ответ — def. Конец ввода без
// ответа — io.EOF: вызывающий не должен выбирать за человека.
func (c *console) ask(prompt, def string) (string, error) {
	if def != "" {
		c.printf("%s [%s]: ", prompt, def)
	} else {
		c.printf("%s: ", prompt)
	}
	line, err := c.in.ReadString('\n')
	if err != nil && line == "" {
		return "", io.EOF
	}
	if v := strings.TrimSpace(line); v != "" {
		return v, nil
	}
	return def, nil
}

func (c *console) readSecret(prompt string) (string, error) {
	c.printf("%s: ", prompt)
	if c.secret != nil {
		return c.secret()
	}
	line, err := c.in.ReadString('\n')
	if err != nil && line == "" {
		return "", io.EOF
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ownPassword спрашивает свой пароль дважды и проверяет его по правилам
// панели. В терминале даёт три попытки; из трубы — одну.
func (c *console) ownPassword(login string) (string, error) {
	tries := 1
	if c.secret != nil {
		tries = 3
	}
	var last error
	for i := 0; i < tries; i++ {
		a, err := c.readSecret("Новый пароль (от 10 символов, буквы и цифры)")
		if err != nil {
			return "", err
		}
		if last = install.ValidatePassword(login, a); last != nil {
			c.printf("Не подходит: %v\n", last)
			continue
		}
		b, err := c.readSecret("Пароль ещё раз")
		if err != nil {
			return "", err
		}
		if a != b {
			last = errors.New("пароли не совпадают")
			c.printf("%v\n", last)
			continue
		}
		return a, nil
	}
	return "", last
}

// choosePassword: сгенерировать или задать свой. Пустая строка — сгенерировать.
func (c *console) choosePassword(login string) (string, error) {
	c.printf("  1) сгенерировать пароль\n  2) задать свой\n")
	v, err := c.ask("Выбор", "1")
	if err != nil {
		return "", err
	}
	switch v {
	case "1":
		return "", nil
	case "2":
		return c.ownPassword(login)
	}
	return "", fmt.Errorf("нет варианта %q", v)
}

// firstAdmin — логин администратора с наименьшим номером (тот, что создан
// установщиком); пусто — администраторов нет.
func firstAdmin(ctx context.Context, st *store.Store) string {
	us, err := st.Users(ctx)
	if err != nil {
		return ""
	}
	var best *store.User
	for i := range us {
		if u := &us[i]; u.Role == store.RoleAdmin && !u.Disabled && (best == nil || u.ID < best.ID) {
			best = u
		}
	}
	if best == nil {
		return ""
	}
	return best.Login
}

// panelAddress — где открывается панель: panel.public_url, иначе по ответам
// мастера (install.env), иначе локальный адрес из конфига.
func panelAddress() string {
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return ""
	}
	if cfg.Panel.PublicURL != "" {
		return cfg.Panel.PublicURL
	}
	base := cfg.Panel.BasePath
	if base == "" {
		base = "/"
	}
	if data, err := os.ReadFile(filepath.Join(paths.Etc(), "install.env")); err == nil {
		if env, err := install.ParseEnvFile(data); err == nil {
			host := env[install.KeyDomain]
			if host == "" {
				host = env[install.KeyAddress]
			}
			switch {
			case host == "":
			case env[install.KeyAccess] == install.AccessPath:
				return "https://" + host + base
			case env[install.KeyAccess] == install.AccessPort:
				port := env[install.KeyPort]
				if port == "" {
					port = strconv.Itoa(install.DefaultPort)
				}
				return "https://" + host + ":" + port + "/"
			}
		}
	}
	return "http://" + cfg.Panel.Listen + base + " (только с самого сервера; снаружи — через SSH-туннель)"
}

// menuPassword — пункт «сменить пароль»: логин, затем сгенерировать или свой.
func menuPassword(ctx context.Context, c *console, st *store.Store, now time.Time) error {
	login, err := c.ask("Логин", firstAdmin(ctx, st))
	if err != nil {
		return err
	}
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return errors.New("логин не задан")
	}
	pw, err := c.choosePassword(login)
	if err != nil {
		return err
	}
	shown, err := userSetPassword(ctx, st, login, pw, now)
	if err != nil {
		return err
	}
	printPasswordResult(c, "Пароль пользователя "+login+" изменён", shown)
	c.printf("Сессии пользователя завершены, двухфакторная проверка выключена.\n")
	return nil
}

// menuAddAdmin — пункт «добавить администратора».
func menuAddAdmin(ctx context.Context, c *console, st *store.Store, now time.Time) error {
	login, err := c.ask("Логин нового администратора (3-32 знака: a-z, 0-9, _ . -)", "")
	if err != nil {
		return err
	}
	login = strings.ToLower(strings.TrimSpace(login))
	if !install.ValidLogin(login) {
		return errors.New("логин: 3-32 знака, строчные латинские буквы, цифры и _ . -")
	}
	pw, err := c.choosePassword(login)
	if err != nil {
		return err
	}
	login, shown, err := userAdd(ctx, st, login, store.RoleAdmin, pw, now)
	if err != nil {
		return err
	}
	printPasswordResult(c, "Администратор "+login+" создан", shown)
	return nil
}

// printPasswordResult: сгенерированный пароль показывается один раз, свой —
// не печатается вовсе.
func printPasswordResult(c *console, what, generated string) {
	if generated == "" {
		c.printf("%s.\n", what)
		return
	}
	c.printf("%s. Пароль: %s\n", what, generated)
	c.printf("Пароль показан один раз; при первом входе панель попросит его сменить.\n")
}

// cmdMenu — «azpanel menu» и «azpanel» без аргументов в терминале: частые
// действия по номерам, без запоминания команд.
func cmdMenu(c *console) error {
	ctx := context.Background()
	for {
		c.printf("\nazpanel %s", version)
		if addr := panelAddress(); addr != "" {
			c.printf(" — %s", addr)
		}
		c.printf(`
  1) Состояние и проверка установки
  2) Пользователи панели
  3) Сменить пароль пользователя
  4) Добавить администратора
  5) Обновить azpanel
  6) Перезапустить службы azpanel
  0) Выход
`)
		v, err := c.ask("Выбор", "")
		if errors.Is(err, io.EOF) {
			return nil
		}
		var actErr error
		switch v {
		case "0", "q", "й":
			return nil
		case "1":
			c.sub("doctor")
		case "2", "3", "4":
			actErr = withStore(func(st *store.Store) error {
				switch v {
				case "2":
					return userList(ctx, st, c.out)
				case "3":
					return menuPassword(ctx, c, st, time.Now())
				}
				return menuAddAdmin(ctx, c, st, time.Now())
			})
		case "5":
			c.sub("update")
		case "6":
			if actErr = c.systemctl("restart", "azpanel-node", "azpanel-panel"); actErr == nil {
				c.printf("Службы перезапущены.\n")
			}
		case "":
			continue
		default:
			c.printf("Нет пункта %q.\n", v)
		}
		if errors.Is(actErr, io.EOF) {
			return nil
		}
		if actErr != nil {
			c.printf("Ошибка: %v\n", actErr)
		}
	}
}

func withStore(fn func(st *store.Store) error) error {
	st, err := openPanelStore()
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(st)
}
