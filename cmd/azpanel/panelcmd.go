package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/panel"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

// cmdPanel — «azpanel panel» и «azpanel panel passwd».
func cmdPanel(args []string) error {
	if len(args) == 0 {
		return runPanel()
	}
	if args[0] != "passwd" {
		return errUsage
	}
	var read func() ([]byte, error)
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		read = func() ([]byte, error) { return term.ReadPassword(fd) }
	}
	return cmdPanelPasswd(args[1:], os.Stdin, read, os.Stdout)
}

func runPanel() error {
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return panel.Run(ctx, cfg, version)
}

// cmdPanelPasswd задаёт пароль администратора. readTerm не nil — stdin
// терминал: пароль спрашивается дважды без эха; иначе берётся одна строка из in.
func cmdPanelPasswd(args []string, in io.Reader, readTerm func() ([]byte, error), out io.Writer) error {
	user := ""
	for i := 0; i < len(args); i++ {
		if args[i] != "--user" || i+1 >= len(args) {
			return errUsage
		}
		i++
		user = args[i]
	}
	if user != "" && strings.ContainsAny(user, "\r\n") {
		return errors.New("недопустимое имя пользователя")
	}
	var pw string
	if readTerm != nil {
		fmt.Fprint(out, "Новый пароль: ")
		a, err := readTerm()
		fmt.Fprintln(out)
		if err != nil {
			return err
		}
		fmt.Fprint(out, "Повторите пароль: ")
		b, err := readTerm()
		fmt.Fprintln(out)
		if err != nil {
			return err
		}
		if !bytes.Equal(a, b) {
			return errors.New("пароли не совпадают")
		}
		pw = string(a)
	} else {
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("пароль не прочитан из stdin")
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if pw == "" {
		return errors.New("пустой пароль")
	}
	hash, err := panel.HashPassword(pw)
	if err != nil {
		return err
	}
	// Хеш и имя — одной записью: иначе сбой между ними оставил бы новый
	// пароль при старом имени.
	kv := map[string]string{panel.SecretAdminHash: hash}
	if user != "" {
		kv[panel.SecretAdminUser] = user
	}
	if err := secrets.SetMany(paths.SecretsFile(), kv); err != nil {
		return err
	}
	fmt.Fprintln(out, "пароль задан; перезапустите панель: systemctl restart azpanel-panel")
	return nil
}
