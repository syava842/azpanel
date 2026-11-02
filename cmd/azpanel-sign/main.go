// Команда azpanel-sign - утилита разработчика: ключ релиза и подпись файла.
//
//	azpanel-sign keygen <файл-закрытого-ключа>   (открытый ключ - в stdout, hex)
//	azpanel-sign sign <файл-закрытого-ключа> <файл>   (подпись - в <файл>.sig)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "azpanel-sign:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 2 && args[0] == "keygen" {
		return keygen(args[1], out)
	}
	if len(args) == 3 && args[0] == "sign" {
		return sign(args[1], args[2])
	}
	return errors.New("использование: azpanel-sign keygen <ключ> | sign <ключ> <файл>")
}

func keygen(keyPath string, out io.Writer) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// O_EXCL: существующий ключ релиза затирать нельзя.
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("создание ключа: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintln(out, hex.EncodeToString(pub))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение ключа: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("файл закрытого ключа повреждён")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func sign(keyPath, file string) error {
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	// Подпись - сырые 64 байта, как ждёт update.Verify.
	return os.WriteFile(file+".sig", ed25519.Sign(priv, data), 0o644)
}
