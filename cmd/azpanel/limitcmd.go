package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/syava842/azpanel/internal/limits"
	"github.com/syava842/azpanel/internal/paths"
)

var errUsage = errors.New("неверные аргументы")

// cmdLimit — azpanel limit set|unset|get|list. Агент подхватывает файл сам.
func cmdLimit(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	path := paths.LimitsFile()
	m, err := limits.Load(path)
	if err != nil {
		return err
	}
	switch {
	case args[0] == "list" && len(args) == 1:
		for _, n := range sortedKeys(m) {
			fmt.Fprintf(out, "%s\t%d\n", n, m[n])
		}
		return nil
	case args[0] == "get" && len(args) == 2:
		if n, ok := m[args[1]]; ok {
			fmt.Fprintf(out, "%d\n", n)
		} else {
			fmt.Fprintln(out, "без ограничения")
		}
		return nil
	case args[0] == "set" && len(args) == 3:
		if !limits.ValidName(args[1]) {
			return fmt.Errorf("недопустимое имя клиента %q: 1–32 символа a-z, A-Z, 0-9, _ и -", args[1])
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 1 {
			return fmt.Errorf("лимит — целое число от 1, получено %q", args[2])
		}
		m[args[1]] = n
	case args[0] == "unset" && len(args) == 2:
		delete(m, args[1])
	default:
		return errUsage
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return limits.Save(path, m)
}

// formatSessions печатает клиентов с сессиями или лимитом; «-» — без ограничения.
func formatSessions(counts, lim map[string]int, out io.Writer) {
	all := map[string]int{}
	for n := range counts {
		all[n] = 0
	}
	for n := range lim {
		all[n] = 0
	}
	fmt.Fprintf(out, "%-32s %7s %7s\n", "клиент", "сессий", "лимит")
	for _, n := range sortedKeys(all) {
		l := "-"
		if v, ok := lim[n]; ok {
			l = strconv.Itoa(v)
		}
		fmt.Fprintf(out, "%-32s %7d %7s\n", n, counts[n], l)
	}
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func runInstall(args []string) error   { return errors.New("установщик — задача 13") }
func runUninstall(args []string) error { return errors.New("установщик — задача 13") }
