package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCmdLimit(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	var out bytes.Buffer
	if err := cmdLimit([]string{"set", "alice", "3"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdLimit([]string{"set", "bob", "1"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	cmdLimit([]string{"get", "alice"}, &out)
	if out.String() != "3\n" {
		t.Fatalf("get alice: %q", out.String())
	}
	out.Reset()
	cmdLimit([]string{"list"}, &out)
	if out.String() != "alice\t3\nbob\t1\n" {
		t.Fatalf("list: %q", out.String())
	}
	cmdLimit([]string{"unset", "alice"}, &out)
	out.Reset()
	cmdLimit([]string{"get", "alice"}, &out)
	if !strings.Contains(out.String(), "без ограничения") {
		t.Fatalf("после unset: %q", out.String())
	}
}

func TestCmdLimitRejects(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", t.TempDir())
	for _, args := range [][]string{
		{"set", "a b", "1"}, {"set", "alice", "0"}, {"set", "alice", "x"}, {"set", "alice"}, {"что"},
	} {
		if err := cmdLimit(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v: ждали ошибку", args)
		}
	}
}

func TestFormatSessions(t *testing.T) {
	var out bytes.Buffer
	formatSessions(map[string]int{"alice": 2, "carol": 1}, map[string]int{"alice": 3, "bob": 1}, &out)
	got := out.String()
	for _, want := range []string{"alice", "2", "3", "bob", "0", "carol", "-"} {
		if !strings.Contains(got, want) {
			t.Fatalf("нет %q в:\n%s", want, got)
		}
	}
	if strings.Index(got, "alice") > strings.Index(got, "bob") || strings.Index(got, "bob") > strings.Index(got, "carol") {
		t.Fatalf("не по алфавиту:\n%s", got)
	}
}
