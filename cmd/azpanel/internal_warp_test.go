package main

import (
	"strings"
	"testing"
)

func TestSplitSteps(t *testing.T) {
	steps, err := splitSteps([]string{"--", "add", "a.example.com", "--", "domains", "save", "--", "sync"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range steps {
		got = append(got, strings.Join(s, " "))
	}
	if strings.Join(got, "|") != "add a.example.com|domains save|sync" {
		t.Fatalf("%q", got)
	}
	for _, bad := range [][]string{nil, {"add", "x"}, {"--", "--", "sync"}, {"--"}} {
		if _, err := splitSteps(bad); err == nil {
			t.Errorf("ждали ошибку для %q", bad)
		}
	}
}
