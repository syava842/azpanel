//go:build linux

package update

import (
	"path/filepath"
	"testing"
)

func TestAcquireLockExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "data", "update", "lock")
	rel, err := acquireLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(p); err != errLocked {
		t.Fatalf("второй замок: %v", err)
	}
	rel()
	rel2, err := acquireLock(p)
	if err != nil {
		t.Fatalf("после снятия замок не берётся: %v", err)
	}
	rel2()
}
