package paths

import (
	"path/filepath"
	"testing"
)

func TestRootDefault(t *testing.T) {
	t.Setenv("AZPANEL_ROOT", "")
	if got := Root(); got != "/opt/azpanel" {
		t.Fatalf("Root() = %q", got)
	}
	if got := NodeSocket(); got != "/run/azpanel/node.sock" {
		t.Fatalf("NodeSocket() = %q", got)
	}
}

func TestRootOverride(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AZPANEL_ROOT", root)
	if got, want := LimitsFile(), filepath.Join(root, "data", "limits.json"); got != want {
		t.Fatalf("LimitsFile() = %q, want %q", got, want)
	}
	if got, want := NodeSocket(), filepath.Join(root, "run", "node.sock"); got != want {
		t.Fatalf("NodeSocket() = %q, want %q", got, want)
	}
}
