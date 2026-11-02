package node

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSweepParamsRemovesOnlyStaleParamsFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "params-111.json")
	fresh := filepath.Join(dir, "params-222.json")
	other := filepath.Join(dir, "keep.json")
	for _, f := range []string{old, fresh, other} {
		if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * time.Hour)
	os.Chtimes(old, past, past)
	os.Chtimes(other, past, past)
	if n := SweepParams(dir, time.Hour); n != 1 {
		t.Fatalf("удалено %d", n)
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("старый файл параметров остался")
	}
	for _, f := range []string{fresh, other} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("удалён лишний файл %s", f)
		}
	}
	if SweepParams(filepath.Join(dir, "нет"), time.Hour) != 0 {
		t.Error("несуществующий каталог")
	}
}

// Новый файл параметров создаётся уже после уборки старых.
func TestWriteParamsFileSweepsStale(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "params-old.json")
	os.WriteFile(old, []byte("{}"), 0o600)
	past := time.Now().Add(-3 * time.Hour)
	os.Chtimes(old, past, past)
	f, err := writeParamsFile(dir, map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("устаревший файл не убран")
	}
	if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("новый файл: %v %v", st, err)
	}
}

func TestTasksOnFinishCalled(t *testing.T) {
	e := newAZ(t)
	called := make(chan struct{}, 1)
	e.u.Tasks.OnFinish = func() { called <- struct{}{} }
	if _, err := e.u.Tasks.Start("doall", []string{"doall.sh"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("OnFinish не вызван после задачи")
	}
}
