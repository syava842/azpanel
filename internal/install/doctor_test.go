package install

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
)

type fakeEntry struct {
	name string
	mode fs.FileMode
}

func (f fakeEntry) Name() string               { return f.name }
func (f fakeEntry) IsDir() bool                { return false }
func (f fakeEntry) Type() fs.FileMode          { return f.mode }
func (f fakeEntry) Info() (fs.FileInfo, error) { return nil, nil }

func healthyDoctor(t *testing.T) (*Doctor, *bytes.Buffer) {
	t.Helper()
	t.Setenv("AZPANEL_ROOT", filepath.Join(t.TempDir(), "opt", "azpanel"))
	out := &bytes.Buffer{}
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	return &Doctor{
		Out: out, UnitDir: "/etc/systemd/system", Cfg: config.Default(),
		Stat:     func(string) (fs.FileInfo, error) { return nil, nil },
		ReadFile: func(string) ([]byte, error) { return []byte("CERT=/c/fullchain.pem\n"), nil },
		ReadDir: func(string) ([]os.DirEntry, error) {
			return []os.DirEntry{fakeEntry{"antizapret-udp.sock", fs.ModeSocket}}, nil
		},
		IsActive:      func(string) bool { return true },
		HookInstalled: func() (bool, error) { return true, nil },
		AgentList:     func() error { return nil },
		Healthz:       func(string) error { return nil },
		CertNotAfter:  func(string) (time.Time, error) { return now.Add(60 * 24 * time.Hour), nil },
		DiskFreeMB:    func(string) (uint64, error) { return 5000, nil },
		NginxTest:     func() error { return nil },
		Now:           func() time.Time { return now },
	}, out
}

func TestDoctorAllOK(t *testing.T) {
	d, out := healthyDoctor(t)
	if n := d.Run(); n != 0 {
		t.Fatalf("проблем %d:\n%s", n, out)
	}
	if strings.Contains(out.String(), "ПРОБЛЕМА") || strings.Count(out.String(), "OK") < 7 {
		t.Fatalf("вывод:\n%s", out)
	}
}

func TestDoctorBrokenHook(t *testing.T) {
	d, out := healthyDoctor(t)
	d.HookInstalled = func() (bool, error) { return false, nil }
	if n := d.Run(); n != 1 {
		t.Fatalf("проблем %d:\n%s", n, out)
	}
	if !strings.Contains(out.String(), "ПРОБЛЕМА  хук лимита не установлен") {
		t.Fatalf("нет причины:\n%s", out)
	}
	d, out = healthyDoctor(t)
	d.HookInstalled = func() (bool, error) { return false, errors.New("файл повреждён") }
	if n := d.Run(); n != 1 || !strings.Contains(out.String(), "файл повреждён") {
		t.Fatalf("%d\n%s", n, out)
	}
}

func TestDoctorFindsEachProblem(t *testing.T) {
	cases := map[string]func(*Doctor){
		"azpanel-node не запущена": func(d *Doctor) { d.IsActive = func(u string) bool { return u != "azpanel-node" } },
		"нет сокетов управления":   func(d *Doctor) { d.ReadDir = func(string) ([]os.DirEntry, error) { return nil, nil } },
		"API агента не отвечает":   func(d *Doctor) { d.AgentList = func() error { return errors.New("отказ") } },
		"панель не отвечает":       func(d *Doctor) { d.Healthz = func(string) error { return errors.New("отказ") } },
		"истекает": func(d *Doctor) {
			d.CertNotAfter = func(string) (time.Time, error) { return d.Now().Add(5 * 24 * time.Hour), nil }
		},
		"истёк": func(d *Doctor) {
			d.CertNotAfter = func(string) (time.Time, error) { return d.Now().Add(-time.Hour), nil }
		},
		"свободно 100 МБ":      func(d *Doctor) { d.DiskFreeMB = func(string) (uint64, error) { return 100, nil } },
		"nginx -t не проходит": func(d *Doctor) { d.NginxTest = func() error { return errors.New("syntax error") } },
		"azpanel-node: юнит":   func(d *Doctor) { d.Stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist } },
	}
	for want, mod := range cases {
		d, out := healthyDoctor(t)
		mod(d)
		if n := d.Run(); n == 0 || !strings.Contains(out.String(), want) {
			t.Errorf("%q: проблем %d\n%s", want, n, out)
		}
	}
}

func TestDoctorSkipsNginxWithoutSnippet(t *testing.T) {
	d, out := healthyDoctor(t)
	called := false
	d.NginxTest = func() error { called = true; return nil }
	d.Stat = func(p string) (fs.FileInfo, error) {
		if p == SnippetPath {
			return nil, fs.ErrNotExist
		}
		return nil, nil
	}
	if n := d.Run(); n != 0 || called {
		t.Fatalf("%d %v\n%s", n, called, out)
	}
}
