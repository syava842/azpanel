package node

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// I7: удаляется только то, что перечислено явно. Неполный архив (в нём один
// файл) больше не стирает PKI и ключи реплики.
func TestRunSyncApplyRemovesOnlyListedFiles(t *testing.T) {
	l := newSyncLayout(t)
	keep := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	gone := filepath.Join(l.set.AntiZapretDir, "client", "openvpn", "antizapret", "antizapret-alice-(1.2.3.4).ovpn")
	ca := filepath.Join(l.set.EasyRSADir, "pki", "ca.crt")
	wgKey := filepath.Join(l.set.WireGuardDir, "key")
	warp := filepath.Join(l.set.WireGuardDir, "warp-vpn.conf")
	if _, err := applyTar(t, l.set, map[string]string{keep: "новое\n"}, gone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(gone); err == nil {
		t.Error("перечисленный профиль не удалён")
	}
	for _, p := range []string{ca, wgKey, warp, filepath.Join(l.set.AntiZapretDir, "setup"), filepath.Join(l.set.AntiZapretDir, "doall.sh")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("не перечисленный файл удалён: %s", p)
		}
	}
	// Удаление файла, которого уже нет, не ошибка.
	if _, err := applyTar(t, l.set, map[string]string{}, gone); err != nil {
		t.Errorf("повторное удаление: %v", err)
	}
}

func TestRunSyncApplyRefusesCriticalRemoval(t *testing.T) {
	l := newSyncLayout(t)
	keep := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	ca := filepath.Join(l.set.EasyRSADir, "pki", "ca.crt")
	caKey := filepath.Join(l.set.EasyRSADir, "pki", "private", "ca.key")
	wgKey := filepath.Join(l.set.WireGuardDir, "key")
	for _, victim := range []string{ca, caKey, wgKey} {
		_, err := applyTar(t, l.set, map[string]string{keep: "x\n"}, victim)
		if err == nil || !errors.Is(err, ErrRemovalRefused) {
			t.Fatalf("удаление %s без force: %v", victim, err)
		}
		if _, serr := os.Stat(victim); serr != nil {
			t.Fatalf("%s удалён, хотя задача отказала", victim)
		}
	}
	if b, _ := os.ReadFile(keep); string(b) == "x\n" {
		t.Fatal("при отказе файлы архива всё же записаны")
	}
	// С force — можно.
	if _, err := applyTarForce(t, l.set, map[string]string{keep: "x\n"}, true, ca); err != nil {
		t.Fatalf("force: %v", err)
	}
	if _, err := os.Stat(ca); err == nil {
		t.Error("с force ca.crt не удалён")
	}
}

// Массовое удаление (больше половины набора) без force отклоняется.
func TestRunSyncApplyRefusesMassRemoval(t *testing.T) {
	l := newSyncLayout(t)
	var many []string
	for i := 0; i < 20; i++ {
		p := filepath.Join(l.set.AntiZapretDir, "client", "p", "c"+string(rune('a'+i))+".ovpn")
		put(t, p, "P")
		many = append(many, p)
	}
	hosts := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	_, err := applyTar(t, l.set, map[string]string{hosts: "x\n"}, many...)
	if !errors.Is(err, ErrRemovalRefused) {
		t.Fatalf("массовое удаление без force: %v", err)
	}
	for _, p := range many {
		if _, serr := os.Stat(p); serr != nil {
			t.Fatal("при отказе файлы удалены")
		}
	}
	if _, err := applyTarForce(t, l.set, map[string]string{hosts: "x\n"}, true, many...); err != nil {
		t.Fatalf("force: %v", err)
	}
}

func TestRunSyncApplyRemoveListValidation(t *testing.T) {
	l := newSyncLayout(t)
	keep := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	for name, victim := range map[string]string{
		"вне набора": filepath.Join(l.set.AntiZapretDir, "doall.sh"),
		"setup":      filepath.Join(l.set.AntiZapretDir, "setup"),
		"WARP":       filepath.Join(l.set.WireGuardDir, "warp-vpn.conf"),
	} {
		if _, err := applyTarForce(t, l.set, map[string]string{keep: "x\n"}, true, victim); err == nil {
			t.Errorf("%s: удаление принято", name)
		}
		if _, serr := os.Stat(victim); serr != nil {
			t.Errorf("%s: файл удалён", name)
		}
	}
	// Файл и в архиве, и в списке удаления.
	if _, err := applyTar(t, l.set, map[string]string{keep: "x\n"}, keep); err == nil {
		t.Error("файл и в архиве, и в списке удаления принят")
	}
}

func TestSyncApplyAPIRemovalRefusedWithoutForce(t *testing.T) {
	l := newSyncLayout(t)
	l.roles.Set(nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: "g"})
	ca := filepath.Join(l.set.EasyRSADir, "pki", "ca.crt")
	body := buildTarRemove(t, map[string]string{}, []string{ca})
	_, err := l.client.SyncApply(context.Background(), body, nodeapi.SyncApplyOpts{})
	if status(err) != 422 || !strings.Contains(err.Error(), "force") {
		t.Fatalf("ждали 422 про force: %v", err)
	}
	if len(l.f.calls) != 0 {
		t.Fatal("задача запущена при отказе")
	}
	if ents, _ := os.ReadDir(l.api.Sync.StageDir); len(ents) != 0 {
		t.Fatalf("остался архив: %d", len(ents))
	}
	// Только удаление (без файлов) с обычным файлом принимается.
	gone := filepath.Join(l.set.AntiZapretDir, "client", "openvpn", "antizapret", "antizapret-alice-(1.2.3.4).ovpn")
	if _, err := l.client.SyncApply(context.Background(), buildTarRemove(t, map[string]string{}, []string{gone}), nodeapi.SyncApplyOpts{}); err != nil {
		t.Fatalf("удаление одного профиля: %v", err)
	}
	l.f.done()
}

func TestSyncRemovalsDiffOfManifests(t *testing.T) {
	m := func(paths ...string) nodeapi.SyncManifest {
		var out nodeapi.SyncManifest
		for _, p := range paths {
			out.Files = append(out.Files, nodeapi.SyncEntry{Path: p})
		}
		return out
	}
	got := nodeapi.SyncRemovals(m("/a", "/b"), m("/c", "/b", "/a", "/d"))
	if strings.Join(got, ",") != "/c,/d" {
		t.Fatalf("%v", got)
	}
	if nodeapi.SyncRemovals(m("/a"), m("/a")) != nil {
		t.Fatal("одинаковые манифесты дали список")
	}
}

// M1: права из архива ограничиваются.
func TestSafeMode(t *testing.T) {
	cases := []struct {
		name  string
		kind  syncKind
		path  string
		mode  os.FileMode
		local os.FileMode
		has   bool
		want  os.FileMode
	}{
		{"запись всем срезается", kindRouting, "/c/include-hosts.txt", 0o666, 0, false, 0o644},
		{"исполняемость txt срезается", kindRouting, "/c/a.txt", 0o755, 0, false, 0o644},
		{"sh остаётся исполняемым", kindProfile, "/c/client.sh", 0o755, 0, false, 0o755},
		{"sh с записью группе", kindProfile, "/c/client.sh", 0o775, 0, false, 0o755},
		{"исполняемый локально остаётся", kindEasyRSA, "/e/easyrsa", 0o755, 0o755, true, 0o755},
		{"не исполняемый локально — не становится", kindEasyRSA, "/e/easyrsa", 0o755, 0o644, true, 0o644},
		{"ключ PKI не шире 0640", kindEasyRSA, "/e/pki/private/ca.key", 0o644, 0, false, 0o640},
		{"ключ WG не шире 0640", kindWireGuard, "/w/key", 0o666, 0, false, 0o640},
		{"ключ 0600 остаётся", kindEasyRSA, "/e/pki/private/x.key", 0o600, 0, false, 0o600},
		{"setup не шире 0640", kindSetup, "/a/setup", 0o644, 0, false, 0o640},
	}
	for _, c := range cases {
		if got := safeMode(c.kind, c.path, c.mode, c.local, c.has); got != c.want {
			t.Errorf("%s: %o, ждали %o", c.name, got, c.want)
		}
	}
}

func TestRunSyncApplyClampsArchiveModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("биты прав POSIX")
	}
	l := newSyncLayout(t)
	hosts := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	stage := t.TempDir()
	arch := filepath.Join(stage, "archive.tar")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct {
		p    string
		mode int64
	}{{hosts, 0o777}, {filepath.Join(l.set.WireGuardDir, "key"), 0o666}} {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: e.p, Mode: e.mode, Size: 2})
		tw.Write([]byte("zz"))
	}
	tw.Close()
	os.WriteFile(arch, buf.Bytes(), 0o600)
	if err := RunSyncApply(context.Background(), SyncApplyParams{Set: l.set, Archive: arch, Stage: stage}, &SyncEnv{Run: (&recorder{}).run}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{hosts: 0o644, filepath.Join(l.set.WireGuardDir, "key"): 0o640} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != want {
			t.Errorf("%s: %o, ждали %o", p, fi.Mode().Perm(), want)
		}
	}
}

// M2: смена одних прав не считается изменением и не перезапускает службы.
func TestRunSyncApplyChmodOnlyDoesNotRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("биты прав POSIX")
	}
	l := newSyncLayout(t)
	ca := filepath.Join(l.set.EasyRSADir, "pki", "ca.crt")
	os.Chmod(ca, 0o600) // разошлись права при том же содержимом "CA"
	rec, err := applyTar(t, l.set, map[string]string{ca: "CA"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("смена прав перезапустила службы: %v", rec.calls)
	}
	if fi, _ := os.Stat(ca); fi.Mode().Perm() != 0o644 {
		t.Fatalf("права не поправлены: %o", fi.Mode().Perm())
	}
}

// M3: записанные списки и setup сами не применяются — задача говорит об этом.
func TestRunSyncApplyReportsWhatNeedsApplying(t *testing.T) {
	l := newSyncLayout(t)
	stage := t.TempDir()
	arch := filepath.Join(stage, "archive.tar")
	hosts := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	os.WriteFile(arch, buildTar(t, map[string]string{hosts: "new\n"}).Bytes(), 0o600)
	var log bytes.Buffer
	if err := RunSyncApply(context.Background(), SyncApplyParams{Set: l.set, Archive: arch, Stage: stage}, &SyncEnv{Run: (&recorder{}).run, Out: &log}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "НУЖНО ПРИМЕНИТЬ") {
		t.Fatalf("журнал без напоминания:\n%s", log.String())
	}
}

// M4: корень набора — симлинк: запись отклоняется.
func TestSyncRejectsSymlinkedRoot(t *testing.T) {
	l := newSyncLayout(t)
	real := filepath.Join(l.base, "real-knot")
	if err := os.Rename(l.set.KnotDir, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, l.set.KnotDir); err != nil {
		t.Skip("симлинки недоступны:", err)
	}
	_, err := ValidateArchive(l.set, buildTar(t, map[string]string{filepath.Join(l.set.KnotDir, "custom-a.lua"): "x"}))
	if err == nil || !strings.Contains(err.Error(), "символическая ссылка") {
		t.Fatalf("корень-ссылка принят: %v", err)
	}
}

// M13: симлинк, жёсткая ссылка и каталог как записи tar отклоняются.
func TestValidateArchiveRejectsNonRegularEntries(t *testing.T) {
	l := newSyncLayout(t)
	target := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	for name, h := range map[string]tar.Header{
		"симлинк":        {Typeflag: tar.TypeSymlink, Name: target, Linkname: "/etc/passwd"},
		"жёсткая ссылка": {Typeflag: tar.TypeLink, Name: target, Linkname: "/etc/passwd"},
		"каталог":        {Typeflag: tar.TypeDir, Name: filepath.ToSlash(filepath.Dir(target)) + "/", Mode: 0o755},
	} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		h := h
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Close()
		if _, err := ValidateArchive(l.set, &buf); err == nil || !strings.Contains(err.Error(), "обычные файлы") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
