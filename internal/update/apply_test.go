package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syava842/azpanel/internal/config"
)

type sysFixture struct {
	t    *testing.T
	root string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	env  *Env
	cmds []string
	// ok управляет проверкой живости: false — «новая версия не поднялась».
	ok func() bool
}

func newSysFixture(t *testing.T) *sysFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &sysFixture{t: t, root: t.TempDir(), pub: pub, priv: priv, ok: func() bool { return true }}
	f.write("bin/azpanel", "\x7fELF-old")
	f.write("etc/config.toml", "config_version = 2\n[node]\napi_listen = \"127.0.0.1:9100\"\n")
	f.write("etc/secrets.env", "NODE_TOKEN=abc\n")
	f.write("data/azpanel.db", "live-db")
	f.write("data/azpanel.db-wal", "wal")
	f.write("data/limits.json", "{}")
	f.write("data/params/p.json", "secret")
	f.env = &Env{
		Root: f.root, Version: "0.9.0", Pub: pub, Arch: "amd64",
		Units: []string{"azpanel-node", "azpanel-panel"},
		BackupDB: func(_ context.Context, src, dst string) error {
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, append([]byte("snapshot:"), b...), 0o600)
		},
		Systemctl: func(_ context.Context, args ...string) error {
			f.cmds = append(f.cmds, strings.Join(args, " "))
			return nil
		},
		Checks:     []Check{func(context.Context, string) error { return f.healthy() }},
		HealthWait: 150 * time.Millisecond, HealthEach: 10 * time.Millisecond,
		Now: func() time.Time { return time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC) },
	}
	return f
}

func (f *sysFixture) healthy() error {
	if !f.ok() {
		return errors.New("/healthz: 500")
	}
	return nil
}

func (f *sysFixture) write(rel, content string) {
	f.t.Helper()
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *sysFixture) read(rel string) string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(rel)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *sysFixture) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(rel)))
	return err == nil
}

// release собирает архив, суммы и подпись; key — чем подписать.
func (f *sysFixture) release(version, binary string, key ed25519.PrivateKey) Input {
	f.t.Helper()
	name := ArchiveName(version, "amd64")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "azpanel", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		f.t.Fatal(err)
	}
	tw.Write([]byte(binary))
	tw.Close()
	zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	return Input{Name: name, Archive: buf.Bytes(), Sums: sums, Sig: ed25519.Sign(key, sums)}
}

// snapshot — содержимое всего, что обновление не должно менять при отказе.
func (f *sysFixture) snapshot() string {
	var sb strings.Builder
	filepath.Walk(f.root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(f.root, p)
			fmt.Fprintf(&sb, "%s=%s\n", filepath.ToSlash(rel), b)
		}
		return nil
	})
	return sb.String()
}

func TestApplySuccess(t *testing.T) {
	f := newSysFixture(t)
	in := f.release("0.9.1", "\x7fELF-new", f.priv)
	res, err := f.env.Apply(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.From != "0.9.0" || res.To != "0.9.1" {
		t.Fatalf("итог: %+v", res)
	}
	if f.read("bin/azpanel") != "\x7fELF-new" || f.read("bin/azpanel.prev") != "\x7fELF-old" {
		t.Fatal("бинарник не заменён или нет azpanel.prev")
	}
	if f.exists("bin/azpanel.new") {
		t.Fatal("остался azpanel.new")
	}
	if got := strings.Join(f.cmds, "|"); got != "restart azpanel-node|restart azpanel-panel" {
		t.Fatalf("systemctl: %s", got)
	}
	got, err := ReadResult(f.root)
	if err != nil || got == nil || !got.OK || got.To != "0.9.1" {
		t.Fatalf("result.json: %+v %v", got, err)
	}
	if want := "backup/update-0.9.0-20261102-120000.tar.gz"; !f.exists(want) {
		t.Fatalf("нет бэкапа %s", want)
	}
}

func TestApplyBackupUsesDBSnapshot(t *testing.T) {
	f := newSysFixture(t)
	res, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", f.priv))
	if err != nil {
		t.Fatal(err)
	}
	// Ломаем всё и разворачиваем бэкап: база должна быть снимком, а не живым файлом.
	f.write("data/azpanel.db", "broken")
	if err := f.env.restoreBackup(res.Backup); err != nil {
		t.Fatal(err)
	}
	if f.read("data/azpanel.db") != "snapshot:live-db" {
		t.Fatalf("база в бэкапе: %q", f.read("data/azpanel.db"))
	}
	// В бэкап не входят wal, params и update.
	var names []string
	zr, _ := os.Open(res.Backup)
	gz, _ := gzip.NewReader(zr)
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	zr.Close()
	for _, n := range names {
		if strings.Contains(n, "wal") || strings.Contains(n, "params") || strings.Contains(n, "update") {
			t.Fatalf("лишнее в бэкапе: %s", n)
		}
	}
}

func TestApplyForeignSignatureChangesNothing(t *testing.T) {
	f := newSysFixture(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	before := f.snapshot()
	_, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", other))
	if err == nil || !strings.Contains(err.Error(), "подпись") {
		t.Fatalf("ждали отказ по подписи: %v", err)
	}
	if f.snapshot() != before || len(f.cmds) != 0 {
		t.Fatal("отказ изменил систему")
	}
}

func TestApplyPlaceholderKeyRefuses(t *testing.T) {
	f := newSysFixture(t)
	f.env.Pub = ReleasePublicKey // заглушка: Verify всегда отказывает
	before := f.snapshot()
	if _, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", f.priv)); err == nil {
		t.Fatal("с ключом-заглушкой обновление поставилось")
	}
	if f.snapshot() != before {
		t.Fatal("отказ изменил систему")
	}
}

func TestApplyTamperedArchiveChangesNothing(t *testing.T) {
	f := newSysFixture(t)
	in := f.release("0.9.1", "\x7fELF-new", f.priv)
	in.Archive = append(in.Archive, 0)
	before := f.snapshot()
	if _, err := f.env.Apply(context.Background(), in); err == nil {
		t.Fatal("подменённый архив принят")
	}
	if f.snapshot() != before {
		t.Fatal("отказ изменил систему")
	}
}

func TestApplyHealthFailureRollsBack(t *testing.T) {
	f := newSysFixture(t)
	before := f.snapshot()
	f.ok = func() bool { return false }
	res, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", f.priv))
	if err == nil || !strings.Contains(err.Error(), "откатено") || !strings.Contains(err.Error(), "/healthz: 500") {
		t.Fatalf("ждали откат с причиной: %v", err)
	}
	if res.OK {
		t.Fatal("итог OK при откате")
	}
	for _, rel := range []string{"bin/azpanel", "etc/config.toml", "etc/secrets.env", "data/azpanel.db", "data/limits.json"} {
		if !strings.Contains(f.snapshot(), rel+"=") {
			t.Fatalf("нет %s", rel)
		}
	}
	// База после отката — снимок (содержимое то же, что и было, плюс метка снимка).
	if f.read("bin/azpanel") != "\x7fELF-old" || f.read("etc/config.toml") != "config_version = 2\n[node]\napi_listen = \"127.0.0.1:9100\"\n" || f.read("etc/secrets.env") != "NODE_TOKEN=abc\n" {
		t.Fatal("bin/etc не вернулись")
	}
	if f.read("data/azpanel.db") != "snapshot:live-db" || f.read("data/limits.json") != "{}" {
		t.Fatalf("data не вернулась: %q", f.read("data/azpanel.db"))
	}
	if f.exists("data/azpanel.db-wal") {
		t.Fatal("wal остался после отката")
	}
	want := "restart azpanel-node|restart azpanel-panel|stop azpanel-panel|stop azpanel-node|start azpanel-node|start azpanel-panel"
	if got := strings.Join(f.cmds, "|"); got != want {
		t.Fatalf("systemctl:\n got %s\nwant %s", got, want)
	}
	r, _ := ReadResult(f.root)
	if r == nil || r.OK || !strings.Contains(r.Reason, "healthz") {
		t.Fatalf("result.json: %+v", r)
	}
	// Всё, кроме снимка базы, совпало с исходным состоянием.
	after := strings.ReplaceAll(f.snapshot(), "snapshot:", "")
	for _, line := range strings.Split(before, "\n") {
		if strings.HasPrefix(line, "data/azpanel.db-wal=") || line == "" {
			continue
		}
		if !strings.Contains(after, line+"\n") {
			t.Fatalf("после отката нет строки %q", line)
		}
	}
}

func TestApplyHealthRecoversInTime(t *testing.T) {
	f := newSysFixture(t)
	n := 0
	f.ok = func() bool { n++; return n > 3 }
	if _, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", f.priv)); err != nil {
		t.Fatalf("поздний, но успешный старт: %v", err)
	}
}

func TestApplyUnansweredQuestionChangesNothing(t *testing.T) {
	f := newSysFixture(t)
	q := config.Question{Key: "node.x", Text: "значение?"}
	asked := 0
	f.env.Migrate = func(data []byte, answers map[string]string) ([]byte, []config.Question, error) {
		asked++
		if _, ok := answers["node.x"]; !ok {
			return nil, []config.Question{q}, &config.QuestionsError{Questions: []config.Question{q}}
		}
		return append(data, []byte("x = 1\n")...), nil, nil
	}
	in := f.release("0.9.1", "\x7fELF-new", f.priv)
	before := f.snapshot()
	_, err := f.env.Apply(context.Background(), in)
	var qe *config.QuestionsError
	if !errors.As(err, &qe) || len(qe.Questions) != 1 {
		t.Fatalf("ждали QuestionsError: %v", err)
	}
	if f.snapshot() != before || len(f.cmds) != 0 {
		t.Fatal("вопрос без ответа изменил систему")
	}
	in.Answers = map[string]string{"node.x": "1"}
	if _, err := f.env.Apply(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.read("etc/config.toml"), "x = 1") {
		t.Fatal("мигрированный конфиг не записан")
	}
}

func TestApplyMigratesRealConfig(t *testing.T) {
	f := newSysFixture(t)
	f.write("etc/config.toml", "[node]\n")
	if _, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", f.priv)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.read("etc/config.toml"), "config_version = 2") {
		t.Fatalf("конфиг не поднят до v2: %s", f.read("etc/config.toml"))
	}
}

func TestApplyDevBuildRefuses(t *testing.T) {
	f := newSysFixture(t)
	f.env.Version = "dev"
	before := f.snapshot()
	if _, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", f.priv)); err == nil {
		t.Fatal("dev-сборка поставила обновление")
	}
	if f.snapshot() != before {
		t.Fatal("отказ изменил систему")
	}
}

func TestApplyRefusesOlderAndWrongArch(t *testing.T) {
	f := newSysFixture(t)
	if _, err := f.env.Apply(context.Background(), f.release("0.9.0", "\x7fELF-new", f.priv)); err == nil {
		t.Fatal("поставлена та же версия")
	}
	if _, err := f.env.Apply(context.Background(), f.release("0.8.0", "\x7fELF-new", f.priv)); err == nil {
		t.Fatal("поставлена более старая версия")
	}
	f.env.Arch = "arm64"
	if _, err := f.env.Apply(context.Background(), f.release("0.9.1", "\x7fELF-new", f.priv)); err == nil {
		t.Fatal("поставлен архив чужой архитектуры")
	}
}

func TestApplyRejectsNonELF(t *testing.T) {
	f := newSysFixture(t)
	if _, err := f.env.Apply(context.Background(), f.release("0.9.1", "#!/bin/sh", f.priv)); err == nil {
		t.Fatal("принят не-ELF")
	}
}
