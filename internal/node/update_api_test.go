package node

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/update"
)

type updEnv struct {
	apiEnv
	f      *fakeExec
	tk     *Tasks
	root   string
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	stage  string
	params string
}

func newUpdEnv(t *testing.T) updEnv {
	t.Helper()
	e, f, tk := tasksEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "config.toml"), []byte("config_version = 2\n"), 0o600)
	u := updEnv{apiEnv: e, f: f, tk: tk, root: root, pub: pub, priv: priv,
		stage: filepath.Join(root, "data", "update", "stage"), params: filepath.Join(root, "data", "params")}
	e.api.Version = "0.9.0"
	e.api.Update = &UpdateService{Root: root, Pub: pub, Self: "/opt/azpanel/bin/azpanel", ParamsDir: u.params, StageDir: u.stage}
	return u
}

func (u updEnv) release(t *testing.T, ver string, key ed25519.PrivateKey, pad int) nodeapi.UpdateRequest {
	t.Helper()
	name := update.ArchiveName(ver, runtime.GOARCH)
	body := "\x7fELF" + strings.Repeat("x", pad)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "azpanel", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	return nodeapi.UpdateRequest{Name: name, Archive: buf.Bytes(), Sums: sums, Sig: ed25519.Sign(key, sums)}
}

func (u updEnv) noTraces(t *testing.T) {
	t.Helper()
	if len(u.f.calls) != 0 {
		t.Fatalf("задача запущена: %v", u.f.calls)
	}
	for _, d := range []string{u.stage, u.params} {
		if m, _ := os.ReadDir(d); len(m) != 0 {
			t.Fatalf("следы в %s: %v", d, m)
		}
	}
}

func TestUpdateAcceptsSignedReleaseAndStartsTask(t *testing.T) {
	u := newUpdEnv(t)
	// Архив больше обычного предела тела (64 КБ): у этого маршрута свой.
	req := u.release(t, "0.9.1", u.priv, 300<<10)
	req.Answers = map[string]string{"a.b": "1"}
	task, err := u.client.Update(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if task.Kind != TaskSelfUpdate || len(task.ID) != 12 {
		t.Fatalf("%+v", task)
	}
	files, _ := filepath.Glob(filepath.Join(u.params, "params-*.json"))
	if len(files) != 1 {
		t.Fatalf("файлов параметров %d", len(files))
	}
	data, _ := os.ReadFile(files[0])
	var p updateParams
	if err := json.Unmarshal(data, &p); err != nil || p.Name != req.Name || p.Answers["a.b"] != "1" {
		t.Fatalf("%s %v", data, err)
	}
	for _, f := range []string{p.ArchivePath, p.SumsPath, p.SigPath} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("файл не подготовлен: %v", err)
		}
	}
	if b, _ := os.ReadFile(p.ArchivePath); !bytes.Equal(b, req.Archive) {
		t.Fatal("архив подготовлен искажённым")
	}
	u.f.done()
	waitFinished(t, u.tk, task.ID)
	call := strings.Join(argvOf(u.f.calls[0]), " ")
	if !strings.Contains(call, "/opt/azpanel/bin/azpanel internal selfupdate --params "+files[0]) {
		t.Fatalf("команда: %s", call)
	}
	if DefaultTaskTimeouts[TaskSelfUpdate].Seconds() != 600 {
		t.Fatal("предел задачи не 600 с")
	}
}

func TestUpdateRejectsForeignSignature(t *testing.T) {
	u := newUpdEnv(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_, err := u.client.Update(context.Background(), u.release(t, "0.9.1", other, 10))
	if status(err) != 422 || !strings.Contains(err.Error(), "подпись") {
		t.Fatalf("ждали 422 по подписи: %v", err)
	}
	u.noTraces(t)
}

func TestUpdateRejectsWhenKeyIsPlaceholder(t *testing.T) {
	u := newUpdEnv(t)
	u.api.Update.Pub = update.ReleasePublicKey
	if _, err := u.client.Update(context.Background(), u.release(t, "0.9.1", u.priv, 10)); status(err) != 422 {
		t.Fatalf("ключ-заглушка: %v", err)
	}
	u.noTraces(t)
}

func TestUpdateRejectsTamperedArchiveAndStaleVersion(t *testing.T) {
	u := newUpdEnv(t)
	req := u.release(t, "0.9.1", u.priv, 10)
	req.Archive = append(req.Archive, 1)
	if _, err := u.client.Update(context.Background(), req); status(err) != 422 {
		t.Fatalf("подменённый архив: %v", err)
	}
	if _, err := u.client.Update(context.Background(), u.release(t, "0.9.0", u.priv, 10)); status(err) != 422 {
		t.Fatalf("та же версия: %v", err)
	}
	u.api.Version = "dev"
	if _, err := u.client.Update(context.Background(), u.release(t, "0.9.1", u.priv, 10)); status(err) != 422 {
		t.Fatalf("dev-агент: %v", err)
	}
	u.noTraces(t)
}

func TestUpdateQuestionsComeBackAs409(t *testing.T) {
	u := newUpdEnv(t)
	q := config.Question{Key: "node.x", Text: "значение?"}
	u.api.Update.Migrate = func([]byte, map[string]string) ([]byte, []config.Question, error) {
		return nil, []config.Question{q}, &config.QuestionsError{Questions: []config.Question{q}}
	}
	_, err := u.client.Update(context.Background(), u.release(t, "0.9.1", u.priv, 10))
	var ae *nodeapi.Error
	if status(err) != 409 || !errors.As(err, &ae) || len(ae.Questions) != 1 || ae.Questions[0].Key != "node.x" || ae.Questions[0].Text != "значение?" {
		t.Fatalf("ждали 409 с вопросом: %v", err)
	}
	u.noTraces(t)
}

func TestUpdateMalformedRequests(t *testing.T) {
	u := newUpdEnv(t)
	req := u.release(t, "0.9.1", u.priv, 10)
	req.Sig = nil
	// Пустая подпись — часть есть, но подпись неверна.
	if _, err := u.client.Update(context.Background(), req); status(err) != 422 {
		t.Fatalf("пустая подпись: %v", err)
	}
	u.noTraces(t)
	u.api.Update = nil
	if _, err := u.client.Update(context.Background(), u.release(t, "0.9.1", u.priv, 10)); status(err) != 503 {
		t.Fatalf("не настроено: %v", err)
	}
}

func TestUpdateLimitAppliesOnlyToUpdateRoute(t *testing.T) {
	u := newUpdEnv(t)
	// Остальные маршруты по-прежнему режутся на 64 КБ.
	big := strings.NewReader(`{"limit":` + strings.Repeat(" ", 100<<10) + `1}`)
	req, _ := http.NewRequest(http.MethodPut, u.srv.URL+"/v1/clients/alice/limit", big)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 && resp.StatusCode != 400 {
		t.Fatalf("большое тело на другом маршруте: %d", resp.StatusCode)
	}
}

func TestUpdateResultEndpoint(t *testing.T) {
	u := newUpdEnv(t)
	if r, err := u.client.UpdateResult(context.Background()); err != nil || r != nil {
		t.Fatalf("до обновлений: %+v %v", r, err)
	}
	os.MkdirAll(filepath.Join(u.root, "data", "update"), 0o755)
	os.WriteFile(filepath.Join(u.root, "data", "update", update.ResultName),
		[]byte(`{"ok":false,"from":"0.9.0","to":"0.9.1","reason":"откат: healthz"}`), 0o600)
	r, err := u.client.UpdateResult(context.Background())
	if err != nil || r == nil || r.OK || r.To != "0.9.1" || !strings.Contains(r.Reason, "healthz") {
		t.Fatalf("%+v %v", r, err)
	}
}
