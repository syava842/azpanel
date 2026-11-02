package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Подменённые в testdata/status.json значения: ни одно не должно уйти панели.
var planted = []string{"ПОДМЕНЁН==", "ПОДМЕНЁН"}

func statusSample(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSanitizeStatusRemovesSecrets(t *testing.T) {
	clean, err := SanitizeStatus(statusSample(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range planted {
		if bytes.Contains(clean, []byte(p)) {
			t.Fatalf("подменённое значение %q осталось в ответе: %s", p, clean)
		}
	}
	var v map[string]any
	json.Unmarshal(clean, &v)
	slave := v["slave"].(map[string]any)
	if _, has := slave["password"]; has {
		t.Fatal("slave.password остался")
	}
	if slave["server"] != "203.0.113.7" {
		t.Fatal("несекретные поля slave потеряны")
	}
	if _, has := v["warp_keys_source"]; has {
		t.Fatal("поле с key в имени осталось")
	}
}

func TestSanitizeStatusNested(t *testing.T) {
	in := `{"a":{"b":[{"private_key":"X1","name":"ok"},{"x":{"Token":"X2","n":1}}]},"api_key":"X3","uuid":"X4"}`
	out, err := SanitizeStatus([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"X1", "X2", "X3", "X4"} {
		if strings.Contains(string(out), s) {
			t.Fatalf("%s не вырезан: %s", s, out)
		}
	}
	if !strings.Contains(string(out), `"name":"ok"`) {
		t.Fatal("несекретное потеряно")
	}
	if _, err := SanitizeStatus([]byte("не json")); err == nil {
		t.Fatal("ждали ошибку разбора")
	}
}

// Ответ API (полный JSON панели) не содержит подменённых значений.
func TestParseStatusJSONHasNoSecrets(t *testing.T) {
	st, err := ParseStatus(statusSample(t))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(st)
	for _, p := range planted {
		if strings.Contains(string(out), p) {
			t.Fatalf("подменённое значение %q в ответе: %s", p, out)
		}
	}
	if !st.Installed || st.Version != "1.5.7" || st.RemoteVersion != "1.5.8" || !st.UpdateAvailable ||
		st.OutboundMode != "warp" || !st.AntizapretWarp || st.AntizapretMode != "selective" ||
		!st.DomainsSynced || st.Subnet.Fake != "10.224.0.0/16" || st.Singbox.MTU != 1420 || !st.IPRanges.Synced {
		t.Fatalf("%+v", st)
	}
}

func TestWarperStatusUsesRunner(t *testing.T) {
	dir := t.TempDir()
	w := &Warper{Dir: dir, Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "status json" {
			t.Errorf("вызов %s %v", name, args)
		}
		return statusSample(t), nil
	}}
	if st := w.Status(context.Background()); st.Installed {
		t.Fatal("без файла version AZ-WARP не установлен")
	}
	os.WriteFile(filepath.Join(dir, "version"), []byte("1.5.7\n"), 0o644)
	st := w.Status(context.Background())
	if !st.Installed || st.Version != "1.5.7" || st.Error != "" {
		t.Fatalf("%+v", st)
	}
	// Сбой warper: ошибка без вывода секретов.
	w.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(`password: ПОДМЕНЁН==`), errors.New("exit status 1")
	}
	st = w.Status(context.Background())
	if st.Error == "" || strings.Contains(st.Error, "ПОДМЕНЁН") {
		t.Fatalf("ошибка %q", st.Error)
	}
}

func TestRedactText(t *testing.T) {
	cases := map[string]string{
		`password: S3cret`:                  `password: ***`,
		`"password": "S3 cret"`:             `"password": ***`,
		`PrivateKey = AbC=`:                 `PrivateKey = ***`,
		`warp_keys_source=/etc/x private=1`: `warp_keys_source=*** private=***`,
		`обычная строка`:                    `обычная строка`,
	}
	for in, want := range cases {
		if got := RedactText(in); got != want {
			t.Errorf("%q -> %q, ждали %q", in, got, want)
		}
	}
}

func TestSteps(t *testing.T) {
	steps, err := Steps([]Op{
		{Op: "add", Arg: "azpanel-test.example.com"}, {Op: "remove", Arg: "*.old.example"},
		{Op: "enable", Arg: "gemini"}, {Op: "save"}, {Op: "sync"},
		{Op: "ipadd", Arg: "198.51.100.0/24"}, {Op: "ipremove", Arg: "203.0.113.9"}, {Op: "ipsync"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(steps))
	for i, s := range steps {
		got[i] = strings.Join(s, " ")
	}
	want := "add azpanel-test.example.com|remove *.old.example|enable gemini|domains save|sync|ipadd 198.51.100.0/24|ipremove 203.0.113.9|ipsync"
	if strings.Join(got, "|") != want {
		t.Fatalf("%q", strings.Join(got, "|"))
	}
	bad := [][]Op{
		nil,
		{{Op: "add", Arg: "x; rm -rf /"}},
		{{Op: "add", Arg: "-h"}},
		{{Op: "add", Arg: ""}},
		{{Op: "enable", Arg: "other"}},
		{{Op: "ipadd", Arg: "300.1.1.1/24"}},
		{{Op: "ipadd", Arg: "--flag"}},
		{{Op: "update"}},
		{{Op: "sync"}, {Op: "add", Arg: "a b"}},
	}
	for _, ops := range bad {
		if _, err := Steps(ops); err == nil {
			t.Errorf("ждали отказ для %+v", ops)
		}
	}
}

func TestRunStepsStopsOnFailureAndHidesSecrets(t *testing.T) {
	var calls []string
	w := &Warper{Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch strings.Join(args, " ") {
		case "status json":
			return statusSample(t), nil
		case "doctor":
			return []byte("\x1b[0;32mOK\x1b[0m\npassword: ПОДМЕНЁН==\n"), nil
		case "boom":
			return []byte("ошибка"), errors.New("exit status 2")
		}
		return nil, nil
	}}
	var out bytes.Buffer
	err := w.RunSteps(context.Background(), [][]string{{"update"}, {StatusJSONStep}, {"doctor"}, {"boom"}, {"never"}}, &out)
	if err == nil || strings.Join(calls, "|") != "update|status json|doctor|boom" {
		t.Fatalf("err=%v calls=%v", err, calls)
	}
	for _, p := range planted {
		if strings.Contains(out.String(), p) {
			t.Fatalf("секрет %q в журнале задачи:\n%s", p, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("цвета в журнале")
	}
	if !strings.Contains(out.String(), "$ warper status json") || !strings.Contains(out.String(), `"version": "1.5.7"`) {
		t.Fatalf("журнал:\n%s", out.String())
	}
}

func TestDomainsListParsing(t *testing.T) {
	// Образец с 94: домен|источник|включён.
	sample := "# комментарий\n\x1b[0;32mclaud.ai|user|1\x1b[0m\n\ngemini.google.com|gemini|0\n chat.openai.com|chatgpt|1 \nold.example.com\n*.wild.example|user|\n"
	w := &Warper{Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(sample), nil
	}}
	got, err := w.Domains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []DomainEntry{
		{Domain: "claud.ai", Source: "user", Enabled: true},
		{Domain: "gemini.google.com", Source: "gemini", Enabled: false},
		{Domain: "chat.openai.com", Source: "chatgpt", Enabled: true},
		{Domain: "old.example.com", Enabled: true},
		{Domain: "*.wild.example", Source: "user", Enabled: true},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("строка %d: %+v, ждали %+v", i, got[i], want[i])
		}
	}
}

func TestIPsListParsing(t *testing.T) {
	w := &Warper{Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("198.51.100.0/24\n# c\n203.0.113.0/24\n"), nil
	}}
	got, err := w.IPs(context.Background())
	if err != nil || strings.Join(got, "|") != "198.51.100.0/24|203.0.113.0/24" {
		t.Fatalf("%v %v", got, err)
	}
}
