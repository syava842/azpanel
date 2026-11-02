package telemt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// stand — поддельный узел: файлы во временном каталоге, systemctl, journalctl
// и GitHub в одном месте. Версия бинарника — его содержимое.
type stand struct {
	t        *testing.T
	env      *Env
	srv      *httptest.Server
	mu       sync.Mutex
	calls    []string
	restarts int                                        // NRestarts, который вернёт systemctl show
	active   string                                     // ActiveState
	journal  string                                     // что вернёт journalctl
	onRun    func(s *stand, name string, args []string) // дополнительное поведение
	sums     map[string]string                          // подмена .sha256 по имени архива
	newBin   string
	freeNow  bool
}

func tarGz(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(content))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func newStand(t *testing.T, oldBin, newBin string) *stand {
	t.Helper()
	dir := t.TempDir()
	s := &stand{t: t, active: "active", newBin: newBin, sums: map[string]string{}}
	arch := tarGz(t, "telemt", newBin)
	sum := sha256.Sum256(arch)
	asset := AssetName("x86_64", "gnu")
	mux := http.NewServeMux()
	mux.HandleFunc(releasePath, func(w http.ResponseWriter, r *http.Request) {
		rel := Release{Tag: newBin, Assets: []Asset{
			{Name: asset, URL: s.srv.URL + "/dl/" + asset},
			{Name: asset + ".sha256", URL: s.srv.URL + "/dl/" + asset + ".sha256"},
		}}
		json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/dl/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(arch) })
	mux.HandleFunc("/dl/"+asset+".sha256", func(w http.ResponseWriter, r *http.Request) {
		h := hex.EncodeToString(sum[:])
		if v, ok := s.sums[asset]; ok {
			h = v
		}
		fmt.Fprintf(w, "%s  %s\n", h, asset)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)

	bin := filepath.Join(dir, "telemt")
	cfg := filepath.Join(dir, "etc", "config.toml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	if oldBin != "" {
		os.WriteFile(bin, []byte(oldBin), 0o755)
		data, _ := os.ReadFile("testdata/config-example.toml")
		os.WriteFile(cfg, data, 0o640)
	}
	s.env = &Env{
		Binary: bin, Config: cfg, Unit: "telemt", StateDir: filepath.Join(dir, "state"),
		HTTP: s.srv.Client(), APIBase: s.srv.URL, Arch: "x86_64", Libc: "gnu",
		Sleep: func(time.Duration) {}, Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
		LookupHost: func(context.Context, string) ([]string, error) { return []string{"1.2.3.4"}, nil },
		PortFree: func(int) error {
			if s.freeNow {
				return nil
			}
			return fmt.Errorf("занят")
		},
	}
	s.env.Run = s.run
	s.freeNow = true
	return s
}

func (s *stand) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	if s.onRun != nil {
		s.onRun(s, name, args)
	}
	switch {
	case name == "systemctl" && args[0] == "show":
		return []byte(fmt.Sprintf("ActiveState=%s\nNRestarts=%d\n", s.active, s.restarts)), nil
	case name == "journalctl":
		return []byte(s.journal), nil
	case len(args) == 1 && args[0] == "--version":
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		return []byte("telemt " + string(data) + "\n"), nil
	}
	return nil, nil
}

func (s *stand) count(prefix string) int {
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (s *stand) binContent() string {
	b, _ := os.ReadFile(s.env.Binary)
	return string(b)
}

func (s *stand) configText() string {
	b, _ := os.ReadFile(s.env.Config)
	return string(b)
}

func goodJournal() string {
	d, _ := os.ReadFile("testdata/journal-link.txt")
	return string(d)
}

func TestUpdateOK(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	s.journal = goodJournal()
	cfgBefore := s.configText()
	if err := s.env.Update(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if s.binContent() != "3.5.16" {
		t.Fatalf("бинарник %q", s.binContent())
	}
	if b, _ := os.ReadFile(s.env.Binary + ".prev"); string(b) != "3.5.7" {
		t.Fatalf("telemt.prev %q", b)
	}
	if s.configText() != cfgBefore {
		t.Fatal("конфиг изменился")
	}
	if s.count("systemctl restart") != 1 {
		t.Fatalf("перезапусков %d", s.count("systemctl restart"))
	}
	if _, err := os.Stat(s.env.Binary + ".new"); err == nil {
		t.Fatal("остался промежуточный файл")
	}
}

func TestUpdateNotNeeded(t *testing.T) {
	s := newStand(t, "3.5.16", "3.5.16")
	if err := s.env.Update(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if s.count("systemctl restart") != 0 || s.binContent() != "3.5.16" {
		t.Fatal("обновление без нужды")
	}
}

// Рост NRestarts после перезапуска — откат к прежнему бинарнику.
func TestUpdateRollbackOnRestartsGrowth(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	s.onRun = func(s *stand, name string, args []string) {
		if name == "systemctl" && args[0] == "restart" && s.binContent() == "3.5.16" {
			s.restarts++ // новый бинарник падает, Restart=always поднимает снова
		}
	}
	err := s.env.Update(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "откачено") || !strings.Contains(err.Error(), "NRestarts") {
		t.Fatalf("ошибка %v", err)
	}
	if s.binContent() != "3.5.7" {
		t.Fatalf("бинарник не возвращён: %q", s.binContent())
	}
	if s.count("systemctl restart") != 2 {
		t.Fatalf("перезапусков %d, ждали 2 (обновление и откат)", s.count("systemctl restart"))
	}
}

// Ссылка в журнале с чужим секретом — откат.
func TestUpdateRollbackOnJournalMismatch(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	s.journal = strings.ReplaceAll(goodJournal(), "00112233445566778899aabbccddeeff", "ffffffffffffffffffffffffffffffff")
	err := s.env.Update(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "откачено") {
		t.Fatalf("ошибка %v", err)
	}
	if s.binContent() != "3.5.7" {
		t.Fatal("бинарник не возвращён")
	}
}

func TestUpdateNotActiveRollsBack(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	s.onRun = func(s *stand, name string, args []string) {
		if name == "systemctl" && args[0] == "restart" {
			if s.binContent() == "3.5.16" {
				s.active = "failed"
			} else {
				s.active = "active"
			}
		}
	}
	err := s.env.Update(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "откачено") {
		t.Fatalf("ошибка %v", err)
	}
	if s.binContent() != "3.5.7" || s.active != "active" {
		t.Fatalf("бинарник %q, служба %s", s.binContent(), s.active)
	}
}

func TestUpdateBadChecksumTouchesNothing(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	s.sums[AssetName("x86_64", "gnu")] = strings.Repeat("0", 64)
	err := s.env.Update(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatalf("ошибка %v", err)
	}
	if s.binContent() != "3.5.7" || s.count("systemctl restart") != 0 {
		t.Fatal("при несовпавшей сумме ничего не должно меняться")
	}
	if _, err := os.Stat(s.env.Binary + ".prev"); err == nil {
		t.Fatal("telemt.prev не должен появляться")
	}
}

func TestApplyAddAndRemove(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	s.journal = ""
	const second = "ffeeddccbbaa99887766554433221100"
	if err := s.env.Apply(context.Background(), ApplyParams{Op: "add", Name: "azpanel-test", Secret: second}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.configText(), `azpanel-test = "`+second+`"`) || s.count("systemctl restart") != 1 {
		t.Fatalf("конфиг:\n%s", s.configText())
	}
	baks, _ := filepath.Glob(s.env.Config + ".bak-*")
	if len(baks) != 1 {
		t.Fatalf("копий конфига %d", len(baks))
	}
	if err := s.env.Apply(context.Background(), ApplyParams{Op: "remove", Name: "azpanel-test"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.configText(), "azpanel-test") {
		t.Fatal("пользователь не удалён")
	}
}

func TestApplyRemoveLastUserRefused(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	if err := s.env.Apply(context.Background(), ApplyParams{Op: "remove", Name: "user"}); err == nil {
		t.Fatal("ждали отказ")
	}
	if s.count("systemctl restart") != 0 {
		t.Fatal("перезапуск при отказе")
	}
}

func TestApplyRollsBackConfigWhenServiceFails(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	before := s.configText()
	s.onRun = func(s *stand, name string, args []string) {
		if name == "systemctl" && args[0] == "restart" {
			if strings.Contains(s.configText(), "bad-user") {
				s.active = "failed"
			} else {
				s.active = "active"
			}
		}
	}
	err := s.env.Apply(context.Background(), ApplyParams{Op: "add", Name: "bad-user", Secret: "ffeeddccbbaa99887766554433221100"})
	if err == nil || !strings.Contains(err.Error(), "откачена") {
		t.Fatalf("ошибка %v", err)
	}
	if s.configText() != before {
		t.Fatal("конфиг не возвращён")
	}
	if s.count("systemctl restart") != 2 {
		t.Fatalf("перезапусков %d", s.count("systemctl restart"))
	}
}

func TestInstall(t *testing.T) {
	s := newStand(t, "", "3.5.16")
	s.freeNow = true
	s.onRun = func(s *stand, name string, args []string) {
		switch {
		case len(args) > 0 && args[0] == "--init":
			// Имитация telemt --init: минимальный конфиг с секретом из аргументов.
			get := func(flag string) string {
				for i, a := range args {
					if a == flag {
						return args[i+1]
					}
				}
				return ""
			}
			cfg := fmt.Sprintf("[server]\nport = %s\n\n[censorship]\ntls_domain = %q\n\n[access.users]\n%s = %q\n",
				get("--port"), get("--domain"), get("--user"), get("--secret"))
			os.MkdirAll(filepath.Dir(s.env.Config), 0o755)
			os.WriteFile(s.env.Config, []byte(cfg), 0o640)
		case name == "systemctl" && len(args) > 0 && args[0] == "enable":
			s.freeNow = false // порт занят самим telemt
		}
	}
	err := s.env.Install(context.Background(), InstallParams{Port: 902, Domain: "www.example.com", Secret: testSecret, MaxConnections: 100, BufDivisor: 8})
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.configText()
	for _, w := range []string{
		`max_connections = 100`, `log_level = "silent"`, `direct_relay_copy_buf_c2s_bytes = 8192`,
		`direct_relay_copy_buf_s2c_bytes = 32768`, `[server.api]` + "\nenabled = false", `unknown_sni_action = "mask"`,
	} {
		if !strings.Contains(cfg, w) {
			t.Errorf("в конфиге нет %q:\n%s", w, cfg)
		}
	}
	if s.binContent() != "3.5.16" {
		t.Fatal("бинарник не установлен")
	}
	if s.count("systemctl enable --now telemt") != 1 {
		t.Fatalf("вызовы: %v", s.calls)
	}
}

func TestInstallRefusals(t *testing.T) {
	s := newStand(t, "", "3.5.16")
	s.freeNow = false
	if err := s.env.Install(context.Background(), InstallParams{Port: 902, Domain: "www.example.com"}); err == nil || !strings.Contains(err.Error(), "занят") {
		t.Fatalf("занятый порт: %v", err)
	}
	s.freeNow = true
	bad := []InstallParams{
		{Port: 70000, Domain: "a.example"},
		{Port: 902, Domain: "bad domain"},
		{Port: 902, Domain: "a.example", Secret: "abc"},
		{Port: 902, Domain: "a.example", User: "x y"},
	}
	for _, p := range bad {
		if err := s.env.Install(context.Background(), p); err == nil {
			t.Errorf("ждали отказ для %+v", p)
		}
	}
	if s.count("systemctl") != 0 || s.binContent() != "" {
		t.Fatal("отказ не должен ничего менять")
	}
	s2 := newStand(t, "3.5.7", "3.5.16")
	if err := s2.env.Install(context.Background(), InstallParams{Port: 902, Domain: "a.example"}); err == nil {
		t.Fatal("повторная установка должна отклоняться")
	}
}

func TestStatusMasksSecrets(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	st := s.env.Status(context.Background())
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), testSecret) || strings.Contains(string(raw), "445566778899aabb") {
		t.Fatalf("секрет в статусе: %s", raw)
	}
	if !st.Installed || st.Version != "3.5.7" || st.Port != 902 || st.Domain != "www.example.com" || len(st.Users) != 1 || st.ActiveState != "active" {
		t.Fatalf("%+v", st)
	}
	st2 := newStand(t, "", "x").env.Status(context.Background())
	if st2.Installed {
		t.Fatal("пустой узел не установлен")
	}
}

func TestUserLink(t *testing.T) {
	s := newStand(t, "3.5.7", "3.5.16")
	s.journal = goodJournal()
	li, err := s.env.UserLink(context.Background(), "user", "")
	if err != nil {
		t.Fatal(err)
	}
	// Совпадает со строкой из журнала telemt.
	if li.Link != "tg://proxy?server=192.0.2.94&port=902&secret="+testKey {
		t.Fatal(li.Link)
	}
	if _, err := s.env.UserLink(context.Background(), "нет", "1.1.1.1"); err == nil {
		t.Fatal("ждали ошибку для неизвестного пользователя")
	}
	s.journal = ""
	if _, err := s.env.UserLink(context.Background(), "user", ""); err == nil {
		t.Fatal("без адреса и без журнала ссылку собрать нельзя")
	}
}

func TestWatcher(t *testing.T) {
	var w Watcher
	now := time.Unix(100, 0)
	if w.Observe(0, now) != nil || w.Observe(0, now) != nil {
		t.Fatal("роста нет")
	}
	g := w.Observe(2, now.Add(time.Minute))
	if g == nil || !g.Equal(now.Add(time.Minute)) {
		t.Fatal("рост не замечен")
	}
	if g2 := w.Observe(2, now.Add(2*time.Minute)); g2 == nil || !g2.Equal(*g) {
		t.Fatal("момент роста должен сохраняться")
	}
}

func TestReleaseTestdata(t *testing.T) {
	data, err := os.ReadFile("testdata/release-latest.json")
	if err != nil {
		t.Fatal(err)
	}
	var rel Release
	if err := json.Unmarshal(data, &rel); err != nil {
		t.Fatal(err)
	}
	name := AssetName("x86_64", "gnu")
	a, ok := rel.asset(name)
	if !ok || !strings.HasPrefix(a.Digest, "sha256:") || rel.Version() == "" {
		t.Fatalf("релиз не разобран: %+v", rel.Tag)
	}
	if _, ok := rel.asset(name + ".sha256"); !ok {
		t.Fatal("нет файла .sha256")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"3.5.7", "3.5.16", -1}, {"3.5.16", "3.5.7", 1}, {"v3.5.7", "3.5.7", 0}, {"telemt 3.10.0", "3.9.9", 1}}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d", c.a, c.b, got)
		}
	}
}
