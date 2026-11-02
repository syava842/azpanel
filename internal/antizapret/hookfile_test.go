package antizapret

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stock — custom-client-connect.sh из поставки AntiZapret (19 байт).
const stock = "#!/bin/bash\n\nexit 0"

const bin = "/opt/azpanel/bin/azpanel"

func mustInsert(t *testing.T, content, block string) string {
	t.Helper()
	s, err := Insert(content, block)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInsertIntoStock(t *testing.T) {
	got := mustInsert(t, stock, ConnectBlock(bin))
	want := "#!/bin/bash\n# azpanel begin\n/opt/azpanel/bin/azpanel hook connect || { [ $? -ne 3 ] || exit 1; }\n# azpanel end\n\nexit 0"
	if got != want {
		t.Fatalf("получено:\n%s", got)
	}
}

func TestInsertIsIdempotentAndReplacesOld(t *testing.T) {
	once := mustInsert(t, stock, ConnectBlock(bin))
	if twice := mustInsert(t, once, ConnectBlock(bin)); twice != once {
		t.Fatalf("повторная вставка изменила файл:\n%s", twice)
	}
	moved := mustInsert(t, once, ConnectBlock("/new/azpanel"))
	if strings.Contains(moved, bin) || strings.Count(moved, "# azpanel begin") != 1 {
		t.Fatalf("старый блок не заменён:\n%s", moved)
	}
}

func TestStripRestoresOriginal(t *testing.T) {
	for _, orig := range []string{"#!/bin/bash\necho своё\nexit 0\n", stock} {
		got, err := Strip(mustInsert(t, orig, ConnectBlock(bin)))
		if err != nil || got != orig {
			t.Fatalf("получено %q, err=%v; ждали %q", got, err, orig)
		}
	}
}

// Ручная правка стёрла «# azpanel end»: хвост файла не должен пропасть.
func TestUnterminatedBlockIsRefused(t *testing.T) {
	broken := "#!/bin/bash\n# azpanel begin\n/x hook connect\necho своё\nexit 0\n"
	if _, err := Strip(broken); err == nil {
		t.Fatal("Strip: ждали ошибку")
	}
	if _, err := Insert(broken, ConnectBlock(bin)); err == nil {
		t.Fatal("Insert: ждали ошибку")
	}
}

func TestInsertWithoutShebangAndEmpty(t *testing.T) {
	if got := mustInsert(t, "echo x\n", DisconnectBlock(bin)); !strings.HasPrefix(got, "# azpanel begin\n") {
		t.Fatalf("без shebang:\n%s", got)
	}
	if got := mustInsert(t, "", DisconnectBlock(bin)); !strings.HasPrefix(got, "#!/bin/bash\n# azpanel begin\n") || !strings.HasSuffix(got, "exit 0\n") {
		t.Fatalf("пустой:\n%s", got)
	}
}

// Строку хука исполняет настоящий bash, в том числе с set -e: отказ — только
// код 3, любой другой код скрипт не обрывает.
func TestConnectBlockSemanticsInBash(t *testing.T) {
	bash := workingBash(t)
	for _, mode := range []string{"", "-e"} {
		for code, wantRC := range map[int]int{0: 0, 1: 0, 2: 0, 3: 1, 127: 0} {
			script := "f() { return " + strconv.Itoa(code) + "; }\n" + strings.Replace(ConnectBlock("f"), "f hook connect", "f", 1) + "exit 0\n"
			args := []string{"-c", script}
			if mode != "" {
				args = append([]string{mode}, args...)
			}
			err := exec.Command(bash, args...).Run()
			rc := 0
			if ee, ok := err.(*exec.ExitError); ok {
				rc = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if rc != wantRC {
				t.Errorf("bash %s: хук вернул %d → скрипт %d, ждали %d", mode, code, rc, wantRC)
			}
		}
	}
}

func TestHookFilesEnsureRemove(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"custom-client-connect.sh", "custom-client-disconnect.sh"} {
		os.WriteFile(filepath.Join(dir, n), []byte(stock), 0o755)
	}
	h := HookFiles{ScriptsDir: dir, Binary: bin}
	if ok, _ := h.Installed(); ok {
		t.Fatal("до установки Installed = true")
	}
	changed, err := h.Ensure()
	if err != nil || !changed {
		t.Fatalf("Ensure: changed=%v err=%v", changed, err)
	}
	if changed, _ := h.Ensure(); changed {
		t.Fatal("второй Ensure что-то изменил")
	}
	if ok, _ := h.Installed(); !ok {
		t.Fatal("после установки Installed = false")
	}
	bak, err := os.ReadFile(filepath.Join(dir, "custom-client-connect.sh.bak-azpanel"))
	if err != nil || string(bak) != stock {
		t.Fatalf("копия: %q err=%v", bak, err)
	}
	if err := h.Remove(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"custom-client-connect.sh", "custom-client-disconnect.sh"} {
		b, _ := os.ReadFile(filepath.Join(dir, n))
		if string(b) != stock {
			t.Fatalf("%s после Remove:\n%q", n, b)
		}
	}
}

func TestHookFilesRefuseBrokenAndSymlink(t *testing.T) {
	dir := t.TempDir()
	broken := "#!/bin/bash\n# azpanel begin\necho своё\n"
	os.WriteFile(filepath.Join(dir, "custom-client-connect.sh"), []byte(broken), 0o755)
	os.WriteFile(filepath.Join(dir, "custom-client-disconnect.sh"), []byte(stock), 0o755)
	h := HookFiles{ScriptsDir: dir, Binary: bin}
	if _, err := h.Ensure(); err == nil {
		t.Fatal("Ensure: ждали отказ на блоке без конца")
	}
	if err := h.Remove(); err == nil {
		t.Fatal("Remove: ждали отказ на блоке без конца")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "custom-client-connect.sh")); string(b) != broken {
		t.Fatalf("испорченный файл тронут:\n%q", b)
	}

	target := filepath.Join(dir, "secret")
	os.WriteFile(target, []byte("секрет"), 0o600)
	link := filepath.Join(dir, "custom-client-connect.sh")
	os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		t.Skip("символьные ссылки недоступны:", err)
	}
	if _, err := h.Ensure(); err == nil {
		t.Fatal("Ensure: ждали отказ на символьной ссылке")
	}
	if _, err := os.Stat(link + ".bak-azpanel"); !os.IsNotExist(err) {
		t.Fatal("копия цели ссылки записана")
	}
}
