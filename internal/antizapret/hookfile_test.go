package antizapret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stock — custom-client-connect.sh из поставки AntiZapret (19 байт).
const stock = "#!/bin/bash\n\nexit 0"

const bin = "/opt/azpanel/bin/azpanel"

func TestInsertIntoStock(t *testing.T) {
	got := Insert(stock, ConnectBlock(bin))
	want := "#!/bin/bash\n# azpanel begin\n/opt/azpanel/bin/azpanel hook connect; [ $? -ne 3 ] || exit 1\n# azpanel end\n\nexit 0"
	if got != want {
		t.Fatalf("получено:\n%s", got)
	}
}

func TestInsertIsIdempotentAndReplacesOld(t *testing.T) {
	once := Insert(stock, ConnectBlock(bin))
	if twice := Insert(once, ConnectBlock(bin)); twice != once {
		t.Fatalf("повторная вставка изменила файл:\n%s", twice)
	}
	moved := Insert(once, ConnectBlock("/new/azpanel"))
	if strings.Contains(moved, bin) || strings.Count(moved, "# azpanel begin") != 1 {
		t.Fatalf("старый блок не заменён:\n%s", moved)
	}
}

func TestStripRestoresOriginal(t *testing.T) {
	custom := "#!/bin/bash\necho своё\nexit 0\n"
	if got := Strip(Insert(custom, ConnectBlock(bin))); got != custom {
		t.Fatalf("получено:\n%q", got)
	}
	if got := Strip(Insert(stock, ConnectBlock(bin))); got != stock {
		t.Fatalf("штатный файл после снятия:\n%q", got)
	}
}

func TestInsertWithoutShebangAndEmpty(t *testing.T) {
	if got := Insert("echo x\n", DisconnectBlock(bin)); !strings.HasPrefix(got, "# azpanel begin\n") {
		t.Fatalf("без shebang:\n%s", got)
	}
	if got := Insert("", DisconnectBlock(bin)); !strings.HasPrefix(got, "#!/bin/bash\n# azpanel begin\n") || !strings.HasSuffix(got, "exit 0\n") {
		t.Fatalf("пустой:\n%s", got)
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
