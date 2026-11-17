package warp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Без явного выбора домены Gemini и ChatGPT не добавляются, хотя у
// установщика Enter — «да».
func TestDialogNoDomainListsByDefault(t *testing.T) {
	a := InstallAnswers{Mode: "warp"}
	_, got, err := runScript(t, a.NewDialog(nil), []step{
		{out: "Добавить Gemini в список доменов для WARP? (Y/n): "},
		{out: "Добавить ChatGPT в список доменов для WARP? (Y/n): "},
	})
	if err != nil || strings.Join(got, "|") != "n|n" {
		t.Fatalf("err=%v ответы %q", err, got)
	}
}

// Источник ключей выбирается по напечатанному меню, а не по номеру: номера
// зависят от того, какие ключи нашлись на сервере.
func TestDialogWarpSourceByMenu(t *testing.T) {
	menu := "Выбор источника WARP-ключей:\r\n" +
		" " + cG + "1." + cN + " /etc/wireguard/warp.conf (172.16.0.2/32) — ключи AntiZapret, рекомендуется\r\n" +
		" 2. /root/warper/wgcf/wgcf-profile.conf (172.16.0.3/32)\r\n" +
		" 3. Сгенерировать новый ключ WARP\r\n\r\nВыбор [по умолчанию 1]: "
	for src, want := range map[string]string{"": "1", "system": "1", "wgcf": "2", "generate": "3"} {
		a := InstallAnswers{Mode: "warp", WarpSource: src}
		_, got, err := runScript(t, a.NewDialog(nil), []step{{out: menu}})
		if err != nil || len(got) != 1 || got[0] != want {
			t.Errorf("%q: err=%v ответы %q, ждали %s", src, err, got, want)
		}
	}
	// Источника нет в меню — остановка, а не первый пункт.
	a := InstallAnswers{Mode: "warp", WarpSource: "root"}
	_, got, err := runScript(t, a.NewDialog(nil), []step{{out: menu}})
	if err == nil || got[0] != "<нет ответа>" {
		t.Fatalf("err=%v got=%q", err, got)
	}
}

func TestDialogWGConfByPath(t *testing.T) {
	menu := "Найдено конфигов: 2\r\n " + cG + "1." + cN + " /root/a.conf (198.51.100.5:51820)\r\n" +
		" 2. /root/warper/b.conf (198.51.100.6:51820)\r\n\r\n M. Ввести данные вручную\r\n R. Обновить список\r\nВыбор: "
	a := InstallAnswers{Mode: "wg", WGConf: "/root/warper/b.conf"}
	_, got, err := runScript(t, a.NewDialog(nil), []step{{out: menu}})
	if err != nil || got[0] != "2" {
		t.Fatalf("err=%v got=%q", err, got)
	}
	a.WGConf = "/root/c.conf"
	if _, got, err = runScript(t, a.NewDialog(nil), []step{{out: menu}}); err == nil || got[0] != "<нет ответа>" {
		t.Fatalf("чужой конфиг: err=%v got=%q", err, got)
	}
	if _, got, err = runScript(t, a.NewDialog(nil), []step{
		{out: "WireGuard-конфиги не найдены.\r\n 1. Ввести данные вручную\r\n 0. Выбрать другой режим\r\nВыбор: "},
	}); err == nil || got[0] != "<нет ответа>" {
		t.Fatalf("конфигов нет: err=%v got=%q", err, got)
	}
}

func TestWebDialogPortsHTTPSDomain(t *testing.T) {
	a := WebAnswers{User: "boss", Password: "Pa55word!", Port: 7443, BackendPort: 17000, HTTPS: true, Domain: "panel.example.com"}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	_, got, err := runScript(t, a.NewDialog(nil), []step{
		{out: "Внешний порт веб-панели [6060]: "},
		{out: "Внутренний порт (gunicorn) [16060]: "},
		{out: "Логин администратора [admin]: "},
		{out: "Пароль: "},
		{out: "Подтвердите пароль: "},
		{out: "Включить HTTPS? (y/N): "},
		{out: "Доменное имя (для Let's Encrypt) или Enter для самоподписанного: "},
		{out: "Варианты:\r\n  1. Временно остановить OpenVPN\r\nВыбор [1/2/3, по умолчанию 1]: "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "7443|17000|boss|Pa55word!|Pa55word!|y|panel.example.com|"; strings.Join(got, "|") != want {
		t.Fatalf("ответы %q, ждали %q", strings.Join(got, "|"), want)
	}
}

// Режим публикации: пусто — Enter (умолчание установщика зависит от порта 80).
func TestWebDialogPublishMode(t *testing.T) {
	menu := "Режим публикации панели:\r\n  1) через nginx (reverse-proxy)\r\n  2) напрямую, без nginx\r\nВыбор [1]: "
	for publish, want := range map[string]string{"": "", "nginx": "1", "direct": "2"} {
		a := WebAnswers{User: "boss", Password: "Pa55word!", Publish: publish}
		_, got, err := runScript(t, a.NewDialog(nil), []step{{out: menu}})
		if err != nil || len(got) != 1 || got[0] != want {
			t.Errorf("%q: err=%v ответы %q", publish, err, got)
		}
	}
	if (&WebAnswers{User: "boss", Password: "Pa55word!", Publish: "apache"}).Validate() == nil {
		t.Fatal("неизвестный режим публикации принят")
	}
}

// Без nginx gunicorn слушает внешний порт: туда и пересылать; TLS — по юниту.
func TestWebStandaloneBackend(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "version"), "1.5.8\n")
	writeFile(t, filepath.Join(dir, "web", ".env"), "PORT=16060\nWEB_MODE=standalone\nEXTERNAL_PORT=6060\n")
	unit := filepath.Join(dir, "warper-web.service")
	writeFile(t, unit, "ExecStart=/x/gunicorn --bind 0.0.0.0:6060 --certfile /etc/warper-web/ssl/warper-web.crt app:app\n")
	old := webUnitPath
	webUnitPath = unit
	t.Cleanup(func() { webUnitPath = old })
	status := "installed=true\nactive=active\nmode=standalone\nexternal_port=6060\n"
	w := &Warper{Dir: dir, Run: func(_ context.Context, _ string, _ ...string) ([]byte, error) { return []byte(status), nil }}
	st, err := w.Web(context.Background())
	if err != nil || st.Mode != "standalone" || st.BackendPort != 6060 || !st.TLS {
		t.Fatalf("%+v %v", st, err)
	}
	status = "installed=true\nactive=active\nmode=nginx\nexternal_port=6060\n"
	if st, _ = w.Web(context.Background()); st.BackendPort != 16060 || st.TLS {
		t.Fatalf("через nginx: %+v", st)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Варианты установки находятся по тем же правилам, что в install.sh.
func TestInstallOptions(t *testing.T) {
	root := t.TempDir()
	at := func(p string) string { return filepath.Join(root, filepath.FromSlash(p)) }
	writeFile(t, at("/proc/net/route"), "Iface\tDestination\tGateway\neth0\t00000000\t0197B75E\n")
	writeFile(t, at("/sys/class/net/eth0/mtu"), "1450\n")
	writeFile(t, at("/root/warper/domains.txt"), "# --- CHATGPT ---\nchatgpt.com\n")
	// Системный конфиг WARP AntiZapret и wgcf из прошлой установки.
	writeFile(t, at("/etc/wireguard/warp.conf"), "[Interface]\nPrivateKey = SYSKEY=\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = "+cfWarpPubKey+"\n")
	writeFile(t, at("/root/warper/wgcf/wgcf-profile.conf"), "[Interface]\nPrivateKey = WGCFKEY=\nAddress = 172.16.0.3/32\n[Peer]\nPublicKey = "+cfWarpPubKey+"\n")
	// WireGuard: годный, конфиг самого WARP (не предлагается) и без Endpoint.
	writeFile(t, at("/root/home.conf"), "[Interface]\nPrivateKey = K=\n[Peer]\nPublicKey = P=\nEndpoint = 198.51.100.5:51820\n")
	writeFile(t, at("/root/warp-copy.conf"), "[Peer]\nPublicKey = "+cfWarpPubKey+"\nEndpoint = engage.cloudflareclient.com:2408\n")
	writeFile(t, at("/root/warper/warper.conf"), "SUBNET=10.224.0.0/16\n")
	// OpenVPN: с логином, без него и файл без remote.
	writeFile(t, at("/root/warper/b.ovpn"), "client\nremote vpn.example.org 1194\n")
	writeFile(t, at("/root/a.ovpn"), "client\n  remote 203.0.113.1 443\nauth-user-pass\n")
	writeFile(t, at("/root/empty.ovpn"), "client\n")

	o := (&Warper{}).Options(root)
	if o.PhysMTU != 1450 || o.RecMTU != 1370 {
		t.Fatalf("MTU %d/%d", o.PhysMTU, o.RecMTU)
	}
	if o.GeminiListed || !o.ChatGPTListed {
		t.Fatalf("списки: gemini %v chatgpt %v", o.GeminiListed, o.ChatGPTListed)
	}
	var ids []string
	for _, s := range o.WarpSources {
		ids = append(ids, s.ID)
	}
	if strings.Join(ids, ",") != "system,wgcf,generate" || !strings.Contains(o.WarpSources[0].Label, "172.16.0.2/32") ||
		strings.Contains(o.WarpSources[0].Label+o.WarpSources[1].Label, "KEY=") {
		t.Fatalf("источники ключей: %+v", o.WarpSources)
	}
	if len(o.WGConfs) != 1 || o.WGConfs[0] != (WGConfFound{"/root/home.conf", "198.51.100.5:51820"}) {
		t.Fatalf("WireGuard: %+v", o.WGConfs)
	}
	if len(o.OvpnFiles) != 2 || o.OvpnFiles[0] != (OvpnFound{"/root/a.ovpn", true}) || o.OvpnFiles[1] != (OvpnFound{"/root/warper/b.ovpn", false}) {
		t.Fatalf("OpenVPN: %+v", o.OvpnFiles)
	}
	// Пустой сервер: только «сгенерировать», MTU 1500 − 80.
	o = (&Warper{}).Options(t.TempDir())
	if len(o.WarpSources) != 1 || o.WarpSources[0].ID != "generate" || o.RecMTU != 1420 {
		t.Fatalf("пустой сервер: %+v", o)
	}
}
