package install

import (
	"path/filepath"
	"strings"
	"testing"
)

// Сайт другого сервиса на нестандартном порту (StatusOpenVPN на 1234 с тем же
// доменом) не берётся ни для раздела, ни в умолчание порта: azpanel заводит
// свой сайт на порту из вопроса 1.
func TestSiteForOnlyOnAzpanelPort(t *testing.T) {
	status := NginxServer{File: "statusopenvpn", Listen: []string{"1234 ssl http2"}, ServerName: []string{"peshkovvv.ru"}}
	main := NginxServer{File: "default", Listen: []string{"443 ssl"}, ServerName: []string{"peshkovvv.ru"}}
	a := Answers{Access: AccessPath, HTTPS: true, Domain: "peshkovvv.ru", Port: 8443}

	if p := defaultPort([]NginxServer{status}, a); p != DefaultPort {
		t.Fatalf("умолчание порта при сайте на 1234: %d", p)
	}
	if _, ok := siteFor([]NginxServer{status}, a); ok {
		t.Fatal("раздел встал в сайт на чужом порту")
	}
	if p := defaultPort([]NginxServer{status, main}, a); p != 443 {
		t.Fatalf("умолчание порта при сайте на 443: %d", p)
	}
	a.Port = 443
	if s, ok := siteFor([]NginxServer{status, main}, a); !ok || s.File != "default" {
		t.Fatalf("на 443 выбран %q, %v", s.File, ok)
	}
	// Порт явно 1234 — встраивание в этот сайт по желанию человека.
	a.Port = 1234
	if s, ok := siteFor([]NginxServer{status, main}, a); !ok || s.File != "statusopenvpn" {
		t.Fatalf("на 1234 выбран %q, %v", s.File, ok)
	}
	// HTTP-сайт на 443 для HTTPS не годится, и наоборот.
	a.Port, a.HTTPS = 443, false
	if _, ok := siteFor([]NginxServer{main}, a); ok {
		t.Fatal("для HTTP взят сайт с ssl")
	}
	// Режим по порту в умолчание чужой порт не берёт.
	a.Access, a.HTTPS = AccessPort, true
	if p := defaultPort([]NginxServer{main}, a); p != DefaultPort {
		t.Fatalf("по порту умолчание %d", p)
	}
}

// Переустановка там, где прошлая вписала раздел в сайт другого сервиса на
// другом порту (как StatusOpenVPN на :1234): свой сайт на порту azpanel, а
// строка include из прежнего сайта убирается.
func TestWizardDropsIncludeFromPreviousSite(t *testing.T) {
	prev := filepath.Join(testNginxDir, "sites-enabled", "warper-web")
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_ACCESS": "path", "AZPANEL_ADMIN": "boss"})
	e.files["install.env"] = "MODE=panel+node\nACCESS=path\nPORT=8443\nHTTPS=y\nNGINX_FILE=" + prev + "\nADMIN=boss\n"
	e.useRealNginx()
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !strings.Contains(e.out.String(), "убирается из прежнего сайта "+prev) {
		t.Fatalf("нет строки об уборке:\n%s", e.out)
	}
	if e.written.Panel.PublicURL != "https://203.0.113.7:8443" {
		t.Fatalf("адрес: %s", e.written.Panel.PublicURL)
	}
	if !strings.Contains(string(e.fs.files[testNginxDir+"/sites-available/azpanel"]), "listen 8443 ssl;") {
		t.Fatal("свой сайт не на 8443")
	}
}
