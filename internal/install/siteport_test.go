package install

import (
	"path/filepath"
	"strings"
	"testing"
)

// По пути — только разделом существующего сайта: подходящие сайты с портом,
// по которому раздел откроется; по порту из них ничего не берётся.
func TestSiteCandidatesAndPort(t *testing.T) {
	status := NginxServer{File: "statusopenvpn", Listen: []string{"1234 ssl http2"}, ServerName: []string{"peshkovvv.ru"}}
	main := NginxServer{File: "default", Listen: []string{"80", "443 ssl"}, ServerName: []string{"peshkovvv.ru"}}
	other := NginxServer{File: "other", Listen: []string{"443 ssl"}, ServerName: []string{"other.example"}}
	a := Answers{Access: AccessPath, HTTPS: true, Domain: "peshkovvv.ru", Address: "203.0.113.7"}

	c := siteCandidates([]NginxServer{status, main, other}, a)
	if len(c) != 2 || c[0].File != "statusopenvpn" || c[1].File != "default" {
		t.Fatalf("кандидаты: %+v", c)
	}
	if s, ok := siteFor([]NginxServer{status, main}, a); !ok || s.File != "default" {
		t.Fatalf("умолчание — сайт на 443: %q %v", s.File, ok)
	}
	if got := siteURL(status, a); got != "https://peshkovvv.ru:1234/azpanel/" {
		t.Fatalf("адрес раздела: %s", got)
	}
	a.NginxFile = "statusopenvpn"
	if s, ok := siteFor([]NginxServer{status, main}, a); !ok || s.File != "statusopenvpn" {
		t.Fatalf("заданный сайт: %q %v", s.File, ok)
	}
	// Без HTTPS — порт без ssl.
	a.HTTPS, a.NginxFile = false, ""
	if s, ok := siteFor([]NginxServer{status, main}, a); !ok || sitePort(s, false) != 80 {
		t.Fatalf("без HTTPS: %q %v", s.File, ok)
	}
	if _, ok := siteFor([]NginxServer{status}, a); ok {
		t.Fatal("без HTTPS взят сайт только с ssl")
	}
}

// По пути без подходящего сайта — отказ до изменений, а не свой сайт с
// разделом: способы не смешиваются.
func TestWizardPathWithoutSiteRefused(t *testing.T) {
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_ACCESS": "path", "AZPANEL_DOMAIN": "nosite.example", "AZPANEL_ADMIN": "boss"})
	e.useRealNginx()
	err := e.w.Run()
	if err == nil || !strings.Contains(err.Error(), "откройте azpanel по порту") || len(e.mut) != 0 {
		t.Fatalf("ошибка %v, изменения %v", err, e.mut)
	}
}

// По порту — свой сайт на 5000 без раздела /azpanel/; прежняя строка include
// в сайте другого сервиса убирается.
func TestWizardPortDropsPreviousInclude(t *testing.T) {
	prev := filepath.Join(testNginxDir, "sites-enabled", "warper-web")
	e := newWizEnv(t, "", false, map[string]string{"AZPANEL_ADMIN": "boss"})
	e.files["install.env"] = "MODE=panel+node\nACCESS=port\nHTTPS=y\nNGINX_FILE=" + prev + "\nADMIN=boss\n"
	e.useRealNginx()
	if err := e.w.Run(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !strings.Contains(e.out.String(), "убирается из прежнего сайта "+prev) {
		t.Fatalf("нет строки об уборке:\n%s", e.out)
	}
	if e.written.Panel.PublicURL != "https://203.0.113.7:5000" || e.written.Panel.BasePath != "" {
		t.Fatalf("адрес: %+v", e.written.Panel)
	}
	block := string(e.fs.files[testNginxDir+"/sites-available/azpanel"])
	if !strings.Contains(block, "listen 5000 ssl;") || strings.Contains(block, "/azpanel/") {
		t.Fatalf("свой сайт:\n%s", block)
	}
}
