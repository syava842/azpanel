package install

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func testServers(t *testing.T) []NginxServer {
	t.Helper()
	s, err := FindServers(testNginxDir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestTLS(n *Nginx, f *fakeSys) *TLS {
	return &TLS{
		Nginx:     n,
		WriteFile: func(p string, d []byte, _ os.FileMode) error { f.files[p] = d; return nil },
		MkdirAll:  func(string, os.FileMode) error { return nil },
		Stat: func(p string) (fs.FileInfo, error) {
			if _, ok := f.files[p]; ok {
				return nil, nil
			}
			return nil, fs.ErrNotExist
		},
		Run: n.Run,
		Now: n.Now,
	}
}

func TestSelfSignedParses(t *testing.T) {
	n, f := newFakeNginx(nil)
	tl := newTestTLS(n, f)
	cert, key, err := tl.SelfSigned([]string{"panel.example", "192.0.2.7"}, "/etc/azpanel/tls")
	if err != nil {
		t.Fatal(err)
	}
	if cert != "/etc/azpanel/tls/azpanel.crt" || key != "/etc/azpanel/tls/azpanel.key" {
		t.Fatal(cert, key)
	}
	blk, _ := pem.Decode(f.files[cert])
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.DNSNames[0] != "panel.example" || c.IPAddresses[0].String() != "192.0.2.7" {
		t.Fatalf("SAN: %v %v", c.DNSNames, c.IPAddresses)
	}
	if days := c.NotAfter.Sub(n.Now()).Hours() / 24; days < 824 || days > 826 {
		t.Fatalf("срок %v дней", days)
	}
	if c.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatal("ожидался ECDSA")
	}
	if kb, _ := pem.Decode(f.files[key]); kb == nil || kb.Type != "EC PRIVATE KEY" {
		t.Fatal("ключ не разобрался")
	}
	if _, _, err := tl.SelfSigned(nil, "/x"); err == nil {
		t.Fatal("пустые имена должны давать ошибку")
	}
}

func TestPlanACME(t *testing.T) {
	servers := testServers(t)
	// На 94 первым по алфавиту читается vpn.test с return: блок warper-web
	// с тем же server_name nginx отбрасывает, проверка получила бы редирект (I3).
	if p, err := PlanACME(servers, "vpn.test", "nginx"); err == nil || !strings.Contains(err.Error(), "return") {
		t.Fatalf("первый блок домена с return должен давать отказ: %+v %v", p, err)
	}
	// Первым стоит блок с location проверки (порядок обратный): берём его root.
	var swapped []NginxServer
	for _, s := range servers {
		if strings.HasSuffix(s.File, "warper-web") {
			swapped = append([]NginxServer{s}, swapped...)
		} else {
			swapped = append(swapped, s)
		}
	}
	p, err := PlanACME(swapped, "vpn.test", "nginx")
	if err != nil || p.Mode != ACMEExisting || p.Webroot != "/var/www/html" {
		t.Fatalf("%+v %v", p, err)
	}
	// Чужой домен: универсальный default без return.
	p, err = PlanACME(servers, "other.example", "nginx")
	if err != nil || p.Mode != ACMETemp || p.Webroot != AcmeWebroot || !strings.HasSuffix(p.Server.File, "default") {
		t.Fatalf("%+v %v", p, err)
	}
	// 80 свободен.
	p, err = PlanACME(nil, "x.example", "")
	if err != nil || p.Mode != ACMEStandalone {
		t.Fatalf("%+v %v", p, err)
	}
	// 80 занят не nginx.
	_, err = PlanACME(servers, "x.example", "openvpn")
	if err == nil || !strings.Contains(err.Error(), "OPENVPN_BACKUP_TCP") {
		t.Fatal(err)
	}
	// Только редиректы на 80.
	var onlyRedirect []NginxServer
	for _, s := range servers {
		if s.Redirects && s.ListensOn(80) {
			onlyRedirect = append(onlyRedirect, s)
		}
	}
	if _, err = PlanACME(onlyRedirect, "vpn.test", "nginx"); err == nil {
		t.Fatal("блок только с return должен давать отказ")
	}
}

func TestCertbotArgs(t *testing.T) {
	got := strings.Join(CertbotArgs(ACMEPlan{Mode: ACMETemp, Webroot: AcmeWebroot}, "a.example", "m@x.ru"), " ")
	want := "certonly --webroot -w /var/www/azpanel-acme -d a.example --non-interactive --agree-tos -m m@x.ru --deploy-hook systemctl reload nginx"
	if got != want {
		t.Fatal(got)
	}
	got = strings.Join(CertbotArgs(ACMEPlan{Mode: ACMEStandalone}, "a.example", "m@x.ru"), " ")
	if got != "certonly --standalone -d a.example --non-interactive --agree-tos -m m@x.ru --deploy-hook systemctl reload nginx" {
		t.Fatal(got)
	}
}

func TestIssueTempKeepsLocationForRenewal(t *testing.T) {
	_, orig := copyTestdata(t, "default")
	const file = "/etc/nginx/sites-enabled/default"
	n, f := newFakeNginx(map[string]string{file: orig})
	tl := newTestTLS(n, f)
	srv := parseServers(file, orig)[0].NginxServer
	var during string
	run := n.Run
	n.Run = func(name string, args ...string) ([]byte, error) {
		if name == "certbot" {
			during = string(f.files[file])
			f.files[LetsEncryptDir+"/a.example/fullchain.pem"] = []byte("c")
			f.files[LetsEncryptDir+"/a.example/privkey.pem"] = []byte("k")
		}
		return run(name, args...)
	}
	tl.Run = n.Run
	plan := ACMEPlan{Mode: ACMETemp, Webroot: AcmeWebroot, Server: srv}
	cert, key, err := tl.IssueLetsEncrypt(plan, "a.example", "m@x.ru")
	if err != nil {
		t.Fatal(err)
	}
	if cert != LetsEncryptDir+"/a.example/fullchain.pem" || key != LetsEncryptDir+"/a.example/privkey.pem" {
		t.Fatal(cert, key)
	}
	if !strings.Contains(during, "azpanel-acme.conf; # azpanel") {
		t.Fatal("во время certbot location проверки не подключён")
	}
	if !strings.Contains(string(f.files[file]), "azpanel-acme.conf; # azpanel") {
		t.Fatal("после выпуска location проверки убран: продление не пройдёт")
	}
	if !strings.Contains(string(f.files[AcmeSnippetPath]), "acme-challenge") {
		t.Fatal("фрагмент проверки удалён")
	}
	if len(f.stray) != 0 || len(f.strayFiles()) != 0 {
		t.Fatalf("посторонние файлы в каталогах nginx: %v", f.stray)
	}
	// uninstall убирает и его.
	if err := n.Disable(file); err != nil {
		t.Fatal(err)
	}
	if string(f.files[file]) != orig {
		t.Fatal("Disable не убрал include проверки")
	}
	if _, ok := f.files[AcmeSnippetPath]; ok {
		t.Fatal("фрагмент проверки остался после Disable")
	}
}

func TestIssueCertbotFailureStillCleans(t *testing.T) {
	_, orig := copyTestdata(t, "default")
	const file = "/etc/nginx/sites-enabled/default"
	n, f := newFakeNginx(map[string]string{file: orig})
	tl := newTestTLS(n, f)
	run := n.Run
	n.Run = func(name string, args ...string) ([]byte, error) {
		if name == "certbot" {
			return []byte("Challenge failed"), errors.New("exit 1")
		}
		return run(name, args...)
	}
	tl.Run = n.Run
	plan := ACMEPlan{Mode: ACMETemp, Webroot: AcmeWebroot, Server: parseServers(file, orig)[0].NginxServer}
	_, _, err := tl.IssueLetsEncrypt(plan, "a.example", "m@x.ru")
	if err == nil || !strings.Contains(err.Error(), "Challenge failed") {
		t.Fatal(err)
	}
	if string(f.files[file]) != orig {
		t.Fatal("временная строка не убрана после ошибки certbot")
	}
}

func TestExistingLetsEncrypt(t *testing.T) {
	n, f := newFakeNginx(nil)
	tl := newTestTLS(n, f)
	f.files[LetsEncryptDir+"/vpn.test/fullchain.pem"] = []byte("c")
	f.files[LetsEncryptDir+"/vpn.test/privkey.pem"] = []byte("k")
	if _, _, ok := tl.ExistingLetsEncrypt("vpn.test"); !ok {
		t.Fatal("сертификат должен найтись")
	}
	if _, _, ok := tl.ExistingLetsEncrypt("../etc"); ok {
		t.Fatal("путь с .. недопустим")
	}
	if _, _, ok := tl.ExistingLetsEncrypt("nope.example"); ok {
		t.Fatal("чужого домена нет")
	}
}
