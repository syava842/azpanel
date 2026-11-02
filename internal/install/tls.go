package install

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

const (
	// LetsEncryptDir — где certbot хранит выпущенные сертификаты.
	LetsEncryptDir = "/etc/letsencrypt/live"
	// AcmeWebroot — корень временной проверки домена.
	AcmeWebroot = "/var/www/azpanel-acme"

	selfSignedDays = 825
)

// ACMEMode — как certbot докажет владение доменом.
type ACMEMode int

const (
	ACMEStandalone ACMEMode = iota // порт 80 свободен: certbot слушает сам
	ACMEExisting                   // в nginx на 80 уже есть location проверки: берём его root
	ACMETemp                       // на 80 слушает nginx: временный location во фрагменте
)

// ACMEPlan — решение PlanACME.
type ACMEPlan struct {
	Mode    ACMEMode
	Webroot string      // для ACMEExisting и ACMETemp
	Server  NginxServer // блок на 80, куда вставляется временный location (ACMETemp)
}

// PlanACME выбирает способ проверки домена. port80Owner — кто держит порт
// 80 сейчас: "" свободен, "nginx", иначе имя процесса (например openvpn
// при OPENVPN_BACKUP_TCP=y) — тогда отказ с причиной.
func PlanACME(servers []NginxServer, domain, port80Owner string) (ACMEPlan, error) {
	var on80 []NginxServer
	for _, s := range servers {
		if s.ListensOn(80) && !s.SSL() {
			on80 = append(on80, s)
		}
	}
	owner := strings.ToLower(strings.TrimSpace(port80Owner))
	if owner != "" && owner != "nginx" {
		return ACMEPlan{}, fmt.Errorf("порт 80 занят процессом %q, а не nginx: выпустить сертификат Let's Encrypt нельзя; "+
			"освободите порт (для AntiZapret это OPENVPN_BACKUP_TCP=y) или выберите самоподписанный сертификат", port80Owner)
	}
	if owner == "" && len(on80) == 0 {
		return ACMEPlan{Mode: ACMEStandalone}, nil
	}
	if len(on80) == 0 {
		return ACMEPlan{}, errors.New("nginx занимает порт 80, но в его конфигах нет server на 80: проверьте nginx -T")
	}
	// Уже есть location проверки у блока этого домена.
	for _, s := range on80 {
		if s.ACMERoot != "" && s.NamedFor(domain) {
			return ACMEPlan{Mode: ACMEExisting, Webroot: s.ACMERoot, Server: s}, nil
		}
	}
	// Блок без return: вставленный location в нём сработает. Сначала по
	// имени домена, затем универсальный.
	for _, catchAll := range []bool{false, true} {
		for _, s := range on80 {
			if s.Redirects {
				continue
			}
			if !catchAll && s.NamedFor(domain) || catchAll && (s.NamedFor("_") || len(s.ServerName) == 0) {
				return ACMEPlan{Mode: ACMETemp, Webroot: AcmeWebroot, Server: s}, nil
			}
		}
	}
	return ACMEPlan{}, fmt.Errorf("на порту 80 у домена %s только блоки с return (редирект): location проверки в них не сработает; "+
		"добавьте в такой блок location /.well-known/acme-challenge/ вручную или выберите другой способ", domain)
}

// TLS — сертификаты. Всё, что меняет систему, идёт через поля.
type TLS struct {
	Nginx     *Nginx
	WriteFile func(path string, data []byte, perm os.FileMode) error
	MkdirAll  func(path string, perm os.FileMode) error
	Stat      func(path string) (fs.FileInfo, error)
	Run       func(name string, args ...string) ([]byte, error)
	Now       func() time.Time
}

// NewTLS — рабочий вариант на реальной системе.
func NewTLS(n *Nginx) *TLS {
	return &TLS{
		Nginx:     n,
		WriteFile: writeKeepOrNew,
		MkdirAll:  os.MkdirAll,
		Stat:      os.Stat,
		Run:       runCombined,
		Now:       time.Now,
	}
}

// SelfSigned выпускает самоподписанный сертификат (ECDSA P-256, 825 дней) на
// имена и адреса hosts; пишет dir/azpanel.crt и dir/azpanel.key (0600).
func (t *TLS) SelfSigned(hosts []string, dir string) (certPath, keyPath string, err error) {
	if len(hosts) == 0 {
		return "", "", errors.New("не задано ни одного имени или адреса для сертификата")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", err
	}
	now := t.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"azpanel"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, selfSignedDays),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := t.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	certPath, keyPath = path.Join(dir, "azpanel.crt"), path.Join(dir, "azpanel.key")
	if err := t.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}
	if err := t.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// ExistingLetsEncrypt: есть ли выпущенный сертификат на домен; если да —
// пути к fullchain.pem и privkey.pem, которые стоит предложить.
func (t *TLS) ExistingLetsEncrypt(domain string) (certPath, keyPath string, ok bool) {
	if domain == "" || strings.ContainsAny(domain, "/\\") || strings.Contains(domain, "..") {
		return "", "", false
	}
	base := LetsEncryptDir + "/" + domain
	certPath, keyPath = base+"/fullchain.pem", base+"/privkey.pem"
	if _, err := t.Stat(certPath); err != nil {
		return "", "", false
	}
	if _, err := t.Stat(keyPath); err != nil {
		return "", "", false
	}
	return certPath, keyPath, true
}

// CertbotArgs — аргументы certbot для плана.
func CertbotArgs(plan ACMEPlan, domain, email string) []string {
	args := []string{"certonly"}
	if plan.Mode == ACMEStandalone {
		args = append(args, "--standalone")
	} else {
		args = append(args, "--webroot", "-w", plan.Webroot)
	}
	return append(args, "-d", domain, "--non-interactive", "--agree-tos", "-m", email)
}

// IssueLetsEncrypt выпускает сертификат. Для ACMETemp на время выпуска во
// фрагмент добавляется location проверки и сразу убирается. Возвращает пути
// к сертификату и ключу.
func (t *TLS) IssueLetsEncrypt(plan ACMEPlan, domain, email string) (certPath, keyPath string, err error) {
	if domain == "" || email == "" {
		return "", "", errors.New("для Let's Encrypt нужны домен и почта")
	}
	if plan.Mode == ACMETemp {
		if err := t.MkdirAll(plan.Webroot, 0o755); err != nil {
			return "", "", err
		}
		srv := plan.Server
		aerr := t.Nginx.Apply([]string{srv.File, AcmeSnippetPath}, func() error {
			if err := t.Nginx.MkdirAll(path.Dir(AcmeSnippetPath), 0o755); err != nil {
				return err
			}
			if err := t.Nginx.WriteFile(AcmeSnippetPath, []byte(AcmeSnippet(plan.Webroot)), 0o644); err != nil {
				return err
			}
			return t.Nginx.editInclude(srv.File, func(src string) (string, error) {
				return AddInclude(srv.File, src, srv, AcmeSnippetPath)
			})
		})
		if aerr != nil {
			return "", "", fmt.Errorf("временный location проверки домена: %w", aerr)
		}
		defer func() {
			cerr := t.Nginx.Apply([]string{srv.File, AcmeSnippetPath}, func() error {
				if err := t.Nginx.editInclude(srv.File, func(src string) (string, error) {
					return DropInclude(src, AcmeSnippetPath), nil
				}); err != nil {
					return err
				}
				if err := t.Nginx.Remove(AcmeSnippetPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				return nil
			})
			if cerr != nil {
				err = errors.Join(err, fmt.Errorf("уборка временного location: %w", cerr))
			}
		}()
	}
	out, rerr := t.Run("certbot", CertbotArgs(plan, domain, email)...)
	if rerr != nil {
		return "", "", fmt.Errorf("certbot: %w\n%s", rerr, strings.TrimSpace(string(out)))
	}
	cert, key, ok := t.ExistingLetsEncrypt(domain)
	if !ok {
		return "", "", fmt.Errorf("certbot завершился, но сертификата нет в %s/%s", LetsEncryptDir, domain)
	}
	return cert, key, nil
}
