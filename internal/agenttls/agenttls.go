// Package agenttls — TLS агентов (узла и прокси): самоподписанный сертификат
// в etc/tls, белый список IP до рукопожатия и клиентская сторона с
// закреплённым отпечатком SHA-256. Общий код агента узла и агента прокси.
package agenttls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/fsutil"
)

// Имена файлов в каталоге сертификата агента.
const (
	CertFile = "node.crt"
	KeyFile  = "node.key"
)

// ErrFingerprint — сертификат агента не тот, что закреплён при добавлении узла.
var ErrFingerprint = errors.New("сертификат узла сменился")

// Fingerprint — SHA-256 DER-сертификата, строчные hex без разделителей.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// NormalizeFingerprint приводит отпечаток к виду Fingerprint: допускает
// двоеточия, пробелы и верхний регистр (так его печатают openssl и браузеры).
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("отпечаток — 64 шестнадцатеричных символа (SHA-256)")
	}
	return s, nil
}

// FormatFingerprint — отпечаток для показа человеку: пары через двоеточие.
func FormatFingerprint(fp string) string {
	var b strings.Builder
	for i := 0; i+1 < len(fp); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(fp[i : i+2]))
	}
	return b.String()
}

// LoadOrCreate читает сертификат агента из dir (node.crt, node.key) или, если
// обоих файлов нет, создаёт самоподписанный на 10 лет. Есть только один из
// двух — ошибка: молча пересоздать значило бы сменить отпечаток, закреплённый
// панелью. Возвращает сертификат и его отпечаток.
func LoadOrCreate(dir string) (tls.Certificate, string, error) {
	crtPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	_, crtErr := os.Stat(crtPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case crtErr == nil && keyErr == nil:
	case os.IsNotExist(crtErr) && os.IsNotExist(keyErr):
		if err := create(dir, crtPath, keyPath); err != nil {
			return tls.Certificate{}, "", err
		}
	default:
		return tls.Certificate{}, "", fmt.Errorf("в %s есть только один из файлов %s и %s — удалите оставшийся, отпечаток изменится", dir, CertFile, KeyFile)
	}
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("сертификат агента не прочитан: %w", err)
	}
	return cert, Fingerprint(cert.Certificate[0]), nil
}

// FingerprintFile — отпечаток сертификата из файла (для мастера установки).
func FingerprintFile(crtPath string) (string, error) {
	data, err := os.ReadFile(crtPath)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", errors.New(crtPath + ": нет PEM-сертификата")
	}
	return Fingerprint(blk.Bytes), nil
}

func create(dir, crtPath, keyPath string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "azpanel-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if host != "" {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// Сначала ключ: пока нет сертификата, LoadOrCreate видит «одного файла нет».
	if err := fsutil.WriteFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Listen открывает TLS-порт агента: сначала белый список IP (чужой адрес
// закрывается до рукопожатия), затем TLS 1.3 с сертификатом из certDir.
// Белый список пуст — не пускается никто. rejected (может быть nil) вызывается
// с адресом отклонённого соединения. Возвращает отпечаток сертификата.
func Listen(addr, certDir string, allow []netip.Prefix, rejected func(remote string)) (net.Listener, string, error) {
	cert, fp, err := LoadOrCreate(certDir)
	if err != nil {
		return nil, "", err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	return tls.NewListener(NewAllowListener(ln, allow, rejected), cfg), fp, nil
}

type allowListener struct {
	net.Listener
	allow    []netip.Prefix
	rejected func(string)

	// now — часы для ограничения частоты записей в журнал; nil — time.Now.
	now func() time.Time
	mu  sync.Mutex
	// lastLog — когда в последний раз сообщали об отказе этому адресу.
	lastLog map[string]time.Time
}

// rejectLogEvery — не чаще раза за это время сообщать об отказах одному
// адресу: сканер, стучащийся в порт тысячу раз в минуту, иначе вытеснит из
// журнала всё полезное.
const rejectLogEvery = time.Minute

// maxRejectTracked — сколько адресов помнить для ограничения; больше —
// память забывается целиком (журнал после этого один раз повторится).
const maxRejectTracked = 4096

// NewAllowListener оборачивает ln: соединения с адресов вне списка закрываются
// в Accept, не доходя до вызывающего. Пустой список — не пускается никто.
func NewAllowListener(ln net.Listener, allow []netip.Prefix, rejected func(remote string)) net.Listener {
	return &allowListener{Listener: ln, allow: allow, rejected: rejected}
}

func (l *allowListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allowed(c.RemoteAddr()) {
			return c, nil
		}
		if l.rejected != nil && l.shouldReport(c.RemoteAddr()) {
			l.rejected(c.RemoteAddr().String())
		}
		c.Close()
	}
}

// shouldReport — стоит ли сообщить об отказе этому адресу (раз в rejectLogEvery).
func (l *allowListener) shouldReport(a net.Addr) bool {
	key := a.String()
	if tcp, ok := a.(*net.TCPAddr); ok {
		key = tcp.IP.String() // порт у каждого соединения свой
	}
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := now()
	if last, ok := l.lastLog[key]; ok && t.Sub(last) < rejectLogEvery {
		return false
	}
	if l.lastLog == nil || len(l.lastLog) >= maxRejectTracked {
		l.lastLog = map[string]time.Time{}
	}
	l.lastLog[key] = t
	return true
}

func (l *allowListener) allowed(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, p := range l.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// PinnedConfig — клиентская TLS-настройка с закреплённым отпечатком. Цепочку
// доверия не проверяет (сертификат самоподписанный): единственное условие —
// SHA-256 листа равен fp. Иначе рукопожатие обрывается ошибкой ErrFingerprint.
func PinnedConfig(fp string) (*tls.Config, error) {
	fp, err := NormalizeFingerprint(fp)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // проверка ниже: закрепление отпечатка вместо цепочки
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("%w: узел не прислал сертификат", ErrFingerprint)
			}
			if got := Fingerprint(cs.PeerCertificates[0].Raw); got != fp {
				return fmt.Errorf("%w: закреплён %s, пришёл %s", ErrFingerprint, FormatFingerprint(fp), FormatFingerprint(got))
			}
			return nil
		},
	}, nil
}

// Probe подключается к addr (хост:порт) и возвращает отпечаток сертификата, не
// проверяя его: для первого знакомства, когда оператор сверяет отпечаток с тем,
// что напечатал узел при установке. Токен не передаётся.
func Probe(ctx context.Context, addr string) (string, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}, // знакомство: отпечаток сверяет человек
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("узел не прислал сертификат")
	}
	return Fingerprint(certs[0].Raw), nil
}
