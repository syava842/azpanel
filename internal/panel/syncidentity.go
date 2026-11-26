package panel

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"path"
	"strings"
)

// «Личность» сервера — файлы, которые у основного и реплики группы обязаны
// совпадать заранее (реплика ставится с бэкапа основного или выравнивается
// «Выровнять»): CA, DH, серверные сертификат и ключ OpenVPN, ключ
// WireGuard/AmneziaWG. Расходятся они — значит, реплика — другой сервер со
// своими клиентами, и автоматическое копирование молча заменило бы ей CA и
// ключи: все её клиенты отвалились бы. Такую реплику автоматика не трогает.
// index.txt, serial, crl.pem, клиентские сертификаты и пиры WireGuard в
// личность не входят: они расходятся законно (новые клиенты).

// identityPath — файл личности по пути из манифеста. Шаблоны — как у
// criticalSyncFile агента (internal/node/syncapply.go) без index.txt,
// serial и crl.pem, плюс pki/reqs/*server*.
func identityPath(p string) bool {
	if strings.Contains(p, "/client/") {
		return false
	}
	if i := strings.LastIndex(p, "/pki/"); i >= 0 {
		rel := p[i+1:]
		switch rel {
		case "pki/ca.crt", "pki/private/ca.key", "pki/dh.pem":
			return true
		}
		return serverCertPath(p)
	}
	return path.Base(p) == "key" // ключ WireGuard/AmneziaWG
}

// serverCertPath — серверные сертификат, ключ и запрос OpenVPN
// (pki/issued|private|reqs/*server*, у AntiZapret — antizapret-server).
func serverCertPath(p string) bool {
	i := strings.LastIndex(p, "/pki/")
	if i < 0 || strings.Contains(p, "/client/") {
		return false
	}
	rel := p[i+1:]
	for _, dir := range []string{"pki/issued/", "pki/private/", "pki/reqs/"} {
		if strings.HasPrefix(rel, dir) && strings.Contains(path.Base(rel), "server") {
			return true
		}
	}
	return false
}

// wgConfPath — antizapret.conf или vpn.conf WireGuard/AmneziaWG: в них ключ
// интерфейса (личность) и пиры (не личность).
func wgConfPath(p string) bool {
	if strings.Contains(p, "/client/") || strings.Contains(p, "/pki/") {
		return false
	}
	b := path.Base(p)
	return b == "antizapret.conf" || b == "vpn.conf"
}

// identityDiffs — файлы личности, которые у основного и реплики разные (по
// расхождениям diffs). У конфигов WireGuard сравнивается только PrivateKey
// секции [Interface]: оба файла читаются у агентов, ключи не выходят за
// пределы функции и в журнал не пишутся — наружу только пути.
func identityDiffs(ctx context.Context, primary, replica SyncNode, diffs []fileDiff) ([]string, error) {
	var out []string
	for _, d := range diffs {
		switch {
		case identityPath(d.Path) && d.Kind == "missing" && serverCertPath(d.Path):
			// Файл есть только у основного: это новый клиент с «server» в
			// имени, а не другой сертификат сервера — тот виден как лишний
			// (extra) у реплики или как отличие.
		case identityPath(d.Path):
			out = append(out, d.Path)
		case wgConfPath(d.Path) && d.Kind != "differs":
			out = append(out, d.Path) // конфиг интерфейса есть только с одной стороны
		case wgConfPath(d.Path):
			pk, err := interfaceKeyOf(ctx, primary, d.Path)
			if err != nil {
				return nil, fmt.Errorf("основной, %s: %w", d.Path, err)
			}
			rk, err := interfaceKeyOf(ctx, replica, d.Path)
			if err != nil {
				return nil, fmt.Errorf("реплика, %s: %w", d.Path, err)
			}
			if subtle.ConstantTimeCompare(pk[:], rk[:]) != 1 {
				out = append(out, d.Path)
			}
		}
	}
	return out, nil
}

// maxWGConf — предел чтения конфига WireGuard при сверке ключа.
const maxWGConf = 4 << 20

// interfaceKeyOf — отпечаток PrivateKey секции [Interface] файла p на узле.
func interfaceKeyOf(ctx context.Context, n SyncNode, p string) ([sha256.Size]byte, error) {
	rc, err := n.SyncFile(ctx, p)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer rc.Close()
	return interfaceKey(io.LimitReader(rc, maxWGConf))
}

// interfaceKey — отпечаток значения PrivateKey в [Interface]; ключа нет —
// отпечаток пустой строки (у обеих сторон без ключа они совпадут).
func interfaceKey(r io.Reader) ([sha256.Size]byte, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxWGConf)
	inIface := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inIface = strings.EqualFold(line, "[Interface]")
			continue
		}
		if !inIface {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "PrivateKey") {
			return sha256.Sum256([]byte(strings.TrimSpace(v))), nil
		}
	}
	if err := sc.Err(); err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(nil), nil
}
