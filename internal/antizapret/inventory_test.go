package antizapret

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert пишет сертификат так, как его кладёт EasyRSA: текстовая
// расшифровка, затем PEM.
func writeCert(t *testing.T, path, cn string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := "Certificate:\n    Data:\n        Subject: CN=" + cn + "\n" +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const wgConf = `[Interface]
PrivateKey = SERVERPRIVATE
Address = 10.29.8.1/24

# Client = alice
# PrivateKey = ALICEPRIVATE
[Peer]
PublicKey = ALICEPUB
PresharedKey = ALICEPSK
AllowedIPs = 10.29.8.2/32

# Client = bob
# PrivateKey = BOBPRIVATE
[Peer]
PublicKey = BOBPUB
PresharedKey = BOBPSK
AllowedIPs = 10.29.8.3/32
`

func newInventory(t *testing.T) Inventory {
	t.Helper()
	root := t.TempDir()
	inv := Inventory{PKI: filepath.Join(root, "pki"), WireGuardDir: filepath.Join(root, "wireguard")}
	issued := filepath.Join(inv.PKI, "issued")
	os.MkdirAll(issued, 0o755)
	os.MkdirAll(inv.WireGuardDir, 0o755)
	exp := time.Date(2030, 5, 30, 11, 54, 53, 0, time.UTC)
	writeCert(t, filepath.Join(issued, "alice.crt"), "alice", exp)
	writeCert(t, filepath.Join(issued, "antizapret-server.crt"), "antizapret-server", exp)
	os.WriteFile(filepath.Join(issued, "carol.crt"), []byte("не сертификат"), 0o644)
	os.WriteFile(filepath.Join(issued, "readme.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(inv.WireGuardDir, "antizapret.conf"), []byte(wgConf), 0o600)
	os.WriteFile(filepath.Join(inv.WireGuardDir, "vpn.conf"), []byte(strings.ReplaceAll(wgConf, "bob", "dave")), 0o600)
	return inv
}

func TestInventoryClients(t *testing.T) {
	got, err := newInventory(t).Clients()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "alice,bob,carol,dave" {
		t.Fatalf("имена %v", names)
	}
	alice, bob, carol := got[0], got[1], got[2]
	if !alice.OpenVPN || !alice.WireGuard || !alice.CertExpires.Equal(time.Date(2030, 5, 30, 11, 54, 53, 0, time.UTC)) {
		t.Fatalf("alice %+v", alice)
	}
	if !carol.OpenVPN || carol.WireGuard || !carol.CertExpires.IsZero() {
		t.Fatalf("carol (сертификат не читается) %+v", carol)
	}
	if bob.OpenVPN || !bob.WireGuard {
		t.Fatalf("bob %+v", bob)
	}
}

func TestInventoryEmptyDirs(t *testing.T) {
	root := t.TempDir()
	got, err := Inventory{PKI: filepath.Join(root, "нет"), WireGuardDir: filepath.Join(root, "нет")}.Clients()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, err %v", got, err)
	}
}

func TestWireGuardPeers(t *testing.T) {
	m, err := newInventory(t).WireGuardPeers()
	if err != nil {
		t.Fatal(err)
	}
	if m["antizapret"]["ALICEPUB"] != "alice" || m["antizapret"]["BOBPUB"] != "bob" || m["vpn"]["BOBPUB"] != "dave" {
		t.Fatalf("m = %v", m)
	}
	if len(m["antizapret"]) != 2 {
		t.Fatalf("лишние ключи: %v", m["antizapret"])
	}
}
