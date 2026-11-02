package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

func fixture(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte, []byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("архив")
	h := sha256.Sum256(data)
	sums := []byte(fmt.Sprintf("%x  azpanel_1.0.0_linux_amd64.tar.gz\n%x  other\n", h, h))
	return pub, priv, data, sums, ed25519.Sign(priv, sums)
}

const name = "azpanel_1.0.0_linux_amd64.tar.gz"

func TestVerifyOK(t *testing.T) {
	pub, _, data, sums, sig := fixture(t)
	if err := Verify(pub, sums, sig, name, data); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyForeignKey(t *testing.T) {
	_, _, data, sums, sig := fixture(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(other, sums, sig, name, data) == nil {
		t.Fatal("подпись чужим ключом принята")
	}
}

func TestVerifyTamperedArchive(t *testing.T) {
	pub, _, data, sums, sig := fixture(t)
	if Verify(pub, sums, sig, name, append(data, 'x')) == nil {
		t.Fatal("подменённый архив принят")
	}
}

func TestVerifyTamperedSums(t *testing.T) {
	pub, _, data, sums, sig := fixture(t)
	sums[0] ^= 1
	if Verify(pub, sums, sig, name, data) == nil {
		t.Fatal("изменённый SHA256SUMS принят")
	}
}

func TestVerifyMissingLine(t *testing.T) {
	pub, _, data, sums, sig := fixture(t)
	if Verify(pub, sums, sig, "azpanel_1.0.0_linux_arm64.tar.gz", data) == nil {
		t.Fatal("файл без строки в SHA256SUMS принят")
	}
}

func TestVerifyEmptyOrStubKey(t *testing.T) {
	_, _, data, sums, sig := fixture(t)
	for _, k := range []ed25519.PublicKey{nil, {}, make(ed25519.PublicKey, 5)} {
		if Verify(k, sums, sig, name, data) == nil {
			t.Fatalf("ключ длины %d принят", len(k))
		}
	}
	if Verify(ReleasePublicKey, sums, sig, name, data) == nil {
		t.Fatal("заглушечный ключ релиза принят")
	}
}
