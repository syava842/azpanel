package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/update"
)

func TestKeygenSign(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "r.key")
	var out bytes.Buffer
	if err := run([]string{"keygen", key}, &out); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(out.String()))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("открытый ключ: %v", err)
	}
	if err := run([]string{"keygen", key}, &out); err == nil {
		t.Fatal("ключ затёрт повторным keygen")
	}
	f := filepath.Join(dir, "SHA256SUMS")
	msg := []byte("abc  file\n")
	os.WriteFile(f, msg, 0o644)
	if err := run([]string{"sign", key, f}, &out); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(f + ".sig")
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("подпись не сходится с открытым ключом")
	}
}

func TestUsageAndBadKey(t *testing.T) {
	var out bytes.Buffer
	if run(nil, &out) == nil {
		t.Fatal("пустые аргументы приняты")
	}
	bad := filepath.Join(t.TempDir(), "b.key")
	os.WriteFile(bad, []byte("zz"), 0o600)
	if run([]string{"sign", bad, bad}, &out) == nil {
		t.Fatal("битый ключ принят")
	}
}

// I6: pub вычисляет открытый ключ из закрытого - ровно тот, что напечатал keygen.
func TestPubMatchesKeygen(t *testing.T) {
	key := filepath.Join(t.TempDir(), "r.key")
	var gen, got bytes.Buffer
	if err := run([]string{"keygen", key}, &gen); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"pub", key}, &got); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(gen.String()) != strings.TrimSpace(got.String()) {
		t.Fatalf("keygen %q, pub %q", gen.String(), got.String())
	}
	bad := filepath.Join(t.TempDir(), "b.key")
	os.WriteFile(bad, []byte("zz"), 0o600)
	if run([]string{"pub", bad}, &got) == nil {
		t.Fatal("битый ключ принят")
	}
	if run([]string{"pub"}, &got) == nil {
		t.Fatal("pub без аргумента принят")
	}
}

// Пока в pubkey.go заглушка, embedded отказывает: release.sh на этом остановится.
func TestEmbeddedRefusesPlaceholder(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"embedded"}, &out)
	if len(update.ReleasePublicKey) == 0 && err == nil {
		t.Fatal("заглушка выдана за ключ")
	}
	if len(update.ReleasePublicKey) != 0 && (err != nil || strings.TrimSpace(out.String()) != hex.EncodeToString(update.ReleasePublicKey)) {
		t.Fatalf("%v %q", err, out.String())
	}
}
