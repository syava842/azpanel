package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// scripts/setup.sh проверяет подпись релиза своим вшитым ключом: он обязан
// совпадать с ключом бинарника, иначе установка одной командой отказывает
// на каждом релизе (или, хуже, принимает чужой).
func TestSetupScriptKeyMatches(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte("-----BEGIN PUBLIC KEY-----"))
	if i < 0 {
		t.Fatal("в setup.sh нет PEM ключа")
	}
	const end = "-----END PUBLIC KEY-----"
	j := bytes.Index(data[i:], []byte(end))
	if j < 0 {
		t.Fatal("в setup.sh нет конца PEM")
	}
	// В скрипте за концом PEM сразу кавычка: pem.Decode ждёт перевод строки.
	blk, _ := pem.Decode(append(append([]byte{}, data[i:i+j+len(end)]...), '\n'))
	if blk == nil {
		t.Fatal("PEM в setup.sh не разбирается")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("ключ в setup.sh не ed25519: %T", k)
	}
	if !pub.Equal(ReleasePublicKey) {
		t.Fatal("ключ в scripts/setup.sh не совпадает с internal/update/pubkey.go")
	}
}
