package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestDecodePublicKey(t *testing.T) {
	if decodePublicKey("") != nil {
		t.Fatal("пустая строка должна давать nil (заглушка)")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if got := decodePublicKey(hex.EncodeToString(pub)); !got.Equal(pub) {
		t.Fatal("ключ декодирован неверно")
	}
	for _, bad := range []string{"zz", "abcd"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%q принят", bad)
				}
			}()
			decodePublicKey(bad)
		}()
	}
}
