//go:build release

package update

import (
	"crypto/ed25519"
	"testing"
)

// TestReleaseKeySet запускает scripts/release.sh перед публикацией: релиз с
// ключом-заглушкой невозможно обновить ни на одном хосте.
func TestReleaseKeySet(t *testing.T) {
	if len(ReleasePublicKey) != ed25519.PublicKeySize {
		t.Fatal("в internal/update/pubkey.go не задан открытый ключ релиза (releasePublicKeyHex)")
	}
}
