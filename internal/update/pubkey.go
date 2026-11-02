package update

import (
	"crypto/ed25519"
	"encoding/hex"
)

// releasePublicKeyHex - открытый ключ ed25519 релизов, hex (64 символа): его
// печатает `azpanel-sign keygen` и `azpanel-sign pub <ключ>`. Пока пуст:
// заменяется при создании ключа релиза. scripts/release.sh сверяет его с
// закрытым ключом и отказывается публиковать релиз с пустым или чужим.
const releasePublicKeyHex = ""

// ReleasePublicKey - открытый ключ релизов, вшитый в бинарник. С пустым или
// неверной длины ключом Verify всегда отказывает.
var ReleasePublicKey = decodePublicKey(releasePublicKeyHex)

func decodePublicKey(s string) ed25519.PublicKey {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		// Опечатка в вшитом ключе - ошибка сборки, а не повод молча отказывать
		// в каждом обновлении.
		panic("update: releasePublicKeyHex - не ключ ed25519 в hex")
	}
	return ed25519.PublicKey(b)
}
