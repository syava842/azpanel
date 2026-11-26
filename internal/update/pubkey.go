package update

import (
	"crypto/ed25519"
	"encoding/hex"
)

// releasePublicKeyHex - открытый ключ ed25519 релизов, hex (64 символа): его
// печатает `azpanel-sign keygen` и `azpanel-sign pub <ключ>`. Тот же ключ в
// PEM вшит в scripts/setup.sh (сверяет TestSetupScriptKeyMatches).
// scripts/release.sh сверяет его с закрытым ключом и отказывается
// публиковать релиз с пустым или чужим.
const releasePublicKeyHex = "87763729f5b1f98071964e59344a55d253397a2c07d0195b4a5bf0a75b3278d1"

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
