package update

import "crypto/ed25519"

// ReleasePublicKey - открытый ключ ed25519 релизов, вшитый в бинарник.
// Пока пуст: заменяется при создании ключа релиза (azpanel-sign keygen).
// С пустым или неверной длины ключом Verify всегда отказывает.
var ReleasePublicKey = ed25519.PublicKey(nil)
