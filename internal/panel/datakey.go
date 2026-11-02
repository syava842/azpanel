package panel

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
)

// recoverDataKey доводит до конца смену PANEL_DATA_KEY, прерванную сбоем.
// Смена кладёт прежний ключ в secrets.env как PANEL_DATA_KEY_PREV и убирает его
// только после фиксации перешифровки в базе. Значит, PREV при старте — след
// незавершённой смены: секреты 2FA, не читающиеся текущим ключом, пробуются
// прежним и перезаписываются текущим. Когда все секреты читаются текущим
// ключом, PREV убирается. Секрет, не читающийся ни тем, ни другим, остаётся
// как есть, а PREV сохраняется.
func recoverDataKey(ctx context.Context, st *store.Store, file string, sec map[string]string, key []byte, log *slog.Logger) error {
	prevHex := sec[SecretDataKeyPrev]
	if prevHex == "" || st == nil {
		return nil
	}
	prev, err := hex.DecodeString(prevHex)
	if err != nil || len(prev) != 32 {
		log.Warn("прежний ключ данных испорчен, смена ключа не доводится до конца", "ключ", SecretDataKeyPrev)
		return nil
	}
	unreadable := 0
	moved, err := st.ReencryptTOTP(ctx, func(sealed []byte) ([]byte, bool, error) {
		if _, err := Open(key, sealed); err == nil {
			return nil, false, nil // уже текущим ключом
		}
		plain, err := Open(prev, sealed)
		if err != nil {
			unreadable++
			return nil, false, nil
		}
		next, err := Seal(key, plain)
		if err != nil {
			return nil, false, fmt.Errorf("перешифровка секрета 2FA: %w", err)
		}
		return next, true, nil
	}, nil)
	if err != nil {
		return fmt.Errorf("доведение смены %s: %w", SecretDataKey, err)
	}
	if moved > 0 {
		log.Info("доведена прерванная смена ключа данных: секреты 2FA перешифрованы", "секретов", moved)
	}
	if unreadable > 0 {
		log.Warn("секреты 2FA не читаются ни текущим, ни прежним ключом; прежний ключ оставлен", "секретов", unreadable, "ключ", SecretDataKeyPrev)
		return nil
	}
	if err := secrets.Delete(file, SecretDataKeyPrev); err != nil {
		// Не мешает работе: секреты уже читаются текущим ключом, уберётся при следующем старте.
		log.Warn("прежний ключ данных не убран из secrets.env", "ключ", SecretDataKeyPrev, "err", err)
	}
	return nil
}
