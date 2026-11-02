package panel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/syava842/azpanel/internal/fsutil"
	"github.com/syava842/azpanel/internal/secrets"
)

// applySecrets записывает ключи в secrets.env. Сменился NODE_TOKEN — сначала
// агент получает команду перезапуститься (по старому токену, перезапуск
// отложен), потому что иначе агент поднимется со старым токеном. Сменился
// PANEL_DATA_KEY — секреты 2FA перешифровываются. Панель после этого
// перезапускает вызывающий. Вызывается под settings.mu.
func (s *Server) applySecrets(ctx context.Context, kv map[string]string) error {
	for k, v := range kv {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s: пустое значение", k)
		}
	}
	cur, err := secrets.Load(s.secretsPath())
	if err != nil {
		return err
	}
	if v, ok := kv[SecretDataKey]; ok && v != cur[SecretDataKey] {
		if b, err := hex.DecodeString(v); err != nil || len(b) != 32 {
			return fmt.Errorf("%s: нужно 64 шестнадцатеричных знака", SecretDataKey)
		}
	}
	if v, ok := kv[secrets.NodeToken]; ok && v != cur[secrets.NodeToken] && s.RestartNode != nil {
		if err := s.RestartNode(ctx); err != nil {
			return fmt.Errorf("агент не перезапущен, токен не менялся: %w", err)
		}
	}
	if v, ok := kv[SecretDataKey]; ok && v != cur[SecretDataKey] {
		return s.rotateDataKey(ctx, cur, kv)
	}
	return secrets.SetMany(s.secretsPath(), kv)
}

// rotateDataKey меняет PANEL_DATA_KEY так, чтобы сбой в любой точке не терял
// секреты 2FA. Порядок: новый secrets.env целиком во временный файл
// secrets.env.new; одна транзакция перешифровывает все секреты и перед
// фиксацией атомарно заменяет secrets.env; только потом новый ключ — в памяти.
// Сбой до фиксации откатывает базу, а файл остаётся прежним; сбой самой
// фиксации после замены файла возвращает прежний файл.
func (s *Server) rotateDataKey(ctx context.Context, cur, kv map[string]string) error {
	if s.Store == nil {
		return errors.New("база панели недоступна: 2FA нельзя перешифровать")
	}
	newKey, _ := hex.DecodeString(kv[SecretDataKey])
	oldKey := s.DataKey
	next := make(map[string]string, len(cur)+len(kv))
	for k, v := range cur {
		next[k] = v
	}
	for k, v := range kv {
		next[k] = v
	}
	file := s.secretsPath()
	tmp := file + ".new"
	if err := fsutil.WriteFileAtomic(tmp, secrets.Marshal(next), 0o600); err != nil {
		return fmt.Errorf("новый secrets.env не записан, ключ не менялся: %w", err)
	}
	defer os.Remove(tmp) // после замены файла его уже нет
	rename := s.settings.rename
	if rename == nil {
		rename = os.Rename
	}
	swapped := false
	_, err := s.Store.ReencryptTOTP(ctx, func(sealed []byte) ([]byte, bool, error) {
		if len(oldKey) != 32 {
			return nil, false, nil // 2FA без ключа недоступна: перешифровывать нечего
		}
		plain, err := Open(oldKey, sealed)
		if err != nil {
			s.Log.Warn("секрет 2FA не расшифровался, пропущен")
			return nil, false, nil
		}
		out, err := Seal(newKey, plain)
		if err != nil {
			return nil, false, fmt.Errorf("перешифровка секрета 2FA: %w", err)
		}
		return out, true, nil
	}, func() error {
		if err := rename(tmp, file); err != nil {
			return fmt.Errorf("замена secrets.env: %w", err)
		}
		swapped = true
		return nil
	})
	if err != nil {
		if swapped {
			if rerr := fsutil.WriteFileAtomic(file, secrets.Marshal(cur), 0o600); rerr != nil {
				return fmt.Errorf("%w; прежний secrets.env не возвращён: %v", err, rerr)
			}
		}
		return err
	}
	s.DataKey = newKey
	return nil
}

// settingsSecrets — действия над секретами: replace, delete, regen.
func (s *Server) settingsSecrets(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	s.settings.mu.Lock()
	defer s.settings.mu.Unlock()
	cfg, err := s.loadConfig()
	if err != nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "настройки недоступны: "+err.Error())
		return
	}
	key, action := r.PostForm.Get("key"), r.PostForm.Get("action")
	var sv *secretView
	for i := range knownSecrets {
		if knownSecrets[i].Key == key {
			sv = &knownSecrets[i]
		}
	}
	fail := func(status int, text string) {
		s.renderSettings(w, r, status, cfg, map[string]any{"Error": text})
	}
	if sv == nil {
		fail(http.StatusBadRequest, "этот ключ здесь не меняется")
		return
	}
	switch {
	case action == "replace" && sv.Replace:
		v := r.PostForm.Get("value")
		if v == "" || strings.ContainsAny(v, " \t\r\n") {
			fail(http.StatusBadRequest, "Значение не может быть пустым или содержать пробелы.")
			return
		}
		if err := secrets.Set(s.secretsPath(), key, v); err != nil {
			fail(http.StatusInternalServerError, "Не записано: "+err.Error())
			return
		}
		s.audit(r, "secret_set", key, "", "заменён, значение скрыто")
	case action == "delete" && sv.Delete:
		if err := secrets.Delete(s.secretsPath(), key); err != nil {
			fail(http.StatusInternalServerError, "Не удалено: "+err.Error())
			return
		}
		s.audit(r, "secret_delete", key, "", "")
	case action == "regen" && sv.Regen:
		if r.PostForm.Get("confirm") != "1" {
			fail(http.StatusBadRequest, "Отметьте подтверждение: "+sv.WarnRegen)
			return
		}
		v, err := secrets.NewToken()
		if err != nil {
			fail(http.StatusInternalServerError, "Не создан: "+err.Error())
			return
		}
		if err := s.applySecrets(r.Context(), map[string]string{key: v}); err != nil {
			fail(http.StatusBadGateway, "Не заменён: "+err.Error())
			return
		}
		s.audit(r, "secret_regen", key, "", "создан заново, значение скрыто")
	default:
		fail(http.StatusBadRequest, "это действие для ключа недоступно")
		return
	}
	s.exitSoon()
	s.renderRestart(w, r, cfg, false, nil)
}
