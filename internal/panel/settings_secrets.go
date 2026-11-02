package panel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/syava842/azpanel/internal/secrets"
)

// reencryptTOTP перешифровывает секреты 2FA всех пользователей с ключа old
// на new. Возвращает функцию отката; секрет, который не расшифровался
// (повреждён ещё до замены), пропускается и остаётся как был.
func (s *Server) reencryptTOTP(ctx context.Context, oldKey, newKey []byte) (undo func(), err error) {
	if len(oldKey) != 32 {
		return func() {}, nil // 2FA без ключа недоступна: перешифровывать нечего
	}
	users, err := s.Store.Users(ctx)
	if err != nil {
		return nil, err
	}
	type saved struct {
		id   int64
		raw  []byte
		step int64
	}
	var done []saved
	undo = func() {
		for _, x := range done {
			if err := s.Store.SetTOTP(context.Background(), x.id, x.raw, x.step); err != nil {
				s.Log.Error("откат перешифровки 2FA не удался", "user_id", x.id, "err", err)
			}
		}
	}
	for _, u := range users {
		if len(u.TOTPSecret) == 0 {
			continue
		}
		plain, err := Open(oldKey, u.TOTPSecret)
		if err != nil {
			s.Log.Warn("секрет 2FA не расшифровался, пропущен", "user_id", u.ID)
			continue
		}
		sealed, err := Seal(newKey, plain)
		if err == nil {
			err = s.Store.SetTOTP(ctx, u.ID, sealed, u.TOTPLastStep)
		}
		if err != nil {
			undo()
			return nil, fmt.Errorf("перешифровка секрета 2FA: %w", err)
		}
		done = append(done, saved{u.ID, u.TOTPSecret, u.TOTPLastStep})
	}
	return undo, nil
}

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
	undo := func() {}
	if v, ok := kv[SecretDataKey]; ok && v != cur[SecretDataKey] {
		if s.Store == nil {
			return errors.New("база панели недоступна: 2FA нельзя перешифровать")
		}
		newKey, _ := hex.DecodeString(v)
		if undo, err = s.reencryptTOTP(ctx, s.DataKey, newKey); err != nil {
			return err
		}
	}
	if err := secrets.SetMany(s.secretsPath(), kv); err != nil {
		undo()
		return err
	}
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
