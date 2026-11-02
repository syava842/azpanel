package panel

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
	"github.com/syava842/azpanel/internal/store"
)

var (
	oldDataKey = bytes.Repeat([]byte{0x11}, 32)
	newDataKey = bytes.Repeat([]byte{0x22}, 32)
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// crashedRotation готовит состояние «процесс умер между заменой secrets.env и
// COMMIT»: в secrets.env уже новый ключ и PREV, а в базе секреты 2FA ещё
// запечатаны старым ключом.
func crashedRotation(t *testing.T, secret []byte) (st *store.Store, file string, userID int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sealed, err := Seal(oldDataKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(context.Background(), store.User{Login: "admin", Hash: "x", Role: store.RoleAdmin, TOTPSecret: sealed, TOTPLastStep: 7})
	if err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(t.TempDir(), "secrets.env")
	if err := secrets.SetMany(file, map[string]string{
		secrets.NodeToken: "tok", SecretDataKey: hex.EncodeToString(newDataKey), SecretDataKeyPrev: hex.EncodeToString(oldDataKey),
	}); err != nil {
		t.Fatal(err)
	}
	return st, file, u.ID
}

func TestRecoverDataKeyFinishesInterruptedRotation(t *testing.T) {
	secret := []byte("12345678901234567890")
	st, file, id := crashedRotation(t, secret)
	sec, _ := secrets.Load(file)
	if err := recoverDataKey(context.Background(), st, file, sec, newDataKey, discardLog()); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByID(context.Background(), id)
	got, err := Open(newDataKey, u.TOTPSecret)
	if err != nil || !bytes.Equal(got, secret) || u.TOTPLastStep != 7 {
		t.Fatalf("секрет 2FA не перешифрован новым ключом: %v", err)
	}
	after, _ := secrets.Load(file)
	if _, has := after[SecretDataKeyPrev]; has {
		t.Fatal("PANEL_DATA_KEY_PREV остался после перешифровки")
	}
	if after[SecretDataKey] != hex.EncodeToString(newDataKey) || after[secrets.NodeToken] != "tok" {
		t.Fatalf("secrets.env испорчен: %v", after)
	}
}

// Коммит прошёл, но PREV не успели убрать: секреты уже читаются текущим
// ключом, остаётся убрать PREV.
func TestRecoverDataKeyOnlyDropsStalePrev(t *testing.T) {
	secret := []byte("12345678901234567890")
	st, file, id := crashedRotation(t, secret)
	sealed, _ := Seal(newDataKey, secret)
	if err := st.SetTOTP(context.Background(), id, sealed, 7); err != nil {
		t.Fatal(err)
	}
	sec, _ := secrets.Load(file)
	if err := recoverDataKey(context.Background(), st, file, sec, newDataKey, discardLog()); err != nil {
		t.Fatal(err)
	}
	after, _ := secrets.Load(file)
	if _, has := after[SecretDataKeyPrev]; has {
		t.Fatal("PREV не убран")
	}
	u, _ := st.UserByID(context.Background(), id)
	if got, err := Open(newDataKey, u.TOTPSecret); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("секрет затронут: %v", err)
	}
}

// Без PREV ничего не делается; секрет, который не читается ни тем, ни другим
// ключом, не уничтожается и PREV не теряется.
func TestRecoverDataKeyNoPrevAndUnreadable(t *testing.T) {
	st, file, id := crashedRotation(t, []byte("12345678901234567890"))
	sec, _ := secrets.Load(file)
	delete(sec, SecretDataKeyPrev)
	if err := recoverDataKey(context.Background(), st, file, sec, newDataKey, discardLog()); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByID(context.Background(), id)
	if _, err := Open(oldDataKey, u.TOTPSecret); err != nil {
		t.Fatalf("без PREV секрет изменён: %v", err)
	}
	// третий ключ: секрет не читается ни текущим, ни PREV
	other := bytes.Repeat([]byte{0x33}, 32)
	junk, _ := Seal(other, []byte("zzz"))
	if err := st.SetTOTP(context.Background(), id, junk, 1); err != nil {
		t.Fatal(err)
	}
	sec, _ = secrets.Load(file)
	if err := recoverDataKey(context.Background(), st, file, sec, newDataKey, discardLog()); err != nil {
		t.Fatal(err)
	}
	u, _ = st.UserByID(context.Background(), id)
	if !bytes.Equal(u.TOTPSecret, junk) {
		t.Fatal("нечитаемый секрет перезаписан")
	}
	if after, _ := secrets.Load(file); after[SecretDataKeyPrev] == "" {
		t.Fatal("PREV удалён, хотя не всё перешифровано")
	}
}

// Битый PREV старт не роняет.
func TestRecoverDataKeyBadPrevIgnored(t *testing.T) {
	st, file, _ := crashedRotation(t, []byte("12345678901234567890"))
	sec, _ := secrets.Load(file)
	sec[SecretDataKeyPrev] = "не-hex"
	if err := recoverDataKey(context.Background(), st, file, sec, newDataKey, discardLog()); err != nil {
		t.Fatalf("битый PREV уронил старт: %v", err)
	}
}

// Смена ключа из настроек: в заменяющем файле рядом с новым ключом лежит
// прежний как PREV (замена файла и COMMIT не одно действие), а после успеха
// PREV убран.
func TestRotateDataKeyKeepsPrevUntilCommit(t *testing.T) {
	e := newSetEnv(t)
	secret := []byte("12345678901234567890")
	sealed, _ := Seal(e.srv.DataKey, secret)
	if err := e.st.SetTOTP(context.Background(), e.admin.ID, sealed, 5); err != nil {
		t.Fatal(err)
	}
	oldHex := strings.Repeat("ab", 32)
	var inSwap map[string]string
	e.srv.settings.rename = func(tmp, file string) error {
		m, err := secrets.Load(tmp)
		if err != nil {
			t.Error(err)
		}
		inSwap = m
		return os.Rename(tmp, file)
	}
	rec := e.post(t, "/settings/secrets", "10.0.0.1", url.Values{"key": {SecretDataKey}, "action": {"regen"}, "confirm": {"1"}})
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	if inSwap[SecretDataKeyPrev] != oldHex || inSwap[SecretDataKey] == oldHex || inSwap[SecretDataKey] == "" {
		t.Fatalf("в заменяющем файле нет прежнего ключа как PREV: %v", inSwap)
	}
	after, _ := secrets.Load(e.secFile)
	if _, has := after[SecretDataKeyPrev]; has {
		t.Fatal("PREV остался после успешной смены")
	}
	if after[SecretDataKey] != inSwap[SecretDataKey] {
		t.Fatal("ключ в файле не тот, что вставлен при замене")
	}
}

// Сквозной случай: панель стартует с secrets.env «после замены» и базой «до
// COMMIT», 2FA снова читается, PREV убран.
func TestRunRecoversInterruptedRotation(t *testing.T) {
	runEnv(t)
	secret := []byte("12345678901234567890")
	if err := os.MkdirAll(paths.Data(), 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(paths.Data(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := Seal(oldDataKey, secret)
	u, err := st.CreateUser(context.Background(), store.User{Login: "admin", Hash: "x", Role: store.RoleAdmin, TOTPSecret: sealed, TOTPLastStep: 3})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := secrets.SetMany(paths.SecretsFile(), map[string]string{
		secrets.NodeToken: strings.Repeat("ab", 32), SecretDataKey: hex.EncodeToString(newDataKey), SecretDataKeyPrev: hex.EncodeToString(oldDataKey),
	}); err != nil {
		t.Fatal(err)
	}
	_, stop := runPanel(t, config.Default())
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(filepath.Join(paths.Data(), "azpanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.UserByID(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := Open(newDataKey, got.TOTPSecret); err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("после старта 2FA не читается новым ключом: %v", err)
	}
	if sec, _ := secrets.Load(paths.SecretsFile()); sec[SecretDataKeyPrev] != "" {
		t.Fatal("PREV остался")
	}
}
