package nodeapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Ответ 423 на манифест — ErrBusy; другие коды — нет.
func TestSyncManifestBusyIsErrBusy(t *testing.T) {
	code := http.StatusLocked
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write([]byte(`{"error":"набор файлов сейчас меняется"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "t")
	_, err := c.SyncManifest(context.Background())
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("423: %v", err)
	}
	if wrapped := errors.Join(errors.New("манифест основного"), err); !errors.Is(wrapped, ErrBusy) {
		t.Fatal("обёрнутая ошибка потеряла ErrBusy")
	}
	code = http.StatusInternalServerError
	if _, err := c.SyncManifest(context.Background()); err == nil || errors.Is(err, ErrBusy) {
		t.Fatalf("500 — не ErrBusy: %v", err)
	}
}
