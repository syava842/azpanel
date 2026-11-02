package nodeapi

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/agenttls"
)

// ErrCertChanged — сертификат узла не совпал с закреплённым отпечатком.
// Проверяется через errors.Is; текст — «сертификат узла сменился».
var ErrCertChanged = agenttls.ErrFingerprint

// NewPinned — клиент агента по TLS: baseURL вида https://хост:порт, сертификат
// принимается, только если его SHA-256 равен fingerprint (hex, допускаются
// двоеточия). Отпечаток панель запоминает при добавлении узла; другой
// сертификат — ошибка ErrCertChanged, запрос с токеном не уходит.
func NewPinned(baseURL, token, fingerprint string) (*HTTPClient, error) {
	cfg, err := agenttls.PinnedConfig(fingerprint)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:     cfg,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     time.Minute,
	}
	return &HTTPClient{
		BaseURL: strings.TrimRight(baseURL, "/"), Token: token,
		HTTP: &http.Client{Timeout: 11 * time.Minute, Transport: tr},
	}, nil
}
