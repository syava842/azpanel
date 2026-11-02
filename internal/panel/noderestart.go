package panel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// NodeFingerprintKey — ключ в secrets.env: SHA-256 сертификата агента по https.
const NodeFingerprintKey = "NODE_FINGERPRINT"

// restartNodeHTTP просит агента перезапуститься: POST /v1/system/restart с
// токеном панели. Агент отвечает и завершает себя чуть позже, systemd
// поднимает его заново (Restart=always). Запрос идёт через клиент nodeapi: для
// https:// агента сертификат принимается только с закреплённым отпечатком
// fingerprint, для http:// отпечаток не нужен.
func restartNodeHTTP(ctx context.Context, nodeURL, token, fingerprint string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var c *nodeapi.HTTPClient
	if strings.HasPrefix(strings.ToLower(nodeURL), "https://") {
		if fingerprint == "" {
			return errors.New("агент по https: не задан отпечаток сертификата (" + NodeFingerprintKey + " в secrets.env)")
		}
		var err error
		if c, err = nodeapi.NewPinned(nodeURL, token, fingerprint); err != nil {
			return err
		}
	} else {
		c = nodeapi.New(nodeURL, token)
	}
	err := c.RestartNode(ctx)
	var ae *nodeapi.Error
	switch {
	case err == nil:
		return nil
	case errors.Is(err, nodeapi.ErrCertChanged):
		return fmt.Errorf("сертификат агента не совпал с закреплённым отпечатком: %w", err)
	case errors.As(err, &ae) && ae.Status == 404:
		return fmt.Errorf("агент не знает перезапуск (%d): обновите агент", ae.Status)
	case errors.As(err, &ae):
		return fmt.Errorf("агент ответил %d", ae.Status)
	}
	return fmt.Errorf("агент недоступен: %w", err)
}
