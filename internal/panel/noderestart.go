package panel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// restartNodeHTTP просит агента перезапуститься: POST /v1/system/restart с
// токеном панели. Агент отвечает и завершает себя чуть позже, systemd
// поднимает его заново (Restart=always).
func restartNodeHTTP(ctx context.Context, nodeURL, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(nodeURL, "/")+"/v1/system/restart", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("агент недоступен: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("агент не знает перезапуск (%d): обновите агент", resp.StatusCode)
	}
	return fmt.Errorf("агент ответил %d", resp.StatusCode)
}
