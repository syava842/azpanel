// Пакет update - проверка подлинности релизов azpanel.
package update

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Verify проверяет подпись sig файла sums (SHA256SUMS) ключом pub, затем
// сверяет SHA-256 данных data со строкой файла file в sums.
func Verify(pub ed25519.PublicKey, sums, sig []byte, file string, data []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("открытый ключ релиза не задан: обновление не проверить")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, sums, sig) {
		return errors.New("подпись SHA256SUMS неверна")
	}
	want := ""
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		// формат sha256sum: "<hex>  <имя>" или "<hex> *<имя>"
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == file {
			want = strings.ToLower(f[0])
			break
		}
	}
	if want == "" {
		return fmt.Errorf("в SHA256SUMS нет строки для %q", file)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("контрольная сумма %q не совпала", file)
	}
	return nil
}
