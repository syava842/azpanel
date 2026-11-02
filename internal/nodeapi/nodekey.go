package nodeapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
)

// NodeKeyPrefix начинает ключ узла.
const NodeKeyPrefix = "azn1."

// NodeKey — содержимое ключа узла: адрес панели (его узел впишет в белый
// список) и токен, которым панель обращается к агенту.
type NodeKey struct {
	PanelIP string `json:"panel_ip"`
	Token   string `json:"token"`
}

// Encode — «azn1.<base64url(JSON)>» без заполнителя «=».
func (k NodeKey) Encode() (string, error) {
	if err := k.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(k)
	if err != nil {
		return "", err
	}
	return NodeKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseNodeKey разбирает ключ узла; пробелы по краям и заполнитель «=» (если
// ключ прошёл через почтовую программу) терпятся.
func ParseNodeKey(s string) (NodeKey, error) {
	var k NodeKey
	s = strings.TrimSpace(s)
	body, ok := strings.CutPrefix(s, NodeKeyPrefix)
	if !ok {
		return k, errors.New("ключ узла должен начинаться с azn1.")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body, "="))
	if err != nil {
		return k, errors.New("ключ узла повреждён: не base64")
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return NodeKey{}, errors.New("ключ узла повреждён: не JSON")
	}
	if err := k.validate(); err != nil {
		return NodeKey{}, err
	}
	return k, nil
}

// NodeKeyFileEnv — переменная окружения с путём к файлу ключа узла.
const NodeKeyFileEnv = "AZPANEL_NODE_KEY_FILE"

// maxNodeKeyInput — ключ узла короче 200 байт; больше читать незачем.
const maxNodeKeyInput = 4096

// ReadNodeKey читает ключ узла так, чтобы токен не попал в argv (его видно в
// ps и в истории shell). src — что передал оператор:
//
//	"-"          ключ со стандартного ввода (stdin);
//	""           путь к файлу из переменной NodeKeyFileEnv (getenv);
//	путь         файл с ключом, права не шире 0600 (кроме Windows);
//	"azn1.…"     отказ: сам ключ в аргументе командной строки не принимается.
func ReadNodeKey(src string, getenv func(string) string, stdin io.Reader) (NodeKey, error) {
	switch {
	case strings.HasPrefix(strings.TrimSpace(src), NodeKeyPrefix):
		return NodeKey{}, errors.New("ключ узла нельзя передавать аргументом: он виден в ps и в истории shell; передайте «-» (stdin), путь к файлу или задайте " + NodeKeyFileEnv)
	case src == "-":
		if stdin == nil {
			return NodeKey{}, errors.New("стандартный ввод недоступен")
		}
		return parseNodeKeyBytes(stdin, "стандартный ввод")
	case src == "":
		src = getenv(NodeKeyFileEnv)
		if src == "" {
			return NodeKey{}, errors.New("ключ узла не указан: передайте «-» (stdin), путь к файлу или задайте " + NodeKeyFileEnv)
		}
	}
	f, err := os.Open(src)
	if err != nil {
		return NodeKey{}, fmt.Errorf("файл ключа узла: %w", err)
	}
	defer f.Close()
	if runtime.GOOS != "windows" {
		fi, err := f.Stat()
		if err != nil {
			return NodeKey{}, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return NodeKey{}, fmt.Errorf("файл ключа узла %s доступен другим пользователям (права %o): chmod 600", src, fi.Mode().Perm())
		}
	}
	return parseNodeKeyBytes(f, src)
}

func parseNodeKeyBytes(r io.Reader, what string) (NodeKey, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxNodeKeyInput+1))
	if err != nil {
		return NodeKey{}, fmt.Errorf("%s: %w", what, err)
	}
	if len(data) > maxNodeKeyInput {
		return NodeKey{}, fmt.Errorf("%s: слишком длинный ключ узла", what)
	}
	return ParseNodeKey(string(data))
}

func (k NodeKey) validate() error {
	if _, err := netip.ParseAddr(k.PanelIP); err != nil {
		return errors.New("в ключе узла неверный адрес панели")
	}
	if b, err := hex.DecodeString(k.Token); err != nil || len(b) != 32 {
		return errors.New("в ключе узла токен не из 64 hex-символов")
	}
	return nil
}
