package nodeapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
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

func (k NodeKey) validate() error {
	if _, err := netip.ParseAddr(k.PanelIP); err != nil {
		return errors.New("в ключе узла неверный адрес панели")
	}
	if b, err := hex.DecodeString(k.Token); err != nil || len(b) != 32 {
		return errors.New("в ключе узла токен не из 64 hex-символов")
	}
	return nil
}
