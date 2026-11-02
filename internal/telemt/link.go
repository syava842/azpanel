package telemt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Key — разобранный ключ telemt: секрет и домен маскировки; из ссылки ещё
// адрес и порт сервера.
type Key struct {
	Secret string // 32 hex в нижнем регистре
	Domain string
	Server string
	Port   int
}

var domainRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// ValidDomain — домен маскировки: буквы, цифры, точки и дефисы.
func ValidDomain(s string) bool { return len(s) <= 253 && domainRe.MatchString(s) }

// SecretKey собирает «ee» + секрет + hex(домен) — то, что стоит в secret= ссылки.
func SecretKey(secret, domain string) string {
	return "ee" + secret + hex.EncodeToString([]byte(domain))
}

// Link — ссылка tg://proxy.
func Link(server string, port int, secret, domain string) string {
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", url.QueryEscape(server), port, SecretKey(secret, domain))
}

// WebLink — та же ссылка для пересылки: https://t.me/proxy.
func WebLink(server string, port int, secret, domain string) string {
	return fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s", url.QueryEscape(server), port, SecretKey(secret, domain))
}

// MaskSecret — секрет для показа: начало и конец, середина скрыта.
func MaskSecret(secret string) string {
	if len(secret) < 8 {
		return strings.Repeat("•", len(secret))
	}
	return secret[:4] + "…" + secret[len(secret)-2:]
}

// ParseKey разбирает ключ вида «ee<32 hex><домен в hex>» либо ссылку
// tg://proxy?…&secret=ee… (и https://t.me/proxy?…).
func ParseKey(s string) (Key, error) {
	s = strings.TrimSpace(s)
	var k Key
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Query().Get("secret") == "" {
			return Key{}, errors.New("в ссылке нет параметра secret")
		}
		q := u.Query()
		k.Server = q.Get("server")
		k.Port, _ = strconv.Atoi(q.Get("port"))
		s = q.Get("secret")
	}
	s = strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "dd"):
		return Key{}, errors.New("ключ вида dd (secure) не поддерживается: нужен ee с доменом маскировки")
	case !strings.HasPrefix(s, "ee"):
		return Key{}, errors.New("ключ должен начинаться с ee")
	}
	body := s[2:]
	if len(body) <= 32 || len(body)%2 != 0 {
		return Key{}, fmt.Errorf("неверная длина ключа: после ee нужно 32 hex секрета и домен в hex, получено %d символов", len(body))
	}
	raw, err := hex.DecodeString(body)
	if err != nil {
		return Key{}, errors.New("ключ содержит не hex-символы")
	}
	k.Secret = body[:32]
	k.Domain = string(raw[16:])
	if !ValidDomain(k.Domain) {
		return Key{}, errors.New("домен внутри ключа выглядит неправильно")
	}
	return k, nil
}

// SecretFromInput принимает от администратора либо 32 hex, либо ключ/ссылку
// целиком. Домен из ключа обязан совпасть с tls_domain конфига: ключ чужого
// домена в этом прокси работать не будет.
func SecretFromInput(input, tlsDomain string) (string, error) {
	in := strings.ToLower(strings.TrimSpace(input))
	if ValidSecret(in) {
		return in, nil
	}
	k, err := ParseKey(input)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(k.Domain, tlsDomain) {
		return "", fmt.Errorf("домен в ключе (%s) не совпадает с tls_domain прокси (%s)", k.Domain, tlsDomain)
	}
	return k.Secret, nil
}

var journalLinkRe = regexp.MustCompile(`tg://proxy\?\S+`)

// JournalLinks — ключи ee…, которые telemt напечатал при старте (строки
// «EE-TLS: tg://proxy?…» из journalctl), в порядке появления.
func JournalLinks(journal string) []Key {
	var out []Key
	for _, line := range strings.Split(journal, "\n") {
		link := journalLinkRe.FindString(line)
		if link == "" {
			continue
		}
		if k, err := ParseKey(link); err == nil {
			out = append(out, k)
		}
	}
	return out
}

// CheckJournal сверяет ссылки журнала с конфигом: каждый напечатанный ключ
// должен принадлежать одному из пользователей и иметь домен tls_domain.
// Пустой журнал — не ошибка (при log_level silent ссылок нет): found == false.
func CheckJournal(journal string, users []User, tlsDomain string) (found bool, err error) {
	keys := JournalLinks(journal)
	if len(keys) == 0 {
		return false, nil
	}
	known := map[string]bool{}
	for _, u := range users {
		known[u.Secret] = true
	}
	for _, k := range keys {
		if !known[k.Secret] || !strings.EqualFold(k.Domain, tlsDomain) {
			return true, fmt.Errorf("ссылка в журнале telemt не совпадает с конфигом (секрет %s…, домен %s)", k.Secret[:4], k.Domain)
		}
	}
	return true, nil
}
