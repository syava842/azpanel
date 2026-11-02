// Package telemt — MTProxy telemt на узле: разбор и точечная правка
// config.toml, ссылки tg://proxy, установка и обновление с откатом.
package telemt

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Пути telemt на узле (раскладка установщика telemt --init).
const (
	DefaultBinary = "/usr/local/bin/telemt"
	DefaultConfig = "/etc/telemt/config.toml"
	DefaultUnit   = "telemt"
)

var (
	secretRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	userNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	headerRe   = regexp.MustCompile(`^\s*(\[\[?)\s*([A-Za-z0-9_."\- ]+?)\s*\]\]?\s*(#.*)?$`)
	keyRe      = regexp.MustCompile(`^\s*([A-Za-z0-9_\-]+|"[^"]+")\s*=\s*(.*)$`)
)

// User — пользователь [access.users]: имя и секрет (32 hex).
type User struct {
	Name   string
	Secret string
}

// ValidSecret — ровно 32 hex-символа в нижнем регистре.
func ValidSecret(s string) bool { return secretRe.MatchString(s) }

// ValidUserName — имя пользователя в конфиге: 1–32 символа a-z, A-Z, 0-9, _ и -.
func ValidUserName(s string) bool { return userNameRe.MatchString(s) }

// Doc — config.toml как список строк: правка меняет только нужные строки,
// комментарии и порядок остальных сохраняются.
type Doc struct {
	lines []string
	eol   string
}

// ParseConfig разбирает config.toml. Файл, который не разбирается как TOML,
// отвергается: править то, что telemt всё равно не прочтёт, нельзя.
func ParseConfig(data []byte) (*Doc, error) {
	if err := checkTOML(data); err != nil {
		return nil, err
	}
	eol := "\n"
	if bytes.Contains(data, []byte("\r\n")) {
		eol = "\r\n"
	}
	text := strings.TrimSuffix(string(data), "\n")
	text = strings.TrimSuffix(text, "\r")
	d := &Doc{eol: eol}
	if text != "" {
		d.lines = strings.Split(text, "\n")
		for i, l := range d.lines {
			d.lines[i] = strings.TrimSuffix(l, "\r")
		}
	}
	return d, nil
}

func checkTOML(data []byte) error {
	var v map[string]any
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&v); err != nil {
		return fmt.Errorf("config.toml не разбирается как TOML: %w", err)
	}
	return nil
}

// Bytes — текст конфига с исходными окончаниями строк.
func (d *Doc) Bytes() []byte {
	if len(d.lines) == 0 {
		return nil
	}
	return []byte(strings.Join(d.lines, d.eol) + d.eol)
}

// section — границы раздела: строка заголовка и первая строка следующего.
// array — искать [[имя]] (таблица-массив), иначе [имя]. Нет раздела — head -1.
func (d *Doc) section(name string, array bool) (head, end int) {
	head = -1
	for i, l := range d.lines {
		m := headerRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if head >= 0 {
			return head, i
		}
		if (m[1] == "[[") == array && m[2] == name {
			head = i
		}
	}
	if head >= 0 {
		return head, len(d.lines)
	}
	return -1, -1
}

// strValue — строковое значение справа от «=»: первая пара кавычек.
func strValue(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, `"`) {
		return "", false
	}
	end := strings.Index(raw[1:], `"`)
	if end < 0 {
		return "", false
	}
	return raw[1 : 1+end], true
}

func keyName(k string) string { return strings.Trim(k, `"`) }

// get — значение ключа в разделе (сырая строка справа от «=», без комментария).
func (d *Doc) get(name string, array bool, key string) (string, bool) {
	head, end := d.section(name, array)
	if head < 0 {
		return "", false
	}
	for _, l := range d.lines[head+1 : end] {
		if m := keyRe.FindStringSubmatch(l); m != nil && keyName(m[1]) == key {
			return stripComment(m[2]), true
		}
	}
	return "", false
}

// stripComment отрезает «# …» после значения, не трогая # внутри кавычек.
func stripComment(raw string) string {
	in := false
	for i, r := range raw {
		switch {
		case r == '"':
			in = !in
		case r == '#' && !in:
			return strings.TrimSpace(raw[:i])
		}
	}
	return strings.TrimSpace(raw)
}

// Users — пользователи [access.users] в порядке файла.
func (d *Doc) Users() []User {
	head, end := d.section("access.users", false)
	if head < 0 {
		return nil
	}
	var out []User
	for _, l := range d.lines[head+1 : end] {
		m := keyRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if s, ok := strValue(m[2]); ok {
			out = append(out, User{Name: keyName(m[1]), Secret: strings.ToLower(s)})
		}
	}
	return out
}

// TLSDomain — домен маскировки tls_domain (раздел [censorship]; если там нет —
// первый tls_domain в файле, как у установщика).
func (d *Doc) TLSDomain() string {
	if v, ok := d.get("censorship", false, "tls_domain"); ok {
		if s, ok := strValue(v); ok {
			return s
		}
	}
	for _, l := range d.lines {
		if m := keyRe.FindStringSubmatch(l); m != nil && keyName(m[1]) == "tls_domain" {
			if s, ok := strValue(stripComment(m[2])); ok {
				return s
			}
		}
	}
	return ""
}

// Port — порт прокси: [server] port, иначе порт первого [[server.listeners]].
func (d *Doc) Port() int {
	for _, src := range []struct {
		name  string
		array bool
	}{{"server", false}, {"server.listeners", true}} {
		if v, ok := d.get(src.name, src.array, "port"); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
				return n
			}
		}
	}
	return 0
}

// mutate применяет правку и проверяет, что файл остался корректным TOML;
// иначе возвращает прежние строки.
func (d *Doc) mutate(f func() error) error {
	saved := append([]string(nil), d.lines...)
	if err := f(); err != nil {
		d.lines = saved
		return err
	}
	if err := checkTOML(d.Bytes()); err != nil {
		d.lines = saved
		return err
	}
	return nil
}

// insertAt вставляет строки перед индексом i.
func (d *Doc) insertAt(i int, ls ...string) {
	out := make([]string, 0, len(d.lines)+len(ls))
	out = append(out, d.lines[:i]...)
	out = append(out, ls...)
	out = append(out, d.lines[i:]...)
	d.lines = out
}

// lastKeyLine — индекс последней строки «ключ = …» раздела либо заголовка.
func (d *Doc) lastKeyLine(head, end int) int {
	last := head
	for i := head + 1; i < end; i++ {
		if keyRe.MatchString(d.lines[i]) {
			last = i
		}
	}
	return last
}

// AddUser добавляет «имя = "секрет"» в конец [access.users].
func (d *Doc) AddUser(name, secret string) error {
	if !ValidUserName(name) {
		return errors.New("имя пользователя: 1–32 символа a-z, A-Z, 0-9, _ и -")
	}
	if !ValidSecret(secret) {
		return errors.New("секрет должен быть ровно 32 hex-символа в нижнем регистре")
	}
	for _, u := range d.Users() {
		if u.Name == name {
			return fmt.Errorf("пользователь %q уже есть", name)
		}
		if u.Secret == secret {
			return errors.New("такой секрет уже выдан другому пользователю")
		}
	}
	return d.mutate(func() error {
		head, end := d.section("access.users", false)
		line := fmt.Sprintf("%s = %q", name, secret)
		if head < 0 {
			if n := len(d.lines); n > 0 && strings.TrimSpace(d.lines[n-1]) != "" {
				d.lines = append(d.lines, "")
			}
			d.lines = append(d.lines, "[access.users]", line)
			return nil
		}
		d.insertAt(d.lastKeyLine(head, end)+1, line)
		return nil
	})
}

// RemoveUser удаляет строку пользователя.
func (d *Doc) RemoveUser(name string) error {
	head, end := d.section("access.users", false)
	if head >= 0 {
		for i := head + 1; i < end; i++ {
			m := keyRe.FindStringSubmatch(d.lines[i])
			if m == nil || keyName(m[1]) != name {
				continue
			}
			return d.mutate(func() error {
				d.lines = append(d.lines[:i], d.lines[i+1:]...)
				return nil
			})
		}
	}
	return fmt.Errorf("пользователя %q нет", name)
}

// Set задаёт «ключ = значение» в разделе: заменяет строку или вставляет
// первой в раздел; нет раздела — дописывает его в конец. raw — готовый
// TOML-литерал (кавычки у строк ставит вызывающий).
func (d *Doc) Set(section, key, raw string) error {
	return d.mutate(func() error {
		head, end := d.section(section, false)
		if head < 0 {
			if n := len(d.lines); n > 0 && strings.TrimSpace(d.lines[n-1]) != "" {
				d.lines = append(d.lines, "")
			}
			d.lines = append(d.lines, "["+section+"]", key+" = "+raw)
			return nil
		}
		for i := head + 1; i < end; i++ {
			if m := keyRe.FindStringSubmatch(d.lines[i]); m != nil && keyName(m[1]) == key {
				d.lines[i] = key + " = " + raw
				return nil
			}
		}
		d.insertAt(head+1, key+" = "+raw)
		return nil
	})
}

// DisableIPv6Listener комментирует IPv6-слушатель: ipv6 в telemt отключён.
func (d *Doc) DisableIPv6Listener() error {
	return d.mutate(func() error {
		for i, l := range d.lines {
			if strings.TrimSpace(l) == `listen_addr_ipv6 = "::"` {
				d.lines[i] = "#" + strings.TrimSpace(l)
			}
		}
		for i := 0; i+2 < len(d.lines); i++ {
			if strings.TrimSpace(d.lines[i]) != "[[server.listeners]]" ||
				strings.TrimSpace(d.lines[i+1]) != `ip = "::"` ||
				!strings.HasPrefix(strings.TrimSpace(d.lines[i+2]), "port = ") {
				continue
			}
			for j := i; j < i+3; j++ {
				d.lines[j] = "#" + strings.TrimSpace(d.lines[j])
			}
		}
		return nil
	})
}
