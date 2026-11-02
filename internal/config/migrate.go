package config

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// Question — обязательное значение без умолчания, которое миграция не может
// подставить сама. Key — путь через точку («node.api_listen»), Check —
// проверка ответа (nil — принимается любой непустой).
type Question struct {
	Key   string
	Text  string
	Check func(answer string) error
}

// QuestionsError — миграция остановлена: нужны ответы. Панель и
// `azpanel update` достают вопросы через errors.As и показывают их.
type QuestionsError struct {
	Questions []Question
}

func (e *QuestionsError) Error() string {
	parts := make([]string, len(e.Questions))
	for i, q := range e.Questions {
		parts[i] = q.Key + ": " + q.Text
	}
	return "для миграции конфига нужны ответы: " + strings.Join(parts, "; ")
}

// migration поднимает разобранный конфиг на одну версию. Карту можно менять
// на месте. Вопрос возвращается, если ключ обязателен и умолчания нет; ответ
// Migrate подставит по Key сам.
type migration func(map[string]any) (map[string]any, []Question, error)

// migrations[i] поднимает версию i+1 до i+2. Длина обязана быть
// CurrentVersion-1 — это проверяет тест.
var migrations = []migration{
	migrateV1toV2,
}

// migrateV1toV2: версия 2 добавила node.api_listen и пути AntiZapret,
// node.client_sh_timeout_seconds и раздел [panel]. Недостающее заполняется
// умолчаниями явно, заданное владельцем не трогается.
func migrateV1toV2(m map[string]any) (map[string]any, []Question, error) {
	d := Default()
	node, err := section(m, "node")
	if err != nil {
		return nil, nil, err
	}
	setDefault(node, "api_listen", d.Node.APIListen)
	setDefault(node, "antizapret_dir", d.Node.AntiZapretDir)
	setDefault(node, "easyrsa_pki", d.Node.EasyRSAPKI)
	setDefault(node, "wireguard_dir", d.Node.WireGuardDir)
	setDefault(node, "client_sh_timeout_seconds", int64(d.Node.ClientShTimeoutS))
	panel, err := section(m, "panel")
	if err != nil {
		return nil, nil, err
	}
	setDefault(panel, "listen", d.Panel.Listen)
	setDefault(panel, "node_url", d.Panel.NodeURL)
	setDefault(panel, "collect_seconds", int64(d.Panel.CollectSeconds))
	setDefault(panel, "history_days", int64(d.Panel.HistoryDays))
	setDefault(panel, "session_hours", int64(d.Panel.SessionHours))
	return m, nil, nil
}

// section возвращает таблицу name, создавая её при отсутствии.
func section(m map[string]any, name string) (map[string]any, error) {
	v, ok := m[name]
	if !ok {
		t := map[string]any{}
		m[name] = t
		return t, nil
	}
	t, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("раздел [%s] не таблица", name)
	}
	return t, nil
}

func setDefault(t map[string]any, key string, v any) {
	if _, ok := t[key]; !ok {
		t[key] = v
	}
}

// Migrate поднимает конфиг до CurrentVersion. Версия уже текущая — data
// возвращается как есть. answers — ответы на вопросы по Key. Остались
// вопросы без ответа — возвращаются они же и *QuestionsError, ничего не
// меняется. Комментарии файла при миграции не сохраняются.
func Migrate(data []byte, answers map[string]string) ([]byte, []Question, error) {
	return runMigrations(migrations, data, answers)
}

func runMigrations(chain []migration, data []byte, answers map[string]string) ([]byte, []Question, error) {
	target := int64(len(chain) + 1)
	m := map[string]any{}
	if _, err := toml.Decode(string(data), &m); err != nil {
		return nil, nil, err
	}
	ver := int64(1)
	if v, ok := m["config_version"]; ok {
		n, ok := v.(int64)
		if !ok {
			return nil, nil, errors.New("config_version должен быть целым числом")
		}
		ver = max(n, 1)
	}
	if ver > target {
		return nil, nil, fmt.Errorf("config_version %d новее, чем знает эта версия azpanel (%d)", ver, target)
	}
	if ver == target {
		return data, nil, nil
	}
	var missing []Question
	for v := ver; v < target; v++ {
		var qs []Question
		var err error
		m, qs, err = chain[v-1](m)
		if err != nil {
			return nil, nil, fmt.Errorf("миграция конфига %d → %d: %w", v, v+1, err)
		}
		for _, q := range qs {
			a, ok := answers[q.Key]
			if !ok {
				missing = append(missing, q)
				continue
			}
			if strings.TrimSpace(a) == "" {
				return nil, nil, fmt.Errorf("%s: ответ пуст", q.Key)
			}
			if q.Check != nil {
				if err := q.Check(a); err != nil {
					return nil, nil, fmt.Errorf("%s: %w", q.Key, err)
				}
			}
			if err := setPath(m, q.Key, a); err != nil {
				return nil, nil, err
			}
		}
	}
	if len(missing) > 0 {
		return nil, missing, &QuestionsError{Questions: missing}
	}
	m["config_version"] = target
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), nil, nil
}

// setPath кладёт значение по пути через точку, создавая таблицы.
func setPath(m map[string]any, key, val string) error {
	parts := strings.Split(key, ".")
	for _, p := range parts[:len(parts)-1] {
		t, err := section(m, p)
		if err != nil {
			return err
		}
		m = t
	}
	m[parts[len(parts)-1]] = val
	return nil
}
