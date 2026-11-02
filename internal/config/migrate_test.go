package config

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestMigrationsCoverCurrentVersion(t *testing.T) {
	if len(migrations) != CurrentVersion-1 {
		t.Fatalf("миграций %d, а CurrentVersion = %d", len(migrations), CurrentVersion)
	}
}

func TestMigrateV1(t *testing.T) {
	data, err := os.ReadFile("testdata/config-v1.toml")
	if err != nil {
		t.Fatal(err)
	}
	out, qs, err := Migrate(data, nil)
	if err != nil || len(qs) != 0 {
		t.Fatalf("err = %v, вопросов %d", err, len(qs))
	}
	c := Default()
	if _, err := toml.Decode(string(out), &c); err != nil {
		t.Fatal(err)
	}
	if c.ConfigVersion != 2 {
		t.Fatalf("config_version = %d", c.ConfigVersion)
	}
	if c.Node.PollSeconds != 7 || c.Node.QueryTimeoutMs != 1500 || c.Log.MaxSizeMB != 20 || c.Log.Keep != 3 {
		t.Fatalf("заданные значения потеряны: %+v", c)
	}
	if !strings.Contains(string(out), "api_listen") || !strings.Contains(string(out), "[panel]") {
		t.Fatalf("умолчания версии 2 не записаны явно:\n%s", out)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateKeepsExplicitValues(t *testing.T) {
	in := "config_version = 1\n[node]\napi_listen = \"\"\n[panel]\nlisten = \"127.0.0.1:9000\"\n"
	out, _, err := Migrate([]byte(in), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := Default()
	if _, err := toml.Decode(string(out), &c); err != nil {
		t.Fatal(err)
	}
	if c.Node.APIListen != "" || c.Panel.Listen != "127.0.0.1:9000" {
		t.Fatalf("явные значения затёрты: %+v %+v", c.Node, c.Panel)
	}
}

func TestMigrateCurrentUnchanged(t *testing.T) {
	in := []byte("# комментарий\nconfig_version = 2\n")
	out, qs, err := Migrate(in, nil)
	if err != nil || len(qs) != 0 || string(out) != string(in) {
		t.Fatalf("out = %q, qs = %v, err = %v", out, qs, err)
	}
}

func TestMigrateRejectsNewer(t *testing.T) {
	if _, _, err := Migrate([]byte("config_version = 99\n"), nil); err == nil {
		t.Fatal("версия новее принята")
	}
}

func TestMigrateNoVersionIsV1(t *testing.T) {
	out, _, err := Migrate([]byte("[log]\nkeep = 2\n"), nil)
	if err != nil || !strings.Contains(string(out), "config_version = 2") {
		t.Fatalf("out = %q, err = %v", out, err)
	}
}

// Цепочка из двух шагов с вопросами — проверка механизма, не реальных версий.
func testChain() []migration {
	return []migration{
		func(m map[string]any) (map[string]any, []Question, error) {
			m["a"] = "x"
			return m, []Question{{Key: "node.token", Text: "токен узла", Check: func(s string) error {
				if len(s) < 3 {
					return errors.New("короче 3 символов")
				}
				return nil
			}}}, nil
		},
		func(m map[string]any) (map[string]any, []Question, error) {
			return m, []Question{{Key: "site", Text: "адрес сайта"}}, nil
		},
	}
}

func TestMigrateQuestionsUnanswered(t *testing.T) {
	in := []byte("config_version = 1\n")
	out, qs, err := runMigrations(testChain(), in, map[string]string{"site": "s"})
	var qe *QuestionsError
	if !errors.As(err, &qe) {
		t.Fatalf("err = %v", err)
	}
	if out != nil || len(qs) != 1 || qs[0].Key != "node.token" || len(qe.Questions) != 1 {
		t.Fatalf("out = %q, qs = %v", out, qs)
	}
	if !strings.Contains(err.Error(), "токен узла") {
		t.Fatalf("текст вопроса не в ошибке: %v", err)
	}
	// Без ответов вопросов два, из разных шагов цепочки.
	_, qs, _ = runMigrations(testChain(), in, nil)
	if len(qs) != 2 {
		t.Fatalf("вопросов %d, нужно 2", len(qs))
	}
}

func TestMigrateAnswersApplied(t *testing.T) {
	out, qs, err := runMigrations(testChain(), []byte("config_version = 1\n"),
		map[string]string{"node.token": "abcd", "site": "example.org"})
	if err != nil || len(qs) != 0 {
		t.Fatalf("err = %v, qs = %v", err, qs)
	}
	var m map[string]any
	if _, err := toml.Decode(string(out), &m); err != nil {
		t.Fatal(err)
	}
	if m["config_version"] != int64(3) || m["site"] != "example.org" || m["a"] != "x" ||
		m["node"].(map[string]any)["token"] != "abcd" {
		t.Fatalf("результат: %v", m)
	}
}

func TestMigrateAnswerChecked(t *testing.T) {
	_, _, err := runMigrations(testChain(), []byte("config_version = 1\n"),
		map[string]string{"node.token": "ab", "site": "s"})
	if err == nil || !strings.Contains(err.Error(), "node.token") {
		t.Fatalf("плохой ответ принят: %v", err)
	}
	_, _, err = runMigrations(testChain(), []byte("config_version = 1\n"),
		map[string]string{"node.token": "abcd", "site": "  "})
	if err == nil {
		t.Fatal("пустой ответ принят")
	}
}

func TestLoadMigratesV1File(t *testing.T) {
	c, err := Load("testdata/config-v1.toml")
	if err != nil {
		t.Fatal(err)
	}
	if c.ConfigVersion != CurrentVersion || c.Node.PollSeconds != 7 || c.Panel.Listen != Default().Panel.Listen {
		t.Fatalf("%+v", c)
	}
}

func TestLoadReturnsQuestionsError(t *testing.T) {
	old := migrations
	migrations = append(append([]migration{}, old...), func(m map[string]any) (map[string]any, []Question, error) {
		return m, []Question{{Key: "x.y", Text: "вопрос"}}, nil
	})
	defer func() { migrations = old }()
	_, err := loadMigrated([]byte("config_version = 2\n"), "f.toml")
	var qe *QuestionsError
	if !errors.As(err, &qe) || len(qe.Questions) != 1 {
		t.Fatalf("err = %v", err)
	}
}
