package config

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// leafPaths — все листья Config по тегам toml, как их видит рефлексия.
func leafPaths(t reflect.Type, prefix string, out map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Tag.Get("toml")
		if name == "" {
			panic("у поля " + f.Name + " нет тега toml")
		}
		p := prefix + name
		if f.Type.Kind() == reflect.Struct {
			leafPaths(f.Type, p+".", out)
			continue
		}
		out[p] = f.Type
	}
}

// Сторож: каждое поле Config имеет описание, и лишних описаний нет.
func TestMetaCoversConfig(t *testing.T) {
	have := map[string]reflect.Type{}
	leafPaths(reflect.TypeOf(Config{}), "", have)
	seen := map[string]bool{}
	for _, f := range fields {
		if seen[f.Path] {
			t.Errorf("описание %s задано дважды", f.Path)
		}
		seen[f.Path] = true
		typ, ok := have[f.Path]
		if !ok {
			t.Errorf("описание %s: такого поля нет в Config", f.Path)
			continue
		}
		if f.Title == "" || f.Hint == "" {
			t.Errorf("%s: нет названия или подсказки", f.Path)
		}
		if !slices.Contains([]Apply{ApplyNow, ApplyRestartPanel, ApplyRestartNode, ApplyForeign, ApplyDangerous}, f.Apply) {
			t.Errorf("%s: неизвестный способ применения %q", f.Path, f.Apply)
		}
		if f.Kind != KindReadonly && !slices.ContainsFunc(Sections, func(s Section) bool { return s.Key == f.Section }) {
			t.Errorf("%s: неизвестный раздел %q", f.Path, f.Section)
		}
		var want []Kind
		switch {
		case typ.Kind() == reflect.String:
			want = []Kind{KindString, KindChoice}
		case typ.Kind() == reflect.Int:
			want = []Kind{KindInt, KindReadonly}
		case typ.Kind() == reflect.Bool:
			want = []Kind{KindBool}
		case typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.String:
			want = []Kind{KindList, KindMulti}
		case typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Int64:
			want = []Kind{KindIntList}
		}
		if !slices.Contains(want, f.Kind) {
			t.Errorf("%s: вид %q не подходит типу %s", f.Path, f.Kind, typ)
		}
		if (f.Kind == KindChoice || f.Kind == KindMulti) && len(f.Choices) == 0 {
			t.Errorf("%s: нет списка вариантов", f.Path)
		}
	}
	for p := range have {
		if !seen[p] {
			t.Errorf("поле Config %s без описания в meta.go", p)
		}
	}
}

func TestMetaGetSetRoundTrip(t *testing.T) {
	d := Default()
	for _, f := range fields {
		var c Config
		if err := Set(&c, f.Path, Get(d, f.Path)); err != nil {
			t.Fatalf("%s: %v", f.Path, err)
		}
		if got, want := Get(c, f.Path), Get(d, f.Path); got != want {
			t.Errorf("%s: %q, нужно %q", f.Path, got, want)
		}
	}
}

func TestMetaSetKinds(t *testing.T) {
	c := Default()
	if err := Set(&c, "node.poll_seconds", "abc"); err == nil || !strings.Contains(err.Error(), "node.poll_seconds") {
		t.Fatalf("число: %v", err)
	}
	if err := Set(&c, "telegram.notify_chats", "1, -100, x"); err == nil {
		t.Fatal("мусор в списке чисел принят")
	}
	if err := Set(&c, "telegram.notify_chats", "1, -100\n7"); err != nil || len(c.Telegram.NotifyChats) != 3 {
		t.Fatalf("%v %v", err, c.Telegram.NotifyChats)
	}
	if err := Set(&c, "panel.trusted_proxies", "10.0.0.0/8\n127.0.0.1"); err != nil || len(c.Panel.TrustedProxies) != 2 {
		t.Fatalf("%v %v", err, c.Panel.TrustedProxies)
	}
	if err := Set(&c, "panel.require_admin_2fa", "on"); err != nil || !c.Panel.RequireAdmin2FA {
		t.Fatal("флажок не принят")
	}
	if err := Set(&c, "нет.такого", "1"); err == nil {
		t.Fatal("неизвестное поле принято")
	}
}

func TestErrorFieldAndDiff(t *testing.T) {
	c := Default()
	c.Panel.BasePath = "azpanel"
	f, ok := ErrorField(c.Validate())
	if !ok || f.Path != "panel.base_path" {
		t.Fatalf("%v %v", f, ok)
	}
	if _, ok := ErrorField(errors.New("что-то иное")); ok {
		t.Fatal("поле угадано из ничего")
	}
	a, b := Default(), Default()
	b.Panel.HistoryDays = 7
	b.Telegram.Notify = []string{"reboot"}
	d := Diff(a, b)
	if len(d) != 2 || d[0].Field.Path != "panel.history_days" || d[0].Old != "30" || d[0].New != "7" {
		t.Fatalf("%+v", d)
	}
}
