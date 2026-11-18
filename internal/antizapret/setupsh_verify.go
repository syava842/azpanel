package antizapret

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	shUntilRe = regexp.MustCompile(`^until \[\[ "\$([A-Z_]+)" =~ (.+?) \]\]`)
	shReadRe  = regexp.MustCompile(`-e -i (\S+) ([A-Z_]+)$`)
	shSavedRe = regexp.MustCompile(`(?m)^([A-Z_]+)=\$([A-Z_]+)$`)
	// shTopReadRe — read без отступа (не внутри until/while-повтора): такой
	// вопрос задаётся всегда и читает стандартный ввод.
	shTopReadRe = regexp.MustCompile(`^(?:while )?read -rp .* ([A-Z_]+)$`)
)

// CheckSetupShQuestions сверяет вопросы скачанного setup.sh с таблицей
// shPrompts, по которой агент собирает окружение и стандартный ввод. Пусто —
// скрипт спрашивает ровно то, на что у агента есть ответы. Иначе вопрос без
// ответа оставил бы `until … read` крутиться на конце ввода, а установка
// стояла бы с остановленными службами.
//
// Проверяется: набор, шаблоны и умолчания вопросов с «until … =~»; набор и
// порядок вопросов, читающих ввод всегда (SetupShStdinKeys); набор ключей,
// которые скрипт записывает в setup из окружения.
func CheckSetupShQuestions(text string) []string {
	var problems []string
	type q struct{ pattern, def string }
	got := map[string]q{}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		m := shUntilRe.FindStringSubmatch(l)
		if m == nil || m[1] == shKeyMTU || i+1 >= len(lines) {
			continue
		}
		r := shReadRe.FindStringSubmatch(lines[i+1])
		if r == nil || r[2] != m[1] {
			problems = append(problems, fmt.Sprintf("строка %d: после until %s не нашёлся read с -i", i+1, m[1]))
			continue
		}
		got[m[1]] = q{pattern: m[2], def: strings.Trim(r[1], `"`)}
	}
	want := map[string]q{}
	for _, p := range shPrompts {
		want[p.key] = q{pattern: p.pattern, def: p.def}
	}
	for _, k := range sortedKeys(want) {
		g, ok := got[k]
		switch {
		case !ok:
			problems = append(problems, k+": в setup.sh такого вопроса нет")
		case g != want[k]:
			problems = append(problems, fmt.Sprintf("%s: setup.sh %+v, таблица %+v", k, g, want[k]))
		}
	}
	for _, k := range sortedKeys(got) {
		if _, ok := want[k]; !ok {
			problems = append(problems, k+": вопрос есть в setup.sh, в таблице нет")
		}
	}

	// Вопросы без «until» читают стандартный ввод всегда — по строке в
	// порядке появления. Их набор и порядок обязаны совпасть с
	// SetupShStdinKeys: лишний или переставленный сдвинул бы все ответы.
	var stdin []string
	for _, l := range lines {
		if m := shTopReadRe.FindStringSubmatch(strings.TrimRight(l, "")); m != nil {
			stdin = append(stdin, m[1])
		}
	}
	if strings.Join(stdin, ",") != strings.Join(SetupShStdinKeys, ",") {
		problems = append(problems, fmt.Sprintf("вопросы ввода: в setup.sh %s, у агента %s", strings.Join(stdin, ", "), strings.Join(SetupShStdinKeys, ", ")))
	}

	// Ключи, которые скрипт переносит из окружения в setup.
	wantSaved := map[string]bool{}
	for _, k := range SetupShStdinKeys {
		wantSaved[k] = true
	}
	for _, p := range shPrompts {
		wantSaved[p.key] = true
	}
	for _, k := range shPassthrough {
		wantSaved[k] = true
	}
	gotSaved := map[string]bool{}
	for _, m := range shSavedRe.FindAllStringSubmatch(text, -1) {
		if m[1] != m[2] {
			problems = append(problems, fmt.Sprintf("%s=$%s: ключ записывается из другой переменной", m[1], m[2]))
		}
		gotSaved[m[1]] = true
	}
	for _, k := range sortedBool(gotSaved) {
		if !wantSaved[k] {
			problems = append(problems, k+": setup.sh берёт его из окружения, а таблица не передаёт")
		}
	}
	for _, k := range sortedBool(wantSaved) {
		if !gotSaved[k] {
			problems = append(problems, k+": в таблице есть, а setup.sh в setup не записывает")
		}
	}
	return problems
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBool(m map[string]bool) []string { return sortedKeys(m) }
