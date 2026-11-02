package antizapret

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func readSetupSh(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// fullSetup — setup сервера со всеми вопросными ключами.
func fullSetup() map[string]string {
	m := map[string]string{
		"SETUP_DATE": "2026-10-01T10:00:00+03:00", "MTU": "1380", "WARP_MTU": "1300",
		"OPENVPN_UDP_ENABLE": "y", "OPENVPN_TCP_ENABLE": "y", "WIREGUARD_ENABLE": "y",
		"OPENVPN_PATCH": "3", "OPENVPN_DCO": "n", "ANTIZAPRET_WARP": "3", "VPN_WARP": "1",
		"WARP_PROTECTION": "n", "ANTIZAPRET_DNS": "2", "VPN_DNS": "2", "DNS_WARP": "y",
		"ANTIZAPRET_ADBLOCK": "n", "VPN_ADBLOCK": "y", "ALTERNATIVE_CLIENT_IP": "y",
		"ALTERNATIVE_FAKE_IP": "n", "OPENVPN_BACKUP_UDP": "n", "OPENVPN_BACKUP_TCP": "y",
		"WIREGUARD_BACKUP": "n", "OPENVPN_DUPLICATE": "n", "OPENVPN_LOG": "y",
		"SSH_PROTECTION": "n", "ATTACK_PROTECTION": "n", "SCAN_PROTECTION": "n",
		"TORRENT_GUARD": "n", "RESTRICT_FORWARD": "n", "CLIENT_ISOLATION": "n",
		"OPENVPN_HOST": "vpn.example.com", "WIREGUARD_HOST": "wg.example.com",
		"ROUTE_ALL": "y", "CLOUDFLARE_INCLUDE": "n", "TELEGRAM_INCLUDE": "n", "WHATSAPP_INCLUDE": "n",
		"DISCORD_INCLUDE": "y", "AMAZON_INCLUDE": "y",
		"ANTIZAPRET_WARP_PRIVATE_KEY": "СЕКРЕТ", "ANTIZAPRET_WARP_PUBLIC_KEY": "pub",
		"RECONNECT_WARP": "y", "TXQUEUELEN": "5000",
	}
	return m
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		m[k] = v
	}
	return m
}

func TestPlanSetupShEnvAndStdin(t *testing.T) {
	p := PlanSetupSh(fullSetup(), nil)
	if len(p.Problems) != 0 {
		t.Fatalf("причины отказа: %v", p.Problems)
	}
	env := envMap(p.Env)
	if _, has := env["SETUP_DATE"]; has {
		t.Fatal("SETUP_DATE не должен попадать в окружение")
	}
	if _, has := env["ANTIZAPRET_WARP_PRIVATE_KEY"]; has {
		t.Fatal("секретный ключ попал в окружение")
	}
	for _, e := range p.Env {
		if strings.Contains(e, "СЕКРЕТ") {
			t.Fatalf("секрет в окружении: %s", e)
		}
	}
	for _, k := range append(SetupShPromptKeys(), "DISCORD_INCLUDE", "AMAZON_INCLUDE") {
		want := fullSetup()[k]
		if env[k] != want {
			t.Errorf("%s = %q, ожидалось %q", k, env[k], want)
		}
	}
	if env["MTU"] != "" || env["OPENVPN_HOST"] != "" {
		t.Fatal("MTU и адреса идут вводом, не окружением")
	}
	if p.Stdin != "1380\nvpn.example.com\nwg.example.com\n" {
		t.Fatalf("ввод: %q", p.Stdin)
	}
	if !sort.StringsAreSorted(p.Env) {
		t.Fatal("окружение должно быть упорядочено")
	}
	if len(p.Notes) != 0 {
		t.Fatalf("умолчаний не было, а пометки есть: %v", p.Notes)
	}
}

func TestPlanSetupShMissingKeysGetDefaults(t *testing.T) {
	m := fullSetup()
	delete(m, "ROUTE_ALL")
	m["WARP_MTU"] = ""
	p := PlanSetupSh(m, nil)
	if len(p.Problems) != 0 {
		t.Fatal(p.Problems)
	}
	env := envMap(p.Env)
	if env["ROUTE_ALL"] != "n" || env["WARP_MTU"] != "1380" {
		t.Fatalf("умолчания: ROUTE_ALL=%q WARP_MTU=%q", env["ROUTE_ALL"], env["WARP_MTU"])
	}
	if len(p.Notes) != 2 {
		t.Fatalf("пометки: %v", p.Notes)
	}
}

func TestPlanSetupShLegacyWarpNone(t *testing.T) {
	m := fullSetup()
	m["ANTIZAPRET_WARP"], m["VPN_WARP"] = "n", "n"
	p := PlanSetupSh(m, nil)
	env := envMap(p.Env)
	if len(p.Problems) != 0 || env["ANTIZAPRET_WARP"] != "1" || env["VPN_WARP"] != "1" {
		t.Fatalf("n -> 1: %v %v", p.Problems, env)
	}
}

func TestPlanSetupShRejectsValuesSetupShWouldLoopOn(t *testing.T) {
	for key, bad := range map[string]string{
		"OPENVPN_UDP_ENABLE": "yes", "OPENVPN_PATCH": "5", "VPN_WARP": "4",
		"VPN_DNS": "3", "ANTIZAPRET_DNS": "8", "WARP_MTU": "1500", "MTU": "1200",
	} {
		m := fullSetup()
		m[strings.TrimSpace(key)] = bad
		p := PlanSetupSh(m, nil)
		if len(p.Problems) == 0 {
			t.Errorf("%s=%q принято", key, bad)
		}
	}
	m := fullSetup()
	m["OPENVPN_HOST"] = "bad host\nx"
	if p := PlanSetupSh(m, nil); len(p.Problems) == 0 {
		t.Fatal("адрес с переводом строки принят")
	}
	m = fullSetup()
	m["DISCORD_INCLUDE"] = "y\nrm -rf"
	if p := PlanSetupSh(m, nil); len(p.Problems) == 0 {
		t.Fatal("значение с переводом строки принято")
	}
	m = fullSetup()
	delete(m, "MTU")
	if p := PlanSetupSh(m, nil); len(p.Problems) == 0 {
		t.Fatal("без MTU запускать нельзя: первый вопрос остался бы без ответа")
	}
}

func TestPlanSetupShOverrides(t *testing.T) {
	p := PlanSetupSh(fullSetup(), map[string]string{"MTU": "1400", "OPENVPN_HOST": "new.example.com", "CLIENT_ISOLATION": "y", "OPENVPN_PATCH": "1"})
	if len(p.Problems) != 0 {
		t.Fatal(p.Problems)
	}
	env := envMap(p.Env)
	if env["CLIENT_ISOLATION"] != "y" || env["OPENVPN_PATCH"] != "1" || !strings.HasPrefix(p.Stdin, "1400\nnew.example.com\n") {
		t.Fatalf("правки не применены: %v %q", env, p.Stdin)
	}
	for _, key := range []string{"SETUP_DATE", "ANTIZAPRET_WARP_PRIVATE_KEY", "TXQUEUELEN", "PATH"} {
		p := PlanSetupSh(fullSetup(), map[string]string{key: "x"})
		if len(p.Problems) == 0 {
			t.Errorf("правка ключа %s принята", key)
		}
	}
}

// Сверка таблицы вопросов с настоящим setup.sh. Упала после обновления
// testdata/setup.sh — setup.sh изменил вопросы: правьте shPrompts.
func TestShPromptsMatchSetupSh(t *testing.T) {
	text := readSetupSh(t)
	lines := strings.Split(text, "\n")
	untilRe := regexp.MustCompile(`^until \[\[ "\$([A-Z_]+)" =~ (.+?) \]\]`)
	readRe := regexp.MustCompile(`-e -i (\S+) ([A-Z_]+)$`)
	type q struct{ pattern, def string }
	got := map[string]q{}
	for i, l := range lines {
		m := untilRe.FindStringSubmatch(l)
		if m == nil || m[1] == "MTU" || i+1 >= len(lines) {
			continue
		}
		r := readRe.FindStringSubmatch(lines[i+1])
		if r == nil || r[2] != m[1] {
			t.Fatalf("строка %d: после until %s не нашёлся read с -i", i+1, m[1])
		}
		def := strings.Trim(r[1], `"`)
		got[m[1]] = q{pattern: m[2], def: def}
	}
	want := map[string]q{}
	for _, p := range shPrompts {
		want[p.key] = q{pattern: p.pattern, def: p.def}
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("%s: в setup.sh такого вопроса нет", k)
			continue
		}
		if g != w {
			t.Errorf("%s: setup.sh %+v, таблица %+v", k, g, w)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: вопрос есть в setup.sh, в таблице нет", k)
		}
	}

	// Все ключи, которые setup.sh переносит из окружения в setup.
	saved := regexp.MustCompile(`(?m)^([A-Z_]+)=\$([A-Z_]+)$`)
	wantSaved := map[string]bool{shKeyMTU: true, shKeyOpenVPNHost: true, shKeyWireGuardHost: true}
	for _, p := range shPrompts {
		wantSaved[p.key] = true
	}
	for _, k := range shPassthrough {
		wantSaved[k] = true
	}
	gotSaved := map[string]bool{}
	for _, m := range saved.FindAllStringSubmatch(text, -1) {
		if m[1] != m[2] {
			t.Errorf("%s=$%s: ключ записывается из другой переменной", m[1], m[2])
		}
		gotSaved[m[1]] = true
	}
	for k := range gotSaved {
		if !wantSaved[k] {
			t.Errorf("%s: setup.sh берёт его из окружения, а таблица не передаёт", k)
		}
	}
	for k := range wantSaved {
		if !gotSaved[k] {
			t.Errorf("%s: в таблице есть, а setup.sh в setup не записывает", k)
		}
	}
}

// Порядок ввода и ключевые свойства, на которые опирается агент.
func TestSetupShFacts(t *testing.T) {
	text := readSetupSh(t)
	idx := func(s string) int {
		i := strings.Index(text, s)
		if i < 0 {
			t.Fatalf("в setup.sh нет %q", s)
		}
		return i
	}
	if !(idx("-i \"$MTU\" MTU") < idx("WARP_MTU") && idx("OPENVPN_HOST\ndo") < idx("WIREGUARD_HOST\ndo")) {
		t.Fatal("порядок вопросов ввода изменился")
	}
	if !strings.HasSuffix(strings.TrimSpace(text), "reboot") {
		t.Fatal("setup.sh больше не заканчивается перезагрузкой — агент должен перезагружать сам")
	}
	for _, s := range []string{"git clone --depth 1 https://github.com/GubernievS/AntiZapret-VPN.git", "/root/backup*.tar.gz"} {
		idx(s)
	}
}

// Настоящий bash проходит секцию вопросов setup.sh с нашими окружением и
// вводом: ни один вопрос не остаётся без ответа, ввод читается в нужном порядке.
func TestPlanDrivesRealQuestionSection(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("нет bash")
	}
	text := readSetupSh(t)
	start := strings.Index(text, "# Спрашиваем о настройках")
	end := strings.Index(text, "echo 'Installation, please wait...'")
	if start < 0 || end < start {
		t.Fatal("не нашлась секция вопросов")
	}
	section := text[start:end]
	script := "getent() { echo 1.2.3.4; }\nMTU=1300\n" + section +
		"\necho \"RESULT $MTU|$WARP_MTU|$OPENVPN_HOST|$WIREGUARD_HOST|$ROUTE_ALL|$DISCORD_INCLUDE\"\n"
	dir := t.TempDir()
	path := dir + "/q.sh"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	p := PlanSetupSh(fullSetup(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, path)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}, p.Env...)
	cmd.Stdin = strings.NewReader(p.Stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "RESULT 1380|1300|vpn.example.com|wg.example.com|y|y") {
		t.Fatalf("секция вопросов отработала не так:\n%s", out)
	}
}

// Значение вне шаблона зациклило бы вопрос на конце ввода: без таблицы-защиты
// bash крутился бы до предела времени. Проверка, что зацикливание реально.
func TestInvalidValueLoopsSetupShQuestion(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("нет bash")
	}
	script := "until [[ \"$X\" =~ (y|n) ]]; do\n\tread -rp 'q: ' -e -i y X\ndone\necho done\n"
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "-c", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "X=zzz"}
	cmd.Stdin = strings.NewReader("")
	if err := cmd.Run(); err == nil {
		t.Fatal("вопрос с неподходящим значением и пустым вводом завершился сам")
	}
	if ctx.Err() == nil {
		t.Fatal("ожидалось зависание до предела времени")
	}
}
