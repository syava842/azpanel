package antizapret

import (
	"context"
	"os"
	"os/exec"
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
		"FLOOD_PROTECTION": "n", "CLEAR_DNS_CACHE": "n", "CLEAR_HOSTS": "n",
		"WARP_ENDPOINT": "162.159.192.7:500",
		"DEFAULT_IP":    "203.0.113.5", "ANTIZAPRET_OUT_IP": "", "VPN_OUT_IP": "203.0.113.6",
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
	if p.Stdin != "1380\n162.159.192.7:500\nvpn.example.com\nwg.example.com\n203.0.113.5\n\n203.0.113.6\n" {
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
	if env["CLIENT_ISOLATION"] != "y" || env["OPENVPN_PATCH"] != "1" || !strings.HasPrefix(p.Stdin, "1400\n162.159.192.7:500\nnew.example.com\n") {
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
	if problems := CheckSetupShQuestions(readSetupSh(t)); len(problems) > 0 {
		t.Fatalf("setup.sh и таблица вопросов расходятся:\n%s", strings.Join(problems, "\n"))
	}
}

// Сверка в коде ловит то, что меняет upstream: новый вопрос, другой шаблон,
// переставленный ввод.
func TestCheckSetupShQuestionsCatchesDrift(t *testing.T) {
	text := readSetupSh(t)
	cases := map[string]string{
		"новый вопрос":        strings.Replace(text, "until [[ \"$ROUTE_ALL\" =~ (y|n) ]]", "until [[ \"$ROUTE_ALL\" =~ (y|n|a) ]]", 1),
		"нет вопроса":         strings.Replace(text, "until [[ \"$TORRENT_GUARD\" =~ (y|n) ]]", "until [[ \"$NEW_ASK\" =~ (y|n) ]]", 1),
		"ввод переставлен":    strings.Replace(text, "OPENVPN_HOST\ndo", "OPENVPN_HOST_X\ndo", 1),
		"адрес выхода сменён": strings.Replace(text, "-e ANTIZAPRET_OUT_IP\n", "-e ANTIZAPRET_OUT_IP_X\n", 1),
	}
	for name, mod := range cases {
		if mod == text {
			t.Fatalf("%s: подмена не сработала — поправьте тест", name)
		}
		if len(CheckSetupShQuestions(mod)) == 0 {
			t.Errorf("%s: расхождение не замечено", name)
		}
	}
	if len(CheckSetupShQuestions("#!/bin/bash\necho hi\n")) == 0 {
		t.Error("чужой скрипт признан совпавшим")
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
	if !(idx("-i \"$MTU\" MTU") < idx("WARP_MTU") && idx("OPENVPN_HOST\ndo") < idx("WIREGUARD_HOST\ndo") &&
		idx("WIREGUARD_HOST\ndo") < idx("-e DEFAULT_IP\n") && idx("-e DEFAULT_IP\n") < idx("-e ANTIZAPRET_OUT_IP\n") &&
		idx("-e ANTIZAPRET_OUT_IP\n") < idx("-e VPN_OUT_IP\n")) {
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
	bash := workingBash(t)
	text := readSetupSh(t)
	start := strings.Index(text, "# Спрашиваем о настройках")
	end := strings.Index(text, "echo 'Installation, please wait...'")
	if start < 0 || end < start {
		t.Fatal("не нашлась секция вопросов")
	}
	section := text[start:end]
	script := "getent() { echo 1.2.3.4; }\nMTU=1300\n" + section +
		"\necho \"RESULT $MTU|$WARP_MTU|$OPENVPN_HOST|$WIREGUARD_HOST|$ROUTE_ALL|$DISCORD_INCLUDE|$DEFAULT_IP|$ANTIZAPRET_OUT_IP|$VPN_OUT_IP\"\n"
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
	if !strings.Contains(string(out), "RESULT 1380|1300|vpn.example.com|wg.example.com|y|y|203.0.113.5||203.0.113.6") {
		t.Fatalf("секция вопросов отработала не так:\n%s", out)
	}
}

// Значение вне шаблона зациклило бы вопрос на конце ввода: без таблицы-защиты
// bash крутился бы до предела времени. Проверка, что зацикливание реально.
func TestInvalidValueLoopsSetupShQuestion(t *testing.T) {
	bash := workingBash(t)
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

// workingBash — путь к bash, который действительно запускается. На Windows
// «bash» из System32 — заглушка WSL без дистрибутива: тесты, которым нужен
// настоящий bash, там пропускаются, а не падают.
func workingBash(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("нет bash")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-c", "echo ok").Output()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Skipf("bash %s не запускается (%v)", path, err)
	}
	return path
}

// Свежий setup.sh пишет вопросы-заглушки пустыми (DISCORD_INCLUDE= и т. п.):
// пустое значение переносится, а не отвергается.
func TestPlanSetupShEmptyPassthrough(t *testing.T) {
	m := fullSetup()
	for _, k := range shPassthrough {
		m[k] = ""
	}
	p := PlanSetupSh(m, nil)
	if len(p.Problems) != 0 {
		t.Fatalf("пустые ключи отвергнуты: %v", p.Problems)
	}
	env := envMap(p.Env)
	for _, k := range shPassthrough {
		if v, ok := env[k]; !ok || v != "" {
			t.Errorf("%s: в окружении %q, %v", k, v, ok)
		}
	}
	m["DISCORD_INCLUDE"] = "$(id)"
	if p := PlanSetupSh(m, nil); len(p.Problems) == 0 {
		t.Fatal("значение с подстановкой оболочки должно отвергаться")
	}
}

// 17.11.2026: GeoHide переехал с 7 на 6; адрес WARP — строкой ввода, пустой
// или «хост:порт» без знаков оболочки.
func TestPlanSetupShDNSAndWarpEndpoint(t *testing.T) {
	m := fullSetup()
	m["ANTIZAPRET_DNS"] = "7"
	p := PlanSetupSh(m, nil)
	if len(p.Problems) != 0 || envMap(p.Env)["ANTIZAPRET_DNS"] != "6" {
		t.Fatalf("7 -> 6: %v %v", p.Problems, p.Env)
	}
	m = fullSetup()
	delete(m, "WARP_ENDPOINT")
	if p := PlanSetupSh(m, nil); len(p.Problems) != 0 || p.Stdin != "1380\n\nvpn.example.com\nwg.example.com\n203.0.113.5\n\n203.0.113.6\n" {
		t.Fatalf("без адреса WARP: %v %q", p.Problems, p.Stdin)
	}
	for _, bad := range []string{"$(id):500", "a b:1", "host", "host:port", "x:1\ny"} {
		m := fullSetup()
		m["WARP_ENDPOINT"] = bad
		if p := PlanSetupSh(m, nil); len(p.Problems) == 0 || strings.Contains(p.Stdin, bad) {
			t.Errorf("WARP_ENDPOINT=%q принят: %q", bad, p.Stdin)
		}
	}
}

// 26.11.2026: адреса входа/выхода DEFAULT_IP, ANTIZAPRET_OUT_IP, VPN_OUT_IP —
// последние три строки ввода; значение берётся из setup, пусто — автоопределение;
// небезопасное значение отвергается и в ввод не попадает.
func TestPlanSetupShOutIPs(t *testing.T) {
	p := PlanSetupSh(fullSetup(), nil)
	lines := strings.Split(strings.TrimRight(p.Stdin, "\n"), "\n")
	if len(lines) != len(SetupShStdinKeys) {
		t.Fatalf("строк ввода %d, ключей %d", len(lines), len(SetupShStdinKeys))
	}
	tail := SetupShStdinKeys[len(SetupShStdinKeys)-3:]
	if strings.Join(tail, ",") != "DEFAULT_IP,ANTIZAPRET_OUT_IP,VPN_OUT_IP" {
		t.Fatalf("порядок ввода: %v", SetupShStdinKeys)
	}
	m := fullSetup()
	delete(m, "DEFAULT_IP")
	if p := PlanSetupSh(m, nil); len(p.Problems) != 0 || !strings.HasSuffix(p.Stdin, "\n\n\n203.0.113.6\n") {
		t.Fatalf("без DEFAULT_IP: %v %q", p.Problems, p.Stdin)
	}
	for _, k := range []string{"DEFAULT_IP", "ANTIZAPRET_OUT_IP", "VPN_OUT_IP"} {
		for _, bad := range []string{"$(id)", "1.2.3.4;rm", "a b", "::1", "x\ny"} {
			m := fullSetup()
			m[k] = bad
			if p := PlanSetupSh(m, nil); len(p.Problems) == 0 || strings.Contains(p.Stdin, bad) {
				t.Errorf("%s=%q принят: %q", k, bad, p.Stdin)
			}
		}
		if !SetupShTakes(k) {
			t.Errorf("SetupShTakes(%s) = false", k)
		}
	}
}
