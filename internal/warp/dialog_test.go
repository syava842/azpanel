package warp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

type pipeRW struct {
	io.Reader
	io.Writer
}

// step — реплика поддельного установщика: вывод (часто приглашение без
// перевода строки), затем он ждёт ответ и эхом возвращает его, как терминал.
type step struct {
	out string
	// noRead — вывод без чтения ответа (обычная строка).
	noRead bool
}

// runScript прогоняет Dialog против поддельного установщика и возвращает
// журнал диалога и фактические ответы.
func runScript(t *testing.T, d *Dialog, steps []step) (log string, got []string, err error) {
	t.Helper()
	outR, outW := io.Pipe()
	inR, inW := io.Pipe()
	var logBuf bytes.Buffer
	d.Log = &logBuf
	d.Quiet, d.Unknown, d.Stall = 15*time.Millisecond, 150*time.Millisecond, 2*time.Second
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer outW.Close()
		br := bufio.NewReader(inR)
		for _, s := range steps {
			outW.Write([]byte(s.out))
			if s.noRead {
				continue
			}
			ansCh := make(chan string, 1)
			go func() {
				l, err := br.ReadString('\n')
				if err != nil {
					l = "<нет ответа>\n"
				}
				ansCh <- strings.TrimSuffix(l, "\n")
			}()
			select {
			case a := <-ansCh:
				got = append(got, a)
				if a == "<нет ответа>" {
					return
				}
				outW.Write([]byte(a + "\r\n")) // эхо терминала
			case <-time.After(700 * time.Millisecond):
				got = append(got, "<нет ответа>")
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = d.Run(ctx, pipeRW{outR, inW})
	inW.Close()
	<-done
	return logBuf.String(), got, err
}

const (
	cG = "\x1b[0;32m"
	cN = "\x1b[0m"
)

func TestDialogWarpMode(t *testing.T) {
	a := InstallAnswers{Mode: "warp", NoChatGPT: true, MTU: 1380}
	steps := []step{
		{out: cG + "== установка ==" + cN + "\r\n", noRead: true},
		{out: "Добавить Gemini в список доменов для WARP? (Y/n): "},
		{out: "Добавить ChatGPT в список доменов для WARP? (Y/n): "},
		{out: "Использовать фейковую подсеть 10.224.0.0/16 (рекомендуется)? [Y/n]: "},
		{out: " - Обнаружен MTU: " + cG + "1500" + cN + "\r\n", noRead: true},
		{out: "Использовать рекомендуемый MTU 1420? [Y/n] (или введите вручную от 1280 до 1500): "},
		{out: "Выбор [1-6] (по умолчанию 1): "},
		{out: " " + cG + "1." + cN + " /etc/wireguard/warp.conf\r\n", noRead: true},
		{out: "Выбор [по умолчанию 1]: "},
		{out: "Установить веб-панель? (y/N): "},
		{out: "готово\r\n", noRead: true},
	}
	log, got, err := runScript(t, a.NewDialog(nil), steps)
	if err != nil {
		t.Fatalf("%v\n%s", err, log)
	}
	want := []string{"y", "n", "Y", "1380", "1", "1", "n"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("ответы %q, ждали %q\n%s", got, want, log)
	}
	if strings.Contains(log, "\x1b[") {
		t.Fatal("в журнале остались управляющие последовательности")
	}
}

func TestDialogCustomSubnetAndForce(t *testing.T) {
	a := InstallAnswers{Mode: "warp", Subnet: "10.99.0.0/16", ForceSubnet: true}
	_, got, err := runScript(t, a.NewDialog(nil), []step{
		{out: "Использовать фейковую подсеть 10.224.0.0/16 (рекомендуется)? [Y/n]: "},
		{out: "Введите новую подсеть (например 10.10.0.0/16): "},
		{out: "Предупреждение: подсеть уже может использоваться.\r\nИспользовать её всё равно? [y/N]: "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "n|10.99.0.0/16|y" {
		t.Fatalf("ответы %q", got)
	}
	// Без force_subnet диалог останавливается, а не отвечает «y» наугад.
	a.ForceSubnet = false
	_, got, err = runScript(t, a.NewDialog(nil), []step{
		{out: "Использовать её всё равно? [y/N]: "},
	})
	if err == nil || !strings.Contains(err.Error(), "force_subnet") || len(got) != 1 || got[0] != "<нет ответа>" {
		t.Fatalf("err=%v got=%q", err, got)
	}
}

func TestDialogSlaveSecretsNotLogged(t *testing.T) {
	const link = "ss://c2VjcmV0cGFzcw@203.0.113.7:8444#donor"
	a := InstallAnswers{Mode: "slave", SlaveLink: link}
	log, got, err := runScript(t, a.NewDialog(nil), []step{
		{out: "Выбор [1-6] (по умолчанию 1): "},
		{out: "Ссылка или адрес донора (Enter — назад): "},
		{out: "- Режим: Slave\r\n", noRead: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "2|"+link {
		t.Fatalf("ответы %q", got)
	}
	// Эхо терминала вернуло ссылку в вывод, но в журнале её быть не должно.
	if strings.Contains(log, "c2VjcmV0cGFzcw") || strings.Contains(log, link) {
		t.Fatalf("секрет в журнале:\n%s", log)
	}
}

func TestDialogWGMenusByContext(t *testing.T) {
	w := &WGManual{Endpoint: "198.51.100.5:51820", Address: "172.28.8.3/32", PrivateKey: "ПРИВАТНЫЙ-КЛЮЧ-1", PublicKey: "ПУБЛИЧНЫЙ-КЛЮЧ-1"}
	a := InstallAnswers{Mode: "wg", WG: w}
	log, got, err := runScript(t, a.NewDialog(nil), []step{
		// Найдены конфиги: меню с «M.».
		{out: "Найдено конфигов: 1\r\n 1. /root/a.conf\r\n M. Ввести данные вручную\r\n R. Обновить список\r\nВыбор: "},
		{out: "Endpoint (IP:порт): "},
		{out: "Address (например 172.28.8.3/32): "},
		{out: "PrivateKey: "},
		{out: "PublicKey: "},
		{out: "PresharedKey (Enter — нет): "},
		{out: "PersistentKeepalive [15]: "},
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, log)
	}
	if strings.Join(got, "|") != "M|198.51.100.5:51820|172.28.8.3/32|ПРИВАТНЫЙ-КЛЮЧ-1|ПУБЛИЧНЫЙ-КЛЮЧ-1||" {
		t.Fatalf("ответы %q", got)
	}
	if strings.Contains(log, "ПРИВАТНЫЙ-КЛЮЧ-1") {
		t.Fatal("закрытый ключ в журнале")
	}
	// Конфигов нет: меню с «1.».
	_, got, err = runScript(t, a.NewDialog(nil), []step{
		{out: "WireGuard-конфиги не найдены.\r\n 1. Ввести данные вручную\r\n 2. Положите .conf\r\n 0. Выбрать другой режим\r\nВыбор: "},
	})
	if err != nil || got[0] != "1" {
		t.Fatalf("err=%v got=%q", err, got)
	}
}

func TestDialogUnknownPromptStops(t *testing.T) {
	a := InstallAnswers{Mode: "warp"}
	log, got, err := runScript(t, a.NewDialog(nil), []step{
		{out: "Добавить Gemini в список доменов для WARP? (Y/n): "},
		{out: "Включить телеметрию Cloudflare? [y/N]: "},
		{out: "никогда не будет выведено\r\n", noRead: true},
	})
	if !errors.Is(err, ErrUnknownPrompt) || !strings.Contains(err.Error(), "телеметрию") {
		t.Fatalf("err=%v", err)
	}
	if len(got) != 2 || got[1] != "<нет ответа>" {
		t.Fatalf("на неизвестный вопрос ушёл ответ: %q", got)
	}
	if !strings.Contains(log, "Включить телеметрию") {
		t.Fatalf("вопрос не попал в журнал:\n%s", log)
	}
}

func TestDialogRepeatedPromptStops(t *testing.T) {
	a := InstallAnswers{Mode: "warp"}
	var steps []step
	for i := 0; i < 5; i++ {
		steps = append(steps, step{out: "Добавить Gemini в список доменов для WARP? (Y/n): "})
	}
	_, got, err := runScript(t, a.NewDialog(nil), steps)
	if err == nil || !strings.Contains(err.Error(), "повторяет") || len(got) < 3 {
		t.Fatalf("err=%v got=%q", err, got)
	}
}

func TestDialogMissingAnswerStops(t *testing.T) {
	a := InstallAnswers{Mode: "vless"} // ProxyLink не задан
	_, got, err := runScript(t, a.NewDialog(nil), []step{{out: "Ссылка (Enter — назад): "}})
	if err == nil || !strings.Contains(err.Error(), "proxy_link") || got[0] != "<нет ответа>" {
		t.Fatalf("err=%v got=%q", err, got)
	}
}

func TestAnswersValidate(t *testing.T) {
	bad := map[string]InstallAnswers{
		"режим":           {Mode: "x"},
		"подсеть":         {Mode: "warp", Subnet: "10.0.0.5/16"},
		"октет":           {Mode: "warp", Subnet: "10.300.0.0/16"},
		"MTU":             {Mode: "warp", MTU: 1000},
		"slave пусто":     {Mode: "slave"},
		"slave без ключа": {Mode: "slave", SlaveLink: "203.0.113.7"},
		"wg пусто":        {Mode: "wg"},
		"vless схема":     {Mode: "vless", ProxyLink: "http://x"},
		"hy2 схема":       {Mode: "hy2", ProxyLink: "vless://x"},
		"ovpn":            {Mode: "openvpn"},
		"перевод строки":  {Mode: "vless", ProxyLink: "vless://a\nb"},
	}
	for name, a := range bad {
		if a.Validate() == nil {
			t.Errorf("%s: ждали отказ", name)
		}
	}
	good := []InstallAnswers{
		{Mode: "warp"}, {Mode: "warp", Subnet: "10.10.0.0/16", MTU: 1400},
		{Mode: "slave", SlaveLink: "ss://x@h:1"}, {Mode: "slave", SlaveLink: "203.0.113.7", SlaveKey: "k"},
		{Mode: "wg", WG: &WGManual{Endpoint: "h:1", Address: "a", PrivateKey: "p", PublicKey: "q"}},
		{Mode: "wg", WGConfIndex: 1}, {Mode: "hy2", ProxyLink: "hy2://x"}, {Mode: "openvpn", OvpnPath: "/root/a.ovpn"},
	}
	for _, a := range good {
		if err := a.Validate(); err != nil {
			t.Errorf("%+v: %v", a, err)
		}
	}
}

// Все вопросы реального install.sh покрыты таблицей: каждый read -p скрипта
// должен находить правило. Проверка ловит расхождение при обновлении копии.
func TestRulesCoverInstallScript(t *testing.T) {
	data, err := os.ReadFile("testdata/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`read -r (?:-s )?-p "([^"]*)"`)
	a := InstallAnswers{Mode: "warp", WG: &WGManual{}}
	d := a.NewDialog(nil)
	// Подстановки переменных bash в приглашениях.
	repl := strings.NewReplacer("$SUBNET", "10.224.0.0/16", "$REC_MTU", "1420")
	ctxFor := map[string]string{"Выбор: ": "M. Ввести данные вручную"}
	n := 0
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		prompt := repl.Replace(m[1])
		if prompt == "" {
			continue // read -p "" — «нажмите Enter»: правила нет намеренно
		}
		n++
		r, _ := d.match(prompt, ctxFor[prompt])
		if r == nil && prompt == "Выбор: " {
			r, _ = d.match(prompt, "1. Ввести данные вручную")
		}
		if r == nil {
			t.Errorf("нет правила для вопроса установщика: %q", prompt)
		}
	}
	if n < 20 {
		t.Fatalf("найдено всего %d вопросов — разбор install.sh сломан", n)
	}
}

// Управляющие символы в ответах превратились бы в сигналы и стирание строки
// на псевдотерминале: любой байт ниже 0x20 и 0x7f — отказ.
func TestAnswersRejectControlCharacters(t *testing.T) {
	for _, c := range []string{"\x03", "\x04", "\x15", "\x1a", "\x1b", "\t", "\x7f", "\r", "\n", "\x00"} {
		a := InstallAnswers{Mode: "vless", ProxyLink: "vless://u@h:1" + c + "x"}
		if err := a.Validate(); err == nil {
			t.Errorf("символ %q принят в ссылке", c)
		}
		a = InstallAnswers{Mode: "wg", WG: &WGManual{Endpoint: "h:1", Address: "10.0.0.2/32", PrivateKey: "k" + c, PublicKey: "p"}}
		if err := a.Validate(); err == nil {
			t.Errorf("символ %q принят в ключе WireGuard", c)
		}
		a = InstallAnswers{Mode: "openvpn", OvpnPath: "/root/a.ovpn", OvpnPass: "pw" + c}
		if err := a.Validate(); err == nil {
			t.Errorf("символ %q принят в пароле openvpn", c)
		}
	}
	ok := InstallAnswers{Mode: "vless", ProxyLink: "vless://u@h:1?a=b#имя"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("обычная ссылка с юникодом отклонена: %v", err)
	}
}
