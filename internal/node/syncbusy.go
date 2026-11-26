package node

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// azScripts — скрипты AntiZapret, которые по ходу работы переписывают файлы
// набора синхронизации: пока идёт любой из них, манифест показал бы
// промежуточное состояние (недописанный config/*.txt, половину PKI).
var azScripts = map[string]bool{
	"doall.sh": true, "setup.sh": true, "client.sh": true, "parse.sh": true, "update.sh": true,
}

// shells — интерпретаторы скриптов AntiZapret. Скрипт, запущенный по
// shebang, ядро тоже показывает как «/bin/bash /root/antizapret/doall.sh».
var shells = map[string]bool{"bash": true, "sh": true, "dash": true}

// wrappers — программы-обёртки перед интерпретатором («nice -n 19 bash …»,
// «sudo bash …»); valued — их ключи со значением отдельным аргументом.
var (
	wrappers = map[string]bool{"sudo": true, "nice": true, "ionice": true, "timeout": true, "env": true, "nohup": true, "setsid": true, "stdbuf": true}
	valued   = map[string]bool{"-n": true, "-c": true, "-u": true, "-g": true, "-p": true, "-s": true, "-k": true, "-i": true, "-o": true, "-e": true}
)

// scriptOf — имя скрипта AntiZapret, который выполняет процесс с
// аргументами args, или "". Скрипт считается выполняемым, только если
// argv[0] (после обёрток) — интерпретатор, а первый его аргумент-не-ключ —
// путь к скрипту из azScripts. Редактор или пейджер с тем же файлом
// (nano client.sh, less doall.sh) скриптом не считается; «bash -c …» —
// тоже (это не файл скрипта).
func scriptOf(args []string) string {
	i := 0
	for i < len(args) && wrappers[filepath.Base(args[i])] {
		w := filepath.Base(args[i])
		i++
	opts:
		for i < len(args) {
			a := args[i]
			switch {
			case valued[a]:
				i += 2
			case strings.HasPrefix(a, "-"):
				i++
			case w == "env" && strings.Contains(a, "="):
				i++
			case w == "timeout" && strings.Trim(a, "0123456789.smhd") == "":
				i++
				w = "" // длительность одна
			default:
				break opts
			}
		}
	}
	if i >= len(args) || !shells[filepath.Base(args[i])] {
		return ""
	}
	for i++; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c":
			return ""
		case a == "-o" || a == "-O" || a == "+o" || a == "+O":
			i++
		case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+"):
		default:
			if base := filepath.Base(a); azScripts[base] {
				return base
			}
			return ""
		}
	}
	return ""
}

// ProcScripts ищет в procDir (обычно /proc) процесс, выполняющий один из
// скриптов AntiZapret (scriptOf); возвращает имя скрипта или "". Нет
// каталога или нет прав на чужой cmdline — процесс пропускается.
func ProcScripts(procDir string) string {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		if name == "" || strings.Trim(name, "0123456789") != "" {
			continue // не pid
		}
		data, err := os.ReadFile(filepath.Join(procDir, name, "cmdline"))
		if err != nil || len(data) == 0 {
			continue
		}
		var args []string
		for _, a := range bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0}) {
			args = append(args, string(a))
		}
		if s := scriptOf(args); s != "" {
			return s
		}
	}
	return ""
}

// setupMarkerMax — каталог установки старше этого считается остатком
// оборванной установки, а не идущей.
const setupMarkerMax = 2 * time.Hour

// SetupInProgress — идёт установка AntiZapret: штатно setup.sh запускается
// как «bash <(wget …)», и в /proc он виден только как «bash /dev/fd/63».
// Признак — каталог dir (/tmp/antizapret): setup.sh клонирует туда
// репозиторий, раскладывает файлы набора по системе и в конце удаляет
// каталог. После сбоя каталог может остаться, поэтому старше
// setupMarkerMax он не в счёт.
func SetupInProgress(dir string, now time.Time) bool {
	fi, err := os.Stat(dir)
	return err == nil && fi.IsDir() && now.Sub(fi.ModTime()) < setupMarkerMax
}

// azScriptRunning — ScriptRunning агента: скрипт AntiZapret в /proc или
// идущая установка AntiZapret.
func azScriptRunning() string {
	if s := ProcScripts("/proc"); s != "" {
		return s
	}
	if SetupInProgress("/tmp/antizapret", time.Now()) {
		return "setup.sh"
	}
	return ""
}

// syncBusy: набор файлов узла сейчас меняется — идёт задача агента,
// обновление AntiZapret или скрипт AntiZapret, запущенный мимо агента
// (консоль, cron). Возвращает причину для ответа или "".
func (a *API) syncBusy() string {
	if a.AZ != nil && a.AZ.Active() {
		return "идёт обновление AntiZapret"
	}
	if a.Tasks != nil {
		if cur, ok := a.Tasks.Running(); ok {
			return "идёт задача " + taskKindName(cur.Kind)
		}
	}
	if a.ScriptRunning != nil {
		if name := a.ScriptRunning(); name != "" {
			return "запущен " + name + " AntiZapret"
		}
	}
	return ""
}

// syncBusyReply отвечает 423, если набор сейчас меняется: панель повторит
// сверку следующим проходом (nodeapi.ErrBusy).
func (a *API) syncBusyReply(w http.ResponseWriter) bool {
	if why := a.syncBusy(); why != "" {
		writeErr(w, http.StatusLocked, "набор файлов сейчас меняется ("+why+") — повторите после окончания")
		return true
	}
	return false
}
