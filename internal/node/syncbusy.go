package node

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// azScripts — скрипты AntiZapret, которые по ходу работы переписывают файлы
// набора синхронизации: пока идёт любой из них, манифест показал бы
// промежуточное состояние (недописанный config/*.txt, половину PKI).
var azScripts = map[string]bool{
	"doall.sh": true, "setup.sh": true, "client.sh": true, "parse.sh": true, "update.sh": true,
}

// ProcScripts ищет в procDir (обычно /proc) процесс, запущенный одним из
// скриптов AntiZapret; возвращает имя скрипта или "". Смотрятся первые
// аргументы командной строки («bash /root/antizapret/doall.sh», «sudo bash
// client.sh 1 bob»): дальше идут аргументы самого скрипта. Нет каталога или
// нет прав на чужой cmdline — процесс пропускается.
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
		args := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
		if len(args) > 4 {
			args = args[:4]
		}
		for _, a := range args {
			if base := filepath.Base(string(a)); azScripts[base] {
				return base
			}
		}
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
