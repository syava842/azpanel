#!/usr/bin/env bash
# Обновление azpanel до последнего релиза:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/update.sh)"
# Обёртка над `azpanel update`: подпись, бэкап, миграция конфига и откат — там.
# Аргументы передаются как есть (--check, --yes).
# Установку версий до 0.1.2 из /opt/azpanel после обновления переносит в
# /root/azpanel (`azpanel relocate`), к остальным сервисам AntiZapret.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "azpanel update: запустите от root" >&2; exit 1; }
bin=/root/azpanel/bin/azpanel
[ -x "$bin" ] || bin=/opt/azpanel/bin/azpanel
[ -x "$bin" ] || { echo "azpanel не установлен: setup.sh" >&2; exit 1; }
# Вопросы читаются с терминала, даже если скрипт пришёл через трубу.
with_tty() {
	if [ -t 0 ] || ! { : </dev/tty; } 2>/dev/null; then "$@"; else "$@" </dev/tty; fi
}
with_tty "$bin" update "$@"
case " $* " in *" --check "*) exit 0 ;; esac
if [ -d /opt/azpanel/etc ] && [ ! -e /root/azpanel ]; then
	echo
	with_tty /opt/azpanel/bin/azpanel relocate --yes
fi
