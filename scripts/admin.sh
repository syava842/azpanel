#!/usr/bin/env bash
# Меню azpanel: состояние, пользователи, смена пароля (сгенерировать или
# задать свой), новый администратор, обновление, перезапуск служб:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/admin.sh)"
# То же на сервере — команда azpanel без аргументов.
set -euo pipefail
bin=/opt/azpanel/bin/azpanel
[ "$(id -u)" = 0 ] || { echo "запустите от root" >&2; exit 1; }
[ -x "$bin" ] || { echo "azpanel не установлен" >&2; exit 1; }
rc=0
if [ -t 0 ] || ! { : </dev/tty; } 2>/dev/null; then "$bin" menu || rc=$?; else "$bin" menu </dev/tty || rc=$?; fi
# Код 2 — «нет такой команды»: меню появилось в 0.1.2.
if [ "$rc" = 2 ]; then
	echo "В этой версии ($("$bin" version)) меню нет. Обновите:" >&2
	echo "  bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/update.sh)\"" >&2
fi
exit "$rc"
