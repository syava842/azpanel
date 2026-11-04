#!/usr/bin/env bash
# Новый пароль администратора панели:
#   bash -c "$(curl -sL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/change_passwd.sh)" -- [логин]
# Без логина — первый администратор. Сессии и 2FA пользователя сбрасываются.
set -euo pipefail
bin=/opt/azpanel/bin/azpanel
[ "$(id -u)" = 0 ] || { echo "запустите от root" >&2; exit 1; }
[ -x "$bin" ] || { echo "azpanel не установлен" >&2; exit 1; }
args=(panel passwd)
[ $# -gt 0 ] && args+=(--user "$1")
if [ -t 0 ] || ! { : </dev/tty; } 2>/dev/null; then exec "$bin" "${args[@]}"; fi
exec "$bin" "${args[@]}" </dev/tty
