#!/usr/bin/env bash
# Обновление azpanel до последнего релиза:
#   bash -c "$(curl -sL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/update.sh)"
# Обёртка над `azpanel update`: подпись, бэкап, миграция конфига и откат — там.
# Аргументы передаются как есть (--check, --yes).
set -euo pipefail
bin=/opt/azpanel/bin/azpanel
[ "$(id -u)" = 0 ] || { echo "azpanel update: запустите от root" >&2; exit 1; }
[ -x "$bin" ] || { echo "azpanel не установлен: setup.sh" >&2; exit 1; }
if [ -t 0 ] || ! { : </dev/tty; } 2>/dev/null; then exec "$bin" update "$@"; fi
exec "$bin" update "$@" </dev/tty
