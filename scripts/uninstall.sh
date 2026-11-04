#!/usr/bin/env bash
# Удаление azpanel:
#   bash -c "$(curl -sL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/uninstall.sh)"
# Обёртка над `azpanel uninstall`: перед удалением бэкап AntiZapret; AntiZapret
# и его клиенты остаются. Аргументы как есть: --yes, --purge (и /opt/azpanel),
# --skip-backup.
set -euo pipefail
bin=/opt/azpanel/bin/azpanel
[ "$(id -u)" = 0 ] || { echo "azpanel uninstall: запустите от root" >&2; exit 1; }
[ -x "$bin" ] || { echo "azpanel не установлен" >&2; exit 1; }
if [ -t 0 ] || ! { : </dev/tty; } 2>/dev/null; then exec "$bin" uninstall "$@"; fi
exec "$bin" uninstall "$@" </dev/tty
