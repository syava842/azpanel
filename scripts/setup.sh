#!/usr/bin/env bash
# Установка azpanel одной командой:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/setup.sh)"
# Скачивает последний релиз под архитектуру сервера, проверяет подпись
# SHA256SUMS ключом релизов и сумму архива, затем запускает мастер
# `azpanel install`. Аргументы передаются мастеру как есть, например:
#   bash -c "$(curl -fsSL .../setup.sh)" -- --non-interactive --mode node
# Версия: AZPANEL_VERSION=1.2.3 (по умолчанию последняя).
set -euo pipefail

REPO=syava842/azpanel
# Открытый ключ релизов (тот же, что internal/update/pubkey.go).
PUBKEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAKVItcPAHlFlFBhxN8LKupG+lRQD0wyGn8seVvaMpYdk=
-----END PUBLIC KEY-----'

die() { echo "azpanel setup: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "запустите от root"
[ "$(uname -s)" = Linux ] || die "нужен Linux"
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "архитектура $(uname -m) не поддерживается" ;;
esac

if [ -x /opt/azpanel/bin/azpanel ]; then
	echo "azpanel уже установлен. Обновить:"
	echo "  bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/update.sh)\""
	echo "Переустановить с другими ответами: /opt/azpanel/bin/azpanel install"
	exit 0
fi

# Терминал есть, только если /dev/tty открывается: под ssh без -t и в cron
# файл существует, но открыть его нельзя.
have_tty() { [ -t 0 ] || { : </dev/tty; } 2>/dev/null; }
# with_tty запускает команду с вводом с терминала, если stdin — не он.
with_tty() {
	if [ -t 0 ] || ! have_tty; then "$@"; else "$@" </dev/tty; fi
}
# ask читает ответ: с терминала, иначе из stdin. Не прочитан — код 1, и
# вызывающий не должен выбирать действие за человека.
ask() {
	local a
	if [ ! -t 0 ] && have_tty; then
		read -r -p "$1" a </dev/tty || return 1
	else
		read -r -p "$1" a || return 1
	fi
	printf '%s' "$a"
}

# azpanel — панель к AntiZapret-VPN GubernievS: без него ставится только
# агент прокси (VPS с proxy.sh). Признак установки — тот же, что у мастера.
AZ_SETUP=https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup.sh
if [ ! -f /root/antizapret/client.sh ] && [ "${AZPANEL_SKIP_ANTIZAPRET:-}" != 1 ]; then
	echo "AntiZapret-VPN (github.com/GubernievS/AntiZapret-VPN) на этом сервере не найден."
	echo "  1) установить AntiZapret-VPN сейчас (его установщик в конце перезагрузит сервер)"
	echo "  2) продолжить без него — только агент прокси"
	echo "  3) выйти"
	choice=$(ask 'Выбор [1]: ') || die "ответ не получен; без вопросов: AZPANEL_SKIP_ANTIZAPRET=1"
	case "$choice" in
	"" | 1)
		command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
		echo "После перезагрузки запустите эту же команду ещё раз — она продолжит установку azpanel."
		with_tty bash <(curl -fsSL "$AZ_SETUP")
		exit $?
		;;
	2) ;;
	*) exit 0 ;;
	esac
fi

need=""
for c in curl tar sha256sum openssl; do
	command -v "$c" >/dev/null || need="$need $c"
done
if [ -n "$need" ]; then
	echo "Ставлю:$need"
	apt-get update -qq && apt-get install -y -qq curl tar coreutils openssl >/dev/null ||
		die "не удалось поставить:$need"
fi

version=${AZPANEL_VERSION:-}
if [ -z "$version" ]; then
	# Редирект latest -> .../tag/vX.Y.Z: без API и его лимитов.
	url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") ||
		die "GitHub недоступен"
	version=${url##*/v}
fi
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "не удалось узнать последнюю версию (получено: $version)"

# Не /tmp: на части VPS он смонтирован с noexec.
tmp=$(mktemp -d /root/.azpanel-setup.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$REPO/releases/download/v$version"
archive="azpanel_${version}_linux_${arch}.tar.gz"
echo "Скачиваю azpanel $version ($arch)..."
for f in "$archive" SHA256SUMS SHA256SUMS.sig; do
	curl -fsSL -o "$tmp/$f" "$base/$f" || die "не скачан $f"
done

printf '%s\n' "$PUBKEY" > "$tmp/pub.pem"
openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin \
	-in "$tmp/SHA256SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null 2>&1 ||
	die "подпись SHA256SUMS неверна: релиз не от автора, установка остановлена"
(cd "$tmp" && grep -E "^[0-9a-f]{64}  $archive\$" SHA256SUMS | sha256sum -c --quiet -) ||
	die "сумма $archive не совпала"
tar -C "$tmp" -xzf "$tmp/$archive" azpanel
chmod 755 "$tmp/azpanel"
echo "Подпись и сумма проверены."

# Мастер копирует себя в /opt/azpanel/bin и ставит ссылку /usr/local/bin/azpanel.
# Вопросы читаются с терминала, даже если скрипт пришёл через трубу.
with_tty "$tmp/azpanel" install "$@"
