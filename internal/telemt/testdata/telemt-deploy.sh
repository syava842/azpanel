#!/bin/sh
# Развёртывание telemt MTProxy на пустом хосте — в том виде, в каком он
# работает на 192.0.2.185.
#
# За основу взят установщик GubernievS/Telegram-Proxy (те же параметры
# тюнинга), но добавлено три вещи, которых там нет и отсутствие которых
# однажды уже положило прокси:
#   1. приём ключа ЦЕЛИКОМ — строкой "ee...", или ссылкой "tg://proxy?...".
#      Скрипт сам разбирает её на секрет и домен. Вставлять полный ключ
#      в поле секрета руками больше не нужно и не получится;
#   2. починка уже испорченного конфига (секрет в 48 символов вместо 32);
#   3. проверка после запуска: служба жива, порт слушается, а собранная
#      сервером ссылка совпадает с ожидаемой. Без этого падающая служба
#      с Restart=always выглядит как исправная.
#
# Запуск:  bash telemt-deploy.sh [ключи]
#
#   --key <строка>     ключ целиком: "ee<32hex><домен в hex>" или ссылка
#                      tg://proxy?server=...&port=...&secret=ee...
#                      Из него берутся и секрет, и домен, и порт.
#   --secret <32hex>   секрет отдельно (альтернатива --key)
#   --domain <домен>   домен маскировки TLS         (по умолчанию 2gis.ru)
#   --port <порт>      порт прокси                  (по умолчанию 902)
#   --version <верс.>  версия telemt                (по умолчанию последняя)
#   --new-secret       сгенерировать новый секрет, старый не сохранять
#   --no-verify-domain не проверять доступность домена маскировки
#
# Без --key и --secret скрипт сохраняет секрет, домен и порт уже
# установленного telemt, а на пустом хосте генерирует новый секрет.

set -eu

# ---- параметры по умолчанию ----------------------------------------------
PORT=902
DOMAIN=2gis.ru
USER_NAME=user
VERSION=""
KEY=""
SECRET=""
NEW_SECRET=0
VERIFY_DOMAIN=1

# Лимит одновременных TCP-подключений и делитель буферов.
# 4000 при делителе 16 — расчёт автора установщика на 1 ГБ оперативной памяти.
MAX_CONNECTIONS=4000
BUF_DIVISOR=16

BINARY_PATH=/usr/local/bin/telemt
CONFIG_DIR=/etc/telemt
CONFIG_FILE=$CONFIG_DIR/config.toml
LIBC=gnu

die() { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

# ---- разбор аргументов ----------------------------------------------------
while [ $# -gt 0 ]; do
	case "$1" in
		--key)     [ $# -ge 2 ] || die "--key без значения";     KEY=$2;     shift 2 ;;
		--secret)  [ $# -ge 2 ] || die "--secret без значения";  SECRET=$2;  shift 2 ;;
		--domain)  [ $# -ge 2 ] || die "--domain без значения";  DOMAIN=$2;  shift 2 ;;
		--port)    [ $# -ge 2 ] || die "--port без значения";    PORT=$2;    shift 2 ;;
		--version) [ $# -ge 2 ] || die "--version без значения"; VERSION=$2; shift 2 ;;
		--new-secret)       NEW_SECRET=1;    shift ;;
		--no-verify-domain) VERIFY_DOMAIN=0; shift ;;
		-h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*)         die "неизвестный аргумент: $1" ;;
	esac
done

[ "$(id -u)" = 0 ] || die "нужны права root"

# ---- зависимости ----------------------------------------------------------
missing=
for t in curl openssl xxd tar; do
	command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
if [ -n "$missing" ]; then
	info "ставлю недостающее:$missing"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	# shellcheck disable=SC2086
	apt-get install -y -qq $missing >/dev/null
fi

is_hex32() {
	case "$1" in
		*[!0-9a-f]*) return 1 ;;
	esac
	[ "${#1}" -eq 32 ]
}

# Разбор ключа: "ee<32hex><домен hex>", "dd<32hex>", голые 32hex или ссылка.
# Меняет SECRET, DOMAIN и, если ссылка содержала порт, PORT.
parse_key() {
	k=$1
	case "$k" in
		*secret=*)
			p=$(printf '%s' "$k" | sed -n 's/.*[?&]port=\([0-9]\{1,5\}\).*/\1/p')
			[ -n "$p" ] && PORT=$p
			k=$(printf '%s' "$k" | sed -n 's/.*[?&]secret=\([0-9A-Fa-f]\{1,\}\).*/\1/p')
			[ -n "$k" ] || die "в ссылке не нашёлся secret="
			;;
	esac
	k=$(printf '%s' "$k" | tr 'ABCDEF' 'abcdef' | tr -d '[:space:]')
	case "$k" in
		*[!0-9a-f]*) die "ключ содержит не-hex символы: $k" ;;
	esac
	case "$k" in
		ee*)
			[ "${#k}" -gt 34 ] || die "ключ ee-вида короче ожидаемого: ${#k} символов"
			SECRET=$(printf '%s' "$k" | cut -c3-34)
			dhex=$(printf '%s' "$k" | cut -c35-)
			DOMAIN=$(printf '%s' "$dhex" | xxd -r -p)
			[ -n "$DOMAIN" ] || die "не удалось раскодировать домен из ключа"
			;;
		dd*)
			[ "${#k}" -eq 34 ] || die "ключ dd-вида должен быть 34 символа"
			SECRET=$(printf '%s' "$k" | cut -c3-34)
			info "ключ dd-вида (secure), домен маскировки берётся из --domain"
			;;
		*)
			is_hex32 "$k" || die "секрет должен быть ровно 32 hex-символа, получено ${#k}"
			SECRET=$k
			;;
	esac
}

# ---- откуда берём секрет и домен ------------------------------------------
if [ -n "$KEY" ]; then
	parse_key "$KEY"
	info "ключ разобран: секрет 32 hex, домен $DOMAIN, порт $PORT"
elif [ -n "$SECRET" ]; then
	SECRET=$(printf '%s' "$SECRET" | tr 'ABCDEF' 'abcdef')
	is_hex32 "$SECRET" || die "--secret должен быть ровно 32 hex-символа"
elif [ "$NEW_SECRET" = 0 ] && [ -f "$CONFIG_FILE" ]; then
	# Сохраняем то, что уже настроено.
	old_raw=$(sed -n 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)
	old_domain=$(sed -n 's/^[[:space:]]*tls_domain[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)
	old_port=$(awk -F= '/^\[server\]/{s=1;next} /^\[/{s=0} s && $1 ~ /^[[:space:]]*port[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$CONFIG_FILE")
	[ -n "$old_domain" ] && DOMAIN=$old_domain
	[ -n "$old_port" ] && PORT=$old_port
	if [ -n "$old_raw" ] && is_hex32 "$old_raw"; then
		SECRET=$old_raw
		info "секрет и настройки взяты из $CONFIG_FILE"
	elif [ -n "$old_raw" ]; then
		# Тот самый случай: в поле секрета лежит ключ целиком.
		info "в конфиге секрет длиной ${#old_raw} символов вместо 32 — чиню разбором"
		parse_key "$old_raw"
		info "восстановлено: секрет 32 hex, домен $DOMAIN"
	fi
fi
[ -n "$SECRET" ] || { SECRET=$(openssl rand -hex 16); info "сгенерирован новый секрет"; }

is_hex32 "$SECRET" || die "внутренняя ошибка: секрет не 32 hex"
case "$PORT" in
	*[!0-9]*|"") die "порт должен быть числом: $PORT" ;;
esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "порт вне диапазона: $PORT"
case "$DOMAIN" in
	*[!a-zA-Z0-9.-]*|"") die "домен выглядит неправильно: $DOMAIN" ;;
esac

DOMAIN_HEX=$(printf '%s' "$DOMAIN" | xxd -p | tr -d '\n')
EXPECTED_KEY="ee${SECRET}${DOMAIN_HEX}"

# ---- домен маскировки должен быть живым -----------------------------------
# Если он не отвечает, прокси поднимется, но маскировка будет нерабочей —
# ошибки при этом не будет нигде.
if [ "$VERIFY_DOMAIN" = 1 ]; then
	getent hosts "$DOMAIN" >/dev/null 2>&1 || die "домен $DOMAIN не резолвится (обойти: --no-verify-domain)"
	curl -sS --connect-timeout 10 -o /dev/null "https://$DOMAIN/" 2>/dev/null \
		|| info "ВНИМАНИЕ: $DOMAIN не ответил по https — маскировка может работать плохо"
fi

# ---- скачивание бинарника с проверкой контрольной суммы -------------------
ARCH=$(uname -m)
case "$ARCH" in
	x86_64|aarch64) ;;
	*) die "неподдерживаемая архитектура: $ARCH" ;;
esac
ASSET="telemt-${ARCH}-linux-${LIBC}.tar.gz"
if [ -n "$VERSION" ]; then
	BASE="https://github.com/telemt/telemt/releases/download/${VERSION}"
else
	BASE="https://github.com/telemt/telemt/releases/latest/download"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

info "качаю $BASE/$ASSET"
curl -fL --connect-timeout 30 --retry 3 "$BASE/$ASSET" -o "$TMP/$ASSET" || die "не удалось скачать бинарник"

if curl -fsL --connect-timeout 20 "$BASE/${ASSET}.sha256" -o "$TMP/sum" 2>/dev/null; then
	want=$(awk '{print $1}' "$TMP/sum")
	have=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
	[ "$want" = "$have" ] || die "контрольная сумма не сошлась: ждали $want, получили $have"
	info "контрольная сумма сошлась"
else
	info "ВНИМАНИЕ: файл .sha256 недоступен, проверить сумму нечем"
fi

systemctl disable --now telemt >/dev/null 2>&1 || true

tar -xzf "$TMP/$ASSET" -C "$TMP" || die "архив не распаковался"
[ -f "$TMP/telemt" ] || die "в архиве нет файла telemt"
install -m 0755 "$TMP/telemt" "$BINARY_PATH"
info "установлен $BINARY_PATH версии $("$BINARY_PATH" --version 2>&1 | head -1)"

# ---- конфигурация ---------------------------------------------------------
[ -f "$CONFIG_FILE" ] && cp -a "$CONFIG_FILE" "$CONFIG_FILE.bak-$(date +%Y%m%d-%H%M%S)"

"$BINARY_PATH" --init \
	--port "$PORT" \
	--domain "$DOMAIN" \
	--secret "$SECRET" \
	--user "$USER_NAME" \
	--config-dir "$CONFIG_DIR" \
	--no-start >/dev/null 2>&1 || die "telemt --init завершился с ошибкой"

[ -f "$CONFIG_FILE" ] || die "telemt --init не создал $CONFIG_FILE"

# Задать ключ в конфиге: заменить существующий или вставить после секции.
# $1 — ключ, $2 — значение, $3 — секция, в которую вставлять, если ключа нет.
set_kv() {
	kv_key=$1; kv_val=$2; kv_section=$3
	if grep -q "^${kv_key} = " "$CONFIG_FILE"; then
		sed -i "s|^${kv_key} = .*|${kv_key} = ${kv_val}|" "$CONFIG_FILE"
	else
		grep -q "^\[${kv_section}\]" "$CONFIG_FILE" || printf '\n[%s]\n' "$kv_section" >> "$CONFIG_FILE"
		sed -i "/^\[${kv_section}\]/a ${kv_key} = ${kv_val}" "$CONFIG_FILE"
	fi
}

BUF_C2S=$((65536 / BUF_DIVISOR))
BUF_S2C=$((262144 / BUF_DIVISOR))
BUF_CRYPTO=$((262144 / BUF_DIVISOR))

set_kv beobachten                      false              general
set_kv log_level                       '"silent"'         general
set_kv direct_relay_copy_buf_c2s_bytes "$BUF_C2S"         general
set_kv direct_relay_copy_buf_s2c_bytes "$BUF_S2C"         general
set_kv crypto_pending_buffer           "$BUF_CRYPTO"      general
set_kv stun_use                        false              network
set_kv ipv6                            false              network
set_kv max_connections                 "$MAX_CONNECTIONS" server
set_kv unknown_sni_action              '"mask"'           censorship
set_kv core_enabled                    false              general.telemetry
set_kv user_enabled                    false              general.telemetry
set_kv client_keepalive                15                 timeouts
set_kv client_ack                      60                 timeouts

# IPv6-слушатель не нужен: ipv6 отключён выше.
sed -i 's/^listen_addr_ipv6 = "::"/#listen_addr_ipv6 = "::"/' "$CONFIG_FILE"
sed -i '/^\[\[server\.listeners\]\]$/{N;N;s|^\[\[server\.listeners\]\]\nip = "::"\nport = \([0-9]\{1,\}\)|#[[server.listeners]]\n#ip = "::"\n#port = \1|;}' "$CONFIG_FILE"

# WEB-API выключаем прицельно внутри его секции.
grep -q '^\[server\.api\]' "$CONFIG_FILE" || printf '\n[server.api]\nenabled = false\n' >> "$CONFIG_FILE"
sed -i '/^\[server\.api\]/,/^\[/{s/^enabled *=.*/enabled = false/}' "$CONFIG_FILE"

mkdir -p /var/lib/telemt

# ---- запуск ---------------------------------------------------------------
systemctl daemon-reload
systemctl enable --now telemt >/dev/null 2>&1 || die "служба не запустилась"

# ---- проверка -------------------------------------------------------------
# Главное место скрипта. Restart=always маскирует падения: служба в цикле
# перезапусков не попадает в systemctl --failed и выглядит рабочей.
info "проверяю"
sleep 6

state=$(systemctl is-active telemt 2>/dev/null || true)
if [ "$state" != active ]; then
	printf '\n'
	journalctl -u telemt --no-pager -n 15 2>/dev/null || true
	die "служба не в состоянии active (сейчас: $state)"
fi

restarts=$(systemctl show telemt -p NRestarts --value 2>/dev/null || echo 0)
[ "${restarts:-0}" -eq 0 ] || die "служба перезапускалась $restarts раз — она падает, смотрите journalctl -u telemt"

if command -v ss >/dev/null 2>&1; then
	ss -tln 2>/dev/null | grep -q ":${PORT} " || die "порт $PORT не слушается"
	info "порт $PORT слушается"
fi

# Сервер печатает собранную ссылку при старте — сверяем её с ожидаемой.
shown=$(journalctl -u telemt --no-pager --since '-2min' 2>/dev/null \
	| sed -n 's/.*secret=\([0-9a-fA-F]*\).*/\1/p' | tail -1 | tr 'ABCDEF' 'abcdef')
if [ -n "$shown" ]; then
	[ "$shown" = "$EXPECTED_KEY" ] \
		|| die "сервер отдаёт ключ $shown, а ожидался $EXPECTED_KEY"
	info "ссылка сервера совпала с ожидаемой"
else
	info "ссылку в журнале не видно, сверка по журналу пропущена"
fi

IP=$(ip route get 1.2.3.4 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)
[ -n "$IP" ] || IP=$(hostname -I 2>/dev/null | awk '{print $1}')

printf '\n'
info "готово"
printf '\n'
printf 'Ссылка для Telegram:\n'
printf '  tg://proxy?server=%s&port=%s&secret=%s\n\n' "$IP" "$PORT" "$EXPECTED_KEY"
printf 'Она же для пересылки:\n'
printf '  https://t.me/proxy?server=%s&port=%s&secret=%s\n\n' "$IP" "$PORT" "$EXPECTED_KEY"
printf 'Домен маскировки: %s\n' "$DOMAIN"
printf 'Конфиг:           %s\n' "$CONFIG_FILE"
printf 'Журнал:           journalctl -u telemt -f\n'
