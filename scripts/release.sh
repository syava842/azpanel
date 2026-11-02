#!/usr/bin/env bash
# Сборка релиза azpanel: архивы, SHA256SUMS, подпись ed25519.
#   scripts/release.sh <версия> [--publish] [--allow-dirty]
# Без --publish результат только в dist/<версия>/; с ним - gh release create.
# Закрытый ключ: $AZPANEL_RELEASE_KEY или ~/.azpanel-release.key (вне репозитория).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd -P)

version=""; publish=0; dirty=0
for a in "$@"; do
	case "$a" in
	--publish) publish=1 ;;
	--allow-dirty) dirty=1 ;;
	-*) echo "release: неизвестный флаг $a" >&2; exit 2 ;;
	*) version=$a ;;
	esac
done
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || {
	echo "использование: release.sh <версия, напр. 1.2.3> [--publish] [--allow-dirty]" >&2; exit 2; }
if [[ $dirty = 1 && $publish = 1 ]]; then
	echo "release: --allow-dirty несовместим с --publish" >&2; exit 2
fi

key=${AZPANEL_RELEASE_KEY:-$HOME/.azpanel-release.key}
[[ -f $key ]] || { echo "release: нет закрытого ключа $key (azpanel-sign keygen)" >&2; exit 1; }
keyabs=$(cd "$(dirname "$key")" && pwd -P)/$(basename "$key")
case "$keyabs" in
"$root"/*) echo "release: закрытый ключ лежит внутри рабочего дерева ($keyabs) - уберите его" >&2; exit 1 ;;
esac

if [[ $dirty = 0 ]]; then
	[[ -z $(git status --porcelain) ]] || { echo "release: рабочее дерево не чистое" >&2; exit 1; }
	git rev-parse -q --verify "refs/tags/v$version" >/dev/null || {
		echo "release: нет тега v$version" >&2; exit 1; }
	[[ $(git rev-parse HEAD) = $(git rev-parse "v$version^{commit}") ]] || {
		echo "release: тег v$version указывает не на HEAD" >&2; exit 1; }
fi

out="dist/$version"
rm -rf "$out"; mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

for arch in amd64 arm64; do
	d="$stage/$arch"; mkdir -p "$d"
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "$d/azpanel" ./cmd/azpanel
	tar -C "$d" -czf "$out/azpanel_${version}_linux_${arch}.tar.gz" azpanel
done

(cd "$out" && for f in *.tar.gz; do sha256sum "$f"; done | sed -E 's/^([0-9a-f]+) [ *]/\1  /' > SHA256SUMS)
go run ./cmd/azpanel-sign sign "$key" "$out/SHA256SUMS"

# Описание релиза: раздел версии из CHANGELOG.md, иначе "Текущие изменения".
notes="$out/NOTES.md"
awk -v v="$version" '
	/^## /{ if (on) exit; if ($2==v || $2=="["v"]" || $0 ~ /^## Текущие изменения/) {on=1; next} }
	on' CHANGELOG.md > "$notes"
[[ -s $notes ]] || echo "Релиз $version" > "$notes"

echo "release: готово, файлы в $out:"
ls -l "$out"

if [[ $publish = 1 ]]; then
	gh release create "v$version" "$out"/*.tar.gz "$out/SHA256SUMS" "$out/SHA256SUMS.sig" \
		--title "azpanel $version" --notes-file "$notes"
else
	echo "release: без --publish релиз не опубликован"
fi
