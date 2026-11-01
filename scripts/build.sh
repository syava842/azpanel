#!/usr/bin/env bash
# Сборка azpanel под linux: dist/azpanel-linux-<arch>.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
mkdir -p dist
for arch in amd64 arm64; do
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$version" \
		-o "dist/azpanel-linux-$arch" ./cmd/azpanel
done
ls -l dist
