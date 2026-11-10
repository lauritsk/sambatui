#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
version=${1:-development}
case "$version" in *[!a-zA-Z0-9._-]*) echo 'Invalid version' >&2; exit 1;; esac
mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
    os=${target%/*}; arch=${target#*/}
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
        -ldflags="-s -w -X main.version=$version" -o "$stage/sambatui" ./cmd/sambatui
    cp LICENSE README.md config.example.json THIRD_PARTY_NOTICES.txt "$stage/"
    tar -C "$stage" -czf "dist/sambatui-${version}-${os}-${arch}.tar.gz" sambatui LICENSE README.md config.example.json THIRD_PARTY_NOTICES.txt
done
if command -v sha256sum >/dev/null 2>&1; then
    (cd dist && sha256sum "sambatui-${version}-"*.tar.gz > "sambatui-${version}-checksums.txt")
else
    (cd dist && shasum -a 256 "sambatui-${version}-"*.tar.gz > "sambatui-${version}-checksums.txt")
fi
