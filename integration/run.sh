#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
case "$(go env GOARCH)" in amd64|arm64) ;; *) echo 'Unsupported integration-test architecture' >&2; exit 1;; esac
name="sambatui-go-lab-$$"
bin=$(mktemp -d)
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$bin"; }
trap cleanup EXIT HUP INT TERM
image=${SAMBATUI_TEST_SERVER_IMAGE:-sambatui-go-test-server}
if [ -z "${SAMBATUI_TEST_SERVER_IMAGE:-}" ]; then docker build -t "$image" integration; fi
for package in dnsrpc directory; do
    GOOS=linux CGO_ENABLED=0 go test -c -o "$bin/$package.test" "./internal/$package"
done
GOOS=linux CGO_ENABLED=0 go test -c -o "$bin/integration.test" ./integration
GOOS=linux CGO_ENABLED=0 go build -trimpath -o "$bin/sambatui" ./cmd/sambatui
# No published ports, no host network, no mounted credentials, no capabilities,
# no application/source mount; only our static native binaries enter the lab.
docker run -d --name "$name" --network none --hostname dc \
    -e SAMBATUI_SERVER_FIXTURE=DISPOSABLE "$image" >/dev/null
ready=0
for i in $(seq 1 90); do
    [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || break
    if docker exec "$name" test -f /tmp/native-ad/ready; then ready=1; break; fi
    sleep 1
done
if [ "$ready" != 1 ]; then docker logs "$name"; exit 1; fi
for file in "$bin"/*; do docker cp "$file" "$name:/tmp/native-ad/$(basename "$file")"; done
for package in dnsrpc directory integration; do
    docker exec -e SAMBATUI_DISPOSABLE_TEST=YES "$name" \
        "/tmp/native-ad/$package.test" -test.v -test.timeout 120s
done
docker exec -e SAMBATUI_SERVER=dc.lab.invalid -e SAMBATUI_DOMAIN=lab.invalid \
    -e SAMBATUI_USER=Administrator@lab.invalid -e SAMBATUI_PASSWORD='Disposable-test-only_42!' \
    -e SAMBATUI_CA_FILE=/tmp/native-ad/cert.pem \
    "$name" /tmp/native-ad/sambatui -config /tmp/native-ad/cli.json -check
