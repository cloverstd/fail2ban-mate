#!/bin/sh
set -eu
VERSION=${1:?usage: scripts/release.sh v0.1.0}
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$ROOT/artifacts"
for ARCH in amd64 arm64; do
  STAGE=$(mktemp -d)
  (cd "$ROOT/client" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$STAGE/fail2ban-mate-client" ./cmd/fail2ban-mate-client)
  mkdir -p "$STAGE/licenses"
  for MODULE in github.com/coder/websocket github.com/oschwald/maxminddb-golang golang.org/x/sys; do
    MODULE_DIR=$(cd "$ROOT/client" && go list -m -f '{{.Dir}}' "$MODULE")
    MODULE_LICENSE="$MODULE_DIR/LICENSE"
    if [ ! -f "$MODULE_LICENSE" ]; then MODULE_LICENSE="$MODULE_DIR/LICENSE.txt"; fi
    cp "$MODULE_LICENSE" "$STAGE/licenses/$(printf '%s' "$MODULE" | tr / _).txt"
  done
  cp "$(go env GOROOT)/LICENSE" "$STAGE/licenses/go.txt"
  cat "$STAGE"/licenses/* > "$ROOT/artifacts/THIRD_PARTY_LICENSES.txt"
  cp "$STAGE/fail2ban-mate-client" "$ROOT/artifacts/fail2ban-mate-client_linux_$ARCH"
  tar -czf "$ROOT/artifacts/fail2ban-mate-client_linux_$ARCH.tar.gz" -C "$STAGE" fail2ban-mate-client licenses -C "$ROOT" LICENSE THIRD_PARTY_NOTICES.md
  rm -rf "$STAGE"
done
(cd "$ROOT/artifacts" && sha256sum fail2ban-mate-client_linux_amd64 fail2ban-mate-client_linux_arm64 fail2ban-mate-client_linux_amd64.tar.gz fail2ban-mate-client_linux_arm64.tar.gz > SHA256SUMS)
