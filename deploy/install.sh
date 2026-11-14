#!/usr/bin/env bash
# Installs Lightning Driver as isolated system-level systemd services.
#
#   deploy/install.sh --ui-dist /path/to/lightning-driver-ui/dist
#
# The state directory (config, database, credentials) is never written to except for the proxy
# entry point, so re-running this after a rebuild upgrades the binary and the UI in place.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: deploy/install.sh --ui-dist DIR [options]

  --ui-dist DIR   Built UI assets (dist/) from the lightning-driver-ui repository. Required.
  --state DIR     State directory with config.toml [default: /var/lib/lightning-driver]
  --prefix DIR    Install prefix for the binary, proxy and assets [default: /usr/local]
  --port PORT     UI port; must match api.public_origin [default: 4400]
  --binary PATH   Install this api-server binary instead of building the workspace
  --no-restart    Install and enable the units without restarting running services
  -h, --help      This text
USAGE
}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE=/var/lib/lightning-driver
PREFIX=/usr/local
UI_DIST=
BINARY=
PORT=4400
RESTART=1

while [ $# -gt 0 ]; do
  case "$1" in
    --ui-dist) UI_DIST=${2:?}; shift 2 ;;
    --state) STATE=${2:?}; shift 2 ;;
    --prefix) PREFIX=${2:?}; shift 2 ;;
    --port) PORT=${2:?}; shift 2 ;;
    --binary) BINARY=${2:?}; shift 2 ;;
    --no-restart) RESTART=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[ -n "$UI_DIST" ] || fail "--ui-dist is required"
[ -f "$UI_DIST/index.html" ] || fail "$UI_DIST does not look like a built UI (missing index.html)"
[ -f "$STATE/config.toml" ] || fail "$STATE/config.toml is missing; write the configuration first"
command -v systemctl >/dev/null || fail "systemctl is required"
[ "$(id -u)" = 0 ] || fail "installation requires root for isolated system services"
for account in lightning-driver-api lightning-driver-ui; do
  id "$account" >/dev/null 2>&1 || fail "create the system account $account before installation"
done
[ "$(id -u lightning-driver-api)" != "$(id -u lightning-driver-ui)" ] || fail "service accounts must have distinct UIDs"
case "$PREFIX/" in /home/*|/root/*) fail "prefix must be outside protected home directories" ;; esac
case "$STATE/" in /home/*|/root/*) fail "state must be outside protected home directories" ;; esac

LIB=$PREFIX/lib/lightning-driver
SHARE=$PREFIX/share/lightning-driver/dist
UNIT_DIR=/etc/systemd/system

printf 'Building the release API\n'
if [ -n "$BINARY" ]; then
  [ -x "$BINARY" ] || fail "$BINARY is not an executable api-server"
  printf 'Using %s\n' "$BINARY"
else
  (cd "$ROOT" && CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2} cargo build --release -p api-server)
  BINARY=$ROOT/target/release/api-server
fi

printf 'Installing into %s and %s\n' "$LIB" "$SHARE"
install -d -m 755 "$LIB" "$(dirname "$SHARE")"
install -m 755 "$BINARY" "$LIB/api-server"
install -m 644 "$ROOT/deploy/server.mjs" "$LIB/server.mjs"
rm -rf "$SHARE"
cp -R "$UI_DIST" "$SHARE"

printf 'Rendering units into %s\n' "$UNIT_DIR"
install -d -m 755 "$UNIT_DIR"
for unit in lightning-driver-api lightning-driver-ui; do
  sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@STATE@|$STATE|g" -e "s|@PORT@|$PORT|g" \
    "$ROOT/deploy/$unit.service.in" > "$UNIT_DIR/$unit.service"
done

systemctl daemon-reload
systemctl enable lightning-driver-api.service lightning-driver-ui.service
if [ "$RESTART" = 1 ]; then
  systemctl restart lightning-driver-api.service lightning-driver-ui.service
fi

cat <<DONE

Installed. Services: lightning-driver-api.service, lightning-driver-ui.service.
  systemctl status lightning-driver-api
  journalctl -u lightning-driver-api -f
  http://localhost:$PORT

Enroll the first sign-in method on this host:
  runuser -u lightning-driver-api -- $LIB/api-server auth enrollment --config $STATE/config.toml
DONE
