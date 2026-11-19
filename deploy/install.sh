#!/usr/bin/env bash
# Installs Lightning Driver as isolated system-level systemd services.
#
#   deploy/install.sh --ui-dist /path/to/lightning-driver-ui/dist
#
# The state directory (config, database, credentials) is never written to except for the proxy
# entry point, so re-running this after a rebuild upgrades the binary and the UI in place.
set -euo pipefail
# Published artifacts must be readable by the two service accounts regardless of the caller's umask.
umask 022

usage() {
  cat <<'USAGE'
Usage: deploy/install.sh --ui-dist DIR [options]

  --ui-dist DIR   Built UI assets (dist/) from the lightning-driver-ui repository. Required.
  --state DIR     State directory with config.toml [default: /var/lib/lightning-driver]
  --prefix DIR    Install prefix for the binary, proxy and assets [default: /usr/local]
  --port PORT     UI port; must match api.public_origin [default: 4400]
  --binary PATH   Release api-server binary built as your own user (required)
  --artifact-manifest PATH  Trusted release manifest for the supplied UI and optional binary
  --manifest-sha256 HEX     Manifest digest obtained through an independent trusted channel
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
MANIFEST=
MANIFEST_SHA256=
PORT=4400
RESTART=1

while [ $# -gt 0 ]; do
  case "$1" in
    --ui-dist) UI_DIST=${2:?}; shift 2 ;;
    --state) STATE=${2:?}; shift 2 ;;
    --prefix) PREFIX=${2:?}; shift 2 ;;
    --port) PORT=${2:?}; shift 2 ;;
    --binary) BINARY=${2:?}; shift 2 ;;
    --artifact-manifest) MANIFEST=${2:?}; shift 2 ;;
    --manifest-sha256) MANIFEST_SHA256=${2:?}; shift 2 ;;
    --no-restart) RESTART=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[ -n "$UI_DIST" ] || fail "--ui-dist is required"
[ -n "$BINARY" ] || fail "build as your own user first (cargo build --locked --release -p lightning-driver-api) and pass --binary target/release/api-server; this installer never builds as root"
[ -f "$UI_DIST/index.html" ] || fail "$UI_DIST does not look like a built UI (missing index.html)"
[ -n "$MANIFEST" ] && [ -n "$MANIFEST_SHA256" ] || fail "trusted --artifact-manifest and --manifest-sha256 are required"
# Resolve symlinks and parent components before the home-directory checks and unit rendering: a
# prefix spelled outside home but linked into it would otherwise slip past ProtectHome=yes.
PREFIX=$(realpath -m -- "$PREFIX") || fail "cannot resolve --prefix"
STATE=$(realpath -m -- "$STATE") || fail "cannot resolve --state"
command -v node >/dev/null || fail "node is required for artifact verification and the UI service"
node "$ROOT/deploy/verify-artifacts.mjs" "$MANIFEST" "$MANIFEST_SHA256" "$UI_DIST" "$BINARY" || fail "artifact verification failed"
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

SUPPLIED_BINARY=1
[ -x "$BINARY" ] || fail "$BINARY is not an executable api-server"
printf 'Using %s\n' "$BINARY"

printf 'Installing into %s and %s\n' "$LIB" "$SHARE"
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
mkdir "$STAGING/ui"
cp -R "$UI_DIST"/. "$STAGING/ui/"
# Readability is fixed on the private staging copy; never chmod a caller-provided directory tree.
chmod -R a+rX "$STAGING/ui"
install -m 755 "$BINARY" "$STAGING/api-server"
# Verify the private snapshot, not a mutable caller-owned path, before publication.
if [ -n "${MANIFEST:-}" ]; then
  cp "$MANIFEST" "$STAGING/manifest.json"
  VERIFIED_BINARY=
  if [ -n "${SUPPLIED_BINARY:-}" ]; then VERIFIED_BINARY=$STAGING/api-server; fi
  node "$ROOT/deploy/verify-artifacts.mjs" "$STAGING/manifest.json" "$MANIFEST_SHA256" "$STAGING/ui" "$VERIFIED_BINARY" || fail "staged artifact verification failed"
fi
install -d -m 755 "$LIB" "$(dirname "$SHARE")"
install -m 755 "$STAGING/api-server" "$LIB/api-server"
install -m 644 "$ROOT/deploy/server.mjs" "$LIB/server.mjs"
rm -rf "$SHARE"
cp -R "$STAGING/ui" "$SHARE"

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
