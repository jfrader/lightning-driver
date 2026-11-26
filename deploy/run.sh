#!/bin/bash
set -euo pipefail
umask 077

if [[ $(id -u) = 0 ]]; then
  printf 'Run Lightning Driver as a non-root user\n' >&2
  exit 1
fi

APP_DIR=${APP_DIR:-/opt/lightning-driver}
STATE_DIR=${STATE_DIR:-/state}
export DIST=${DIST:-$APP_DIR/dist}
export HOST=${HOST:-127.0.0.1}
export PORT=${PORT:-4400}
export API_HOST=127.0.0.1
export API_PORT=8080

if [[ ! -e "$STATE_DIR/config.toml" ]]; then
  # noclobber prevents concurrent starts from replacing an operator's config.
  (set -o noclobber; cat "$APP_DIR/config.localhost.toml" > "$STATE_DIR/config.toml")
  printf 'Created %s/config.toml\n' "$STATE_DIR" >&2
fi

children=()
shutdown_signal=TERM
cleanup() {
  trap '' TERM INT
  if ((${#children[@]})); then
    kill -"$shutdown_signal" "${children[@]}" 2>/dev/null || true
    wait "${children[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'shutdown_signal=INT; exit 130' INT

"$APP_DIR/api-server" serve --config "$STATE_DIR/config.toml" &
children+=("$!")
node "$APP_DIR/server.mjs" &
children+=("$!")

# Even a clean child exit is a failure: both listeners must remain running.
wait -n "${children[@]}" || true
printf 'API or UI exited; stopping both processes\n' >&2
exit 1
