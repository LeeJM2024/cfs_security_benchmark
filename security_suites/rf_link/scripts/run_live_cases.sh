#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/../.."

LINK="${LINK:-radio}"
DIRECTION="${DIRECTION:-both}"
LISTEN_PORT="${LISTEN_PORT:-19000}"
SCENARIO="${SCENARIO:-}"

if [[ "$DIRECTION" != "uplink" && "$DIRECTION" != "downlink" && "$DIRECTION" != "both" ]]; then
  echo "Unsupported DIRECTION=$DIRECTION. Use uplink, downlink, or both." >&2
  exit 2
fi

args=(
  python3 -m benchmark_engine.rf_link.live_runner
  --link "$LINK"
  --direction "$DIRECTION"
  --listen-port "$LISTEN_PORT"
)

if [[ -n "$SCENARIO" ]]; then
  args+=(--scenario "$SCENARIO")
else
  args+=(--all)
fi

exec "${args[@]}" "$@"
