#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"

DURATION="${1:-10}"
LINK="${LINK:-radio}"
LISTEN_PORT="${LISTEN_PORT:-19000}"
IMAGE="${IMAGE:-ivvitc/nos3-64:20251107}"
CONTAINER="${CONTAINER:-cfs-benchmark-rf-link-fabricate}"
COSMOS_CONTAINER="${COSMOS_CONTAINER:-cosmos-openc3-operator-1}"
LOG="${LOG:-reports/rf_link_fabricate_screenshot.jsonl}"
OUT="${OUT:-reports/rf_link_fabricate_screenshot.out}"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
COSMOS_PID=""

mkdir -p reports

resolve_link() {
  case "$LINK" in
    debug)
      TARGET_NAME="${TARGET_NAME:-nos-fsw}"
      TARGET_PORT="${TARGET_PORT:-5012}"
      ;;
    radio)
      TARGET_NAME="${TARGET_NAME:-cryptolib}"
      TARGET_PORT="${TARGET_PORT:-6010}"
      ;;
    *)
      echo "Unsupported LINK=$LINK. Use LINK=debug or LINK=radio." >&2
      exit 2
      ;;
  esac

  TARGET_IP="${TARGET_IP:-$(docker exec "$COSMOS_CONTAINER" getent hosts "$TARGET_NAME" | awk '{print $1; exit}')}"
  if [[ -z "${TARGET_IP:-}" ]]; then
    echo "Could not resolve $TARGET_NAME from $COSMOS_CONTAINER." >&2
    echo "If you are using LINK=radio, confirm the cryptolib container is running." >&2
    exit 2
  fi

  COSMOS_IP="${COSMOS_IP:-$(docker exec "$COSMOS_CONTAINER" ip route get "$TARGET_IP" | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}')}"
  if [[ -z "${COSMOS_IP:-}" ]]; then
    COSMOS_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if .IPAddress}}{{.IPAddress}} {{end}}{{end}}' "$COSMOS_CONTAINER" | awk '{print $1}')"
  fi

  PROXY_HOST="${PROXY_HOST:-$(docker inspect -f '{{range .NetworkSettings.Networks}}{{println .IPAddress .Gateway}}{{end}}' "$COSMOS_CONTAINER" | awk -v ip="$COSMOS_IP" '$1 == ip {print $2; exit}')}"
  if [[ -z "${PROXY_HOST:-}" ]]; then
    PROXY_HOST="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' "$COSMOS_CONTAINER" | awk '{print $1}')"
  fi

  if [[ -z "${PROXY_HOST:-}" ]]; then
    echo "Could not discover Docker gateway for $COSMOS_CONTAINER." >&2
    exit 2
  fi

  COSMOS_PID="$(docker inspect -f '{{.State.Pid}}' "$COSMOS_CONTAINER")"
  if [[ -z "${COSMOS_PID:-}" || "$COSMOS_PID" == "0" ]]; then
    echo "Could not discover PID for $COSMOS_CONTAINER." >&2
    exit 2
  fi

  TARGET="$TARGET_IP:$TARGET_PORT"
}

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

resolve_link
trap cleanup EXIT

echo "[1/5] Cleaning old benchmark container"
cleanup

echo "[2/5] Resetting report files"
rm -f "$LOG" "$OUT"

echo "[3/5] Starting RF-LINK-007 fabricated packet benchmark"
echo "      link:        $LINK"
echo "      cosmos:      $COSMOS_CONTAINER ($COSMOS_IP, pid $COSMOS_PID)"
echo "      target name: $TARGET_NAME"
echo "      target:      $TARGET"
echo "      scenario:    scenarios/rf_link/link_fabricate.yaml"
echo "      duration:    ${DURATION}s"
echo "      log:         $LOG"
echo
echo "This scenario actively sends attacker-controlled payload bytes to the target."
echo "You do not need to send CFS_RADIO CFE_ES_NOOP for fabricate."
echo "Payload/count/interval are configured in scenarios/rf_link/link_fabricate.yaml."
echo

docker run --rm --name "$CONTAINER" \
  --privileged \
  --net=host \
  --pid=host \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  -v "$PWD:/bench" \
  -w /bench \
  "$IMAGE" \
  sh -lc "
    python3 -m cfs_security_benchmark.runner.run_rf_link \
      --scenario scenarios/rf_link/link_fabricate.yaml \
      --target '$TARGET' \
      --listen-port '$LISTEN_PORT' \
      --duration '$DURATION' \
      --log '$LOG'
    status=\$?
    chown \"\$HOST_UID:\$HOST_GID\" '$LOG' 2>/dev/null || true
    exit \$status
  " | tee "$OUT"

chown "$HOST_UID:$HOST_GID" "$OUT" "$LOG" 2>/dev/null || true

echo
echo "[4/5] Checking cleanup"
if docker ps --filter "name=$CONTAINER" --format '{{.Names}}' | grep -q .; then
  echo "WARNING: benchmark container is still running"
else
  echo "OK: no benchmark container is running"
fi

echo "OK: no DNAT rule is used for fabricate mode"

echo
echo "[5/5] Event summary"
python3 - "$LOG" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
counts = {}
destinations = {}
sizes = []

if path.exists():
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        event = item["event"]
        counts[event] = counts.get(event, 0) + 1
        if event == "packet_fabricated":
            destination = str(item.get("destination", "unknown"))
            destinations[destination] = destinations.get(destination, 0) + 1
            sizes.append(item.get("bytes"))

fabricated = counts.get("packet_fabricated", 0)

print("log:", path)
print("counts:", counts)
print("fabricate_destinations:", destinations)
if sizes:
    print("fabricated_payload_sizes:", sizes)

if fabricated > 0:
    print("RESULT: SUCCESS - fabricated packets were generated and sent.")
else:
    print("RESULT: NO FABRICATION OBSERVED - inspect scenario type and target reachability.")
PY
