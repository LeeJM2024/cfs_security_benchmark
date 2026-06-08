#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"

DURATION="${1:-120}"
LINK="${LINK:-radio}"
LISTEN_PORT="${LISTEN_PORT:-19000}"
IMAGE="${IMAGE:-ivvitc/nos3-64:20251107}"
CONTAINER="${CONTAINER:-cfs-benchmark-rf-link-reorder}"
COSMOS_CONTAINER="${COSMOS_CONTAINER:-cosmos-openc3-operator-1}"
LOG="${LOG:-reports/rf_link_reorder_screenshot.jsonl}"
OUT="${OUT:-reports/rf_link_reorder_screenshot.out}"
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

cleanup_rule() {
  docker run --rm --privileged --net=host --pid=host "$IMAGE" \
    nsenter --mount=/proc/1/ns/mnt --net="/proc/$COSMOS_PID/ns/net" /usr/sbin/iptables -t nat -D OUTPUT \
      -p udp -d "$TARGET_IP" --dport "$TARGET_PORT" \
      -j DNAT --to-destination "$PROXY_HOST:$LISTEN_PORT" >/dev/null 2>&1 || true
}

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  cleanup_rule
}

resolve_link
trap cleanup EXIT

echo "[1/5] Cleaning old benchmark container/rule"
cleanup

echo "[2/5] Resetting report files"
rm -f "$LOG" "$OUT"

echo "[3/5] Starting RF-LINK-008 packet reorder benchmark"
echo "      link:        $LINK"
echo "      cosmos:      $COSMOS_CONTAINER ($COSMOS_IP, pid $COSMOS_PID)"
echo "      target name: $TARGET_NAME"
echo "      target:      $TARGET"
echo "      proxy host:  $PROXY_HOST"
echo "      listen port: $LISTEN_PORT"
echo "      redirect:    COSMOS netns OUTPUT DNAT"
echo "      scenario:    scenarios/rf_link/link_reorder.yaml"
echo "      duration:    ${DURATION}s"
echo "      log:         $LOG"
echo
echo "For LINK=radio, send CFS_RADIO CFE_ES_NOOP at least 4 times after socket_bound appears."
echo "For LINK=debug, send CFS CFE_ES_NOOP at least 4 times after socket_bound appears."
echo "Reorder window size is configured in scenarios/rf_link/link_reorder.yaml."
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
    nsenter --mount=/proc/1/ns/mnt --net='/proc/$COSMOS_PID/ns/net' /usr/sbin/iptables -t nat -A OUTPUT \
      -p udp -d '$TARGET_IP' --dport '$TARGET_PORT' \
      -j DNAT --to-destination '$PROXY_HOST:$LISTEN_PORT'
    python3 -m cfs_security_benchmark.runner.run_rf_link \
      --scenario scenarios/rf_link/link_reorder.yaml \
      --target '$TARGET' \
      --listen-port '$LISTEN_PORT' \
      --duration '$DURATION' \
      --log '$LOG'
    status=\$?
    nsenter --mount=/proc/1/ns/mnt --net='/proc/$COSMOS_PID/ns/net' /usr/sbin/iptables -t nat -D OUTPUT \
      -p udp -d '$TARGET_IP' --dport '$TARGET_PORT' \
      -j DNAT --to-destination '$PROXY_HOST:$LISTEN_PORT' >/dev/null 2>&1 || true
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

if docker run --rm --privileged --net=host --pid=host "$IMAGE" \
  nsenter --mount=/proc/1/ns/mnt --net="/proc/$COSMOS_PID/ns/net" /usr/sbin/iptables -t nat -S OUTPUT \
  | grep -E "$TARGET_IP|$LISTEN_PORT|$PROXY_HOST" >/dev/null; then
  echo "WARNING: matching iptables rule still exists"
else
  echo "OK: no matching iptables rule remains"
fi

echo
echo "[5/5] Event summary"
python3 - "$LOG" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
counts = {}
buffer_sizes = []
reordered_counts = []

if path.exists():
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        event = item["event"]
        counts[event] = counts.get(event, 0) + 1
        if event == "packet_buffered_for_reorder":
            buffer_sizes.append(item.get("buffer_size"))
        elif event == "packets_reordered":
            reordered_counts.append(item.get("count"))

received = counts.get("packet_received", 0)
forwarded = counts.get("packet_forwarded", 0)
reordered = counts.get("packets_reordered", 0)

print("log:", path)
print("counts:", counts)
if buffer_sizes:
    print("buffer_sizes:", buffer_sizes)
if reordered_counts:
    print("reordered_batch_sizes:", reordered_counts)

if received >= 4 and reordered > 0 and forwarded >= 4:
    print("RESULT: SUCCESS - packets were buffered, reordered, and forwarded.")
elif received > 0 and received < 4:
    print("RESULT: BUFFERED ONLY - send at least 4 matching NOOP commands to trigger reorder.")
elif received >= 4:
    print("RESULT: CAPTURED BUT REORDER NOT OBSERVED - inspect window_size and event log.")
else:
    print("RESULT: NOT CAPTURED - run again and send matching NOOP commands after socket_bound appears.")
PY
