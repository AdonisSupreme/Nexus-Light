#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="txn-ussd-adapter"
PROCESS_MATCH="txn-ussd-adapter-0.0.1-SNAPSHOT.jar"
JAR_PATH="/srv/afc/txn-mobile/txn-ussd-adapter/lib/txn-ussd-adapter-0.0.1-SNAPSHOT.jar"
CONFIG_PATH="/srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml"
LOG_PATH="/srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log"
WORKING_DIR="/srv"
NOHUP_OUT="$WORKING_DIR/nohup.out"
JAVA_BIN="${JAVA_BIN:-java}"
READINESS_HOST="127.0.0.1"
READINESS_PORT="${READINESS_PORT:-}"
SYSTEMD_UNIT="sentinel-nexus-${SERVICE_NAME}"

matching_pids() {
  pgrep -f "$PROCESS_MATCH" || true
}

discover_readiness_port() {
  if [[ -n "$READINESS_PORT" ]]; then
    echo "$READINESS_PORT"
    return 0
  fi
  [[ -r "$CONFIG_PATH" ]] || return 0
  awk '
    /^[[:space:]]*server:/ { in_server=1; next }
    /^[^[:space:]]/ { in_server=0 }
    in_server && /^[[:space:]]*port:[[:space:]]*[0-9]+/ {
      gsub(/[^0-9]/, "", $0)
      print $0
      exit
    }
  ' "$CONFIG_PATH"
}

readiness_open() {
  local port
  port="$(discover_readiness_port)"
  [[ -z "$port" ]] && return 0
  timeout 1 bash -c ":</dev/tcp/${READINESS_HOST}/${port}" >/dev/null 2>&1
}

readiness_label() {
  local port
  port="$(discover_readiness_port)"
  [[ -z "$port" ]] && echo "readiness port not declared in $CONFIG_PATH" || echo "${READINESS_HOST}:${port}"
}

verify_launch_context() {
  local mismatched=0
  local seen=0

  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    seen=1
    local actual_cwd
    actual_cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
    if [[ "$actual_cwd" != "$WORKING_DIR" ]]; then
      echo "$SERVICE_NAME launch cwd mismatch for pid $pid: expected $WORKING_DIR, actual ${actual_cwd:-unknown}" >&2
      mismatched=1
    fi
  done < <(matching_pids)

  if [[ "$seen" -eq 0 ]]; then
    return 2
  fi
  return "$mismatched"
}

stop_existing_processes() {
  mapfile -t pids < <(matching_pids)
  if [[ "${#pids[@]}" -eq 0 ]]; then
    return 0
  fi

  echo "Replacing non-ready $SERVICE_NAME pid(s): ${pids[*]}"
  kill -TERM "${pids[@]}" 2>/dev/null || true
  for _ in {1..20}; do
    if ! pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done

  mapfile -t pids < <(matching_pids)
  if [[ "${#pids[@]}" -gt 0 ]]; then
    kill -KILL "${pids[@]}" 2>/dev/null || true
  fi
  for _ in {1..20}; do
    if ! pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done

  echo "$SERVICE_NAME could not replace stale process(es): $(pgrep -f -d ' ' "$PROCESS_MATCH")" >&2
  return 1
}

launch_service() {
  cd "$WORKING_DIR"
  echo "Starting $SERVICE_NAME from $(pwd -P) with config $CONFIG_PATH"

  systemctl reset-failed "${SYSTEMD_UNIT}.service" >/dev/null 2>&1 || true
  systemd-run \
    --unit="$SYSTEMD_UNIT" \
    --collect \
    --quiet \
    --property=Restart=no \
    /bin/bash -lc "cd '$WORKING_DIR' && exec '$JAVA_BIN' -jar '$JAR_PATH' --spring.config.location='$CONFIG_PATH' >>'$NOHUP_OUT' 2>&1"
  echo "$SERVICE_NAME launch delegated to systemd transient unit ${SYSTEMD_UNIT}.service"
}

if pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
  if verify_launch_context && readiness_open; then
    echo "$SERVICE_NAME already running from $WORKING_DIR with $(readiness_label): $(pgrep -f -d ' ' "$PROCESS_MATCH")"
    exit 0
  fi
  echo "$SERVICE_NAME has a matching process but is not in the manual-good ready state; Nexus will replace it."
  stop_existing_processes
fi

if [[ ! -r "$JAR_PATH" ]]; then
  echo "Jar path is not readable: $JAR_PATH" >&2
  exit 127
fi

if [[ ! -r "$CONFIG_PATH" ]]; then
  echo "Spring config path is not readable: $CONFIG_PATH" >&2
  exit 127
fi

if [[ ! -x "$JAVA_BIN" ]]; then
  if ! command -v "$JAVA_BIN" >/dev/null 2>&1; then
    echo "Java binary is not executable or resolvable: $JAVA_BIN" >&2
    exit 127
  fi
fi

if [[ ! -d "$WORKING_DIR" ]]; then
  echo "Working directory does not exist: $WORKING_DIR" >&2
  exit 127
fi

mkdir -p "$(dirname "$LOG_PATH")"
touch "$LOG_PATH"
touch "$NOHUP_OUT"

launch_service

for _ in {1..20}; do
  if pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
    if ! verify_launch_context; then
      exit 1
    fi
    echo "$SERVICE_NAME started. running_pid=$(pgrep -f -d ' ' "$PROCESS_MATCH") cwd=$WORKING_DIR"
    exit 0
  fi
  sleep 0.5
done

echo "$SERVICE_NAME did not become visible after start." >&2
exit 1
