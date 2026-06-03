#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="txn-mobile-ussd"
PROCESS_MATCH="txn-mobile-ussd-0.0.1-SNAPSHOT.jar"
JAR_PATH="/srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar"
CONFIG_PATH="/srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml"
LOG_PATH="/srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log"
WORKING_DIR="/srv"
NOHUP_OUT="$WORKING_DIR/nohup.out"
JAVA_BIN="${JAVA_BIN:-java}"

matching_pids() {
  pgrep -f "$PROCESS_MATCH" || true
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

if pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
  if verify_launch_context; then
    echo "$SERVICE_NAME already running from $WORKING_DIR: $(pgrep -f -d ' ' "$PROCESS_MATCH")"
    exit 0
  fi
  echo "$SERVICE_NAME is already running but not from the manual ATE launch directory. Stop it before starting from Nexus." >&2
  exit 1
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

cd "$WORKING_DIR"
echo "Starting $SERVICE_NAME from $(pwd -P) with config $CONFIG_PATH"
nohup "$JAVA_BIN" -jar "$JAR_PATH" --spring.config.location="$CONFIG_PATH" >>"$NOHUP_OUT" 2>&1 &
child_pid="$!"

for _ in {1..20}; do
  if pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
    if ! verify_launch_context; then
      exit 1
    fi
    echo "$SERVICE_NAME started. launcher_pid=$child_pid running_pid=$(pgrep -f -d ' ' "$PROCESS_MATCH")"
    exit 0
  fi
  sleep 0.5
done

echo "$SERVICE_NAME did not become visible after start. launcher_pid=$child_pid" >&2
exit 1
