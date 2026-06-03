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

if pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
  echo "$SERVICE_NAME already running: $(pgrep -f -d ' ' "$PROCESS_MATCH")"
  exit 0
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
nohup "$JAVA_BIN" -jar "$JAR_PATH" --spring.config.location="$CONFIG_PATH" >>"$NOHUP_OUT" 2>&1 &
child_pid="$!"

for _ in {1..20}; do
  if pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
    echo "$SERVICE_NAME started. launcher_pid=$child_pid running_pid=$(pgrep -f -d ' ' "$PROCESS_MATCH")"
    exit 0
  fi
  sleep 0.5
done

echo "$SERVICE_NAME did not become visible after start. launcher_pid=$child_pid" >&2
exit 1
