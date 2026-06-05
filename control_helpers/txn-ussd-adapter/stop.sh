#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="txn-ussd-adapter"
PROCESS_MATCH="txn-ussd-adapter-0.0.1-SNAPSHOT.jar"
SYSTEMD_UNIT="sentinel-nexus-${SERVICE_NAME}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop "${SYSTEMD_UNIT}.service" >/dev/null 2>&1 || true
fi

mapfile -t pids < <(pgrep -f "$PROCESS_MATCH" || true)
if [[ "${#pids[@]}" -eq 0 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reset-failed "${SYSTEMD_UNIT}.service" >/dev/null 2>&1 || true
  fi
  echo "$SERVICE_NAME already stopped."
  exit 0
fi

echo "Stopping $SERVICE_NAME pid(s): ${pids[*]}"
kill -TERM "${pids[@]}" 2>/dev/null || true

for _ in {1..20}; do
  if ! pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
      systemctl reset-failed "${SYSTEMD_UNIT}.service" >/dev/null 2>&1 || true
    fi
    echo "$SERVICE_NAME stopped after SIGTERM."
    exit 0
  fi
  sleep 0.5
done

mapfile -t pids < <(pgrep -f "$PROCESS_MATCH" || true)
if [[ "${#pids[@]}" -gt 0 ]]; then
  echo "Force stopping $SERVICE_NAME pid(s): ${pids[*]}"
  kill -KILL "${pids[@]}" 2>/dev/null || true
fi

for _ in {1..20}; do
  if ! pgrep -f "$PROCESS_MATCH" >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
      systemctl reset-failed "${SYSTEMD_UNIT}.service" >/dev/null 2>&1 || true
    fi
    echo "$SERVICE_NAME stopped after SIGKILL."
    exit 0
  fi
  sleep 0.5
done

echo "$SERVICE_NAME is still running: $(pgrep -f -d ' ' "$PROCESS_MATCH")" >&2
exit 1
