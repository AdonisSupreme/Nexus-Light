from __future__ import annotations

import json
import logging
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import uuid4

from . import __version__
from .system import host_snapshot


MAX_OUTPUT_CHARS = 6000
RESTART_BLOCKED_TYPES = {"db", "database", "cache", "queue", "auth", "infra"}
RESTART_CAPABLE_TYPES = {"app", "worker", "gateway", "channel", "channel_adapter", "integration"}
LOGGER = logging.getLogger("sentinel.nexus.light_agent")


class AgentCommandServer:
    def __init__(self, agent: Any) -> None:
        self.agent = agent
        self.settings = agent.settings.command_server
        self.httpd = ThreadingHTTPServer((self.settings.bind_host, self.settings.port), self._handler_class())
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="nexus-agent-command-server", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            server_version = f"SentinelNexusLightAgent/{__version__}"

            def do_GET(self) -> None:
                if self.path.rstrip("/") == "/health":
                    server._write_json(self, 200, {"status": "healthy", "agent_id": server.agent.settings.agent_id})
                    return
                server._write_json(self, 404, {"error": "not_found"})

            def do_POST(self) -> None:
                if not server._authorized(self):
                    LOGGER.warning("command server rejected unauthorized %s request", self.path.rstrip("/") or "/")
                    server._write_json(self, 401, {"error": "unauthorized"})
                    return
                payload = server._read_json(self)
                if payload is None:
                    server._write_json(self, 400, {"error": "invalid_json"})
                    return
                if self.path.rstrip("/") == "/diagnostics":
                    status, response = server.request_diagnostics(payload)
                    server._write_json(self, status, response)
                    return
                if self.path.rstrip("/") == "/restart":
                    status, response = server.request_restart(payload)
                    server._write_json(self, status, response)
                    return
                if self.path.rstrip("/") == "/control":
                    status, response = server.request_control(payload)
                    server._write_json(self, status, response)
                    return
                server._write_json(self, 404, {"error": "not_found"})

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        return Handler

    def request_diagnostics(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        service_id = str(payload.get("service_id") or "")
        service = self.agent.get_service(service_id)
        if not service:
            return 404, {"error": f"unknown service {service_id}"}
        contract = self.agent.get_cached_remote_contract(service_id)
        if not contract:
            LOGGER.warning("diagnostics rejected for %s: no cached Nexus service contract", service_id)
            return 503, {
                "error": "No cached Nexus service contract is available yet. Wait for agent config refresh or restart the light agent after Nexus is reachable.",
                "service_id": service_id,
            }
        allowed, reason = _diagnostics_allowed(contract)
        if not allowed:
            return 403, {"error": reason}

        request_id = f"diag-exec-{uuid4()}"
        thread = threading.Thread(
            target=self._run_diagnostics_background,
            args=(request_id, service, payload),
            name=f"nexus-diagnostics-{service_id}",
            daemon=True,
        )
        thread.start()
        return 202, {"accepted": True, "execution_id": request_id, "service_id": service_id}

    def request_restart(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        payload = {**payload, "operation": "restart"}
        return self.request_control(payload)

    def request_control(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        service_id = str(payload.get("service_id") or "")
        operation = str(payload.get("operation") or "restart").lower().strip()
        if operation not in {"start", "stop", "restart"}:
            LOGGER.warning("control rejected for %s: unsupported operation %s", service_id or "unknown", operation)
            return 400, {"accepted": False, "error": "unsupported_operation", "operation": operation}
        service = self.agent.get_service(service_id)
        if not service:
            LOGGER.warning("control rejected: unknown service %s", service_id)
            return 404, {"error": f"unknown service {service_id}"}
        contract = self.agent.get_cached_remote_contract(service_id)
        if not contract:
            reason = "No cached Nexus service contract is available yet. Wait for agent config refresh or restart the light agent after Nexus is reachable."
            LOGGER.warning("control rejected for %s %s: %s", service_id, operation, reason)
            return 503, {"accepted": False, "blocked_reasons": [reason], "service_id": service_id}
        allowed, reasons = _restart_allowed(contract, service, self.agent.state.data, operation=operation)
        if not allowed:
            LOGGER.warning("control rejected for %s %s: %s", service_id, operation, "; ".join(reasons))
            return 403, {"accepted": False, "blocked_reasons": reasons, "service_id": service_id}

        command = _control_command(service, operation)
        if not command:
            LOGGER.warning("control rejected for %s %s: no local command or systemd unit configured", service_id, operation)
            return 403, {
                "accepted": False,
                "blocked_reasons": [f"No local {operation} command or systemd unit is configured for this service."],
                "service_id": service_id,
            }

        execution_id = f"{operation}-exec-{uuid4()}"
        LOGGER.info("control accepted for %s %s execution_id=%s command=%s", service_id, operation, execution_id, " ".join(command))
        thread = threading.Thread(
            target=self._run_control_background,
            args=(execution_id, service, payload, command),
            name=f"nexus-{operation}-{service_id}",
            daemon=True,
        )
        thread.start()
        return 202, {"accepted": True, "execution_id": execution_id, "service_id": service_id, "operation": operation}

    def _run_diagnostics_background(self, request_id: str, service: Any, payload: dict[str, Any]) -> None:
        commands = payload.get("commands") or []
        results = [_execute_diagnostic_command(service, command) for command in commands if isinstance(command, dict)]
        result_payload = {
            "agent_id": self.agent.settings.agent_id,
            "bundle_id": payload.get("bundle_id"),
            "incident_id": payload.get("incident_id"),
            "service_id": service.service_id,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "instance_id": service.instance_id,
            "host_id": host_snapshot(service.log_path).get("hostname"),
            "command_results": results,
            "metadata": {"execution_id": request_id, "agent_version": __version__},
            "notes": "Diagnostics executed by Sentinel Nexus light agent allowlist.",
        }
        try:
            self.agent.client.diagnostic_results(result_payload)
        except Exception:
            # The caller already has an accepted response. Keep the result locally for audit/retry review.
            with self.agent._state_lock:
                failed = self.agent.state.data.setdefault("failed_diagnostic_results", [])
                failed.append(result_payload)
                self.agent.state.data["failed_diagnostic_results"] = failed[-50:]
                self.agent.state.save()

    def _run_control_background(
        self,
        execution_id: str,
        service: Any,
        payload: dict[str, Any],
        command: list[str],
    ) -> None:
        operation = str(payload.get("operation") or "restart").lower()
        started = datetime.now(timezone.utc)
        result = _run_command(command, timeout_seconds=90)
        time.sleep(max(int(service.restart_settle_seconds), 0))
        LOGGER.info(
            "control completed for %s %s execution_id=%s return_code=%s",
            service.service_id,
            operation,
            execution_id,
            result["return_code"],
        )
        with self.agent._state_lock:
            history = self.agent.state.data.setdefault("restart_history", {})
            history[service.service_id] = {
                "execution_id": execution_id,
                "operation": operation,
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "incident_id": payload.get("incident_id"),
                "action_execution_id": payload.get("action_execution_id"),
                "approved_by": payload.get("approved_by"),
                "command": command,
                "return_code": result["return_code"],
                "status": "completed" if result["return_code"] == 0 else "failed",
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }
            self.agent.state.save()

    def _authorized(self, handler: BaseHTTPRequestHandler) -> bool:
        token = handler.headers.get("X-Nexus-Agent-Token", "")
        agent_id = handler.headers.get("X-Nexus-Agent-Id", "")
        return token == self.agent.token and agent_id in {"", self.agent.settings.agent_id}

    def _read_json(self, handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
        try:
            length = int(handler.headers.get("content-length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > 1_000_000:
            return None
        try:
            payload = json.loads(handler.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _write_json(self, handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)


def _diagnostics_allowed(contract: dict[str, Any]) -> tuple[bool, str]:
    service = contract.get("service") or {}
    certification = service.get("certification") or {}
    stage = certification.get("lifecycle_stage")
    if not service.get("allow_diagnostics", True):
        return False, "Diagnostics are disabled for this service in Nexus."
    if stage not in {"diagnostics_ready", "restart_ready"}:
        return False, "Service is not certified for diagnostics in Nexus."
    return True, ""


def _restart_allowed(contract: dict[str, Any], local_service: Any, state: dict[str, Any], *, operation: str = "restart") -> tuple[bool, list[str]]:
    service = contract.get("service") or {}
    certification = service.get("certification") or {}
    restart_policy = service.get("restart_policy") or {}
    service_type = str(service.get("service_type") or "").lower()
    reasons: list[str] = []
    if service_type in RESTART_BLOCKED_TYPES:
        reasons.append(f"Service type {service_type} is blocked from restart execution.")
    if service_type not in RESTART_CAPABLE_TYPES:
        reasons.append(f"Service type {service_type or 'unknown'} is not restart-capable for this agent.")
    if certification.get("lifecycle_stage") != "restart_ready":
        reasons.append(f"Service is not certified as restart_ready in Nexus, so {operation} is blocked.")
    if not restart_policy.get("allow_restart", False):
        reasons.append("Restart policy does not allow restart for this service.")
    policy_allowed_types = {str(item).lower() for item in restart_policy.get("allowed_service_types", [])} or RESTART_CAPABLE_TYPES
    if service_type not in policy_allowed_types:
        reasons.append("Restart policy does not include this service type in allowed_service_types.")
    if not service.get("is_stateless", False):
        reasons.append("Restart policy requires a stateless service.")
    database_profile = service.get("database_profile") or {}
    if database_profile.get("shared_dependency"):
        reasons.append("Shared database/dependency services are blocked from restart execution.")
    cooldown_minutes = int(restart_policy.get("cooldown_minutes") or 15)
    history = state.get("restart_history", {}).get(local_service.service_id)
    if history and _inside_cooldown(history.get("completed_at"), cooldown_minutes):
        reasons.append(f"Restart cooldown is still active for {cooldown_minutes} minutes.")
    return not reasons, reasons


def _inside_cooldown(value: str | None, cooldown_minutes: int) -> bool:
    if not value:
        return False
    try:
        completed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - completed).total_seconds() < cooldown_minutes * 60


def _control_command(service: Any, operation: str) -> list[str]:
    if operation == "start" and service.start_command:
        return list(service.start_command)
    if operation == "stop" and service.stop_command:
        return list(service.stop_command)
    if operation == "restart" and service.restart_command:
        return list(service.restart_command)
    if service.systemd_unit:
        return ["systemctl", operation, service.systemd_unit]
    return []


def _execute_diagnostic_command(service: Any, command: dict[str, Any]) -> dict[str, Any]:
    command_id = command.get("command_id")
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if command_id == "systemd_status":
        return _diagnostic_command_result(command_id, ["systemctl", "status", service.systemd_unit or "", "--no-pager"], started_at, skip=not service.systemd_unit)
    if command_id == "recent_journal":
        return _diagnostic_command_result(command_id, ["journalctl", "-u", service.systemd_unit or "", "-n", "200", "--no-pager"], started_at, skip=not service.systemd_unit)
    if command_id == "health_check":
        return {"command_id": command_id, "status": "SKIPPED", "started_at": started_at, "reason": "Health checks are already captured in probe reports."}
    if command_id == "memory_summary":
        return {"command_id": command_id, "status": "COMPLETED", "started_at": started_at, "output": host_snapshot(service.log_path).get("memory")}
    if command_id == "disk_summary":
        return {"command_id": command_id, "status": "COMPLETED", "started_at": started_at, "output": host_snapshot(service.log_path).get("disk")}
    if command_id == "socket_summary":
        return _diagnostic_command_result(command_id, ["ss", "-lntp"], started_at, skip=False)
    return {"command_id": command_id, "status": "SKIPPED", "started_at": started_at, "reason": "Command is not in the agent allowlist."}


def _diagnostic_command_result(command_id: str, command: list[str], started_at: str, *, skip: bool) -> dict[str, Any]:
    if skip:
        return {"command_id": command_id, "status": "SKIPPED", "started_at": started_at, "reason": "Required service-local setting is not configured."}
    result = _run_command(command, timeout_seconds=10)
    return {
        "command_id": command_id,
        "status": "COMPLETED" if result["return_code"] == 0 else "FAILED",
        "started_at": started_at,
        "command": command,
        **result,
    }


def _run_command(command: list[str], *, timeout_seconds: int) -> dict[str, Any]:
    safe_command = [part for part in command if part]
    if not safe_command:
        return {"return_code": 127, "stdout": "", "stderr": "empty command"}
    try:
        completed = subprocess.run(
            safe_command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        return {
            "return_code": completed.returncode,
            "stdout": _truncate(completed.stdout),
            "stderr": _truncate(completed.stderr),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "return_code": 124,
            "stdout": _truncate(exc.stdout or ""),
            "stderr": _truncate(exc.stderr or "command timed out"),
        }
    except OSError as exc:
        return {"return_code": 127, "stdout": "", "stderr": str(exc)}


def _truncate(value: str | bytes) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[:MAX_OUTPUT_CHARS]
