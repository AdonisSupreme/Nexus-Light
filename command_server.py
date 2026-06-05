from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse
from uuid import uuid4

from . import __version__
from .logs import file_owner_summary
from .procfs import enrich_cpu_percent, find_processes
from .system import host_snapshot, resource_pressure


MAX_OUTPUT_CHARS = 6000
RESTART_BLOCKED_TYPES = {"db", "database", "cache", "queue", "auth", "infra"}
RESTART_CAPABLE_TYPES = {"app", "worker", "gateway", "channel", "channel_adapter", "integration"}
BUILTIN_SPRING_BOOT_CONTROL = "__nexus_builtin_spring_boot_jar__"
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
                if self.path.rstrip("/") == "/logs/tail":
                    status, response = server.request_log_tail(payload)
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

        command = _control_command(service, operation, contract)
        if not command:
            LOGGER.warning("control rejected for %s %s: no local command or systemd unit configured", service_id, operation)
            return 403, {
                "accepted": False,
                "blocked_reasons": [f"No local {operation} command, systemd unit, or Spring Boot jar control metadata is configured for this service."],
                "service_id": service_id,
            }

        execution_id = f"{operation}-exec-{uuid4()}"
        LOGGER.info("control accepted for %s %s execution_id=%s command=%s", service_id, operation, execution_id, " ".join(command))
        thread = threading.Thread(
            target=self._run_control_background,
            args=(execution_id, service, payload, command, contract),
            name=f"nexus-{operation}-{service_id}",
            daemon=True,
        )
        thread.start()
        return 202, {"accepted": True, "execution_id": execution_id, "service_id": service_id, "operation": operation}

    def request_log_tail(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        service_id = str(payload.get("service_id") or "")
        service = self.agent.get_service(service_id)
        if not service:
            return 404, {"error": f"unknown service {service_id}"}
        contract = self.agent.get_cached_remote_contract(service_id)
        if not contract:
            LOGGER.warning("log tail rejected for %s: no cached Nexus service contract", service_id)
            return 503, {
                "available": False,
                "reason": "No cached Nexus service contract is available yet.",
                "service_id": service_id,
                "lines": [],
            }
        allowed, reason = _diagnostics_allowed(contract)
        if not allowed:
            return 403, {"available": False, "reason": reason, "service_id": service_id, "lines": []}

        max_lines = _bounded_int(payload.get("max_lines"), default=120, minimum=20, maximum=300)
        max_bytes = _bounded_int(payload.get("max_bytes"), default=196_608, minimum=8_192, maximum=262_144)
        cursor = _optional_int(payload.get("cursor"))
        newest_first = bool(payload.get("newest_first", True))
        return 200, _tail_service_log(
            service,
            max_lines=max_lines,
            max_bytes=max_bytes,
            cursor=cursor,
            newest_first=newest_first,
        )

    def _run_diagnostics_background(self, request_id: str, service: Any, payload: dict[str, Any]) -> None:
        commands = [command for command in (payload.get("commands") or []) if isinstance(command, dict)]
        if not any(command.get("command_id") == "runtime_status" for command in commands):
            commands.insert(0, {"command_id": "runtime_status", "label": "Runtime status"})
        results = [_execute_diagnostic_command(self.agent, service, command) for command in commands]
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
        contract: dict[str, Any],
    ) -> None:
        operation = str(payload.get("operation") or "restart").lower()
        started = datetime.now(timezone.utc)
        progress_sent = False

        def emit_progress(postcheck: dict[str, Any], partial_result: dict[str, Any], *, status: str) -> None:
            nonlocal progress_sent
            if progress_sent:
                return
            progress_sent = True
            partial_payload = self._control_result_payload(
                execution_id,
                service,
                payload,
                operation,
                command,
                partial_result,
                postcheck,
                started,
                status=status,
                successful=bool(postcheck.get("success")),
                phase="progress",
            )
            self._send_control_result_or_spool(partial_payload)

        def observe_progress() -> None:
            probe_result = {"return_code": 0, "stdout": "", "stderr": ""}
            postcheck = _post_control_check(service, operation, probe_result, contract=contract)
            if _postcheck_has_operator_visible_state(operation, postcheck):
                emit_progress(
                    postcheck,
                    probe_result,
                    status="verified" if postcheck.get("success") else "starting",
                )

        result, executed_command = _run_control_command(
            service,
            contract,
            operation,
            command,
            progress_callback=observe_progress,
        )
        immediate_postcheck = _post_control_check(service, operation, result, contract=contract)
        if not progress_sent and _postcheck_is_transitional(operation, immediate_postcheck, result):
            emit_progress(immediate_postcheck, result, status="starting")

        postcheck = (
            immediate_postcheck
            if result["return_code"] != 0 or immediate_postcheck.get("success")
            else _wait_for_post_control_check(
                service,
                operation,
                result,
                initial_postcheck=immediate_postcheck,
                contract=contract,
            )
        )
        verified = bool(postcheck.get("success"))
        history_status = "verified" if verified else ("failed" if result["return_code"] != 0 else "verification_failed")
        log_method = LOGGER.info if verified else LOGGER.warning
        log_method(
            "control completed for %s %s execution_id=%s return_code=%s status=%s postcheck=%s",
            service.service_id,
            operation,
            execution_id,
            result["return_code"],
            history_status,
            postcheck.get("message"),
        )
        completed_at = datetime.now(timezone.utc)
        result_payload = self._control_result_payload(
            execution_id,
            service,
            payload,
            operation,
            executed_command,
            result,
            postcheck,
            completed_at,
            status=history_status,
            successful=verified,
            phase="final",
        )
        with self.agent._state_lock:
            history = self.agent.state.data.setdefault("restart_history", {})
            history[service.service_id] = {
                "execution_id": execution_id,
                "operation": operation,
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "incident_id": payload.get("incident_id"),
                "action_execution_id": payload.get("action_execution_id"),
                "approved_by": payload.get("approved_by"),
                "command": executed_command,
                "return_code": result["return_code"],
                "status": history_status,
                "verified": verified,
                "postcheck": postcheck,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }
            self.agent.state.save()
        self._send_control_result_or_spool(result_payload)

    def _control_result_payload(
        self,
        execution_id: str,
        service: Any,
        payload: dict[str, Any],
        operation: str,
        command: list[str],
        result: dict[str, Any],
        postcheck: dict[str, Any],
        observed_at: datetime,
        *,
        status: str,
        successful: bool,
        phase: str,
    ) -> dict[str, Any]:
        return {
            "agent_id": self.agent.settings.agent_id,
            "execution_id": execution_id,
            "action_execution_id": payload.get("action_execution_id"),
            "incident_id": payload.get("incident_id"),
            "service_id": service.service_id,
            "operation": operation,
            "timestamp": observed_at.isoformat().replace("+00:00", "Z"),
            "accepted": True,
            "successful": successful,
            "status": status,
            "command": command,
            "return_code": result.get("return_code"),
            "stdout": result.get("stdout") or "",
            "stderr": result.get("stderr") or "",
            "postcheck": postcheck,
            "metadata": {
                "approved_by": payload.get("approved_by"),
                "requested_by": payload.get("requested_by"),
                "reason": payload.get("reason"),
                "agent_version": __version__,
                "phase": phase,
            },
        }

    def _send_control_result_or_spool(self, result_payload: dict[str, Any]) -> None:
        try:
            self.agent.client.control_result(result_payload)
        except Exception:
            with self.agent._state_lock:
                failed = self.agent.state.data.setdefault("failed_control_results", [])
                failed.append(result_payload)
                self.agent.state.data["failed_control_results"] = failed[-50:]
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


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _tail_service_log(
    service: Any,
    *,
    max_lines: int,
    max_bytes: int,
    cursor: int | None = None,
    newest_first: bool = True,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    path_value = str(getattr(service, "log_path", None) or "").strip()
    if not path_value:
        return {
            "service_id": service.service_id,
            "service_name": service.service_name,
            "generated_at": generated_at,
            "available": False,
            "reason": "No log_path is configured for this service.",
            "lines": [],
        }
    log_path = Path(path_value)
    if not log_path.exists():
        return {
            "service_id": service.service_id,
            "service_name": service.service_name,
            "generated_at": generated_at,
            "available": False,
            "reason": f"Log path does not exist: {path_value}",
            "log_path": path_value,
            "owner": file_owner_summary(path_value),
            "lines": [],
        }
    try:
        stat = log_path.stat()
        rotated = cursor is not None and stat.st_size < cursor
        if cursor is None or rotated:
            start = max(stat.st_size - max_bytes, 0)
            tail_mode = "snapshot_rotated" if rotated else "snapshot"
            drop_partial_line = start > 0
        else:
            start = min(cursor, stat.st_size)
            if stat.st_size - start > max_bytes:
                start = max(stat.st_size - max_bytes, 0)
                tail_mode = "delta_truncated"
                drop_partial_line = start > 0
            else:
                tail_mode = "delta"
                drop_partial_line = False
        with log_path.open("rb") as handle:
            handle.seek(start)
            raw = handle.read(max_bytes)
    except OSError as exc:
        return {
            "service_id": service.service_id,
            "service_name": service.service_name,
            "generated_at": generated_at,
            "available": False,
            "reason": f"Log tail read failed: {exc}",
            "log_path": path_value,
            "owner": file_owner_summary(path_value),
            "lines": [],
        }

    text = raw.decode("utf-8", errors="replace")
    raw_lines = text.splitlines()
    if drop_partial_line and raw_lines:
        raw_lines = raw_lines[1:]
    selected = raw_lines[-max_lines:]
    first_line_index = max(len(raw_lines) - len(selected), 0)
    line_payload = [
        {
            "index": first_line_index + index + 1,
            "message": _strip_ansi(line),
            "raw": line,
            **_log_line_metadata(line),
        }
        for index, line in enumerate(selected)
    ]
    if newest_first:
        line_payload = list(reversed(line_payload))
    return {
        "service_id": service.service_id,
        "service_name": service.service_name,
        "generated_at": generated_at,
        "available": True,
        "log_path": path_value,
        "owner": file_owner_summary(path_value),
        "file_size": stat.st_size,
        "cursor": stat.st_size,
        "tail_mode": tail_mode,
        "bytes_read": len(raw),
        "max_lines": max_lines,
        "new_line_count": len(selected),
        "newest_first": newest_first,
        "truncated": start > 0 or len(raw_lines) > len(selected),
        "rotated": rotated,
        "lines": line_payload,
    }


def _strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


def _log_line_metadata(line: str) -> dict[str, Any]:
    clean = _strip_ansi(line)
    timestamp_match = re.search(r"\[?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?)\]?", clean)
    level_match = re.search(r"\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b", clean)
    level = level_match.group(1).upper() if level_match else None
    severity = "CRITICAL" if level in {"ERROR", "FATAL"} else "WARN" if level in {"WARN", "WARNING"} else "INFO" if level else None
    return {
        "timestamp": timestamp_match.group(1).replace(",", ".") if timestamp_match else None,
        "level": level,
        "severity": severity,
    }


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
    if operation == "restart" and history and history.get("verified") is True and _inside_cooldown(history.get("completed_at"), cooldown_minutes):
        last_operation = str(history.get("operation") or "").lower()
        if last_operation == "restart":
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


def _control_command(service: Any, operation: str, contract: dict[str, Any] | None = None) -> list[str]:
    if operation == "start" and service.start_command:
        return list(service.start_command)
    if operation == "stop" and service.stop_command:
        return list(service.stop_command)
    if operation == "restart" and service.restart_command:
        return list(service.restart_command)
    if service.systemd_unit:
        return ["systemctl", operation, service.systemd_unit]
    if _spring_boot_control_spec(service, contract):
        return [BUILTIN_SPRING_BOOT_CONTROL, operation]
    return []


def _run_control_command(
    service: Any,
    contract: dict[str, Any],
    operation: str,
    command: list[str],
    *,
    progress_callback: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    if command[:1] == [BUILTIN_SPRING_BOOT_CONTROL]:
        return _run_spring_boot_control(service, contract, operation), command

    result = _run_command(
        command,
        timeout_seconds=_control_command_timeout_seconds(service, operation),
        progress_callback=progress_callback,
    )
    if result["return_code"] == 127 and _spring_boot_control_spec(service, contract):
        LOGGER.warning(
            "control command failed with 127 for %s %s; falling back to built-in Spring Boot jar control: %s",
            service.service_id,
            operation,
            result.get("stderr") or result.get("stdout") or "no command output",
        )
        builtin_command = [BUILTIN_SPRING_BOOT_CONTROL, operation]
        return _run_spring_boot_control(service, contract, operation), builtin_command
    return result, command


def _spring_boot_control_spec(service: Any, contract: dict[str, Any] | None = None) -> dict[str, str] | None:
    metadata = ((contract or {}).get("service") or {}).get("metadata") or {}
    jar_path = str(getattr(service, "jar_path", None) or metadata.get("jar_path") or "").strip()
    config_path = str(getattr(service, "config_path", None) or metadata.get("config_path") or "").strip()
    process_match = str(getattr(service, "process_match", None) or metadata.get("process_match") or "").strip()
    java_bin = str(getattr(service, "java_bin", None) or metadata.get("java_bin") or "java").strip() or "java"
    working_dir = str(getattr(service, "working_dir", None) or metadata.get("working_dir") or "/srv").strip()
    if not jar_path or not config_path or not process_match:
        return None
    return {
        "jar_path": jar_path,
        "config_path": config_path,
        "process_match": process_match,
        "java_bin": java_bin,
        "working_dir": working_dir,
    }


def _run_spring_boot_control(service: Any, contract: dict[str, Any], operation: str) -> dict[str, Any]:
    spec = _spring_boot_control_spec(service, contract)
    if not spec:
        return {
            "return_code": 127,
            "stdout": "",
            "stderr": "Spring Boot jar control requires jar_path, config_path, and process_match.",
        }

    stdout: list[str] = []
    stderr: list[str] = []
    if operation in {"stop", "restart"}:
        stop_result = _stop_matched_processes(spec["process_match"])
        stdout.extend(stop_result["stdout"])
        stderr.extend(stop_result["stderr"])
        if stop_result["return_code"] != 0:
            return {
                "return_code": stop_result["return_code"],
                "stdout": _truncate("\n".join(stdout)),
                "stderr": _truncate("\n".join(stderr)),
            }
        if operation == "stop":
            return {"return_code": 0, "stdout": _truncate("\n".join(stdout)), "stderr": _truncate("\n".join(stderr))}
        time.sleep(2)

    if operation in {"start", "restart"}:
        start_result = _start_spring_boot_service(spec)
        stdout.extend(start_result["stdout"])
        stderr.extend(start_result["stderr"])
        return {
            "return_code": start_result["return_code"],
            "stdout": _truncate("\n".join(stdout)),
            "stderr": _truncate("\n".join(stderr)),
        }

    return {"return_code": 400, "stdout": "", "stderr": f"Unsupported operation {operation}"}


def _stop_matched_processes(process_match: str) -> dict[str, Any]:
    processes = find_processes(process_match)
    if not processes:
        return {"return_code": 0, "stdout": [f"{process_match} is already stopped."], "stderr": []}

    stdout: list[str] = []
    stderr: list[str] = []
    for process in processes:
        pid = int(process["pid"])
        try:
            os.kill(pid, signal.SIGKILL)
            stdout.append(f"Sent SIGKILL to pid {pid}.")
        except ProcessLookupError:
            stdout.append(f"pid {pid} already exited.")
        except PermissionError as exc:
            stderr.append(f"Permission denied killing pid {pid}: {exc}")
        except OSError as exc:
            stderr.append(f"Failed killing pid {pid}: {exc}")

    deadline = time.time() + 10
    while time.time() < deadline:
        if not find_processes(process_match):
            return {"return_code": 0, "stdout": [*stdout, f"{process_match} stopped."], "stderr": stderr}
        time.sleep(0.5)

    remaining = find_processes(process_match)
    stderr.append(f"{len(remaining)} matching process(es) still running after SIGKILL.")
    return {"return_code": 1, "stdout": stdout, "stderr": stderr}


def _start_spring_boot_service(spec: dict[str, str]) -> dict[str, Any]:
    existing = find_processes(spec["process_match"])
    if existing:
        return {
            "return_code": 0,
            "stdout": [f"{spec['process_match']} is already running with {len(existing)} matching process(es)."],
            "stderr": [],
        }
    jar = Path(spec["jar_path"])
    config = Path(spec["config_path"])
    if not jar.exists():
        return {"return_code": 127, "stdout": [], "stderr": [f"Jar path does not exist: {jar}"]}
    if not config.exists():
        return {"return_code": 127, "stdout": [], "stderr": [f"Spring config path does not exist: {config}"]}
    working_dir = Path(spec.get("working_dir") or "/srv")
    if not working_dir.exists():
        return {"return_code": 127, "stdout": [], "stderr": [f"Working directory does not exist: {working_dir}"]}
    command = [
        "nohup",
        spec["java_bin"],
        "-jar",
        str(jar),
        f"--spring.config.location={config}",
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=str(working_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        return {"return_code": 127, "stdout": [], "stderr": [str(exc)]}
    return {
        "return_code": 0,
        "stdout": [
            f"Started {spec['process_match']} with pid {process.pid}.",
            f"Launch cwd={working_dir} config={config}",
        ],
        "stderr": [],
    }


def _post_control_check(
    service: Any,
    operation: str,
    command_result: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if command_result["return_code"] != 0:
        stderr = str(command_result.get("stderr") or "").strip()
        stdout = str(command_result.get("stdout") or "").strip()
        privilege_hint = (
            " The light agent user does not have OS permission to control the target process; configure the root-owned sudo allowlist helper for this service."
            if "Permission denied killing pid" in stderr
            else ""
        )
        return {
            "success": False,
            "status": "command_failed",
            "message": "The local control command exited with a non-zero return code."
            + (f" stderr: {stderr}" if stderr else f" stdout: {stdout}" if stdout else "")
            + privilege_hint,
            "expected_state": _expected_state(operation),
            "return_code": command_result["return_code"],
        }

    if service.process_match:
        processes = find_processes(service.process_match)
        process_count = len(processes)
        if operation == "stop":
            success = process_count == 0
            return {
                "success": success,
                "status": "verified" if success else "process_still_running",
                "message": (
                    "Post-stop verification passed: no matching service process is visible."
                    if success
                    else f"Post-stop verification failed: {process_count} matching process(es) are still running."
                ),
                "expected_state": "stopped",
                "process_match": service.process_match,
                "process_count": process_count,
                "processes": processes[:5],
            }
        readiness = _service_readiness_check(service, contract=contract) if process_count > 0 else {
            "required": bool(_service_readiness_port(service, contract=contract)),
            "ready": False,
        }
        launch_context = _spring_launch_context_check(service, processes, contract=contract) if process_count > 0 else {
            "required": bool(_spring_boot_control_spec(service, contract)),
            "verified": False,
            "reason": "No matching process is visible yet.",
        }
        if launch_context.get("required") and launch_context.get("mismatch"):
            expected_cwd = launch_context.get("expected_cwd")
            actual_cwds = ", ".join(str(item) for item in launch_context.get("actual_cwds") or ["unknown"])
            return {
                "success": False,
                "status": "launch_context_mismatch",
                "message": (
                    f"Post-{operation} verification failed: matching service process is running from {actual_cwds}, "
                    f"but Nexus expects the manual ATE launch directory {expected_cwd}."
                ),
                "expected_state": "running",
                "process_match": service.process_match,
                "process_count": process_count,
                "processes": processes[:5],
                "readiness": readiness,
                "launch_context": launch_context,
            }
        success = process_count > 0 and (not readiness.get("required") or bool(readiness.get("ready")))
        if process_count > 0 and readiness.get("required") and not readiness.get("ready"):
            message = (
                f"Post-{operation} verification waiting: matching service process is running, "
                f"but TCP readiness on {readiness.get('host')}:{readiness.get('port')} is not open yet."
            )
            status = "tcp_not_ready"
        else:
            message = (
                f"Post-{operation} verification passed: matching service process is running"
                + (" and TCP readiness is open." if readiness.get("required") else ".")
                if success
                else f"Post-{operation} verification failed: no matching service process is visible."
            )
            status = "verified" if success else "process_not_running"
        return {
            "success": success,
            "status": status,
            "message": message,
            "expected_state": "running",
            "process_match": service.process_match,
            "process_count": process_count,
            "processes": processes[:5],
            "readiness": readiness,
            "launch_context": launch_context,
        }

    if service.systemd_unit:
        result = _run_command(["systemctl", "is-active", service.systemd_unit], timeout_seconds=8)
        active = result["stdout"].strip() == "active"
        success = not active if operation == "stop" else active
        return {
            "success": success,
            "status": "verified" if success else "systemd_state_mismatch",
            "message": (
                f"Post-{operation} verification passed via systemd."
                if success
                else f"Post-{operation} verification failed: systemd reports {result['stdout'].strip() or 'unknown'}."
            ),
            "expected_state": _expected_state(operation),
            "systemd_unit": service.systemd_unit,
            "systemd_is_active": result,
        }

    return {
        "success": False,
        "status": "verification_unavailable",
        "message": "No process_match or systemd_unit is configured, so Nexus cannot verify the control result.",
        "expected_state": _expected_state(operation),
    }


def _wait_for_post_control_check(
    service: Any,
    operation: str,
    command_result: dict[str, Any],
    *,
    initial_postcheck: dict[str, Any] | None = None,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    postcheck = initial_postcheck or _post_control_check(service, operation, command_result, contract=contract)
    if command_result["return_code"] != 0 or postcheck.get("success"):
        postcheck["verification_elapsed_seconds"] = round(time.monotonic() - started, 3)
        postcheck["verification_timeout_seconds"] = 0
        return postcheck

    timeout_seconds = _control_postcheck_timeout_seconds(service, operation)
    deadline = started + timeout_seconds
    while time.monotonic() < deadline:
        time.sleep(0.5)
        postcheck = _post_control_check(service, operation, command_result, contract=contract)
        if postcheck.get("success"):
            postcheck["verification_elapsed_seconds"] = round(time.monotonic() - started, 3)
            postcheck["verification_timeout_seconds"] = timeout_seconds
            return postcheck

    postcheck["verification_elapsed_seconds"] = round(time.monotonic() - started, 3)
    postcheck["verification_timeout_seconds"] = timeout_seconds
    return postcheck


def _spring_launch_context_check(
    service: Any,
    processes: list[dict[str, Any]],
    *,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    spec = _spring_boot_control_spec(service, contract)
    if not spec:
        return {"required": False, "verified": False, "reason": "No Spring Boot launch metadata is configured."}
    expected_cwd = _normalize_control_path(spec.get("working_dir") or "/srv")
    actual_cwds = [
        _normalize_control_path(str(process.get("cwd") or ""))
        for process in processes
        if process.get("cwd")
    ]
    mismatches = sorted({cwd for cwd in actual_cwds if cwd and cwd != expected_cwd})
    return {
        "required": True,
        "verified": bool(actual_cwds) and not mismatches,
        "mismatch": bool(mismatches),
        "expected_cwd": expected_cwd,
        "actual_cwds": actual_cwds,
        "unavailable": len(actual_cwds) < len(processes),
    }


def _normalize_control_path(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized


def _postcheck_has_operator_visible_state(operation: str, postcheck: dict[str, Any]) -> bool:
    if operation == "stop":
        return postcheck.get("expected_state") == "stopped" and int(postcheck.get("process_count") or 0) == 0
    return int(postcheck.get("process_count") or 0) > 0


def _postcheck_is_transitional(operation: str, postcheck: dict[str, Any], command_result: dict[str, Any]) -> bool:
    if command_result.get("return_code") != 0:
        return False
    if operation not in {"start", "restart"}:
        return False
    return (
        int(postcheck.get("process_count") or 0) > 0
        and postcheck.get("status") in {"tcp_not_ready", "process_not_running"}
    )


def _control_postcheck_timeout_seconds(service: Any, operation: str) -> int:
    configured = max(int(getattr(service, "restart_settle_seconds", 5) or 5), 1)
    if operation == "stop":
        return min(max(configured, 3), 8)
    if operation == "start":
        return min(max(configured, 10), 90)
    return min(max(configured, 30), 180)


def _control_command_timeout_seconds(service: Any, operation: str) -> int:
    configured = max(int(getattr(service, "restart_settle_seconds", 5) or 5), 1)
    if operation == "stop":
        return min(max(configured + 5, 12), 30)
    if operation == "start":
        return min(max(configured + 10, 20), 60)
    return min(max(configured + 20, 35), 90)


def _service_readiness_check(service: Any, *, contract: dict[str, Any] | None = None) -> dict[str, Any]:
    port = _service_readiness_port(service, contract=contract)
    if not port:
        return {"required": False, "ready": False, "reason": "No readiness port or healthcheck port is configured or discoverable."}
    hosts = _readiness_hosts(service, contract=contract)
    started = time.monotonic()
    errors: list[str] = []
    for host in hosts:
        try:
            with socket.create_connection((host, port), timeout=0.75):
                return {
                    "required": True,
                    "ready": True,
                    "host": host,
                    "port": port,
                    "latency_ms": round((time.monotonic() - started) * 1000, 2),
                }
        except OSError as exc:
            errors.append(f"{host}:{port} {exc}")
    return {
        "required": True,
        "ready": False,
        "host": hosts[0] if hosts else "127.0.0.1",
        "port": port,
        "error": "; ".join(errors[-3:]),
        "latency_ms": round((time.monotonic() - started) * 1000, 2),
    }


def _readiness_hosts(service: Any, *, contract: dict[str, Any] | None = None) -> list[str]:
    metadata = _contract_service_metadata(contract)
    endpoint_config = _contract_endpoint_config(contract)
    configured = str(getattr(service, "readiness_host", None) or metadata.get("readiness_host") or "").strip()
    health_host = ""
    healthcheck_url = getattr(service, "healthcheck_url", None) or endpoint_config.get("healthcheck_url")
    if healthcheck_url:
        try:
            health_host = urlparse(str(healthcheck_url)).hostname or ""
        except ValueError:
            health_host = ""
    candidates = [configured, health_host, "127.0.0.1", "localhost"]
    return list(dict.fromkeys([item for item in candidates if item]))


def _service_readiness_port(service: Any, *, contract: dict[str, Any] | None = None) -> int | None:
    metadata = _contract_service_metadata(contract)
    endpoint_config = _contract_endpoint_config(contract)
    configured = getattr(service, "readiness_port", None) or metadata.get("readiness_port") or metadata.get("server_port")
    if configured:
        return int(configured)
    healthcheck_url = getattr(service, "healthcheck_url", None) or endpoint_config.get("healthcheck_url")
    if healthcheck_url:
        try:
            parsed = urlparse(str(healthcheck_url))
        except ValueError:
            parsed = None
        if parsed and parsed.port:
            return int(parsed.port)
    return _discover_spring_server_port(getattr(service, "config_path", None) or metadata.get("config_path"))


def _contract_service_metadata(contract: dict[str, Any] | None) -> dict[str, Any]:
    service = (contract or {}).get("service") or {}
    metadata = service.get("metadata") if isinstance(service, dict) else {}
    return metadata if isinstance(metadata, dict) else {}


def _contract_endpoint_config(contract: dict[str, Any] | None) -> dict[str, Any]:
    service = (contract or {}).get("service") or {}
    endpoint_config = service.get("endpoint_config") if isinstance(service, dict) else {}
    return endpoint_config if isinstance(endpoint_config, dict) else {}


def _discover_spring_server_port(config_path: str | None) -> int | None:
    if not config_path:
        return None
    path = Path(config_path)
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    direct = re.search(r"(?m)^\s*server\.port\s*:\s*(\d{2,5})\s*$", text)
    if direct:
        return int(direct.group(1))
    server_block = re.search(r"(?ms)^server\s*:\s*\n(?P<body>(?:[ \t]+[^\n]*\n?)+)", text)
    if not server_block:
        return None
    port = re.search(r"(?m)^[ \t]+port\s*:\s*(\d{2,5})\s*$", server_block.group("body"))
    return int(port.group(1)) if port else None


def _expected_state(operation: str) -> str:
    return "stopped" if operation == "stop" else "running"


def _execute_diagnostic_command(agent: Any, service: Any, command: dict[str, Any]) -> dict[str, Any]:
    command_id = command.get("command_id")
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if command_id == "runtime_status":
        contract = agent.get_cached_remote_contract(service.service_id)
        return {
            "command_id": command_id,
            "status": "COMPLETED",
            "started_at": started_at,
            "output": _runtime_diagnostic_output(agent, service, contract=contract),
        }
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


def _runtime_diagnostic_output(agent: Any, service: Any, *, contract: dict[str, Any] | None = None) -> dict[str, Any]:
    host = host_snapshot(service.log_path)
    pressure = resource_pressure(
        host,
        agent.settings.resource_guard.high_load_per_core,
        agent.settings.resource_guard.min_available_memory_mb,
    )
    processes = enrich_cpu_percent(find_processes(service.process_match), agent.state.data)
    process_count = len(processes)
    runtime_state = "running" if process_count else "stopped" if service.expected_running else "not_expected"
    readiness = _service_readiness_check(service, contract=contract) if process_count else {
        "required": bool(_service_readiness_port(service, contract=contract)),
        "ready": False,
    }
    return {
        "service_id": service.service_id,
        "service_name": service.service_name,
        "runtime_state": runtime_state,
        "status": "up" if process_count and (not readiness.get("required") or readiness.get("ready")) else "starting" if process_count else "down" if service.expected_running else "idle",
        "expected_running": service.expected_running,
        "process_match": service.process_match,
        "process_count": process_count,
        "processes": processes[:10],
        "readiness": readiness,
        "host": host,
        "resource_pressure": pressure,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


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


def _run_command(
    command: list[str],
    *,
    timeout_seconds: int,
    progress_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    safe_command = [part for part in command if part]
    if not safe_command:
        return {"return_code": 127, "stdout": "", "stderr": "empty command"}
    try:
        process = subprocess.Popen(
            safe_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.75)
                return {
                    "return_code": process.returncode,
                    "stdout": _truncate(stdout or ""),
                    "stderr": _truncate(stderr or ""),
                }
            except subprocess.TimeoutExpired:
                if progress_callback:
                    progress_callback()
                if time.monotonic() >= deadline:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=5)
                    return {
                        "return_code": 124,
                        "stdout": _truncate(stdout or ""),
                        "stderr": _truncate(stderr or "command timed out"),
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
