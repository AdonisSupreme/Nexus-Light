from __future__ import annotations

import logging
import os
import signal
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .client import NexusClient, NexusClientError
from .command_server import AgentCommandServer
from .config import AgentSettings, ServiceWatch
from .logs import BoundedLogTailer, file_owner_summary
from .procfs import enrich_cpu_percent, find_processes
from .service_profiles import analyze_service_profile
from .signatures import LogSignature, classify_line, summarize_signatures
from .spool import BoundedSpool
from .state import StateStore
from .system import host_snapshot, resource_pressure


LOGGER = logging.getLogger("sentinel.nexus.light_agent")


class NexusLightAgent:
    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.token = settings.resolve_agent_token()
        self.client = NexusClient(
            settings.nexus_base_url,
            settings.agent_id,
            self.token,
            settings.http_timeout_seconds,
        )
        self.state = StateStore(settings.state_dir)
        self.spool = BoundedSpool(settings.state_dir, settings.resource_guard.spool_max_records)
        self._stopping = False
        self._last_heartbeat_at = 0.0
        self._last_remote_config_at = 0.0
        self._remote_contracts: dict[str, dict[str, Any]] = {}
        self._state_lock = threading.RLock()
        self.command_server: AgentCommandServer | None = None

    def setup(self) -> None:
        setup_logging(self.settings.log_file)
        self.state.load()
        _apply_nice(self.settings.resource_guard.nice)
        signal.signal(signal.SIGTERM, self._handle_stop)
        signal.signal(signal.SIGINT, self._handle_stop)
        if self.settings.command_server.enabled:
            self.command_server = AgentCommandServer(self)
            self.command_server.start()
        LOGGER.info("Sentinel Nexus light agent %s starting as %s", __version__, self.settings.agent_id)

    def run_forever(self) -> None:
        self.setup()
        while not self._stopping:
            started = time.monotonic()
            try:
                self.run_once()
            except Exception:
                LOGGER.exception("collector cycle failed")
            elapsed = time.monotonic() - started
            time.sleep(max(self.settings.poll_interval_seconds - elapsed, 1.0))
        if self.command_server:
            self.command_server.stop()
        with self._state_lock:
            self.state.save()
        LOGGER.info("Sentinel Nexus light agent stopped")

    def run_once(self) -> list[dict[str, Any]]:
        now = time.time()
        self._refresh_remote_contracts(now)
        primary_log = next((service.log_path for service in self.settings.enabled_services if service.log_path), None)
        host = host_snapshot(primary_log)
        pressure = resource_pressure(
            host,
            self.settings.resource_guard.high_load_per_core,
            self.settings.resource_guard.min_available_memory_mb,
        )
        self._maybe_send_heartbeats(now, host, pressure)

        reports: list[dict[str, Any]] = []
        tailer = BoundedLogTailer(self.state.data)
        for service in self.settings.enabled_services:
            report = self._collect_service(service, host, pressure, tailer)
            reports.append(report)
            self._send_or_spool(report)

        self._flush_spool()
        self._flush_failed_callbacks()
        with self._state_lock:
            self.state.save()
        return reports

    def _collect_service(
        self,
        service: ServiceWatch,
        host: dict[str, Any],
        pressure: dict[str, Any],
        tailer: BoundedLogTailer,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        contract = self._remote_contracts.get(service.service_id, {})
        processes = enrich_cpu_percent(find_processes(service.process_match), self.state.data)
        process_running = bool(processes)

        max_log_bytes = self.settings.resource_guard.max_log_bytes_per_cycle
        max_log_lines = self.settings.resource_guard.max_log_lines_per_cycle
        if pressure["collector_mode"] == "throttled":
            max_log_bytes = max(8192, max_log_bytes // 4)
            max_log_lines = max(20, max_log_lines // 4)

        log_lines: list[str] = []
        log_meta: dict[str, Any] = {"configured": False}
        signatures: list[LogSignature] = []
        if service.log_path:
            log_lines, log_meta = tailer.read_new_lines(
                service.log_path,
                max_bytes=max_log_bytes,
                max_lines=max_log_lines,
                initial_tail_bytes=self.settings.resource_guard.initial_tail_bytes,
            )
            signatures = [
                signature
                for line in log_lines
                if (signature := classify_line(line, default_timestamp=now))
            ]
            log_meta["configured"] = True
            log_meta["owner"] = file_owner_summary(service.log_path)

        profile_analysis = analyze_service_profile(service, log_lines, default_timestamp=now)
        if profile_analysis:
            signatures.extend(profile_analysis.signatures)

        healthcheck = _run_health_check(service.healthcheck_url, timeout_seconds=3)

        status, severity, failure_domain = _status_from_evidence(
            service=service,
            process_running=process_running,
            signatures=signatures,
            pressure=pressure,
            healthcheck=healthcheck,
        )
        if profile_analysis and profile_analysis.status_hint and status == "up":
            status = profile_analysis.status_hint
            severity = profile_analysis.severity_hint or severity
            failure_domain = profile_analysis.failure_domain_hint or failure_domain
        message = _message_for(status, service, process_running, signatures, pressure)
        if profile_analysis and profile_analysis.message_hint and profile_analysis.signatures:
            message = profile_analysis.message_hint

        return {
            "agent_id": self.settings.agent_id,
            "agent_version": __version__,
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "source": "nexus_light_agent",
            "service_id": service.service_id,
            "service_name": service.service_name,
            "environment": service.environment,
            "instance_id": service.instance_id or f"{host.get('hostname')}:{service.service_id}",
            "host_id": host.get("hostname"),
            "cluster": service.cluster_id,
            "business_flow_id": service.business_flow_id,
            "probe_family": "runtime_log_process",
            "vantage_point": "local_agent",
            "observation_layer": "service_runtime",
            "failure_domain_hint": failure_domain,
            "status": status,
            "severity": severity,
            "message": message,
            "metrics": {
                "process_count": len(processes),
                "processes": processes,
                "healthcheck": healthcheck,
                "host": host,
                "resource_pressure": pressure,
                "service_profile": profile_analysis.metrics if profile_analysis else None,
                "remote_contract": {
                    "available": bool(contract),
                    "service_type": contract.get("service", {}).get("service_type"),
                    "criticality": contract.get("service", {}).get("criticality"),
                    "certification": contract.get("service", {}).get("certification"),
                    "restart_policy": contract.get("service", {}).get("restart_policy"),
                },
            },
            "logs": [signature.message for signature in signatures[:20]],
            "log_records": [signature.to_dict() for signature in signatures[:20]],
            "metadata": {
                "failure_domain": failure_domain,
                "log_signatures": summarize_signatures(signatures),
                "log_window": log_meta,
                "expected_running": service.expected_running,
                "process_match": service.process_match,
                "log_path": service.log_path,
                "tags": service.tags,
                "analysis_profile": service.analysis_profile,
                "service_profile_observations": profile_analysis.observations if profile_analysis else [],
                "collector_mode": pressure["collector_mode"],
            },
        }

    def _send_or_spool(self, report: dict[str, Any]) -> None:
        try:
            self.client.probe_report(report)
        except NexusClientError as exc:
            LOGGER.warning("probe report spooled for %s: %s", report.get("service_id"), exc)
            self.spool.append(report)

    def _flush_spool(self) -> None:
        try:
            sent = self.spool.flush(lambda payload: self.client.probe_report(payload))
            if sent:
                LOGGER.info("flushed %s spooled probe reports", sent)
        except Exception:
            LOGGER.exception("failed while flushing probe spool")

    def _flush_failed_callbacks(self) -> None:
        with self._state_lock:
            diagnostic_results = list(self.state.data.get("failed_diagnostic_results") or [])
            control_results = list(self.state.data.get("failed_control_results") or [])

        sent_diagnostics = self._flush_callback_batch(
            diagnostic_results,
            callback=lambda payload: self.client.diagnostic_results(payload),
            state_key="failed_diagnostic_results",
        )
        sent_controls = self._flush_callback_batch(
            control_results,
            callback=lambda payload: self.client.control_result(payload),
            state_key="failed_control_results",
        )
        if sent_diagnostics:
            LOGGER.info("flushed %s delayed diagnostic result callback(s)", sent_diagnostics)
        if sent_controls:
            LOGGER.info("flushed %s delayed control result callback(s)", sent_controls)

    def _flush_callback_batch(self, payloads: list[dict[str, Any]], *, callback: Any, state_key: str) -> int:
        if not payloads:
            return 0
        remaining: list[dict[str, Any]] = []
        sent = 0
        for payload in payloads:
            try:
                callback(payload)
                sent += 1
            except Exception:
                remaining.append(payload)
        with self._state_lock:
            self.state.data[state_key] = remaining[-50:]
        return sent

    def _maybe_send_heartbeats(self, now: float, host: dict[str, Any], pressure: dict[str, Any]) -> None:
        if now - self._last_heartbeat_at < self.settings.heartbeat_interval_seconds:
            return
        for service in self.settings.enabled_services:
            payload = {
                "agent_id": self.settings.agent_id,
                "service_id": service.service_id,
                "environment": service.environment,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "platform": str(host.get("platform") or "linux"),
                "version": __version__,
                "instance_id": service.instance_id or f"{host.get('hostname')}:{service.service_id}",
                "host_id": host.get("hostname"),
                "cluster": service.cluster_id,
                "capabilities": [
                    "runtime_probe",
                    "bounded_log_signatures",
                    "service_profile_analysis",
                    "local_healthcheck",
                    "diagnostics_executor",
                    "guarded_restart_executor",
                ],
                "metadata": {
                    "collector_mode": pressure["collector_mode"],
                    "command_server_enabled": self.settings.command_server.enabled,
                },
            }
            try:
                self.client.heartbeat(payload)
            except NexusClientError as exc:
                LOGGER.warning("heartbeat failed for %s: %s", service.service_id, exc)
        self._last_heartbeat_at = now

    def _refresh_remote_contracts(self, now: float, *, force: bool = False) -> None:
        if not force and now - self._last_remote_config_at < self.settings.config_refresh_interval_seconds:
            return
        for service in self.settings.enabled_services:
            try:
                self._remote_contracts[service.service_id] = self.client.fetch_agent_config(service.service_id)
            except NexusClientError as exc:
                LOGGER.warning("remote config unavailable for %s: %s", service.service_id, exc)
        self._last_remote_config_at = now

    def get_service(self, service_id: str) -> ServiceWatch | None:
        return next((service for service in self.settings.enabled_services if service.service_id == service_id), None)

    def get_remote_contract(self, service_id: str, *, force: bool = False) -> dict[str, Any]:
        if force or service_id not in self._remote_contracts:
            try:
                self._remote_contracts[service_id] = self.client.fetch_agent_config(service_id)
            except NexusClientError as exc:
                LOGGER.warning("remote config unavailable for %s: %s", service_id, exc)
        return self._remote_contracts.get(service_id, {})

    def get_cached_remote_contract(self, service_id: str) -> dict[str, Any]:
        return self._remote_contracts.get(service_id, {})

    def _handle_stop(self, _signum: int, _frame: object) -> None:
        self._stopping = True


def setup_logging(log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )


def _apply_nice(value: int) -> None:
    if value <= 0:
        return
    if not hasattr(os, "nice"):
        return
    try:
        os.nice(value)
    except OSError:
        LOGGER.warning("unable to adjust process nice value to %s", value)


def _run_health_check(url: str | None, timeout_seconds: int = 3) -> dict[str, Any]:
    if not url:
        return {"configured": False}
    started = time.monotonic()
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "sentinel-nexus-light-agent/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response.read(2048)
            status_code = response.getcode()
    except urllib.error.HTTPError as exc:
        return {
            "configured": True,
            "ok": False,
            "status_code": exc.code,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "error": f"HTTP {exc.code}",
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "configured": True,
            "ok": False,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "error": str(exc),
        }
    return {
        "configured": True,
        "ok": 200 <= status_code < 400,
        "status_code": status_code,
        "latency_ms": round((time.monotonic() - started) * 1000, 2),
    }


def _status_from_evidence(
    *,
    service: ServiceWatch,
    process_running: bool,
    signatures: list[LogSignature],
    pressure: dict[str, Any],
    healthcheck: dict[str, Any],
) -> tuple[str, str, str]:
    if service.expected_running and not process_running:
        return "down", "CRITICAL", "service_runtime"
    if healthcheck.get("configured") and not healthcheck.get("ok"):
        return "degraded", "WARN", "service_runtime"
    if any(item.severity == "CRITICAL" for item in signatures):
        critical = next(item for item in signatures if item.severity == "CRITICAL")
        return "degraded", "CRITICAL", critical.failure_domain
    if pressure["collector_mode"] == "throttled":
        return "degraded", "WARN", "host"
    if signatures:
        return "degraded", "WARN", signatures[0].failure_domain
    return "up", "INFO", "service_runtime"


def _message_for(
    status: str,
    service: ServiceWatch,
    process_running: bool,
    signatures: list[LogSignature],
    pressure: dict[str, Any],
) -> str:
    if service.expected_running and not process_running:
        return f"{service.service_name} process is not running on the local host."
    if signatures:
        top = summarize_signatures(signatures)[0]
        return (
            f"{service.service_name} is {status}; observed {top['count']} "
            f"{top['signature_family']} evidence item(s)."
        )
    if pressure["collector_mode"] == "throttled":
        return f"{service.service_name} is being monitored in throttled mode due to host pressure."
    return f"{service.service_name} local runtime appears healthy."
