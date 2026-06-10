from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class CommandServerConfig:
    enabled: bool = False
    bind_host: str = "127.0.0.1"
    port: int = 8765
    public_base_url: str | None = None
    request_timeout_seconds: int = 8

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "CommandServerConfig":
        payload = payload or {}
        return cls(
            enabled=bool(payload.get("enabled", False)),
            bind_host=str(payload.get("bind_host") or "127.0.0.1"),
            port=int(payload.get("port", 8765)),
            public_base_url=payload.get("public_base_url"),
            request_timeout_seconds=int(payload.get("request_timeout_seconds", 8)),
        )


@dataclass(slots=True)
class ResourceGuard:
    nice: int = 10
    max_log_bytes_per_cycle: int = 65536
    max_log_lines_per_cycle: int = 80
    initial_tail_bytes: int = 65536
    high_load_per_core: float = 0.85
    critical_load_per_core: float = 1.2
    min_available_memory_mb: int = 1024
    spool_max_records: int = 200

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "ResourceGuard":
        payload = payload or {}
        defaults = cls()
        return cls(
            nice=int(payload.get("nice", defaults.nice)),
            max_log_bytes_per_cycle=int(payload.get("max_log_bytes_per_cycle", defaults.max_log_bytes_per_cycle)),
            max_log_lines_per_cycle=int(payload.get("max_log_lines_per_cycle", defaults.max_log_lines_per_cycle)),
            initial_tail_bytes=int(payload.get("initial_tail_bytes", defaults.initial_tail_bytes)),
            high_load_per_core=float(payload.get("high_load_per_core", defaults.high_load_per_core)),
            critical_load_per_core=float(payload.get("critical_load_per_core", defaults.critical_load_per_core)),
            min_available_memory_mb=int(payload.get("min_available_memory_mb", defaults.min_available_memory_mb)),
            spool_max_records=int(payload.get("spool_max_records", defaults.spool_max_records)),
        )


@dataclass(slots=True)
class ServiceWatch:
    service_id: str
    service_name: str
    environment: str
    enabled: bool = True
    expected_running: bool = True
    instance_id: str | None = None
    cluster_id: str | None = None
    business_flow_id: str | None = None
    process_match: str | None = None
    log_path: str | None = None
    healthcheck_url: str | None = None
    systemd_unit: str | None = None
    jar_path: str | None = None
    config_path: str | None = None
    java_bin: str = "java"
    working_dir: str | None = None
    readiness_host: str | None = None
    readiness_port: int | None = None
    start_command: list[str] = field(default_factory=list)
    stop_command: list[str] = field(default_factory=list)
    restart_command: list[str] = field(default_factory=list)
    control_timeout_seconds: dict[str, int] = field(default_factory=dict)
    restart_settle_seconds: int = 5
    tags: list[str] = field(default_factory=list)
    analysis_profile: str | None = None
    analysis_config: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any], default_environment: str) -> "ServiceWatch":
        service_id = str(payload.get("service_id") or "").strip()
        if not service_id:
            raise ValueError("service entry is missing service_id")
        return cls(
            service_id=service_id,
            service_name=str(payload.get("service_name") or service_id),
            environment=str(payload.get("environment") or default_environment),
            enabled=bool(payload.get("enabled", True)),
            expected_running=bool(payload.get("expected_running", True)),
            instance_id=payload.get("instance_id"),
            cluster_id=payload.get("cluster_id"),
            business_flow_id=payload.get("business_flow_id"),
            process_match=payload.get("process_match"),
            log_path=payload.get("log_path"),
            healthcheck_url=payload.get("healthcheck_url"),
            systemd_unit=payload.get("systemd_unit"),
            jar_path=payload.get("jar_path"),
            config_path=payload.get("config_path"),
            java_bin=str(payload.get("java_bin") or "java"),
            working_dir=payload.get("working_dir"),
            readiness_host=payload.get("readiness_host"),
            readiness_port=int(payload["readiness_port"]) if payload.get("readiness_port") not in {None, ""} else None,
            start_command=[str(item) for item in payload.get("start_command", [])],
            stop_command=[str(item) for item in payload.get("stop_command", [])],
            restart_command=[str(item) for item in payload.get("restart_command", [])],
            control_timeout_seconds=_parse_control_timeout_seconds(payload),
            restart_settle_seconds=int(payload.get("restart_settle_seconds", 5)),
            tags=list(payload.get("tags") or []),
            analysis_profile=payload.get("analysis_profile"),
            analysis_config=dict(payload.get("analysis_config") or {}),
        )


def _parse_control_timeout_seconds(payload: dict[str, Any]) -> dict[str, int]:
    configured = payload.get("control_timeout_seconds")
    timeouts: dict[str, int] = {}
    if isinstance(configured, dict):
        for operation in ("default", "start", "stop", "restart"):
            value = configured.get(operation)
            if value not in {None, ""}:
                timeouts[operation] = int(value)
    elif configured not in {None, ""}:
        timeouts["default"] = int(configured)

    for operation in ("start", "stop", "restart"):
        value = payload.get(f"{operation}_timeout_seconds")
        if value not in {None, ""}:
            timeouts[operation] = int(value)
    return timeouts


@dataclass(slots=True)
class AgentSettings:
    agent_id: str
    environment: str
    nexus_base_url: str
    services: list[ServiceWatch]
    agent_token_env: str = "NEXUS_AGENT_API_TOKEN"
    agent_token_file: str | None = None
    poll_interval_seconds: int = 30
    heartbeat_interval_seconds: int = 60
    config_refresh_interval_seconds: int = 300
    http_timeout_seconds: int = 5
    state_dir: str = "/var/lib/sentinel-nexus-agent"
    log_file: str | None = "/var/log/sentinel-nexus-agent/agent.log"
    resource_guard: ResourceGuard = field(default_factory=ResourceGuard)
    command_server: CommandServerConfig = field(default_factory=CommandServerConfig)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentSettings":
        agent_id = str(payload.get("agent_id") or "").strip()
        if not agent_id:
            raise ValueError("agent_id is required")
        environment = str(payload.get("environment") or "production")
        nexus_base_url = str(payload.get("nexus_base_url") or "").strip().rstrip("/")
        if not nexus_base_url:
            raise ValueError("nexus_base_url is required")
        services = [
            ServiceWatch.from_dict(item, environment)
            for item in payload.get("services", [])
            if isinstance(item, dict)
        ]
        if not services:
            raise ValueError("at least one service must be configured")
        return cls(
            agent_id=agent_id,
            environment=environment,
            nexus_base_url=nexus_base_url,
            services=services,
            agent_token_env=str(payload.get("agent_token_env") or "NEXUS_AGENT_API_TOKEN"),
            agent_token_file=payload.get("agent_token_file"),
            poll_interval_seconds=int(payload.get("poll_interval_seconds", 30)),
            heartbeat_interval_seconds=int(payload.get("heartbeat_interval_seconds", 60)),
            config_refresh_interval_seconds=int(
                payload.get("config_refresh_interval_seconds", 300)
            ),
            http_timeout_seconds=int(payload.get("http_timeout_seconds", 5)),
            state_dir=str(payload.get("state_dir") or "/var/lib/sentinel-nexus-agent"),
            log_file=payload.get("log_file", "/var/log/sentinel-nexus-agent/agent.log"),
            resource_guard=ResourceGuard.from_dict(payload.get("resource_guard")),
            command_server=CommandServerConfig.from_dict(payload.get("command_server")),
        )

    @property
    def enabled_services(self) -> list[ServiceWatch]:
        return [service for service in self.services if service.enabled]

    def resolve_agent_token(self) -> str:
        token = os.environ.get(self.agent_token_env, "").strip()
        if token:
            return token
        if self.agent_token_file:
            path = Path(self.agent_token_file)
            if path.exists():
                return path.read_text(encoding="utf-8").strip()
        raise ValueError(
            f"Agent token not found. Set {self.agent_token_env} or configure agent_token_file."
        )


def load_settings(path: str | os.PathLike[str]) -> AgentSettings:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("agent config must be a JSON object")
    return AgentSettings.from_dict(payload)


def config_template() -> dict[str, Any]:
    return {
        "agent_id": "agent-txn-mobile-ussd-ate-01",
        "environment": "ate",
        "nexus_base_url": "http://192.168.203.53:8010",
        "agent_token_env": "NEXUS_AGENT_API_TOKEN",
        "poll_interval_seconds": 30,
        "heartbeat_interval_seconds": 60,
        "config_refresh_interval_seconds": 300,
        "http_timeout_seconds": 5,
        "state_dir": "/var/lib/sentinel-nexus-agent",
        "log_file": "/var/log/sentinel-nexus-agent/agent.log",
        "resource_guard": {
            "nice": 10,
            "max_log_bytes_per_cycle": 65536,
            "max_log_lines_per_cycle": 80,
            "initial_tail_bytes": 65536,
            "high_load_per_core": 0.85,
            "critical_load_per_core": 1.2,
            "min_available_memory_mb": 1024,
            "spool_max_records": 200,
        },
        "command_server": {
            "enabled": False,
            "bind_host": "127.0.0.1",
            "port": 8765,
            "public_base_url": "http://ate-test-hostname:8765",
            "request_timeout_seconds": 8,
        },
        "services": [
            {
                "service_id": "txn-mobile-ussd",
                "service_name": "Mobile Banking USSD",
                "environment": "ate",
                "cluster_id": "mobile-banking-ate",
                "business_flow_id": "mobile-ussd-balance-enquiry",
                "instance_id": "ussd-ate-test:txn-mobile-ussd",
                "expected_running": True,
                "process_match": "txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
                "log_path": "/srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log",
                "healthcheck_url": None,
                "systemd_unit": None,
                "jar_path": "/srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
                "config_path": "/srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml",
                "java_bin": "java",
                "working_dir": "/srv",
                "readiness_host": "127.0.0.1",
                "readiness_port": 8091,
                "start_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/start.sh"],
                "stop_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/stop.sh"],
                "restart_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/restart.sh"],
                "restart_settle_seconds": 30,
                "tags": ["mobile-banking", "ussd", "channel"],
                "analysis_profile": "mobile_ussd",
                "analysis_config": {
                    "session_expiry_burst_window_seconds": 60,
                    "session_expiry_warn_threshold": 10,
                    "session_expiry_critical_threshold": 30,
                    "session_expiry_min_carriers": 2,
                    "session_expiry_ratio_warn": 0.25,
                    "session_expiry_compact_window_seconds": 10,
                    "session_expiry_compact_threshold": 5,
                },
            },
            {
                "service_id": "txn-ussd-adapter",
                "service_name": "USSD Adapter",
                "environment": "ate",
                "cluster_id": "mobile-banking-ate",
                "business_flow_id": "mobile-ussd-balance-enquiry",
                "instance_id": "ussd-ate-test:txn-ussd-adapter",
                "expected_running": True,
                "process_match": "txn-ussd-adapter-0.0.1-SNAPSHOT.jar",
                "log_path": "/srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log",
                "healthcheck_url": None,
                "systemd_unit": None,
                "jar_path": "/srv/afc/txn-mobile/txn-ussd-adapter/lib/txn-ussd-adapter-0.0.1-SNAPSHOT.jar",
                "config_path": "/srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml",
                "java_bin": "java",
                "working_dir": "/srv",
                "readiness_host": "127.0.0.1",
                "readiness_port": None,
                "start_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/start.sh"],
                "stop_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh"],
                "restart_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh"],
                "restart_settle_seconds": 30,
                "tags": ["mobile-banking", "ussd", "adapter", "channel-adapter"],
                "analysis_profile": None,
                "analysis_config": {},
            },
        ],
    }
