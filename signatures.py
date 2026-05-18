from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


TIMESTAMP_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"
)
LEVEL_RE = re.compile(r"\b(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b")
TRACE_ID_RE = re.compile(r"\b(?:ATE-Trace-ID|trace[_-]?id|correlation[_-]?id)=?(?P<trace>[A-Za-z0-9_.:-]+)")
SQLSTATE_RE = re.compile(r"\bSQLSTATE(?:\s*[:=])?\s*(?P<code>[A-Z0-9]{5})\b", re.IGNORECASE)
ORA_RE = re.compile(r"\b(?P<code>ORA-\d{5}|TNS-\d{5})\b", re.IGNORECASE)


@dataclass(slots=True)
class LogSignature:
    timestamp: str
    severity: str
    message: str
    signature_family: str
    error_class: str | None = None
    exception_name: str | None = None
    timeout_type: str | None = None
    oom_flag: bool = False
    db_error_code: str | None = None
    failure_domain: str = "service_runtime"
    trace_id: str | None = None
    attributes: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["attributes"] = payload["attributes"] or {}
        return payload


def classify_line(line: str, default_timestamp: datetime | None = None) -> LogSignature | None:
    text = line.strip()
    if not text:
        return None

    lowered = text.lower()
    level = _extract_level(text)
    is_interesting = level in {"WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"}

    signature_family = "service_log_warning" if is_interesting else ""
    error_class: str | None = None
    exception_name: str | None = None
    timeout_type: str | None = None
    oom_flag = False
    db_error_code: str | None = None
    failure_domain = "service_runtime"

    if "connection leak detection triggered" in lowered or "apparent connection leak detected" in lowered:
        signature_family = "database_connection_leak"
        error_class = "db_connection_leak"
        db_error_code = "HIKARI_CONNECTION_LEAK"
        failure_domain = "database"
        level = "CRITICAL"
        is_interesting = True
    elif "hikaripool" in lowered or "hikari" in lowered:
        signature_family = "database_pool_pressure"
        error_class = "db_pool"
        failure_domain = "database"
        db_error_code = "HIKARI_POOL"
        is_interesting = True

    sqlstate = SQLSTATE_RE.search(text)
    if sqlstate:
        signature_family = "database_error"
        error_class = "sqlstate"
        db_error_code = sqlstate.group("code").upper()
        failure_domain = "database"
        is_interesting = True

    ora = ORA_RE.search(text)
    if ora:
        signature_family = "oracle_error"
        error_class = "oracle"
        db_error_code = ora.group("code").upper()
        failure_domain = "database"
        is_interesting = True

    if "outofmemoryerror" in lowered or "java heap space" in lowered or "out of memory" in lowered:
        signature_family = "memory_pressure"
        error_class = "out_of_memory"
        oom_flag = True
        failure_domain = "host"
        level = "CRITICAL"
        is_interesting = True

    if "timeout" in lowered or "timed out" in lowered:
        signature_family = "dependency_timeout"
        error_class = "timeout"
        timeout_type = "read_or_connect_timeout"
        failure_domain = "dependency"
        is_interesting = True

    if "connection refused" in lowered or "could not connect" in lowered or "no route to host" in lowered:
        signature_family = "dependency_connectivity"
        error_class = "connectivity"
        failure_domain = "network_or_dependency"
        is_interesting = True

    exception = re.search(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_.]*(?:Exception|Error))\b", text)
    if exception and not signature_family:
        signature_family = "service_exception"
        exception_name = exception.group("name")
        error_class = "exception"
        is_interesting = True
    elif exception:
        exception_name = exception.group("name")

    if not is_interesting:
        return None

    timestamp = _extract_timestamp(text) or default_timestamp or datetime.now(timezone.utc)
    trace_id_match = TRACE_ID_RE.search(text)
    return LogSignature(
        timestamp=timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        severity=_normalize_level(level),
        message=_truncate(text, 1200),
        signature_family=signature_family or "service_log_warning",
        error_class=error_class,
        exception_name=exception_name,
        timeout_type=timeout_type,
        oom_flag=oom_flag,
        db_error_code=db_error_code,
        failure_domain=failure_domain,
        trace_id=trace_id_match.group("trace") if trace_id_match else None,
        attributes={"raw_level": level},
    )


def summarize_signatures(signatures: list[LogSignature]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str | None], dict[str, Any]] = {}
    for item in signatures:
        key = (item.signature_family, item.db_error_code)
        bucket = buckets.setdefault(
            key,
            {
                "signature_family": item.signature_family,
                "db_error_code": item.db_error_code,
                "failure_domain": item.failure_domain,
                "severity": item.severity,
                "count": 0,
                "first_seen": item.timestamp,
                "last_seen": item.timestamp,
            },
        )
        bucket["count"] += 1
        bucket["first_seen"] = min(bucket["first_seen"], item.timestamp)
        bucket["last_seen"] = max(bucket["last_seen"], item.timestamp)
        bucket["severity"] = _max_severity(bucket["severity"], item.severity)
    return sorted(buckets.values(), key=lambda item: (-int(item["count"]), item["signature_family"]))


def _extract_level(text: str) -> str:
    match = LEVEL_RE.search(text)
    return match.group("level") if match else "INFO"


def _normalize_level(level: str) -> str:
    level = level.upper()
    if level in {"FATAL", "CRITICAL"}:
        return "CRITICAL"
    if level == "ERROR":
        return "WARN"
    if level in {"WARN", "WARNING"}:
        return "WARN"
    return "INFO"


def _max_severity(left: str, right: str) -> str:
    order = {"INFO": 0, "WARN": 1, "CRITICAL": 2}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _extract_timestamp(text: str) -> datetime | None:
    match = TIMESTAMP_RE.search(text)
    if not match:
        return None
    value = match.group("timestamp").replace(",", ".").replace(" ", "T")
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
