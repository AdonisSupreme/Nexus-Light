from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import ServiceWatch
from .signatures import LogSignature


TIMESTAMP_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"
)
USSD_SESSION_EXPIRY_RE = re.compile(
    r"Expiring session with key (?P<carrier>[^:\s]+):(?P<subscriber>[^:\s]+):(?P<session_id>\S+)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ServiceProfileAnalysis:
    profile_name: str
    metrics: dict[str, Any] = field(default_factory=dict)
    observations: list[dict[str, Any]] = field(default_factory=list)
    signatures: list[LogSignature] = field(default_factory=list)
    failure_domain_hint: str | None = None
    status_hint: str | None = None
    severity_hint: str | None = None
    message_hint: str | None = None


def analyze_service_profile(
    service: ServiceWatch,
    log_lines: list[str],
    *,
    default_timestamp: datetime,
) -> ServiceProfileAnalysis | None:
    profile = (service.analysis_profile or "").strip().lower()
    if profile in {"mobile_ussd", "txn_mobile_ussd", "ussd"}:
        return _analyze_mobile_ussd(service, log_lines, default_timestamp=default_timestamp)
    return None


def _analyze_mobile_ussd(
    service: ServiceWatch,
    log_lines: list[str],
    *,
    default_timestamp: datetime,
) -> ServiceProfileAnalysis:
    config = service.analysis_config or {}
    window_seconds = _int_config(config, "session_expiry_burst_window_seconds", 60)
    warn_threshold = _int_config(config, "session_expiry_warn_threshold", 10)
    critical_threshold = _int_config(config, "session_expiry_critical_threshold", 30)
    min_carriers = _int_config(config, "session_expiry_min_carriers", 2)
    ratio_warn = _float_config(config, "session_expiry_ratio_warn", 0.25)
    compact_window_seconds = _int_config(config, "session_expiry_compact_window_seconds", 10)
    compact_threshold = _int_config(config, "session_expiry_compact_threshold", 5)

    current_timestamp = default_timestamp
    expiries: list[dict[str, Any]] = []
    session_responses = 0
    success_responses = 0

    for line in log_lines:
        timestamp = _extract_timestamp(line)
        if timestamp is not None:
            current_timestamp = timestamp
        if "SessionResponse" in line:
            session_responses += 1
        if "REMOTE SERVICE SUCCESS RESPONSE" in line or "HTTP STATUS=200" in line or "Returned status code 200" in line:
            success_responses += 1
        match = USSD_SESSION_EXPIRY_RE.search(line)
        if not match:
            continue
        expiries.append(
            {
                "timestamp": current_timestamp,
                "carrier": _safe_carrier(match.group("carrier")),
            }
        )

    carriers = sorted({item["carrier"] for item in expiries if item.get("carrier")})
    burst_count = _max_count_inside_window([item["timestamp"] for item in expiries], window_seconds)
    compact_count = _max_count_inside_window([item["timestamp"] for item in expiries], compact_window_seconds)
    span_seconds = _span_seconds([item["timestamp"] for item in expiries])
    denominator = max(session_responses, 1)
    expiry_ratio = len(expiries) / denominator

    analysis = ServiceProfileAnalysis(
        profile_name="mobile_ussd",
        metrics={
            "profile": "mobile_ussd",
            "session_expiry_count": len(expiries),
            "session_expiry_burst_count": burst_count,
            "session_expiry_compact_burst_count": compact_count,
            "session_expiry_window_seconds": window_seconds,
            "session_expiry_compact_window_seconds": compact_window_seconds,
            "session_expiry_span_seconds": span_seconds,
            "session_expiry_carrier_count": len(carriers),
            "session_expiry_carriers": carriers,
            "session_response_count": session_responses,
            "remote_success_response_count": success_responses,
            "session_expiry_to_response_ratio": round(expiry_ratio, 4),
            "session_expiry_thresholds": {
                "warn_count": warn_threshold,
                "critical_count": critical_threshold,
                "min_carriers": min_carriers,
                "ratio_warn": ratio_warn,
                "compact_count": compact_threshold,
            },
        },
    )

    if not expiries:
        return analysis

    analysis.observations.append(
        {
            "observation_type": "ussd_session_expiry",
            "count": len(expiries),
            "carrier_count": len(carriers),
            "carriers": carriers,
            "span_seconds": span_seconds,
            "false_positive_note": "Low-volume session expiry can be normal user inactivity; only bursts become degradation evidence.",
        }
    )

    multi_carrier = len(carriers) >= min_carriers
    ratio_triggered = expiry_ratio >= ratio_warn and len(expiries) >= compact_threshold
    compact_triggered = compact_count >= compact_threshold
    burst_triggered = burst_count >= warn_threshold

    if not (multi_carrier and (burst_triggered or ratio_triggered or compact_triggered)):
        return analysis

    trigger_reasons = []
    if burst_triggered:
        trigger_reasons.append("burst_threshold")
    if compact_triggered:
        trigger_reasons.append("compact_burst_threshold")
    if ratio_triggered:
        trigger_reasons.append("expiry_to_response_ratio")

    severity = "CRITICAL" if burst_count >= critical_threshold else "WARN"
    timestamp = max((item["timestamp"] for item in expiries), default=default_timestamp)
    signature = LogSignature(
        timestamp=timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        severity=severity,
        message=(
            f"{service.service_name} observed {len(expiries)} USSD session expiries across "
            f"{len(carriers)} carrier(s) in {max(span_seconds, 0.0):.1f}s. Treat as possible "
            "USSD tunnel/session-path degradation only after correlating with external reachability "
            "and active user-impact evidence."
        ),
        signature_family="ussd_session_expiry_burst",
        error_class="session_expiry_burst",
        failure_domain="channel_tunnel",
        attributes={
            "profile": "mobile_ussd",
            "carrier_count": len(carriers),
            "carriers": carriers,
            "expiry_count": len(expiries),
            "burst_count": burst_count,
            "compact_burst_count": compact_count,
            "span_seconds": span_seconds,
            "session_response_count": session_responses,
            "remote_success_response_count": success_responses,
            "expiry_to_response_ratio": round(expiry_ratio, 4),
            "trigger_reasons": trigger_reasons,
            "pii_redacted": True,
            "diagnostic_hint": "local_runtime_up_external_tunnel_may_be_unreachable",
        },
    )
    analysis.signatures.append(signature)
    analysis.failure_domain_hint = "channel_tunnel"
    analysis.status_hint = "degraded"
    analysis.severity_hint = severity
    analysis.message_hint = signature.message
    return analysis


def _extract_timestamp(text: str) -> datetime | None:
    match = TIMESTAMP_RE.search(text)
    if not match:
        return None
    value = match.group("timestamp").replace(",", ".").replace(" ", "T")
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _max_count_inside_window(timestamps: list[datetime], window_seconds: int) -> int:
    if not timestamps:
        return 0
    ordered = sorted(timestamps)
    best = 1
    left = 0
    for right, timestamp in enumerate(ordered):
        while (timestamp - ordered[left]).total_seconds() > window_seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def _span_seconds(timestamps: list[datetime]) -> float:
    if len(timestamps) < 2:
        return 0.0
    ordered = sorted(timestamps)
    return round((ordered[-1] - ordered[0]).total_seconds(), 3)


def _safe_carrier(value: str) -> str:
    sanitized = re.sub(r"[^a-z0-9_-]+", "", value.strip().lower())
    return sanitized or "unknown"


def _int_config(config: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(config.get(key, default))
    except (TypeError, ValueError):
        return default


def _float_config(config: dict[str, Any], key: str, default: float) -> float:
    try:
        return float(config.get(key, default))
    except (TypeError, ValueError):
        return default
