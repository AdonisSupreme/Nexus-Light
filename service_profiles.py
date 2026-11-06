from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import ServiceWatch
from .signatures import LogSignature


TIMESTAMP_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"
)
LOG_EVENT_START_RE = re.compile(
    r"^\s*\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?\]?\s+"
    r"(?:ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL|CRITICAL)\b"
)
USSD_SESSION_EXPIRY_RE = re.compile(
    r"Expiring session with key (?P<carrier>[^:\s]+):(?P<subscriber>[^:\s]+):(?P<session_id>\S+)",
    re.IGNORECASE,
)
MOBILE_SESSION_REQUEST_RE = re.compile(
    r"SessionControllerImpl[^\r\n]*\s-\sSessionRequest(?:\s*$)",
    re.IGNORECASE | re.MULTILINE,
)
MOBILE_SESSION_RESPONSE_RE = re.compile(
    r"SessionControllerImpl[^\r\n]*\s-\sSessionResponse(?:\s*$)",
    re.IGNORECASE | re.MULTILINE,
)
HIKARI_LEAK_RE = re.compile(
    r"ProxyLeakTask[^\r\n]*\s-\sConnection leak detection triggered",
    re.IGNORECASE,
)
NOTIFICATION_POLL_RE = re.compile(
    r"NotificationServiceImpl[^\r\n]*\s-\sNotificationService\s-\sPoll",
    re.IGNORECASE,
)
ADAPTER_INBOUND_RE = re.compile(r"\b(?P<carrier>ECONET|NETONE) REQUEST INBOUND\b", re.IGNORECASE)
ADAPTER_OUTBOUND_RE = re.compile(r"\b(?P<carrier>ECONET|NETONE) RESPONSE OUTBOUND\b", re.IGNORECASE)
ADAPTER_USSD_DISPATCH_RE = re.compile(
    r"POST to https?://(?:localhost|127\.0\.0\.1)(?::\d+)?/[^\r\n]*txn-mobile-ussd/session",
    re.IGNORECASE,
)
ADAPTER_USSD_SUCCESS_RE = re.compile(
    r"UssdRemoteServiceImpl[^\r\n]*REMOTE SERVICE SUCCESS RESPONSE,\s*HTTP STATUS=2\d\d",
    re.IGNORECASE,
)
ADAPTER_USSD_5XX_RE = re.compile(
    r"REMOTE SERVICE ERROR RESPONSE,\s*HTTP STATUS=(?P<status>5\d\d)",
    re.IGNORECASE,
)
ADAPTER_SERVLET_NPE_RE = re.compile(r"dispatcherServlet[^\r\n]*NullPointerException", re.IGNORECASE)
ADAPTER_TEMPLATE_FAILURE_RE = re.compile(
    r"TemplateProcessingUtil[^\r\n]*\s-\sTemplate Exception",
    re.IGNORECASE,
)
ADAPTER_MISSING_REQUEST_ID_RE = re.compile(
    r"InvalidReferenceException[\s\S]{0,600}?\brequestId\b|requestId\s+\[in template",
    re.IGNORECASE,
)
ADAPTER_SMPP_TIMEOUT_RE = re.compile(
    r"SmppTransciever[^\r\n]*(?:timed out|timeout)|IOException:\s*Connection timed out",
    re.IGNORECASE,
)

ROLLING_SAMPLE_LIMIT = 120
SEVERITY_ORDER = {"INFO": 0, "WARN": 1, "CRITICAL": 2}


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


@dataclass(slots=True)
class _LogEvent:
    timestamp: datetime
    text: str


def analyze_service_profile(
    service: ServiceWatch,
    log_lines: list[str],
    *,
    default_timestamp: datetime,
    state: dict[str, Any] | None = None,
) -> ServiceProfileAnalysis | None:
    profile = (service.analysis_profile or "").strip().lower()
    if profile in {"mobile_ussd", "txn_mobile_ussd", "ussd"}:
        return _analyze_mobile_ussd(
            service,
            log_lines,
            default_timestamp=default_timestamp,
            state=state,
        )
    if profile in {"ussd_adapter", "txn_ussd_adapter", "mobile_ussd_adapter"}:
        return _analyze_ussd_adapter(
            service,
            log_lines,
            default_timestamp=default_timestamp,
            state=state,
        )
    return None


def filter_profile_generic_signatures(
    profile_name: str | None,
    signatures: list[LogSignature],
) -> list[LogSignature]:
    """Remove raw lines owned by a profile so its gated aggregate is authoritative."""
    profile = (profile_name or "").strip().lower()
    filtered: list[LogSignature] = []
    for signature in signatures:
        message = signature.message.lower()
        if profile in {"mobile_ussd", "txn_mobile_ussd", "ussd"}:
            if signature.signature_family == "database_connection_leak":
                continue
        if profile in {"ussd_adapter", "txn_ussd_adapter", "mobile_ussd_adapter"}:
            adapter_owned = (
                ("remote service error response" in message and "http status=5" in message)
                or ("dispatcherservlet" in message and "nullpointerexception" in message)
                or "templateprocessingutil" in message
                or "template exception" in message
                or (
                    signature.signature_family == "dependency_timeout"
                    and "smpptransciever" in message
                )
            )
            if adapter_owned:
                continue
        filtered.append(signature)
    return filtered


def _analyze_mobile_ussd(
    service: ServiceWatch,
    log_lines: list[str],
    *,
    default_timestamp: datetime,
    state: dict[str, Any] | None,
) -> ServiceProfileAnalysis:
    config = service.analysis_config or {}
    expiry_window = _int_config(config, "session_expiry_burst_window_seconds", 60)
    expiry_warn = _int_config(config, "session_expiry_warn_threshold", 10)
    expiry_critical = _int_config(config, "session_expiry_critical_threshold", 30)
    expiry_min_carriers = _int_config(config, "session_expiry_min_carriers", 2)
    expiry_ratio_warn = _float_config(config, "session_expiry_ratio_warn", 0.25)
    compact_window = _int_config(config, "session_expiry_compact_window_seconds", 10)
    compact_threshold = _int_config(config, "session_expiry_compact_threshold", 5)
    health_window = _int_config(config, "health_window_seconds", 60)
    leak_warn = _int_config(config, "db_leak_warn_threshold", 2)
    leak_critical = _int_config(config, "db_leak_critical_threshold", 5)
    stall_min_requests = _int_config(config, "session_stall_min_requests", 5)
    stall_min_deficit = _int_config(config, "session_stall_min_deficit", 3)
    stall_ratio = _float_config(config, "session_stall_completion_ratio", 0.5)
    rolling_window = max(expiry_window, health_window)

    events = _group_log_events(log_lines, default_timestamp=default_timestamp)
    expiries: list[dict[str, Any]] = []
    counts = {
        "session_requests": 0,
        "session_responses": 0,
        "remote_success_responses": 0,
        "database_connection_leaks": 0,
        "notification_polls": 0,
        "session_expiries": 0,
    }
    for event in events:
        text = event.text
        counts["session_requests"] += int(bool(MOBILE_SESSION_REQUEST_RE.search(text)))
        counts["session_responses"] += int(bool(MOBILE_SESSION_RESPONSE_RE.search(text)))
        counts["remote_success_responses"] += int(
            "REMOTE SERVICE SUCCESS RESPONSE" in text
            or "HTTP STATUS=200" in text
            or "Returned status code 200" in text
        )
        counts["database_connection_leaks"] += int(bool(HIKARI_LEAK_RE.search(text)))
        counts["notification_polls"] += int(bool(NOTIFICATION_POLL_RE.search(text)))
        for match in USSD_SESSION_EXPIRY_RE.finditer(text):
            expiries.append(
                {
                    "timestamp": event.timestamp,
                    "carrier": _safe_carrier(match.group("carrier")),
                }
            )
    counts["session_expiries"] = len(expiries)

    carriers = sorted({item["carrier"] for item in expiries})
    rolling, rolling_carriers = _rolling_counts(
        state,
        profile_name="mobile_ussd",
        current_counts=counts,
        carriers=carriers,
        observed_at=default_timestamp,
        window_seconds=rolling_window,
    )
    burst_count = _max_count_inside_window([item["timestamp"] for item in expiries], expiry_window)
    compact_count = _max_count_inside_window([item["timestamp"] for item in expiries], compact_window)
    expiry_span = _span_seconds([item["timestamp"] for item in expiries])
    expiry_ratio = len(expiries) / max(counts["session_responses"], 1)
    requests = rolling["session_requests"]
    responses = rolling["session_responses"]
    completion_ratio = min(responses / max(requests, 1), 1.0)
    response_deficit = max(requests - responses, 0)
    leak_count = rolling["database_connection_leaks"]
    traffic_state = (
        "processing"
        if requests and responses
        else "requests_without_responses"
        if requests
        else "scheduled_runtime_only"
        if rolling["notification_polls"]
        else "quiet"
    )

    analysis = ServiceProfileAnalysis(
        profile_name="mobile_ussd",
        metrics={
            "profile": "mobile_ussd",
            "health_window_seconds": rolling_window,
            "traffic_state": traffic_state,
            "session_request_count": counts["session_requests"],
            "session_response_count": counts["session_responses"],
            "rolling_session_request_count": requests,
            "rolling_session_response_count": responses,
            "rolling_session_completion_ratio": round(completion_ratio, 4),
            "rolling_session_response_deficit": response_deficit,
            "database_connection_leak_count": counts["database_connection_leaks"],
            "rolling_database_connection_leak_count": leak_count,
            "notification_poll_count": counts["notification_polls"],
            "rolling_notification_poll_count": rolling["notification_polls"],
            "session_expiry_count": len(expiries),
            "rolling_session_expiry_count": rolling["session_expiries"],
            "session_expiry_burst_count": burst_count,
            "session_expiry_compact_burst_count": compact_count,
            "session_expiry_window_seconds": expiry_window,
            "session_expiry_compact_window_seconds": compact_window,
            "session_expiry_span_seconds": expiry_span,
            "session_expiry_carrier_count": len(carriers),
            "session_expiry_carriers": carriers,
            "rolling_session_expiry_carriers": rolling_carriers,
            "remote_success_response_count": counts["remote_success_responses"],
            "session_expiry_to_response_ratio": round(expiry_ratio, 4),
            "session_expiry_thresholds": {
                "warn_count": expiry_warn,
                "critical_count": expiry_critical,
                "min_carriers": expiry_min_carriers,
                "ratio_warn": expiry_ratio_warn,
                "compact_count": compact_threshold,
            },
            "runtime_health_thresholds": {
                "db_leak_warn_count": leak_warn,
                "db_leak_critical_count": leak_critical,
                "stall_min_requests": stall_min_requests,
                "stall_min_deficit": stall_min_deficit,
                "stall_completion_ratio": stall_ratio,
            },
        },
    )

    if counts["notification_polls"] and not counts["session_requests"]:
        analysis.observations.append(
            {
                "observation_type": "ussd_scheduled_runtime_activity",
                "poll_count": counts["notification_polls"],
                "traffic_state": traffic_state,
                "interpretation": (
                    "The scheduled worker is alive, but scheduled polling alone does not prove "
                    "that customer USSD requests are reaching or completing in this service."
                ),
            }
        )
    if expiries:
        analysis.observations.append(
            {
                "observation_type": "ussd_session_expiry",
                "count": len(expiries),
                "carrier_count": len(carriers),
                "carriers": carriers,
                "span_seconds": expiry_span,
                "false_positive_note": (
                    "Low-volume session expiry can be normal user inactivity; only bursts become degradation evidence."
                ),
            }
        )

    if leak_count >= leak_warn:
        severity = "CRITICAL" if leak_count >= leak_critical else "WARN"
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(default_timestamp),
                severity=severity,
                message=(
                    f"{service.service_name} observed {leak_count} Hikari connection leak events "
                    f"inside the last {rolling_window} seconds. The runtime is alive, but database "
                    "connections are not returning normally and USSD request processing is at risk."
                ),
                signature_family="database_connection_leak_burst",
                error_class="db_connection_leak_burst",
                db_error_code="HIKARI_CONNECTION_LEAK",
                failure_domain="database",
                attributes={
                    "profile": "mobile_ussd",
                    "window_seconds": rolling_window,
                    "leak_count": leak_count,
                    "warn_threshold": leak_warn,
                    "critical_threshold": leak_critical,
                    "session_request_count": requests,
                    "session_response_count": responses,
                    "notification_poll_count": rolling["notification_polls"],
                    "pii_redacted": True,
                    "diagnostic_hint": "inspect_hikari_pool_and_database_sessions",
                },
            )
        )

    if (
        requests >= stall_min_requests
        and response_deficit >= stall_min_deficit
        and completion_ratio < stall_ratio
    ):
        severity = (
            "CRITICAL"
            if response_deficit >= max(stall_min_deficit * 2, 10)
            and completion_ratio <= min(stall_ratio, 0.2)
            else "WARN"
        )
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(default_timestamp),
                severity=severity,
                message=(
                    f"{service.service_name} observed {requests} session requests but only {responses} "
                    f"session responses inside the last {rolling_window} seconds. "
                    "The request-processing path is stalling."
                ),
                signature_family="ussd_session_processing_stall",
                error_class="session_response_deficit",
                failure_domain="service_runtime",
                attributes={
                    "profile": "mobile_ussd",
                    "window_seconds": rolling_window,
                    "session_request_count": requests,
                    "session_response_count": responses,
                    "response_deficit": response_deficit,
                    "completion_ratio": round(completion_ratio, 4),
                    "minimum_completion_ratio": stall_ratio,
                    "pii_redacted": True,
                    "diagnostic_hint": "inspect_request_threads_database_pool_and_downstream_calls",
                },
            )
        )

    multi_carrier = len(carriers) >= expiry_min_carriers
    expiry_triggered = (
        burst_count >= expiry_warn
        or compact_count >= compact_threshold
        or (expiry_ratio >= expiry_ratio_warn and len(expiries) >= compact_threshold)
    )
    if expiries and multi_carrier and expiry_triggered:
        severity = "CRITICAL" if burst_count >= expiry_critical else "WARN"
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(max(item["timestamp"] for item in expiries)),
                severity=severity,
                message=(
                    f"{service.service_name} observed {len(expiries)} USSD session expiries across "
                    f"{len(carriers)} carrier(s) in {max(expiry_span, 0.0):.1f}s. Treat as possible "
                    "USSD tunnel/session-path degradation only after correlating with external "
                    "reachability and active user-impact evidence."
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
                    "span_seconds": expiry_span,
                    "session_response_count": counts["session_responses"],
                    "remote_success_response_count": counts["remote_success_responses"],
                    "expiry_to_response_ratio": round(expiry_ratio, 4),
                    "pii_redacted": True,
                    "diagnostic_hint": "local_runtime_up_external_tunnel_may_be_unreachable",
                },
            )
        )

    _apply_primary_signature(analysis)
    return analysis


def _analyze_ussd_adapter(
    service: ServiceWatch,
    log_lines: list[str],
    *,
    default_timestamp: datetime,
    state: dict[str, Any] | None,
) -> ServiceProfileAnalysis:
    config = service.analysis_config or {}
    window_seconds = _int_config(config, "flow_window_seconds", 60)
    min_requests = _int_config(config, "minimum_requests", 5)
    warn_failures = _int_config(config, "failure_warn_threshold", 3)
    critical_failures = _int_config(config, "failure_critical_threshold", 10)
    minimum_dispatch_ratio = _float_config(config, "minimum_dispatch_ratio", 0.8)
    minimum_completion_ratio = _float_config(config, "minimum_completion_ratio", 0.5)
    minimum_outbound_ratio = _float_config(config, "minimum_outbound_ratio", 0.5)
    template_warn = _int_config(config, "template_failure_warn_threshold", 2)
    smpp_timeout_warn = _int_config(config, "smpp_timeout_warn_threshold", 3)
    dependency_service_id = str(config.get("dependency_service_id") or "txn-mobile-ussd").strip()

    counts = {
        "carrier_inbound_requests": 0,
        "ussd_dispatches": 0,
        "downstream_successes": 0,
        "downstream_5xx_errors": 0,
        "carrier_outbound_responses": 0,
        "servlet_null_pointer_errors": 0,
        "template_failures": 0,
        "missing_request_id_failures": 0,
        "smpp_transport_timeouts": 0,
    }
    carriers: set[str] = set()
    status_codes: dict[str, int] = {}
    for event in _group_log_events(log_lines, default_timestamp=default_timestamp):
        text = event.text
        inbound = ADAPTER_INBOUND_RE.search(text)
        outbound = ADAPTER_OUTBOUND_RE.search(text)
        if inbound:
            counts["carrier_inbound_requests"] += 1
            carriers.add(_safe_carrier(inbound.group("carrier")))
        if outbound:
            counts["carrier_outbound_responses"] += 1
            carriers.add(_safe_carrier(outbound.group("carrier")))
        counts["ussd_dispatches"] += int(bool(ADAPTER_USSD_DISPATCH_RE.search(text)))
        counts["downstream_successes"] += int(bool(ADAPTER_USSD_SUCCESS_RE.search(text)))
        downstream_error = ADAPTER_USSD_5XX_RE.search(text)
        if downstream_error:
            counts["downstream_5xx_errors"] += 1
            code = downstream_error.group("status")
            status_codes[code] = status_codes.get(code, 0) + 1
        counts["servlet_null_pointer_errors"] += int(bool(ADAPTER_SERVLET_NPE_RE.search(text)))
        counts["template_failures"] += int(bool(ADAPTER_TEMPLATE_FAILURE_RE.search(text)))
        counts["missing_request_id_failures"] += int(bool(ADAPTER_MISSING_REQUEST_ID_RE.search(text)))
        counts["smpp_transport_timeouts"] += int(bool(ADAPTER_SMPP_TIMEOUT_RE.search(text)))

    rolling, rolling_carriers = _rolling_counts(
        state,
        profile_name="ussd_adapter",
        current_counts=counts,
        carriers=sorted(carriers),
        observed_at=default_timestamp,
        window_seconds=window_seconds,
    )
    inbound = rolling["carrier_inbound_requests"]
    dispatched = rolling["ussd_dispatches"]
    completed = rolling["downstream_successes"]
    downstream_5xx = rolling["downstream_5xx_errors"]
    outbound = rolling["carrier_outbound_responses"]
    npe_count = rolling["servlet_null_pointer_errors"]
    template_count = rolling["template_failures"]
    completion_ratio = min(completed / max(inbound, 1), 1.0)
    outbound_ratio = min(outbound / max(inbound, 1), 1.0)
    dispatch_ratio = min(dispatched / max(inbound, 1), 1.0)
    completion_deficit = max(inbound - completed, 0)
    response_deficit = max(inbound - outbound, 0)

    analysis = ServiceProfileAnalysis(
        profile_name="ussd_adapter",
        metrics={
            "profile": "ussd_adapter",
            "flow_window_seconds": window_seconds,
            "dependency_service_id": dependency_service_id,
            "carrier_inbound_request_count": inbound,
            "ussd_dispatch_count": dispatched,
            "downstream_success_count": completed,
            "downstream_5xx_count": downstream_5xx,
            "carrier_outbound_response_count": outbound,
            "servlet_null_pointer_error_count": npe_count,
            "template_failure_count": template_count,
            "missing_request_id_failure_count": rolling["missing_request_id_failures"],
            "smpp_transport_timeout_count": rolling["smpp_transport_timeouts"],
            "carrier_count": len(rolling_carriers),
            "carriers": rolling_carriers,
            "dispatch_ratio": round(dispatch_ratio, 4),
            "downstream_completion_ratio": round(completion_ratio, 4),
            "carrier_response_ratio": round(outbound_ratio, 4),
            "downstream_completion_deficit": completion_deficit,
            "carrier_response_deficit": response_deficit,
            "thresholds": {
                "minimum_requests": min_requests,
                "failure_warn_count": warn_failures,
                "failure_critical_count": critical_failures,
                "minimum_dispatch_ratio": minimum_dispatch_ratio,
                "minimum_completion_ratio": minimum_completion_ratio,
                "minimum_outbound_ratio": minimum_outbound_ratio,
                "template_failure_warn_count": template_warn,
                "smpp_timeout_warn_count": smpp_timeout_warn,
            },
        },
    )
    if inbound:
        analysis.observations.append(
            {
                "observation_type": "ussd_adapter_flow",
                "window_seconds": window_seconds,
                "carrier_request_count": inbound,
                "ussd_dispatch_count": dispatched,
                "downstream_success_count": completed,
                "carrier_response_count": outbound,
                "downstream_completion_ratio": round(completion_ratio, 4),
                "carrier_response_ratio": round(outbound_ratio, 4),
                "carriers": rolling_carriers,
                "pii_redacted": True,
            }
        )

    explicit_5xx_burst = downstream_5xx >= warn_failures
    dispatch_stall = (
        inbound >= min_requests
        and dispatch_ratio < minimum_dispatch_ratio
        and outbound_ratio < minimum_outbound_ratio
        and npe_count >= warn_failures
    )
    completion_collapse = (
        inbound >= min_requests
        and dispatch_ratio >= minimum_dispatch_ratio
        and completion_ratio < minimum_completion_ratio
        and outbound_ratio < minimum_outbound_ratio
        and npe_count >= warn_failures
    )
    signal_attributes = _adapter_signal_attributes(
        window_seconds=window_seconds,
        dependency_service_id=dependency_service_id,
        rolling=rolling,
        carriers=rolling_carriers,
        dispatch_ratio=dispatch_ratio,
        completion_ratio=completion_ratio,
        outbound_ratio=outbound_ratio,
    )

    if explicit_5xx_burst:
        severity = (
            "CRITICAL"
            if downstream_5xx >= critical_failures
            or (inbound >= critical_failures and completion_ratio <= 0.2)
            else "WARN"
        )
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(default_timestamp),
                severity=severity,
                message=(
                    f"{service.service_name} observed {downstream_5xx} HTTP 5xx responses from "
                    f"{dependency_service_id} while handling {inbound} carrier requests inside the last "
                    f"{window_seconds} seconds. Only {outbound} carrier responses completed."
                ),
                signature_family="ussd_adapter_downstream_5xx_burst",
                error_class="downstream_http_5xx",
                failure_domain="dependency",
                attributes={
                    **signal_attributes,
                    "trigger": "downstream_5xx_burst",
                    "status_codes": status_codes,
                },
            )
        )
    elif dispatch_stall:
        failure_count = max(npe_count, response_deficit, inbound - dispatched)
        severity = "CRITICAL" if failure_count >= critical_failures else "WARN"
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(default_timestamp),
                severity=severity,
                message=(
                    f"{service.service_name} received {inbound} carrier requests but dispatched only "
                    f"{dispatched} calls to {dependency_service_id} inside the last {window_seconds} seconds. "
                    f"The accompanying {npe_count} servlet null-pointer failures place the fault inside "
                    "the adapter request path, before the downstream service call."
                ),
                signature_family="ussd_adapter_dispatch_stall",
                error_class="request_dispatch_stall",
                failure_domain="service_runtime",
                attributes={**signal_attributes, "trigger": "dispatch_stall"},
            )
        )
    elif completion_collapse:
        failure_count = max(npe_count, response_deficit, completion_deficit)
        severity = (
            "CRITICAL"
            if failure_count >= critical_failures
            or (inbound >= critical_failures and completion_ratio <= 0.1 and outbound_ratio <= 0.1)
            else "WARN"
        )
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(default_timestamp),
                severity=severity,
                message=(
                    f"{service.service_name} received {inbound} carrier requests and dispatched {dispatched} "
                    f"calls to {dependency_service_id}, but observed only {completed} downstream completions "
                    f"and {outbound} carrier responses inside the last {window_seconds} seconds. "
                    f"The accompanying {npe_count} servlet null-pointer failures indicate a stalled "
                    "adapter-to-USSD path."
                ),
                signature_family="ussd_adapter_completion_collapse",
                error_class="downstream_completion_collapse",
                failure_domain="dependency",
                attributes={**signal_attributes, "trigger": "completion_collapse"},
            )
        )
    elif template_count >= template_warn:
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(default_timestamp),
                severity="WARN",
                message=(
                    f"{service.service_name} observed {template_count} response-template failures inside "
                    f"the last {window_seconds} seconds; {rolling['missing_request_id_failures']} "
                    "involved a missing requestId."
                ),
                signature_family="ussd_adapter_template_failure_burst",
                error_class="response_template_failure",
                exception_name="freemarker.core.InvalidReferenceException",
                failure_domain="service_runtime",
                attributes={**signal_attributes, "trigger": "template_failure_burst"},
            )
        )
    elif rolling["smpp_transport_timeouts"] >= smpp_timeout_warn:
        analysis.signatures.append(
            LogSignature(
                timestamp=_utc_iso(default_timestamp),
                severity="WARN",
                message=(
                    f"{service.service_name} observed {rolling['smpp_transport_timeouts']} SMPP transport "
                    f"timeouts inside the last {window_seconds} seconds. Validate the affected carrier "
                    "transport before sessions accumulate."
                ),
                signature_family="ussd_adapter_carrier_transport_timeout",
                error_class="carrier_transport_timeout",
                timeout_type="smpp_connect_timeout",
                failure_domain="channel_tunnel",
                attributes={**signal_attributes, "trigger": "smpp_transport_timeout"},
            )
        )

    _apply_primary_signature(analysis)
    return analysis


def _adapter_signal_attributes(
    *,
    window_seconds: int,
    dependency_service_id: str,
    rolling: dict[str, int],
    carriers: list[str],
    dispatch_ratio: float,
    completion_ratio: float,
    outbound_ratio: float,
) -> dict[str, Any]:
    return {
        "profile": "ussd_adapter",
        "window_seconds": window_seconds,
        "from_service_id": "txn-ussd-adapter",
        "to_service_id": dependency_service_id,
        "dependency_service_id": dependency_service_id,
        "dependency_type": "sync_api",
        "flow_stage": "adapter_to_mobile_ussd",
        "carrier_request_count": rolling["carrier_inbound_requests"],
        "ussd_dispatch_count": rolling["ussd_dispatches"],
        "downstream_success_count": rolling["downstream_successes"],
        "downstream_5xx_count": rolling["downstream_5xx_errors"],
        "carrier_response_count": rolling["carrier_outbound_responses"],
        "servlet_null_pointer_error_count": rolling["servlet_null_pointer_errors"],
        "template_failure_count": rolling["template_failures"],
        "smpp_transport_timeout_count": rolling["smpp_transport_timeouts"],
        "dispatch_ratio": round(dispatch_ratio, 4),
        "downstream_completion_ratio": round(completion_ratio, 4),
        "carrier_response_ratio": round(outbound_ratio, 4),
        "carriers": carriers,
        "pii_redacted": True,
        "diagnostic_hint": "compare_adapter_ingress_ussd_completion_and_carrier_egress",
    }


def _group_log_events(log_lines: list[str], *, default_timestamp: datetime) -> list[_LogEvent]:
    events: list[_LogEvent] = []
    current_lines: list[str] = []
    current_timestamp = default_timestamp

    def flush() -> None:
        if current_lines:
            events.append(_LogEvent(timestamp=current_timestamp, text="\n".join(current_lines)))

    for line in log_lines:
        if LOG_EVENT_START_RE.match(line):
            flush()
            current_lines = [line]
            current_timestamp = _extract_timestamp(line) or default_timestamp
        elif current_lines:
            current_lines.append(line)
        elif line.strip():
            current_lines = [line]
            current_timestamp = _extract_timestamp(line) or default_timestamp
    flush()
    return events


def _rolling_counts(
    state: dict[str, Any] | None,
    *,
    profile_name: str,
    current_counts: dict[str, int],
    carriers: list[str],
    observed_at: datetime,
    window_seconds: int,
) -> tuple[dict[str, int], list[str]]:
    if state is None:
        return dict(current_counts), sorted(set(carriers))

    now = _as_utc(observed_at)
    if state.get("profile_name") != profile_name:
        state.clear()
        state.update({"profile_name": profile_name, "samples": []})
    samples = state.get("samples")
    if not isinstance(samples, list):
        samples = []
    if any(current_counts.values()):
        samples.append(
            {
                "observed_at": _utc_iso(now),
                "counts": {key: int(value) for key, value in current_counts.items()},
                "carriers": sorted(set(carriers)),
            }
        )

    cutoff = now - timedelta(seconds=max(window_seconds, 1))
    retained: list[dict[str, Any]] = []
    for sample in samples[-ROLLING_SAMPLE_LIMIT:]:
        if not isinstance(sample, dict):
            continue
        timestamp = _parse_utc(sample.get("observed_at"))
        if timestamp is None or timestamp < cutoff or timestamp > now + timedelta(seconds=5):
            continue
        retained.append(sample)
    state["samples"] = retained[-ROLLING_SAMPLE_LIMIT:]

    totals = {key: 0 for key in current_counts}
    rolling_carriers: set[str] = set()
    for sample in retained:
        sample_counts = sample.get("counts")
        if isinstance(sample_counts, dict):
            for key in totals:
                totals[key] += _safe_int(sample_counts.get(key))
        sample_carriers = sample.get("carriers")
        if isinstance(sample_carriers, list):
            rolling_carriers.update(_safe_carrier(str(item)) for item in sample_carriers)
    return totals, sorted(rolling_carriers)


def _apply_primary_signature(analysis: ServiceProfileAnalysis) -> None:
    if not analysis.signatures:
        return
    primary = max(
        enumerate(analysis.signatures),
        key=lambda item: (SEVERITY_ORDER.get(item[1].severity, 0), -item[0]),
    )[1]
    analysis.failure_domain_hint = primary.failure_domain
    analysis.status_hint = "degraded"
    analysis.severity_hint = primary.severity
    analysis.message_hint = primary.message


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


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None
