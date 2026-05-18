from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class NexusClientError(RuntimeError):
    pass


class NexusClient:
    def __init__(self, base_url: str, agent_id: str, token: str, timeout_seconds: int = 5) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.token = token
        self.timeout_seconds = timeout_seconds

    def fetch_agent_config(self, service_id: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({"service_id": service_id})
        return self._request("GET", f"/api/v1/nexus/agents/{self.agent_id}/config?{query}")

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/v1/nexus/agents/heartbeat", payload)

    def probe_report(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/v1/nexus/agents/probe-report", payload)

    def diagnostic_results(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = urllib.parse.quote(str(payload["agent_id"]))
        return self._request("POST", f"/api/v1/nexus/agents/{agent_id}/diagnostic-results", payload)

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None
        headers = {
            "Accept": "application/json",
            "X-Nexus-Agent-Id": self.agent_id,
            "X-Nexus-Agent-Token": self.token,
            "User-Agent": "sentinel-nexus-light-agent/0.1",
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise NexusClientError(f"Nexus returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise NexusClientError(f"Nexus request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise NexusClientError("Nexus request timed out") from exc

        if not body:
            return {}
        try:
            decoded = json.loads(body)
        except json.JSONDecodeError as exc:
            raise NexusClientError("Nexus returned invalid JSON") from exc
        return decoded if isinstance(decoded, dict) else {"data": decoded}
