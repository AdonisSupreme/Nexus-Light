from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any


if hasattr(os, "sysconf"):
    CLK_TCK = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK"))
    PAGE_SIZE = os.sysconf(os.sysconf_names.get("SC_PAGE_SIZE", "SC_PAGE_SIZE"))
else:
    CLK_TCK = 100
    PAGE_SIZE = 4096


def find_processes(match_text: str | None, limit: int = 20) -> list[dict[str, Any]]:
    if not match_text:
        return []
    matches: list[dict[str, Any]] = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            cmdline_raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        if match_text not in cmdline:
            continue
        snapshot = read_process_snapshot(pid, cmdline)
        if snapshot:
            matches.append(snapshot)
        if len(matches) >= limit:
            break
    return matches


def enrich_cpu_percent(processes: list[dict[str, Any]], state: dict[str, Any]) -> list[dict[str, Any]]:
    now = time.time()
    cpu_state = state.setdefault("process_cpu", {})
    enriched: list[dict[str, Any]] = []
    for process in processes:
        pid_key = str(process["pid"])
        cpu_seconds = float(process.get("cpu_seconds") or 0.0)
        previous = cpu_state.get(pid_key)
        cpu_percent = None
        if previous:
            elapsed = max(now - float(previous.get("time", now)), 0.001)
            delta = max(cpu_seconds - float(previous.get("cpu_seconds", cpu_seconds)), 0.0)
            cpu_percent = round((delta / elapsed) * 100.0, 2)
        cpu_state[pid_key] = {"time": now, "cpu_seconds": cpu_seconds}
        process["cpu_percent"] = cpu_percent
        enriched.append(process)
    return enriched


def read_process_snapshot(pid: int, cmdline: str) -> dict[str, Any] | None:
    proc = Path("/proc") / str(pid)
    try:
        stat_text = (proc / "stat").read_text(encoding="utf-8", errors="replace")
        status_text = (proc / "status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    stat_parts = _split_stat(stat_text)
    if len(stat_parts) < 22:
        return None

    utime = int(stat_parts[13])
    stime = int(stat_parts[14])
    rss_pages = int(stat_parts[23]) if len(stat_parts) > 23 else 0
    status = _parse_status(status_text)
    return {
        "pid": pid,
        "state": stat_parts[2],
        "threads": int(status.get("Threads", "0")),
        "rss_mb": round((rss_pages * PAGE_SIZE) / 1024 / 1024, 2),
        "vm_size_mb": _kb_to_mb(status.get("VmSize")),
        "vm_rss_mb": _kb_to_mb(status.get("VmRSS")),
        "cpu_seconds": round((utime + stime) / CLK_TCK, 2),
        "cmdline": cmdline[:500],
    }


def _split_stat(stat_text: str) -> list[str]:
    right = stat_text.rfind(")")
    if right == -1:
        return stat_text.split()
    prefix = stat_text[: right + 1]
    suffix = stat_text[right + 2 :].split()
    pid, comm = prefix.split(" ", 1)
    return [pid, comm] + suffix


def _parse_status(status_text: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for line in status_text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        payload[key.strip()] = value.strip()
    return payload


def _kb_to_mb(value: str | None) -> float | None:
    if not value:
        return None
    try:
        kb = float(value.split()[0])
        return round(kb / 1024, 2)
    except (ValueError, IndexError):
        return None
