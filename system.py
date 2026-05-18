from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Any


def host_snapshot(primary_log_path: str | None = None) -> dict[str, Any]:
    cpu_count = os.cpu_count() or 1
    load_1, load_5, load_15 = _loadavg()
    memory = _meminfo()
    root_disk = _disk_usage("/")
    log_disk = _disk_usage(str(Path(primary_log_path).parent)) if primary_log_path else None
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "cpu_count": cpu_count,
        "load_average": {"one": load_1, "five": load_5, "fifteen": load_15},
        "load_per_core": round(load_1 / cpu_count, 3) if load_1 is not None else None,
        "memory": memory,
        "disk": {"root": root_disk, "log_filesystem": log_disk},
    }


def resource_pressure(snapshot: dict[str, Any], high_load_per_core: float, min_available_memory_mb: int) -> dict[str, Any]:
    load_per_core = snapshot.get("load_per_core")
    memory = snapshot.get("memory") or {}
    available_mb = memory.get("available_mb")
    high_load = load_per_core is not None and load_per_core >= high_load_per_core
    low_memory = available_mb is not None and available_mb <= min_available_memory_mb
    return {
        "high_load": high_load,
        "low_memory": low_memory,
        "load_per_core": load_per_core,
        "available_memory_mb": available_mb,
        "collector_mode": "throttled" if high_load or low_memory else "normal",
    }


def _loadavg() -> tuple[float | None, float | None, float | None]:
    try:
        one, five, fifteen = os.getloadavg()
        return round(one, 2), round(five, 2), round(fifteen, 2)
    except AttributeError:
        return None, None, None
    except OSError:
        return None, None, None


def _meminfo() -> dict[str, Any]:
    path = Path("/proc/meminfo")
    if not path.exists():
        return {}
    values: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        try:
            values[key] = int(value.strip().split()[0])
        except (ValueError, IndexError):
            continue
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    swap_total = values.get("SwapTotal")
    swap_free = values.get("SwapFree")
    return {
        "total_mb": _kb_to_mb(total),
        "available_mb": _kb_to_mb(available),
        "used_percent": round(((total - available) / total) * 100, 2) if total and available is not None else None,
        "swap_total_mb": _kb_to_mb(swap_total),
        "swap_used_mb": _kb_to_mb((swap_total or 0) - (swap_free or 0)) if swap_total is not None else None,
    }


def _disk_usage(path: str) -> dict[str, Any] | None:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return {
        "path": path,
        "total_gb": round(usage.total / 1024**3, 2),
        "used_gb": round(usage.used / 1024**3, 2),
        "free_gb": round(usage.free / 1024**3, 2),
        "used_percent": round((usage.used / usage.total) * 100, 2) if usage.total else None,
    }


def _kb_to_mb(value: int | None) -> float | None:
    if value is None:
        return None
    return round(value / 1024, 2)
