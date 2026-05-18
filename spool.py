from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable


class BoundedSpool:
    def __init__(self, state_dir: str, max_records: int = 200) -> None:
        self.path = Path(state_dir) / "probe-spool.jsonl"
        self.max_records = max_records
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, payload: dict[str, Any]) -> None:
        records = self._read_records()
        records.append(payload)
        records = records[-self.max_records :]
        self._write_records(records)

    def flush(self, sender: Callable[[dict[str, Any]], None], max_batch: int = 20) -> int:
        records = self._read_records()
        if not records:
            return 0
        remaining: list[dict[str, Any]] = []
        sent = 0
        for index, record in enumerate(records):
            if index >= max_batch:
                remaining.append(record)
                continue
            try:
                sender(record)
                sent += 1
            except Exception:
                remaining.extend(records[index:])
                break
        self._write_records(remaining[-self.max_records :])
        return sent

    def _read_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                records.append(item)
        return records[-self.max_records :]

    def _write_records(self, records: list[dict[str, Any]]) -> None:
        if not records:
            if self.path.exists():
                self.path.unlink()
            return
        body = "\n".join(json.dumps(record, separators=(",", ":")) for record in records)
        self.path.write_text(body + "\n", encoding="utf-8")
