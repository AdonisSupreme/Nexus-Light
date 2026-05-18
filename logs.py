from __future__ import annotations

import os
from pathlib import Path
from typing import Any


class BoundedLogTailer:
    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state.setdefault("log_offsets", {})

    def read_new_lines(
        self,
        path: str,
        *,
        max_bytes: int,
        max_lines: int,
        initial_tail_bytes: int,
    ) -> tuple[list[str], dict[str, Any]]:
        log_path = Path(path)
        if not log_path.exists():
            return [], {
                "path": path,
                "exists": False,
                "bytes_read": 0,
                "lines_read": 0,
                "rotation_detected": False,
            }

        stat = log_path.stat()
        key = str(log_path)
        previous = self.state.get(key, {})
        previous_inode = previous.get("inode")
        previous_offset = int(previous.get("offset", 0))

        rotation_detected = bool(previous_inode and previous_inode != stat.st_ino)
        truncated = stat.st_size < previous_offset

        if not previous or rotation_detected or truncated:
            offset = max(stat.st_size - initial_tail_bytes, 0)
        else:
            offset = previous_offset

        available = max(stat.st_size - offset, 0)
        read_size = min(available, max_bytes)
        if read_size <= 0:
            self._save_offset(key, stat.st_ino, stat.st_size)
            return [], {
                "path": path,
                "exists": True,
                "bytes_read": 0,
                "lines_read": 0,
                "rotation_detected": rotation_detected or truncated,
            }

        with log_path.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(read_size)
            new_offset = handle.tell()

        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()[-max_lines:]
        self._save_offset(key, stat.st_ino, new_offset)

        return lines, {
            "path": path,
            "exists": True,
            "bytes_read": len(raw),
            "lines_read": len(lines),
            "rotation_detected": rotation_detected or truncated,
            "file_size": stat.st_size,
            "offset": new_offset,
        }

    def _save_offset(self, key: str, inode: int, offset: int) -> None:
        self.state[key] = {"inode": inode, "offset": offset}


def file_owner_summary(path: str) -> dict[str, Any]:
    try:
        stat = os.stat(path)
        return {
            "uid": stat.st_uid,
            "gid": stat.st_gid,
            "mode": oct(stat.st_mode & 0o777),
            "size": stat.st_size,
        }
    except OSError:
        return {"missing": True}
