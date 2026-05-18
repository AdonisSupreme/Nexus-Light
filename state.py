from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, state_dir: str, filename: str = "state.json") -> None:
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / filename
        self.data: dict[str, Any] = {}

    def load(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.data = {}
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            self.data = payload if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            self.data = {}

    def save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".state-", suffix=".json", dir=str(self.state_dir))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, indent=2, sort_keys=True)
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
