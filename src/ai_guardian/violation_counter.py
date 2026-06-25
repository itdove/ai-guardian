"""
Running violation counter — independent of log rotation.

Maintains a persistent JSON file with cumulative violation counts
that survive log rotation. The violation log caps at max_entries
(default 1000), but this counter increments on every violation
and never resets unless explicitly requested.

File: ~/.local/state/ai-guardian/violation_counters.json
"""

import json
import logging
import os
import stat
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from ai_guardian.config_utils import get_state_dir

logger = logging.getLogger(__name__)

COUNTER_FILENAME = "violation_counters.json"


class ViolationCounter:
    """Thread-safe persistent violation counter."""

    _lock = threading.Lock()

    def __init__(self, counter_path: Optional[Path] = None):
        if counter_path is None:
            counter_path = get_state_dir() / COUNTER_FILENAME
        self._path = counter_path

    def increment(self, violation_type: str) -> None:
        """Increment the counter for a violation type.

        Creates the counter file on first call.
        """
        with self._lock:
            try:
                data = self._read_unlocked()
                if not data.get("since"):
                    data["since"] = (
                        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    )
                data["violation_totals"][violation_type] = (
                    data["violation_totals"].get(violation_type, 0) + 1
                )
                data["total"] = data.get("total", 0) + 1
                self._write_unlocked(data)
            except Exception as e:
                logger.warning(f"Failed to increment violation counter: {e}")

    def get_counters(self) -> Dict:
        """Return current counter state.

        Returns dict with keys: version, since, violation_totals, total.
        Returns sensible defaults if file does not exist.
        """
        with self._lock:
            try:
                return self._read_unlocked()
            except Exception as e:
                logger.warning(f"Failed to read violation counters: {e}")
                return self._empty_counters()

    def reset_to_current_log(self) -> Dict:
        """Reset counters to the current violation log counts.

        Reads violations.jsonl and uses those counts as the new baseline.
        Sets 'since' to the current timestamp.

        Returns:
            The new counter state after reset.
        """
        with self._lock:
            try:
                counts = self._count_current_log()
                total = sum(counts.values())
                data = {
                    "version": 1,
                    "since": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "violation_totals": counts,
                    "total": total,
                }
                self._write_unlocked(data)
                return data
            except Exception as e:
                logger.warning(f"Failed to reset violation counters: {e}")
                return self._empty_counters()

    def _read_unlocked(self) -> Dict:
        """Read counter file (caller must hold _lock)."""
        if not self._path.exists():
            return self._empty_counters()
        try:
            content = self._path.read_text(encoding="utf-8")
            data = json.loads(content)
            if not isinstance(data.get("violation_totals"), dict):
                data["violation_totals"] = {}
            if not isinstance(data.get("total"), int):
                data["total"] = sum(data["violation_totals"].values())
            return data
        except (json.JSONDecodeError, OSError):
            return self._empty_counters()

    def _write_unlocked(self, data: Dict) -> None:
        """Atomic write of counter data (caller must hold _lock)."""
        parent = self._path.parent
        parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(data, indent=2)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(parent), prefix=".violation-cnt-", suffix=".tmp"
        )
        closed = False
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            os.write(fd, content.encode("utf-8"))
            os.close(fd)
            closed = True
            os.replace(tmp_path, str(self._path))
        except BaseException:
            if not closed:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    @staticmethod
    def _count_current_log() -> Dict[str, int]:
        """Count violations by type from the current violations.jsonl."""
        from ai_guardian.violation_logger import ViolationLogger

        vl = ViolationLogger()
        if not vl.log_path.exists():
            return {}

        counts: Dict[str, int] = {}
        try:
            with open(vl.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        vtype = entry.get("violation_type", "unknown")
                        counts[vtype] = counts.get(vtype, 0) + 1
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass  # intentionally silent — best-effort operation
        return counts

    @staticmethod
    def _empty_counters() -> Dict:
        return {
            "version": 1,
            "since": "",
            "violation_totals": {},
            "total": 0,
        }
