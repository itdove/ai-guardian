"""
Result caching and incremental scanning for secret scanning.

Provides:
- ScanResultCache: File-based cache for scan results keyed by content hash
- FileStateTracker: Track file states for incremental scanning
"""

import hashlib
import json
import logging
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional, Dict, Any, List

from ai_guardian.config_utils import get_cache_dir
from ai_guardian.scanners.strategies import ScanResult, SecretMatch

logger = logging.getLogger(__name__)


class ScanResultCache:
    """File-based cache for scan results."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_hours: float = 24.0,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.ttl_hours = ttl_hours
        if cache_dir is None:
            cache_dir = get_cache_dir() / "scan-results"
        self.cache_dir = cache_dir
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def cache_key(
        self, content_hash: str, engine_type: str, config_hash: str
    ) -> str:
        combined = f"{content_hash}:{engine_type}:{config_hash}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    @staticmethod
    def content_hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def config_hash(engine_config) -> str:
        config_str = (
            f"{engine_config.type}:{engine_config.binary}:"
            f"{engine_config.command_template}:{engine_config.extra_flags}:"
            f"{engine_config.config_flag}"
        )
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    def get(
        self, content_hash: str, engine_type: str, config_hash: str
    ) -> Optional[ScanResult]:
        if not self.enabled:
            return None

        key = self.cache_key(content_hash, engine_type, config_hash)
        cache_file = self.cache_dir / f"{key}.json"

        if not cache_file.exists():
            return None

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))

            cached_at = data.get("cached_at", 0)
            age_hours = (time.time() - cached_at) / 3600.0
            if age_hours > self.ttl_hours:
                cache_file.unlink(missing_ok=True)
                logger.debug(
                    f"Cache expired for {engine_type} (age: {age_hours:.1f}h)"
                )
                return None

            result_data = data["result"]
            secrets = [
                SecretMatch(**s) for s in result_data.get("secrets", [])
            ]
            return ScanResult(
                has_secrets=result_data["has_secrets"],
                secrets=secrets,
                engine=result_data["engine"],
                error=result_data.get("error"),
                scan_time_ms=0.0,
            )
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
            return None

    def put(
        self,
        content_hash: str,
        engine_type: str,
        config_hash: str,
        result: ScanResult,
    ) -> None:
        if not self.enabled:
            return

        key = self.cache_key(content_hash, engine_type, config_hash)
        cache_file = self.cache_dir / f"{key}.json"

        try:
            data = {
                "cached_at": time.time(),
                "content_hash": content_hash,
                "engine_type": engine_type,
                "config_hash": config_hash,
                "result": {
                    "has_secrets": result.has_secrets,
                    "secrets": [
                        {
                            "rule_id": s.rule_id,
                            "description": s.description,
                            "file": s.file,
                            "line_number": s.line_number,
                            "end_line": s.end_line,
                            "commit": s.commit,
                            "engine": s.engine,
                            "confidence": s.confidence,
                            "verified": s.verified,
                        }
                        for s in result.secrets
                    ],
                    "engine": result.engine,
                    "error": result.error,
                },
            }
            cache_file.write_text(
                json.dumps(data), encoding="utf-8"
            )
        except Exception as e:
            logger.warning(f"Cache write error: {e}")

    def clear(self) -> int:
        count = 0
        if self.cache_dir.exists():
            for f in self.cache_dir.glob("*.json"):
                f.unlink()
                count += 1
        return count

    def stats(self) -> Dict[str, Any]:
        entries = list(self.cache_dir.glob("*.json")) if self.cache_dir.exists() else []
        total_size = sum(f.stat().st_size for f in entries)
        return {
            "enabled": self.enabled,
            "cache_dir": str(self.cache_dir),
            "entry_count": len(entries),
            "total_size_bytes": total_size,
            "ttl_hours": self.ttl_hours,
        }


class FileStateTracker:
    """Track file states for incremental scanning."""

    def __init__(self, state_dir: Optional[Path] = None):
        if state_dir is None:
            state_dir = get_cache_dir() / "file-state"
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._state_file = self.state_dir / "file_states.json"
        self._states: Dict[str, Dict] = self._load_states()

    def _load_states(self) -> Dict[str, Dict]:
        if self._state_file.exists():
            try:
                return json.loads(
                    self._state_file.read_text(encoding="utf-8")
                )
            except Exception:
                return {}
        return {}

    def _save_states(self) -> None:
        self._state_file.write_text(
            json.dumps(self._states, indent=2), encoding="utf-8"
        )

    def has_changed(self, filepath: str, content: str) -> bool:
        current_hash = ScanResultCache.content_hash(content)
        state = self._states.get(filepath)
        if state is None:
            return True
        return state.get("content_hash") != current_hash

    def record_scan(self, filepath: str, content: str, engine: str) -> None:
        self._states[filepath] = {
            "content_hash": ScanResultCache.content_hash(content),
            "last_scanned": time.time(),
            "engine": engine,
        }
        self._save_states()

    def clear(self) -> None:
        self._states = {}
        if self._state_file.exists():
            self._state_file.unlink()
