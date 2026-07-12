"""
Canary Token Detection Module

Detects user-registered tripwire tokens in AI output to catch data exfiltration.
Complements secret scanning: canary detection uses exact user-registered values,
bypassing entropy thresholds and false-positive filters.

Use cases:
- Plant CANARYTOK_my-db-password in a config file; if AI outputs it, exfil detected.
- Plant SENTINEL_PROD_DB_2026 as a low-entropy value; secret scanner ignores it.
- Register a regex pattern CANARY_[A-Z0-9]{8} to catch any canary-format value.

Config:
    canary_detection:
      enabled: true
      action: "block"   # block | warn | log-only | ask
      tokens:
        - value: "CANARYTOK_my-db-password"
          description: "Production DB canary"
        - pattern: "CANARY_[A-Z0-9]{8}"
          description: "Any canary pattern"
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ai_guardian.config.utils import is_feature_enabled

logger = logging.getLogger(__name__)


class CanaryTokenScanner:
    """Detects user-registered canary tokens in content.

    Supports:
    - Exact value matching (case-sensitive by default)
    - Regex pattern matching
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self.enabled = config.get("enabled", False)
        if isinstance(self.enabled, dict):
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)
            self.enabled = is_feature_enabled(self.enabled, now, default=False)

        self.action = config.get("action", "block")

        self._exact_tokens: List[Tuple[str, str]] = []
        self._pattern_tokens: List[Tuple[re.Pattern, str]] = []

        for token in config.get("tokens", []):
            if not isinstance(token, dict):
                continue
            desc = token.get("description", "canary token")
            if "value" in token:
                val = token["value"]
                if isinstance(val, str) and val:
                    self._exact_tokens.append((val, desc))
            elif "pattern" in token:
                pat = token["pattern"]
                if isinstance(pat, str) and pat:
                    try:
                        self._pattern_tokens.append((re.compile(pat), desc))
                    except re.error as e:
                        logger.warning("Invalid canary pattern %r: %s", pat, e)

        self.last_matched_token: Optional[str] = None
        self.last_matched_text: Optional[str] = None
        self.last_description: Optional[str] = None
        self.last_line_number: Optional[int] = None
        self.last_start_column: Optional[int] = None
        self.last_end_column: Optional[int] = None
        self.findings: List[Dict[str, Any]] = []

    def _record_finding(
        self,
        content: str,
        source: str,
        token_repr: str,
        matched_text: str,
        description: str,
        match_start: int,
        match_end: int,
    ) -> Dict[str, Any]:
        line_number = content[:match_start].count("\n") + 1
        lines = content.split("\n")
        line_start = content.rfind("\n", 0, match_start) + 1
        start_column = match_start - line_start
        end_column = match_end - line_start
        snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""

        error_msg = (
            f"Canary token detected: {description!r} in {source} (line {line_number})"
        )
        finding = {
            "token": token_repr,
            "description": description,
            "matched_text": matched_text,
            "line_number": line_number,
            "start_column": start_column,
            "end_column": end_column,
            "snippet": snippet,
            "source": source,
            "error_message": error_msg,
        }
        return finding

    def scan(
        self,
        content: str,
        source: str = "unknown",
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Scan content for registered canary tokens.

        Args:
            content: Text to scan.
            source: Label for the source (file path, tool name, etc.).

        Returns:
            (should_block, error_message, details)
        """
        self.last_matched_token = None
        self.last_matched_text = None
        self.last_description = None
        self.last_line_number = None
        self.last_start_column = None
        self.last_end_column = None
        self.findings = []

        if not self.enabled:
            return False, None, None
        if not content or not content.strip():
            return False, None, None
        if not self._exact_tokens and not self._pattern_tokens:
            return False, None, None

        for value, description in self._exact_tokens:
            idx = content.find(value)
            if idx != -1:
                finding = self._record_finding(
                    content, source, value, value, description, idx, idx + len(value)
                )
                self.findings.append(finding)

        for compiled, description in self._pattern_tokens:
            for m in compiled.finditer(content):
                finding = self._record_finding(
                    content,
                    source,
                    compiled.pattern,
                    m.group(0),
                    description,
                    m.start(),
                    m.end(),
                )
                self.findings.append(finding)
                break  # one finding per pattern per scan

        if not self.findings:
            return False, None, None

        first = self.findings[0]
        self.last_matched_token = first["token"]
        self.last_matched_text = first["matched_text"]
        self.last_description = first["description"]
        self.last_line_number = first["line_number"]
        self.last_start_column = first["start_column"]
        self.last_end_column = first["end_column"]

        details = {k: v for k, v in first.items() if k != "error_message"}
        details["total_findings"] = len(self.findings)

        if self.action == "block":
            return True, first["error_message"], details
        elif self.action == "log-only":
            return False, None, details
        else:
            warn_msg = f"Canary token detected ({self.action} mode) - execution allowed"
            return False, warn_msg, details
