"""
Offensive Language Scanner

Detects profanity, slurs, and non-inclusive terminology in code, comments,
variable names, and commit messages. Pattern files are TOML-based; categories
are selectable via config so teams can opt into only the checks they need.

Default categories: profanity, slurs
Opt-in: inclusive_language (high false positive rate on legacy codebases)

Disabled by default — users must set scan_offensive.enabled = true.
"""

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Category → TOML filename in patterns/data/
_CATEGORY_FILES: Dict[str, str] = {
    "profanity": "offensive-profanity.toml",
    "slurs": "offensive-slurs.toml",
    "inclusive_language": "offensive-inclusive-language.toml",
}

_DEFAULT_CATEGORIES = ["profanity", "slurs", "inclusive_language"]

# Module-level cache: (frozenset(categories), mtime_tuple) → compiled rules
_rules_cache: Dict[Tuple, List[dict]] = {}
_rules_cache_lock = threading.Lock()


def _load_patterns_for_categories(
    categories: List[str],
) -> List[dict]:
    """Load and compile regex rules for the requested categories.

    Each rule dict has: id, regex (compiled), description, suggestion, category_tag.
    Invalid rules are skipped with a warning (fail-open).
    """
    from ai_guardian.patterns import DATA_DIR
    from ai_guardian.patterns.toml_parser import load_toml_file

    rules = []
    for category in categories:
        filename = _CATEGORY_FILES.get(category)
        if not filename:
            logger.warning(f"Unknown offensive language category: {category!r}")
            continue
        toml_path = DATA_DIR / filename
        if not toml_path.exists():
            logger.error(
                f"Offensive language pattern file not found: {toml_path} "
                f"— patterns directory may be missing from install"
            )
            continue
        try:
            raw_rules = load_toml_file(toml_path)
        except Exception as e:
            logger.error(f"Failed to load {filename}: {e}")
            continue
        for raw in raw_rules:
            rule_id = raw.get("id", "")
            regex_str = raw.get("regex", "")
            if not regex_str:
                logger.warning(f"Skipping rule {rule_id!r}: missing regex")
                continue
            flags = re.IGNORECASE if raw.get("case_insensitive", False) else 0
            try:
                compiled = re.compile(regex_str, flags)
            except re.error as e:
                logger.warning(f"Skipping rule {rule_id!r}: invalid regex: {e}")
                continue
            rules.append(
                {
                    "id": rule_id,
                    "compiled": compiled,
                    "description": raw.get("description", rule_id),
                    "suggestion": raw.get("suggestion", ""),
                    "category_tag": raw.get("category_tag", category),
                }
            )
    return rules


def _get_rules(categories: List[str]) -> List[dict]:
    """Return compiled rules for categories, using module-level cache."""
    cache_key = tuple(sorted(categories))
    with _rules_cache_lock:
        if cache_key not in _rules_cache:
            _rules_cache[cache_key] = _load_patterns_for_categories(categories)
        return _rules_cache[cache_key]


def _offset_to_line_number(text: str, offset: int) -> int:
    """Convert byte offset in text to 1-based line number."""
    return text[:offset].count("\n") + 1


def _offset_to_column(text: str, offset: int) -> int:
    """Convert byte offset in text to 1-based column number."""
    last_nl = text.rfind("\n", 0, offset)
    return offset - last_nl


class OffensiveLanguageScanner:
    """Scan text for offensive language patterns by category.

    Args:
        config: scan_offensive config dict with enabled, action, categories.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.categories: List[str] = config.get("categories", _DEFAULT_CATEGORIES)
        self._rules: Optional[List[dict]] = None

    def _get_compiled_rules(self) -> List[dict]:
        if self._rules is None:
            self._rules = _get_rules(self.categories)
        return self._rules

    def scan(
        self,
        content: str,
        file_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Scan content for offensive language matches.

        Returns list of finding dicts:
            rule_id, category_tag, description, suggestion,
            matched_text, line_number, start_column, end_column
        """
        if not content:
            return []

        findings = []
        rules = self._get_compiled_rules()
        for rule in rules:
            for m in rule["compiled"].finditer(content):
                line_number = _offset_to_line_number(content, m.start())
                start_column = _offset_to_column(content, m.start())
                end_column = start_column + len(m.group()) - 1
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "category_tag": rule["category_tag"],
                        "description": rule["description"],
                        "suggestion": rule["suggestion"],
                        "matched_text": m.group(),
                        "line_number": line_number,
                        "start_column": start_column,
                        "end_column": end_column,
                        "file_path": file_path,
                    }
                )
        return findings
