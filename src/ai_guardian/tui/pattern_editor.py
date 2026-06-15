"""Pattern editor for the ask dialog's "Allow Always" flow.

Provides pattern validation, conversion, and preview logic shared across
tkinter, NiceGUI, and Textual editor implementations.

Reuses find_matches() from tui/regex_tester.py and validate_regex_pattern()
from config_utils for pattern safety checks.
"""

import fnmatch
import json
import re
import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple
from urllib.parse import urlparse

from ai_guardian.config_utils import validate_regex_pattern
from ai_guardian.allowlist_utils import DANGEROUS_PATTERNS

logger = logging.getLogger(__name__)

PATTERN_TYPES = {
    "string": "Plain string (exact match)",
    "glob": "Glob pattern (*, ?)",
    "regex": "Regex pattern",
}

SECTION_PATTERN_TYPE = {
    "secret_scanning": "regex",
    "prompt_injection": "regex",
    "scan_pii": "regex",
    "context_poisoning": "regex",
    "ssrf_protection": "glob",
    "directory_rules": "glob",
    "supply_chain": "glob",
    "config_file_scanning": "glob",
}


def get_pattern_type_for_section(config_section: str) -> str:
    """Return the pattern type for a config section."""
    return SECTION_PATTERN_TYPE.get(config_section, "regex")


@dataclass
class PatternEditorResult:
    """Result from the pattern editor."""
    pattern: str
    pattern_type: str = "regex"
    config_section: str = "secret_scanning"
    valid_until: Optional[str] = None


def convert_to_regex(pattern: str, pattern_type: str) -> str:
    """Convert a pattern to regex format for storage.

    Args:
        pattern: The pattern string.
        pattern_type: One of "string", "glob", "regex".

    Returns:
        A regex pattern string.
    """
    if pattern_type == "string":
        return re.escape(pattern)
    elif pattern_type == "glob":
        return fnmatch.translate(pattern)
    return pattern


def validate_pattern(
    pattern: str,
    pattern_type: str,
    test_text: str,
) -> Tuple[bool, str]:
    """Validate a pattern compiles correctly and matches the test text.

    Args:
        pattern: The pattern to validate.
        pattern_type: One of "string", "glob", "regex".
        test_text: The original matched text to test against.

    Returns:
        (is_valid, message) tuple.
    """
    if not pattern:
        return False, "Pattern is empty"

    regex_pattern = convert_to_regex(pattern, pattern_type)

    if regex_pattern in DANGEROUS_PATTERNS:
        return False, "Pattern is too broad — would disable all detection"

    if not validate_regex_pattern(regex_pattern):
        return False, "Pattern failed ReDoS safety check"

    try:
        compiled = re.compile(regex_pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as e:
        return False, f"Invalid regex: {e}"

    if test_text and not compiled.search(test_text):
        return False, "Pattern does not match the original text"

    return True, "Pattern is valid and matches"


def generate_config_preview(pattern: str, config_section: str) -> str:
    """Generate a JSON config snippet showing where the pattern will be added.

    Args:
        pattern: The regex pattern or domain string to add.
        config_section: The config section (e.g., "secret_scanning").

    Returns:
        Formatted JSON string.
    """
    if config_section == "ssrf_protection":
        return json.dumps(
            {config_section: {"allowed_domains": [pattern]}},
            indent=2,
        )
    if config_section == "directory_rules":
        return json.dumps(
            {config_section: {"exclusions": [pattern]}},
            indent=2,
        )
    return json.dumps(
        {config_section: {"allowlist_patterns": [pattern]}},
        indent=2,
    )


def suggest_domain(url_or_text: str) -> str:
    """Extract a domain from a URL string for SSRF allowlisting.

    Args:
        url_or_text: A URL or text containing a URL.

    Returns:
        The domain string, or the original text if no URL could be parsed.
    """
    text = url_or_text.strip()
    try:
        parsed = urlparse(text)
        if parsed.hostname:
            return parsed.hostname.lower()
    except Exception:
        pass
    url_match = re.search(r'https?://([^/:\s]+)', text)
    if url_match:
        return url_match.group(1).lower()
    return text


def prepare_config_with_pattern(
    pattern: str, config_section: str
) -> tuple:
    """Insert a pattern into config JSON in memory, return (json_text, line_number).

    Loads the current ai-guardian.json, inserts the pattern into the appropriate
    allowlist section, serializes to formatted JSON, and finds the line number
    of the newly inserted pattern.

    Returns:
        (formatted_json_string, 1-based_line_number_of_inserted_pattern)
    """
    from ai_guardian.config_utils import get_config_dir

    config_path = get_config_dir() / "ai-guardian.json"
    config = {}
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (json.JSONDecodeError, OSError):
            config = {}

    if config_section == "ssrf_protection":
        if config_section not in config:
            config[config_section] = {}
        domains = config[config_section].get("allowed_domains", [])
        if pattern not in domains:
            domains.append(pattern)
        config[config_section]["allowed_domains"] = domains
    elif config_section == "directory_rules":
        if config_section not in config:
            config[config_section] = {}
        exclusions = config[config_section].get("exclusions", [])
        if pattern not in exclusions:
            exclusions.append(pattern)
        config[config_section]["exclusions"] = exclusions
    else:
        if config_section not in config:
            config[config_section] = {}
        patterns = config[config_section].get("allowlist_patterns", [])
        if pattern not in patterns:
            patterns.append(pattern)
        config[config_section]["allowlist_patterns"] = patterns

    json_text = json.dumps(config, indent=2) + "\n"

    escaped = json.dumps(pattern)
    line_number = 1
    for i, line in enumerate(json_text.splitlines(), 1):
        if escaped in line:
            line_number = i
    return json_text, line_number


def suggest_pattern(matched_text: str, config_section: str = "") -> str:
    """Suggest an initial pattern based on the matched text.

    For SSRF, extracts the domain from the URL.
    For directory_rules, suggests the directory as a glob pattern.
    For env-variable assignments (KEY=value), suggests KEY\\s*= to match
    the key with any value.
    For other sections, escapes the text for use as a regex.
    """
    if config_section == "ssrf_protection":
        return suggest_domain(matched_text)
    if config_section == "directory_rules":
        import os
        path = matched_text.strip()
        if os.path.isfile(path):
            return os.path.dirname(path) + "/**"
        return path + "/**" if not path.endswith("/**") else path
    env_match = re.match(r'^([A-Z][A-Z0-9_]+)\s*=', matched_text)
    if env_match:
        return env_match.group(1) + r'\s*='
    return re.escape(matched_text)
