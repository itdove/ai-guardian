"""
TOML Patterns Scanner — internal Python-based secret scanner.

Runs in-process (~1-5ms) using pre-compiled patterns from bundled TOML
files. No external binary required. Registered as "toml-patterns" in
the engine preset list alongside gitleaks and betterleaks.

Usage in ai-guardian.json:
    "secret_scanning": {
        "engines": ["toml-patterns", "gitleaks"]
    }
"""

import logging
from pathlib import Path
from typing import List, Optional, Set

from ai_guardian.patterns import BUNDLED_FILES
from ai_guardian.patterns.cache import PatternCache
from ai_guardian.scanners.sdk import Finding, Scanner

logger = logging.getLogger(__name__)


class TomlPatternsScanner(Scanner):
    """Internal Python scanner using pre-compiled TOML patterns.

    Scans content for secrets and PII using patterns loaded from
    bundled TOML files. Optionally loads additional patterns from
    pattern servers (multi-format).
    """

    name = "toml-patterns"
    version = "1.0.0"

    def __init__(self):
        self._cache = PatternCache()
        self._allowed_pii_types: Optional[Set[str]] = None
        toml_paths = []
        for key in ("secrets", "pii"):
            path = BUNDLED_FILES.get(key)
            if path and path.exists():
                toml_paths.append(path)
        if toml_paths:
            self._cache.load(*toml_paths)
        logger.info(f"TomlPatternsScanner: loaded {self._cache.rule_count} rules")

    def configure(self, config: dict) -> None:
        """Accept scanner-specific configuration.

        Supports:
            pattern_servers: list of server configs with 'url' and 'format'
            additional_patterns: list of extra rule dicts
            pii_types: list of PII types to detect (from scan_pii config)
        """
        pii_types = config.get("pii_types")
        if pii_types is not None:
            self._allowed_pii_types = set(pii_types)

        servers = config.get("pattern_servers", [])
        if not servers and "pattern_server" in config:
            servers = [config["pattern_server"]]

        for server_config in servers:
            self._load_from_server(server_config)

        additional = config.get("additional_patterns", [])
        if additional:
            self._cache.load_rules(additional, category="secrets")

    def _load_from_server(self, server_config: dict) -> None:
        """Load patterns from a single pattern server."""
        try:
            from ai_guardian.pattern_server import PatternServerClient
            from ai_guardian.patterns.server_parsers import get_parser

            fmt = server_config.get("format", "gitleaks")
            parser = get_parser(fmt)
            if parser is None:
                logger.warning(f"Unsupported pattern server format: {fmt}")
                return

            client = PatternServerClient(server_config)
            raw_data = client.get_patterns()
            if raw_data:
                rules = parser.parse(raw_data)
                if rules:
                    self._cache.load_rules(rules, category="secrets")
                    logger.info(f"TomlPatternsScanner: loaded {len(rules)} rules from server ({fmt})")
        except Exception as e:
            logger.warning(f"TomlPatternsScanner: failed to load from server: {e}")

    def scan(self, content: str, file_path: str = None) -> List[Finding]:
        """Scan content for secrets and PII using compiled TOML patterns.

        Args:
            content: Text content to scan
            file_path: Optional source file path (for context)

        Returns:
            List of Finding objects
        """
        raw_findings = self._cache.scan(content, categories=["secrets", "pii"])
        findings = []
        for f in raw_findings:
            if self._allowed_pii_types is not None and f.category == "pii":
                pii_type = f.metadata.get("pii_type")
                if pii_type and pii_type not in self._allowed_pii_types:
                    continue
            findings.append(Finding(
                rule_id=f.rule_id,
                line_number=f.line_number,
                matched_text=f.matched_text,
                description=f.description or f.rule_id,
                severity="warning",
                category=f.category,
            ))
        return findings
