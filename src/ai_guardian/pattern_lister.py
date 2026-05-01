#!/usr/bin/env python3
"""
Pattern Lister Module

Lists all available detection patterns across the system for discoverability.
Shows built-in pattern counts and configurable keys users can set in ai-guardian.json.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

EXCLUDED_KEYS = {
    "enabled", "action", "immutable", "detector", "sensitivity",
    "max_score_threshold", "pattern_server", "allow_localhost",
    "allow_rtl_languages", "allow_emoji", "preserve_format",
    "log_redactions", "max_entries", "retention_days",
}

CATEGORY_ALIASES = {
    "pi": "prompt_injection",
    "injection": "prompt_injection",
    "unicode": "prompt_injection.unicode_detection",
    "pii": "scan_pii",
    "ssrf": "ssrf_protection",
    "config": "config_file_scanning",
    "config_scan": "config_file_scanning",
    "secrets": "secret_redaction",
    "redaction": "secret_redaction",
    "logging": "violation_logging",
    "violations": "violation_logging",
}


@dataclass
class ConfigurableKey:
    name: str
    description: str
    value_type: str
    default_value: Any
    current_count: int
    enum_values: Optional[List[str]] = None


@dataclass
class BuiltInGroup:
    name: str
    count: int
    note: str = ""


@dataclass
class PatternCategory:
    name: str
    config_key: str
    built_in_groups: List[BuiltInGroup] = field(default_factory=list)
    configurable_keys: List[ConfigurableKey] = field(default_factory=list)
    subcategories: List["PatternCategory"] = field(default_factory=list)

    @property
    def total_built_in(self) -> int:
        return sum(g.count for g in self.built_in_groups)


class PatternLister:
    """Lists detection patterns and configurable keys across the system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._schema = None

    def _load_schema(self) -> Dict[str, Any]:
        if self._schema is not None:
            return self._schema
        try:
            schema_path = Path(__file__).parent / "schemas" / "ai-guardian-config.schema.json"
            with open(schema_path, "r") as f:
                self._schema = json.load(f)
        except Exception as e:
            logger.warning("Could not load schema: %s", e)
            self._schema = {}
        return self._schema

    def _infer_value_type(self, prop: Dict[str, Any]) -> str:
        prop_type = prop.get("type")
        desc = prop.get("description", "").lower()

        if prop_type == "boolean":
            return "bool"

        if prop_type == "array":
            items = prop.get("items", {})
            if isinstance(items, dict):
                if items.get("type") == "object":
                    return "object list"
                item_enum = items.get("enum")
                if item_enum:
                    return "enum"
                if "glob" in desc:
                    return "glob list"
                if "cidr" in desc:
                    return "CIDR list"
                if "fnmatch" in desc:
                    return "fnmatch list"
                item_desc = items.get("description", "").lower()
                if "wildcard" in desc and "tool name" in desc:
                    return "fnmatch list"
                if "regex" in desc or "detection pattern" in desc:
                    return "regex list"
            return "string list"

        return "string"

    def _get_configurable_keys(
        self, schema_section: Dict[str, Any], config_section: Dict[str, Any]
    ) -> List[ConfigurableKey]:
        props = schema_section.get("properties", {})
        keys = []
        for key_name, prop in props.items():
            if key_name in EXCLUDED_KEYS:
                continue
            if isinstance(prop, dict) and prop.get("type") == "object" and key_name != "path_based_rules":
                continue

            value_type = self._infer_value_type(prop)
            default = prop.get("default")
            enum_values = None

            items = prop.get("items", {})
            if isinstance(items, dict):
                item_enum = items.get("enum")
                if item_enum:
                    enum_values = item_enum

            current = config_section.get(key_name)
            if current is not None:
                if isinstance(current, list):
                    current_count = len(current)
                elif isinstance(current, bool):
                    current_count = 0
                else:
                    current_count = 0
            elif default is not None:
                if isinstance(default, list):
                    current_count = len(default)
                else:
                    current_count = 0
            else:
                current_count = 0

            keys.append(ConfigurableKey(
                name=key_name,
                description=prop.get("description", ""),
                value_type=value_type,
                default_value=default,
                current_count=current_count,
                enum_values=enum_values,
            ))
        return keys

    def _build_prompt_injection_category(self) -> PatternCategory:
        from ai_guardian.prompt_injection import PromptInjectionDetector

        groups = [
            BuiltInGroup("CRITICAL_PATTERNS", len(PromptInjectionDetector.CRITICAL_PATTERNS), "always checked"),
            BuiltInGroup("DOCUMENTATION_PATTERNS", len(PromptInjectionDetector.DOCUMENTATION_PATTERNS), "user prompts only"),
            BuiltInGroup("JAILBREAK_PATTERNS", len(PromptInjectionDetector.JAILBREAK_PATTERNS), "user prompts only"),
            BuiltInGroup("SUSPICIOUS_PATTERNS", len(PromptInjectionDetector.SUSPICIOUS_PATTERNS), "medium/high sensitivity"),
        ]

        schema = self._load_schema()
        schema_section = schema.get("properties", {}).get("prompt_injection", {})
        config_section = self.config.get("prompt_injection", {})
        configurable = self._get_configurable_keys(schema_section, config_section)

        unicode_sub = self._build_unicode_detection_category()

        return PatternCategory(
            name="Prompt Injection",
            config_key="prompt_injection",
            built_in_groups=groups,
            configurable_keys=configurable,
            subcategories=[unicode_sub],
        )

    def _build_unicode_detection_category(self) -> PatternCategory:
        from ai_guardian.prompt_injection import UnicodeAttackDetector

        groups = [
            BuiltInGroup("Zero-width chars", len(UnicodeAttackDetector.ZERO_WIDTH_CHARS), "invisible characters"),
            BuiltInGroup("Bidi override chars", len(UnicodeAttackDetector.BIDI_OVERRIDE_CHARS), "visual deception"),
            BuiltInGroup("Bidi formatting chars", len(UnicodeAttackDetector.BIDI_FORMATTING_CHARS), "context-aware"),
            BuiltInGroup("Homoglyph patterns", len(UnicodeAttackDetector.HOMOGLYPH_PATTERNS), "look-alike pairs"),
        ]

        schema = self._load_schema()
        unicode_schema = (
            schema.get("properties", {})
            .get("prompt_injection", {})
            .get("properties", {})
            .get("unicode_detection", {})
        )
        unicode_config = self.config.get("prompt_injection", {}).get("unicode_detection", {})
        configurable = self._get_configurable_keys(unicode_schema, unicode_config)

        return PatternCategory(
            name="Unicode Detection",
            config_key="prompt_injection.unicode_detection",
            built_in_groups=groups,
            configurable_keys=configurable,
        )

    def _build_pii_category(self) -> PatternCategory:
        from ai_guardian.secret_redactor import SecretRedactor

        groups = [
            BuiltInGroup("PII patterns", len(SecretRedactor.PII_PATTERNS), ""),
        ]

        schema = self._load_schema()
        schema_section = schema.get("properties", {}).get("scan_pii", {})
        config_section = self.config.get("scan_pii", {})
        configurable = self._get_configurable_keys(schema_section, config_section)

        return PatternCategory(
            name="PII Detection",
            config_key="scan_pii",
            built_in_groups=groups,
            configurable_keys=configurable,
        )

    def _build_ssrf_category(self) -> PatternCategory:
        from ai_guardian.ssrf_protector import SSRFProtector

        groups = [
            BuiltInGroup("Blocked IP ranges", len(SSRFProtector.CORE_BLOCKED_IP_RANGES), "RFC 1918 + loopback"),
            BuiltInGroup("Blocked domains", len(SSRFProtector.CORE_BLOCKED_DOMAINS), "cloud metadata"),
            BuiltInGroup("Dangerous schemes", len(SSRFProtector.DANGEROUS_SCHEMES), "file://, gopher://, etc."),
        ]

        schema = self._load_schema()
        schema_section = schema.get("properties", {}).get("ssrf_protection", {})
        config_section = self.config.get("ssrf_protection", {})
        configurable = self._get_configurable_keys(schema_section, config_section)

        return PatternCategory(
            name="SSRF Protection",
            config_key="ssrf_protection",
            built_in_groups=groups,
            configurable_keys=configurable,
        )

    def _build_config_scanning_category(self) -> PatternCategory:
        from ai_guardian.config_scanner import ConfigFileScanner

        groups = [
            BuiltInGroup("Exfiltration patterns", len(ConfigFileScanner.CORE_EXFIL_PATTERNS), "credential theft"),
        ]

        schema = self._load_schema()
        schema_section = schema.get("properties", {}).get("config_file_scanning", {})
        config_section = self.config.get("config_file_scanning", {})
        configurable = self._get_configurable_keys(schema_section, config_section)

        return PatternCategory(
            name="Config File Scanning",
            config_key="config_file_scanning",
            built_in_groups=groups,
            configurable_keys=configurable,
        )

    def _build_secret_redaction_category(self) -> PatternCategory:
        from ai_guardian.secret_redactor import SecretRedactor

        groups = [
            BuiltInGroup("Secret patterns", len(SecretRedactor.PATTERNS), "API keys, tokens, credentials"),
        ]

        schema = self._load_schema()
        schema_section = schema.get("properties", {}).get("secret_redaction", {})
        config_section = self.config.get("secret_redaction", {})
        configurable = self._get_configurable_keys(schema_section, config_section)

        return PatternCategory(
            name="Secret Redaction",
            config_key="secret_redaction",
            built_in_groups=groups,
            configurable_keys=configurable,
        )

    def _build_violation_logging_category(self) -> PatternCategory:
        schema = self._load_schema()
        schema_section = schema.get("properties", {}).get("violation_logging", {})
        config_section = self.config.get("violation_logging", {})
        configurable = self._get_configurable_keys(schema_section, config_section)

        return PatternCategory(
            name="Violation Logging",
            config_key="violation_logging",
            built_in_groups=[],
            configurable_keys=configurable,
        )

    def get_categories(self, category_filter: Optional[str] = None) -> List[PatternCategory]:
        resolved = category_filter
        if resolved and resolved in CATEGORY_ALIASES:
            resolved = CATEGORY_ALIASES[resolved]

        builders = [
            self._build_prompt_injection_category,
            self._build_pii_category,
            self._build_ssrf_category,
            self._build_config_scanning_category,
            self._build_secret_redaction_category,
            self._build_violation_logging_category,
        ]

        categories = []
        for builder in builders:
            cat = builder()
            if resolved:
                if cat.config_key == resolved:
                    categories.append(cat)
                else:
                    for sub in cat.subcategories:
                        if sub.config_key == resolved:
                            categories.append(sub)
            else:
                categories.append(cat)

        return categories

    def print_pattern_list(self, verbose: bool = False, category: Optional[str] = None):
        categories = self.get_categories(category_filter=category)

        if not categories:
            print(f"\nNo pattern category found matching '{category}'")
            print("\nAvailable categories:")
            all_cats = self.get_categories()
            for cat in all_cats:
                print(f"  {cat.config_key}")
                for sub in cat.subcategories:
                    print(f"  {sub.config_key}")
            return

        print("\nDetection Patterns:\n")

        for cat in categories:
            self._print_category(cat, verbose=verbose, indent=2)

        if not verbose:
            print("Use --verbose to show pattern group breakdowns")
        print("Use --category <name> to filter (e.g., prompt_injection, scan_pii)")
        print("Use --json for machine-readable output")

    def _print_category(self, cat: PatternCategory, verbose: bool, indent: int):
        prefix = " " * indent
        print(f"{prefix}{cat.name} ({cat.config_key})")

        if cat.built_in_groups:
            total = cat.total_built_in
            group_count = len(cat.built_in_groups)
            if group_count > 1:
                print(f"{prefix}  Built-in: {total} patterns ({group_count} groups)")
            else:
                print(f"{prefix}  Built-in: {total} patterns")

            if verbose:
                for group in cat.built_in_groups:
                    note = f"  ({group.note})" if group.note else ""
                    print(f"{prefix}    {group.name:<30s} {group.count:>3d} patterns{note}")

        if cat.configurable_keys:
            print(f"{prefix}  Configurable keys (use in ai-guardian.json):")
            for key in cat.configurable_keys:
                if key.value_type == "bool":
                    current_display = str(key.default_value).lower() if key.default_value is not None else "false"
                    configured = self.config
                    parts = cat.config_key.split(".")
                    for part in parts:
                        configured = configured.get(part, {}) if isinstance(configured, dict) else {}
                    if key.name in configured if isinstance(configured, dict) else False:
                        current_display = str(configured[key.name]).lower()
                    print(f"{prefix}    {key.name:<30s} {key.value_type:<14s} (current: {current_display})")
                else:
                    count_label = f"{key.current_count} configured" if key.current_count > 0 else "0 configured"
                    if key.enum_values and key.current_count > 0:
                        count_label = f"{key.current_count} active"
                    print(f"{prefix}    {key.name:<30s} {key.value_type:<14s} ({count_label})")
                    if key.enum_values and verbose:
                        print(f"{prefix}      Values: {', '.join(key.enum_values)}")

        for sub in cat.subcategories:
            print()
            self._print_category(sub, verbose=verbose, indent=indent + 2)

        print()

    def get_pattern_list_json(self, category: Optional[str] = None) -> str:
        categories = self.get_categories(category_filter=category)
        data = {"categories": [self._category_to_dict(cat) for cat in categories]}
        return json.dumps(data, indent=2)

    def _category_to_dict(self, cat: PatternCategory) -> Dict[str, Any]:
        return {
            "name": cat.name,
            "config_key": cat.config_key,
            "total_built_in": cat.total_built_in,
            "built_in_groups": [
                {"name": g.name, "count": g.count, "note": g.note}
                for g in cat.built_in_groups
            ],
            "configurable_keys": [
                {
                    "name": k.name,
                    "value_type": k.value_type,
                    "current_count": k.current_count,
                    "default_value": k.default_value,
                    **({"enum_values": k.enum_values} if k.enum_values else {}),
                }
                for k in cat.configurable_keys
            ],
            "subcategories": [self._category_to_dict(sub) for sub in cat.subcategories],
        }
