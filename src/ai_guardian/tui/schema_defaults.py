#!/usr/bin/env python3
"""
Schema Defaults Utility

Loads default values from the JSON schema and provides helpers
for TUI panels to display defaults and highlight changed values.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class _MissingSentinel:
    """Sentinel for 'no default defined' (distinct from None/False)."""

    def __repr__(self) -> str:
        return "<MISSING>"

    def __bool__(self) -> bool:
        return False


_MISSING = _MissingSentinel()


class SchemaDefaults:
    """Singleton that loads and caches JSON schema defaults."""

    _instance: Optional["SchemaDefaults"] = None
    _schema: Optional[Dict[str, Any]] = None

    @classmethod
    def get(cls) -> "SchemaDefaults":
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None
        cls._schema = None

    def _load(self) -> None:
        schema_path = (
            Path(__file__).parent.parent / "schemas" / "ai-guardian-config.schema.json"
        )
        try:
            with open(schema_path, "r", encoding="utf-8") as f:
                self._schema = json.load(f)
        except Exception:
            self._schema = {}

    def _resolve_path(self, dotted_path: str) -> Optional[Dict[str, Any]]:
        """Resolve a dotted path to its schema property definition."""
        if not self._schema:
            return None
        parts = dotted_path.split(".")
        node = self._schema
        for part in parts:
            props = node.get("properties", {})
            if part in props:
                node = props[part]
            else:
                return None
        return node

    def get_default(self, dotted_path: str) -> Any:
        """Get the default value for a dotted schema path.

        Returns _MISSING if path doesn't exist or has no default.
        """
        prop = self._resolve_path(dotted_path)
        if prop is None:
            return _MISSING
        if "default" in prop:
            return prop["default"]
        return _MISSING

    def get_description(self, dotted_path: str) -> Optional[str]:
        """Get the description for a dotted schema path."""
        prop = self._resolve_path(dotted_path)
        if prop is None:
            return None
        return prop.get("description")

    def is_default(self, dotted_path: str, current_value: Any) -> bool:
        """Check if current_value matches the schema default."""
        default = self.get_default(dotted_path)
        if default is _MISSING:
            return True
        return current_value == default


def select_options_with_default(
    options: List[Tuple[str, str]],
    schema_path: str,
) -> List[Tuple[str, str]]:
    """Mark the default option in a Select widget's choices.

    Appends ' (default)' to the label of the matching option.
    """
    defaults = SchemaDefaults.get()
    default_val = defaults.get_default(schema_path)
    if default_val is _MISSING:
        return list(options)
    result = []
    for label, value in options:
        if value == default_val and "(default)" not in label:
            result.append((f"{label} (default)", value))
        else:
            result.append((label, value))
    return result


def default_indicator(schema_path: str) -> str:
    """Return rich-text default indicator for a field.

    For booleans: '(default: on)' / '(default: off)'
    For other types: '(default: <value>)'
    Returns empty string if no default defined.
    """
    defaults = SchemaDefaults.get()
    default_val = defaults.get_default(schema_path)
    if default_val is _MISSING:
        return ""
    if isinstance(default_val, bool):
        text = "on" if default_val else "off"
    elif isinstance(default_val, list):
        if not default_val:
            text = "none"
        else:
            text = ", ".join(str(v) for v in default_val)
    else:
        text = str(default_val)
    return f"[dim](default: {text})[/dim]"


def default_placeholder(schema_path: str) -> str:
    """Return default value as string for Input placeholder."""
    defaults = SchemaDefaults.get()
    default_val = defaults.get_default(schema_path)
    if default_val is _MISSING:
        return ""
    return str(default_val)


class SchemaDefaultsMixin:
    """Mixin for config panels to show schema defaults and highlight changes.

    Subclasses define:
        SCHEMA_SECTION: str — dotted path prefix (e.g. 'ssrf_protection')
        SCHEMA_FIELDS: list of (widget_id, field_name, widget_type) tuples
    """

    SCHEMA_SECTION: str = ""
    SCHEMA_FIELDS: List[Tuple[str, str, str]] = []

    def _apply_default_indicators(self, config_section: Dict[str, Any]) -> None:
        """Update CSS classes on widgets based on whether values differ from defaults."""
        schema = SchemaDefaults.get()
        for widget_id, field_name, _widget_type in self.SCHEMA_FIELDS:
            path = f"{self.SCHEMA_SECTION}.{field_name}" if self.SCHEMA_SECTION else field_name
            default_val = schema.get_default(path)
            if default_val is _MISSING:
                continue
            current_val = config_section.get(field_name, default_val)
            is_changed = current_val != default_val
            try:
                widget = self.query_one(f"#{widget_id}")
                if is_changed:
                    widget.add_class("changed-from-default")
                else:
                    widget.remove_class("changed-from-default")
            except Exception:
                pass

    def _get_section_default(self, field_name: str) -> Any:
        """Get schema default for a field in this panel's section."""
        path = f"{self.SCHEMA_SECTION}.{field_name}" if self.SCHEMA_SECTION else field_name
        return SchemaDefaults.get().get_default(path)

    def _update_default_indicator(
        self, widget_id: str, field_name: str, new_value: Any
    ) -> None:
        """Update the changed-from-default class for a single widget after save."""
        default_val = self._get_section_default(field_name)
        if default_val is _MISSING:
            return
        try:
            widget = self.query_one(f"#{widget_id}")
            if new_value != default_val:
                widget.add_class("changed-from-default")
            else:
                widget.remove_class("changed-from-default")
        except Exception:
            pass
