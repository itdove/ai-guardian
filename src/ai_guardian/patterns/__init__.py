"""
TOML-based pattern loading for ai-guardian.

Provides PatternCache for pre-compiled pattern matching across all
security features: secrets, PII, prompt injection, unicode attacks,
config exfiltration, and SSRF protection.

Patterns are loaded from bundled TOML files and optionally from
pattern servers, then compiled once into Python objects (re.Pattern,
ipaddress networks, dict lookups) for fast in-memory matching.
"""

from pathlib import Path

from ai_guardian.patterns.cache import PatternCache
from ai_guardian.patterns.toml_parser import CompiledRule, load_toml_file, compile_rule

DATA_DIR = Path(__file__).parent / "data"

BUNDLED_FILES = {
    "secrets": DATA_DIR / "secrets.toml",
    "pii": DATA_DIR / "pii.toml",
    "prompt_injection": DATA_DIR / "prompt-injection.toml",
    "unicode": DATA_DIR / "unicode.toml",
    "config_exfil": DATA_DIR / "config-exfil.toml",
    "ssrf": DATA_DIR / "ssrf.toml",
}

__all__ = ["PatternCache", "CompiledRule", "load_toml_file", "compile_rule",
           "DATA_DIR", "BUNDLED_FILES"]
