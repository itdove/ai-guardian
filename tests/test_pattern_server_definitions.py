"""
Tests for pattern_server_auth and pattern_server_cache definitions.

This test suite validates that the pattern_server_auth and pattern_server_cache
definitions work correctly in all locations where they're referenced:
- secret_redaction.pattern_server
- prompt_injection.unicode_detection.pattern_server
- ssrf_protection.pattern_server
- config_file_scanning.pattern_server
"""

import json
import pytest
from pathlib import Path

# Try to import jsonschema - it's optional
try:
    import jsonschema
    from jsonschema import validate, ValidationError
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


# Get project root directory
PROJECT_ROOT = Path(__file__).parent.parent
SCHEMA_PATH = PROJECT_ROOT / "src" / "ai_guardian" / "schemas" / "ai-guardian-config.schema.json"


@pytest.fixture
def schema():
    """Load the JSON Schema."""
    with open(SCHEMA_PATH, 'r') as f:
        return json.load(f)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_secret_redaction_pattern_server(schema):
    """Test that secret_redaction.pattern_server validates correctly with auth and cache."""
    config = {
        "secret_redaction": {
            "enabled": True,
            "pattern_server": {
                "url": "https://patterns.example.com",
                "patterns_endpoint": "/patterns/secrets/v1",
                "auth": {
                    "method": "bearer",
                    "token_env": "PATTERN_TOKEN"
                },
                "cache": {
                    "path": "~/.cache/ai-guardian/secrets.toml",
                    "refresh_interval_hours": 12,
                    "expire_after_hours": 168
                }
            }
        }
    }

    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        pytest.fail(f"secret_redaction.pattern_server failed validation: {e.message}")


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_unicode_detection_pattern_server(schema):
    """Test that prompt_injection.unicode_detection.pattern_server validates correctly."""
    config = {
        "prompt_injection": {
            "enabled": True,
            "unicode_detection": {
                "enabled": True,
                "pattern_server": {
                    "url": "https://patterns.example.com",
                    "patterns_endpoint": "/patterns/unicode/v1",
                    "auth": {
                        "method": "token",
                        "token_file": "~/.config/pattern-token"
                    },
                    "cache": {
                        "path": "~/.cache/ai-guardian/unicode.toml",
                        "refresh_interval_hours": 24,
                        "expire_after_hours": 336
                    }
                }
            }
        }
    }

    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        pytest.fail(f"unicode_detection.pattern_server failed validation: {e.message}")


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_ssrf_protection_pattern_server(schema):
    """Test that ssrf_protection.pattern_server validates correctly."""
    config = {
        "ssrf_protection": {
            "enabled": True,
            "pattern_server": {
                "url": "https://patterns.example.com",
                "patterns_endpoint": "/patterns/ssrf/v1",
                "allow_override": True,
                "validate_critical": True,
                "auth": {
                    "method": "bearer",
                    "token_env": "SSRF_TOKEN"
                },
                "cache": {
                    "path": "~/.cache/ai-guardian/ssrf.toml",
                    "refresh_interval_hours": 6,
                    "expire_after_hours": 72
                }
            }
        }
    }

    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        pytest.fail(f"ssrf_protection.pattern_server failed validation: {e.message}")


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_config_file_scanning_pattern_server(schema):
    """Test that config_file_scanning.pattern_server validates correctly."""
    config = {
        "config_file_scanning": {
            "enabled": True,
            "pattern_server": {
                "url": "https://patterns.example.com",
                "patterns_endpoint": "/patterns/config-exfil/v1",
                "auth": {
                    "method": "bearer",
                    "token_env": "CONFIG_TOKEN",
                    "token_file": "~/.config/backup-token"
                },
                "cache": {
                    "path": "~/.cache/ai-guardian/config-exfil.toml",
                    "refresh_interval_hours": 48,
                    "expire_after_hours": 720
                }
            }
        }
    }

    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        pytest.fail(f"config_file_scanning.pattern_server failed validation: {e.message}")


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_all_pattern_servers_together(schema):
    """Test that all pattern_server configurations can be used together."""
    config = {
        "secret_redaction": {
            "pattern_server": {
                "url": "https://patterns.example.com",
                "auth": {"method": "bearer", "token_env": "TOKEN1"},
                "cache": {"path": "~/.cache/secrets.toml"}
            }
        },
        "prompt_injection": {
            "unicode_detection": {
                "pattern_server": {
                    "url": "https://patterns.example.com",
                    "auth": {"method": "bearer", "token_env": "TOKEN2"},
                    "cache": {"path": "~/.cache/unicode.toml"}
                }
            }
        },
        "ssrf_protection": {
            "pattern_server": {
                "url": "https://patterns.example.com",
                "auth": {"method": "bearer", "token_env": "TOKEN3"},
                "cache": {"path": "~/.cache/ssrf.toml"}
            }
        },
        "config_file_scanning": {
            "pattern_server": {
                "url": "https://patterns.example.com",
                "auth": {"method": "bearer", "token_env": "TOKEN4"},
                "cache": {"path": "~/.cache/config.toml"}
            }
        }
    }

    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        pytest.fail(f"Combined pattern_server configs failed validation: {e.message}")


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_auth_with_both_env_and_file(schema):
    """Test that auth can have both token_env and token_file."""
    config = {
        "secret_redaction": {
            "pattern_server": {
                "url": "https://patterns.example.com",
                "auth": {
                    "method": "bearer",
                    "token_env": "PRIMARY_TOKEN",
                    "token_file": "~/.config/backup-token"
                }
            }
        }
    }

    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        pytest.fail(f"Auth with both env and file failed validation: {e.message}")


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_minimal_pattern_server(schema):
    """Test that pattern_server with only URL validates correctly."""
    config = {
        "secret_redaction": {
            "pattern_server": {
                "url": "https://patterns.example.com"
            }
        }
    }

    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        pytest.fail(f"Minimal pattern_server failed validation: {e.message}")


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_invalid_auth_method_rejected(schema):
    """Test that invalid auth method is rejected."""
    config = {
        "secret_redaction": {
            "pattern_server": {
                "url": "https://patterns.example.com",
                "auth": {
                    "method": "invalid_method",
                    "token_env": "TOKEN"
                }
            }
        }
    }

    with pytest.raises(ValidationError):
        validate(instance=config, schema=schema)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_invalid_cache_refresh_interval_rejected(schema):
    """Test that invalid cache refresh interval is rejected."""
    config = {
        "secret_redaction": {
            "pattern_server": {
                "url": "https://patterns.example.com",
                "cache": {
                    "refresh_interval_hours": 0  # Must be >= 1
                }
            }
        }
    }

    with pytest.raises(ValidationError):
        validate(instance=config, schema=schema)
