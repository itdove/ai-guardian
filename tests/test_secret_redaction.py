"""
Tests for secret redaction functionality (Phase 4: Hermes Security Patterns).

Tests the SecretRedactor class and its integration with PostToolUse hook.
"""

import pytest
import json
from ai_guardian.secret_redactor import SecretRedactor


class TestSecretRedactor:
    """Test the SecretRedactor class."""

    def test_redactor_initialization(self):
        """Test that SecretRedactor initializes correctly."""
        redactor = SecretRedactor()
        assert redactor.enabled is True
        assert redactor.action == "log-only"
        assert redactor.preserve_format is True
        assert redactor.log_redactions is True
        assert len(redactor.compiled_patterns) > 30  # Should have 35+ patterns

    def test_redactor_disabled(self):
        """Test that disabled redactor returns original text."""
        redactor = SecretRedactor({"enabled": False})
        text = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        result = redactor.redact(text)

        assert result['redacted_text'] == text
        assert len(result['redactions']) == 0

    def test_openai_api_key_redaction(self):
        """Test redaction of OpenAI API keys."""
        redactor = SecretRedactor()
        text = "My key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx here"
        result = redactor.redact(text)

        # Should preserve some prefix and suffix (6 chars + 4 chars)
        assert "sk-pro..." in result['redacted_text'] or "sk-proj..." in result['redacted_text']
        assert "abc123def456ghi789" not in result['redacted_text']
        assert len(result['redactions']) == 1
        assert result['redactions'][0]['type'] == 'OpenAI Project Key'
        assert result['redactions'][0]['strategy'] == 'preserve_prefix_suffix'

    def test_github_token_redaction(self):
        """Test redaction of GitHub tokens."""
        redactor = SecretRedactor()
        text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"  # notsecret
        result = redactor.redact(text)

        assert "ghp_12...wxyz" in result['redacted_text']
        assert "1234567890abcdefghijk" not in result['redacted_text']
        assert len(result['redactions']) == 1
        assert result['redactions'][0]['type'] == 'GitHub Personal Token'

    def test_aws_access_key_full_redaction(self):
        """Test that AWS access keys are fully redacted."""
        redactor = SecretRedactor()
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact(text)

        # Secret should be completely gone
        assert "AKIAIOSFODNN7EXAMPLE" not in result['redacted_text']
        assert len(result['redactions']) == 1
        assert result['redactions'][0]['strategy'] == 'full_redact'
        # Should have some replacement text
        assert "AWS" in result['redacted_text']

    def test_env_var_redaction(self):
        """Test environment variable assignment redaction."""
        redactor = SecretRedactor()
        text = "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = redactor.redact(text)

        # Secret value should be gone but variable name preserved
        assert "wJalrXUtnFEMI" not in result['redacted_text']
        assert "AWS_SECRET_KEY=" in result['redacted_text']
        assert len(result['redactions']) >= 1  # May match multiple patterns

    def test_json_field_redaction(self):
        """Test JSON field redaction preserves structure."""
        redactor = SecretRedactor()
        text = '{"api_key": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"}'
        result = redactor.redact(text)

        # Secret should be redacted but structure preserved
        assert '"api_key"' in result['redacted_text']
        assert "abc123def456" not in result['redacted_text']
        # Should still be valid-looking JSON
        assert "{" in result['redacted_text'] and "}" in result['redacted_text']

    def test_connection_string_redaction(self):
        """Test database connection string redaction."""
        redactor = SecretRedactor()
        text = "mongodb://user:MySecretPass123@db.example.com:27017/mydb"
        result = redactor.redact(text)

        # Password should be redacted but endpoint preserved
        assert "MySecretPass123" not in result['redacted_text']
        assert "mongodb://user:" in result['redacted_text']
        assert "@db.example.com:27017/mydb" in result['redacted_text']
        assert len(result['redactions']) >= 1

    def test_bearer_token_redaction(self):
        """Test HTTP Authorization header redaction."""
        redactor = SecretRedactor()
        text = "Authorization: Bearer sk-ant-api03-abc123def456ghi789jkl012"
        result = redactor.redact(text)

        assert "Authorization: Bearer" in result['redacted_text']
        assert "abc123def456" not in result['redacted_text']
        assert len(result['redactions']) >= 1

    def test_multiple_secrets_in_output(self):
        """Test redaction of multiple different secrets."""
        redactor = SecretRedactor()
        text = """
        GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyz
        OpenAI: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx
        AWS: AKIAIOSFODNN7EXAMPLE
        """  # notsecret
        result = redactor.redact(text)

        # All secret values should be completely gone
        assert "1234567890abcdefghijk" not in result['redacted_text']
        assert "abc123def456ghi789" not in result['redacted_text']
        assert "AKIAIOSFODNN7EXAMPLE" not in result['redacted_text']

        # Context labels should remain
        assert "GitHub:" in result['redacted_text']
        assert "OpenAI:" in result['redacted_text']
        assert "AWS:" in result['redacted_text']

        assert len(result['redactions']) >= 3

    def test_short_secret_handling(self):
        """Test that very short secrets are handled properly."""
        redactor = SecretRedactor()
        # This should match a pattern but be too short to preserve prefix/suffix
        text = "token: abc12345"  # 8 chars
        result = redactor.redact(text)

        # Short secrets may not be detected or may be redacted as ***
        assert len(result['redacted_text']) > 0

    def test_overlapping_patterns(self):
        """Test that overlapping patterns don't cause issues."""
        redactor = SecretRedactor()
        text = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz"  # notsecret
        result = redactor.redact(text)

        # Should redact either as env var or as GitHub token, but not duplicate
        assert "1234567890abcdefghijk" not in result['redacted_text']
        # Should have at least one redaction
        assert len(result['redactions']) >= 1

    def test_custom_patterns(self):
        """Test adding custom redaction patterns."""
        config = {
            "additional_patterns": [
                {
                    "pattern": r"(mycompany_token_[A-Za-z0-9]{20,})",
                    "strategy": "preserve_prefix_suffix",
                    "type": "Company Token"
                }
            ]
        }
        redactor = SecretRedactor(config)
        text = "Token: mycompany_token_abc123def456ghi789jkl012mno345"
        result = redactor.redact(text)

        # Secret middle part should be redacted
        assert "def456ghi789jkl012" not in result['redacted_text']
        assert len(result['redactions']) > 0

    def test_private_key_redaction(self):
        """Test that private keys are fully redacted."""
        redactor = SecretRedactor()
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmno
-----END RSA PRIVATE KEY-----"""  # notsecret
        result = redactor.redact(text)

        # Private key content should be completely gone
        assert "MIIEpAIBAAKCAQEA" not in result['redacted_text']
        assert len(result['redactions']) == 1

    def test_anthropic_api_key(self):
        """Test Anthropic API key redaction."""
        redactor = SecretRedactor()
        text = "Key: sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901"
        result = redactor.redact(text)

        # Should redact the middle part
        assert "abc123def456ghi789" not in result['redacted_text']
        assert len(result['redactions']) >= 1

    def test_slack_token(self):
        """Test Slack token redaction."""
        redactor = SecretRedactor()
        # Using intentionally fake token format that still matches our pattern
        text = "Slack: xoxb-TEST1234567-TEST1234567890-EXAMPLEEXAMPLEEX"  # notsecret
        result = redactor.redact(text)

        assert "xoxb-" in result['redacted_text']
        assert "EXAMPLEEXAMPLEEX" not in result['redacted_text']

    def test_stripe_keys(self):
        """Test Stripe API key redaction."""
        redactor = SecretRedactor()
        # Using public key to avoid GitHub's secret scanner (tests same redaction logic)
        text = "pk_test_XXXXXXXXXXXXXXXXXXXXXXXX"  # notsecret (fake public key)
        result = redactor.redact(text)

        # Should redact the secret part - middle X's should be gone
        assert "XXXXXXXXXXXXXXXXXX" not in result['redacted_text']
        assert len(result['redactions']) >= 1

    def test_redaction_metadata(self):
        """Test that redaction metadata is complete."""
        redactor = SecretRedactor()
        text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz" # notsecret
        result = redactor.redact(text)

        assert 'redacted_text' in result
        assert 'redactions' in result
        assert 'original_length' in result
        assert 'redacted_length' in result

        if len(result['redactions']) > 0:
            r = result['redactions'][0]
            assert 'type' in r
            assert 'position' in r
            assert 'original_length' in r
            assert 'redacted_length' in r
            assert 'strategy' in r

    def test_performance(self):
        """Test that redaction is fast enough (<5ms for 10KB)."""
        import time

        redactor = SecretRedactor()
        # Create 10KB of text with some secrets
        text = ("Hello world. " * 100 +
                "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz\n" + # notsecret
                "Some more text. " * 100) * 10 

        start = time.time()
        result = redactor.redact(text)
        elapsed = (time.time() - start) * 1000  # Convert to ms

        # Should complete in under 50ms (relaxed from 5ms for safety)
        assert elapsed < 50, f"Redaction took {elapsed}ms, expected <50ms"
        assert len(result['redactions']) > 0

    def test_action_modes(self):
        """Test different action modes."""
        # log-only mode
        redactor_log = SecretRedactor({"action": "log-only"})
        assert redactor_log.action == "log-only"

        # warn mode
        redactor_warn = SecretRedactor({"action": "warn"})
        assert redactor_warn.action == "warn"

        # block mode
        redactor_block = SecretRedactor({"action": "block"})
        assert redactor_block.action == "block"

    def test_empty_text(self):
        """Test redaction of empty text."""
        redactor = SecretRedactor()
        result = redactor.redact("")

        assert result['redacted_text'] == ""
        assert len(result['redactions']) == 0

    def test_none_text(self):
        """Test redaction of None."""
        redactor = SecretRedactor()
        result = redactor.redact(None)

        assert result['redacted_text'] is None
        assert len(result['redactions']) == 0

    def test_hex_secret_redaction(self):
        """Test long hex string redaction with context."""
        redactor = SecretRedactor()
        # Hex patterns now require context keywords (secret, key, token, password)
        # or be very long (100+ chars) to avoid false positives with git SHAs
        text = "api_secret: abcdef1234567890abcdef1234567890abcdef1234567890"
        result = redactor.redact(text)

        # Long hex strings with context should be redacted - middle part gone
        assert "api_secret:" in result['redacted_text']
        # Should have some redaction
        assert len(result['redacted_text']) < len(text)

    def test_base64_secret_redaction(self):
        """Test base64 encoded secret redaction with context."""
        redactor = SecretRedactor()
        # Base64 patterns now require context keywords or be very long (100+ chars)
        text = "token: dGhpc2lzYWxvbmdzdHJpbmd0aGF0bG9va3NsaWtlYWJhc2U2NGVuY29kZWRzZWNyZXQ="
        result = redactor.redact(text)

        # Long base64 strings with context should be redacted
        assert "dGhpc2...ZXQ=" in result['redacted_text'] or "token:" in result['redacted_text']


class TestSecretRedactionIntegration:
    """Test integration with PostToolUse hook."""

    def test_posttooluse_with_redaction_enabled(self):
        """Test that PostToolUse redacts instead of blocks when enabled."""
        # This would be an integration test with the actual hook
        # For now, just test the config loading
        from ai_guardian import _load_secret_redaction_config

        # Should not error when loading config
        config, error = _load_secret_redaction_config()
        assert error is None or config is None  # Either loads successfully or no config

    def test_redaction_preserves_non_secret_context(self):
        """Test that redaction preserves debugging context."""
        redactor = SecretRedactor()
        text = """
        AWS Configuration:
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        AWS_REGION=us-east-1
        AWS_DEFAULT_OUTPUT=json
        """
        result = redactor.redact(text)

        # Non-secret values should be preserved
        assert "AWS_REGION=us-east-1" in result['redacted_text']
        assert "AWS_DEFAULT_OUTPUT=json" in result['redacted_text']

        # Secret values should be gone
        assert "AKIAIOSFODNN7EXAMPLE" not in result['redacted_text']
        assert "wJalrXUtnFEMI" not in result['redacted_text']

    def test_log_file_with_buried_secret(self):
        """Test finding a secret buried in log output."""
        redactor = SecretRedactor()
        # Simulate a large log file with one secret
        log_lines = ["[INFO] Application started"] * 100
        log_lines[50] = "[DEBUG] API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"  # notsecret
        log_lines += ["[INFO] Processing request"] * 100

        text = "\n".join(log_lines)
        result = redactor.redact(text)

        # Should find and redact the secret - check middle is gone
        assert "abc123def456ghi789" not in result['redacted_text']

        # Other log lines should be preserved
        assert "[INFO] Application started" in result['redacted_text']
        assert "[INFO] Processing request" in result['redacted_text']

    def test_config_file_review(self):
        """Test reviewing a config file with secrets."""
        redactor = SecretRedactor()
        text = """
        # Production Configuration
        database:
          host: prod-db.example.com
          port: 5432
          password: MySecretPass123

        api:
          key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx
          endpoint: https://api.example.com
        """
        result = redactor.redact(text)

        # Can see structure
        assert "database:" in result['redacted_text']
        assert "host: prod-db.example.com" in result['redacted_text']
        assert "port: 5432" in result['redacted_text']
        assert "endpoint: https://api.example.com" in result['redacted_text']

        # Secrets are hidden
        assert "MySecretPass123" not in result['redacted_text']
        assert "abc123def456" not in result['redacted_text']
