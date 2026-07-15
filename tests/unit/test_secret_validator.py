"""Tests for secret liveness validation (Issue #971).

Tests the SecretValidator module which validates detected secrets against
provider APIs to determine if they're still active.
"""

from unittest.mock import patch, MagicMock

from ai_guardian.scanners.secret_validator import (
    SecretValidator,
    ValidationStatus,
    ValidationResult,
    CustomValidatorConfig,
    BUILTIN_VALIDATORS,
    _build_custom_validator,
    _validate_github_token,
    _validate_openai_key,
    _validate_anthropic_key,
    _validate_slack_token,
    _validate_gitlab_token,
    _validate_npm_token,
    parse_custom_validator,
)


class TestValidationStatus:
    """Test ValidationStatus enum values."""

    def test_verified_value(self):
        assert ValidationStatus.VERIFIED == "verified"

    def test_inactive_value(self):
        assert ValidationStatus.INACTIVE == "inactive"

    def test_unverified_value(self):
        assert ValidationStatus.UNVERIFIED == "unverified"

    def test_is_string_enum(self):
        assert isinstance(ValidationStatus.VERIFIED, str)


class TestValidationResult:
    """Test ValidationResult dataclass."""

    def test_default_values(self):
        result = ValidationResult(
            status=ValidationStatus.VERIFIED,
            rule_id="test-rule",
        )
        assert result.status == ValidationStatus.VERIFIED
        assert result.rule_id == "test-rule"
        assert result.message == ""
        assert result.response_code is None
        assert result.elapsed_ms == 0.0

    def test_with_all_fields(self):
        result = ValidationResult(
            status=ValidationStatus.INACTIVE,
            rule_id="github-personal-token",
            message="Token returned 401",
            response_code=401,
            elapsed_ms=150.5,
        )
        assert result.response_code == 401
        assert result.elapsed_ms == 150.5


class TestBuiltinValidators:
    """Test built-in validator registry."""

    def test_github_token_registered(self):
        assert "github-personal-token" in BUILTIN_VALIDATORS

    def test_github_oauth_registered(self):
        assert "github-oauth-token" in BUILTIN_VALIDATORS

    def test_github_refresh_registered(self):
        assert "github-refresh-token" in BUILTIN_VALIDATORS

    def test_github_secret_registered(self):
        assert "github-secret-token" in BUILTIN_VALIDATORS

    def test_openai_key_registered(self):
        assert "openai-api-key" in BUILTIN_VALIDATORS

    def test_openai_project_key_registered(self):
        assert "openai-project-key" in BUILTIN_VALIDATORS

    def test_anthropic_key_registered(self):
        assert "anthropic-api-key" in BUILTIN_VALIDATORS

    def test_slack_token_registered(self):
        assert "slack-token" in BUILTIN_VALIDATORS

    def test_gitlab_token_registered(self):
        assert "gitlab-personal-token" in BUILTIN_VALIDATORS

    def test_npm_token_registered(self):
        assert "npm-token" in BUILTIN_VALIDATORS

    def test_unknown_rule_not_registered(self):
        assert "aws-access-key" not in BUILTIN_VALIDATORS

    def test_generic_patterns_not_registered(self):
        assert "hex-secret-with-context" not in BUILTIN_VALIDATORS


class TestGitHubTokenValidator:
    """Test GitHub token validation."""

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_active_token(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        result = _validate_github_token("ghp_faketoken12345678901234567890123456", 3.0)
        assert result.status == ValidationStatus.VERIFIED
        assert result.response_code == 200
        mock_get.assert_called_once()

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_revoked_token(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        result = _validate_github_token("ghp_revokedtoken123456789012345678901", 3.0)
        assert result.status == ValidationStatus.INACTIVE
        assert result.response_code == 401

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_network_error(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError("Connection refused")
        result = _validate_github_token("ghp_faketoken12345678901234567890123456", 3.0)
        assert result.status == ValidationStatus.UNVERIFIED
        assert "Network error" in result.message


class TestOpenAIKeyValidator:
    """Test OpenAI API key validation."""

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_active_key(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        result = _validate_openai_key("sk-fakeopenaikey12345678901234567890", 3.0)
        assert result.status == ValidationStatus.VERIFIED

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_revoked_key(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        result = _validate_openai_key("sk-fakeopenaikey12345678901234567890", 3.0)
        assert result.status == ValidationStatus.INACTIVE


class TestAnthropicKeyValidator:
    """Test Anthropic API key validation."""

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_active_key(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        result = _validate_anthropic_key(
            "sk-ant-fakeanth12345678901234567890123456789", 3.0
        )
        assert result.status == ValidationStatus.VERIFIED

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_revoked_key(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        result = _validate_anthropic_key(
            "sk-ant-fakeanth12345678901234567890123456789", 3.0
        )
        assert result.status == ValidationStatus.INACTIVE


class TestSlackTokenValidator:
    """Test Slack token validation."""

    @patch("ai_guardian.scanners.secret_validator.requests.post")
    def test_active_token(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"ok": True}),
        )
        result = _validate_slack_token("xoxb-fakeslacktoken-1234567890", 3.0)
        assert result.status == ValidationStatus.VERIFIED

    @patch("ai_guardian.scanners.secret_validator.requests.post")
    def test_invalid_token(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"ok": False, "error": "invalid_auth"}),
        )
        result = _validate_slack_token("xoxb-fakeslacktoken-1234567890", 3.0)
        assert result.status == ValidationStatus.INACTIVE


class TestGitLabTokenValidator:
    """Test GitLab token validation."""

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_active_token(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        result = _validate_gitlab_token(
            "glpat-fakegitlabtoken123456789", 3.0
        )  # notsecret
        assert result.status == ValidationStatus.VERIFIED

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_revoked_token(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        result = _validate_gitlab_token(
            "glpat-fakegitlabtoken123456789", 3.0
        )  # notsecret
        assert result.status == ValidationStatus.INACTIVE


class TestNpmTokenValidator:
    """Test npm token validation."""

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_active_token(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        result = _validate_npm_token("npm_fakenmptokenvalue1234567890abcdefgh", 3.0)
        assert result.status == ValidationStatus.VERIFIED

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_revoked_token(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        result = _validate_npm_token("npm_fakenmptokenvalue1234567890abcdefgh", 3.0)
        assert result.status == ValidationStatus.INACTIVE


class TestCustomValidator:
    """Test custom validator configuration and execution."""

    def test_parse_custom_validator_success(self):
        rule = {
            "id": "internal-api-key",
            "regex": r"INTERNAL_KEY=([a-zA-Z0-9]{32})",
            "live_validation": {
                "url": "https://internal.corp.com/verify",
                "auth": "bearer",
                "expect": 200,
            },
        }
        result = parse_custom_validator(rule)
        assert result is not None
        rule_id, validator_fn = result
        assert rule_id == "internal-api-key"
        assert callable(validator_fn)

    def test_parse_custom_validator_no_config(self):
        rule = {
            "id": "generic-secret",
            "regex": r"SECRET=([a-zA-Z0-9]+)",
        }
        result = parse_custom_validator(rule)
        assert result is None

    def test_parse_custom_validator_no_url(self):
        rule = {
            "id": "bad-config",
            "live_validation": {"auth": "bearer"},
        }
        result = parse_custom_validator(rule)
        assert result is None

    @patch("ai_guardian.scanners.secret_validator.requests.request")
    def test_custom_validator_active(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        config = CustomValidatorConfig(
            url="https://internal.corp.com/verify",
            auth="bearer",
            expect=200,
        )
        validator = _build_custom_validator(config)
        result = validator("fakesecret123", 3.0)
        assert result.status == ValidationStatus.VERIFIED

    @patch("ai_guardian.scanners.secret_validator.requests.request")
    def test_custom_validator_inactive(self, mock_request):
        mock_request.return_value = MagicMock(status_code=401)
        config = CustomValidatorConfig(
            url="https://internal.corp.com/verify",
            auth="bearer",
            expect=200,
        )
        validator = _build_custom_validator(config)
        result = validator("revoked123", 3.0)
        assert result.status == ValidationStatus.INACTIVE

    @patch("ai_guardian.scanners.secret_validator.requests.request")
    def test_custom_validator_header_auth(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        config = CustomValidatorConfig(
            url="https://internal.corp.com/verify",
            auth="header",
            header_name="X-API-Key",
            expect=200,
        )
        validator = _build_custom_validator(config)
        result = validator("myapikey", 3.0)
        assert result.status == ValidationStatus.VERIFIED
        call_kwargs = mock_request.call_args
        assert call_kwargs[1]["headers"]["X-API-Key"] == "myapikey"


class TestSecretValidator:
    """Test the main SecretValidator orchestrator."""

    def test_disabled_by_default(self):
        validator = SecretValidator()
        assert not validator.enabled

    def test_enabled_via_config(self):
        validator = SecretValidator(config={"validate_secrets": True})
        assert validator.enabled

    def test_timeout_default(self):
        validator = SecretValidator()
        assert validator.timeout_seconds == 3.0

    def test_timeout_custom(self):
        validator = SecretValidator(config={"validation_timeout_ms": 5000})
        assert validator.timeout_seconds == 5.0

    def test_on_inactive_default(self):
        validator = SecretValidator()
        assert validator.on_inactive == "warn"

    def test_on_inactive_custom(self):
        validator = SecretValidator(config={"on_inactive": "allow"})
        assert validator.on_inactive == "allow"

    def test_has_validator_builtin(self):
        validator = SecretValidator(config={"validate_secrets": True})
        assert validator.has_validator("github-personal-token")
        assert validator.has_validator("openai-api-key")
        assert not validator.has_validator("aws-access-key")

    def test_has_validator_custom(self):
        rules = [
            {
                "id": "my-custom-key",
                "live_validation": {"url": "https://example.com/verify"},
            }
        ]
        validator = SecretValidator(
            config={"validate_secrets": True},
            custom_rules=rules,
        )
        assert validator.has_validator("my-custom-key")
        assert validator.has_validator("github-personal-token")  # Built-in still works

    def test_validate_secret_disabled(self):
        validator = SecretValidator(config={"validate_secrets": False})
        result = validator.validate_secret("github-personal-token", "ghp_fake")
        assert result.status == ValidationStatus.UNVERIFIED
        assert "disabled" in result.message.lower()

    def test_validate_secret_no_validator(self):
        validator = SecretValidator(config={"validate_secrets": True})
        result = validator.validate_secret(
            "aws-access-key", "AKIAIOSFODNN7EXAMPLE"
        )  # notsecret
        assert result.status == ValidationStatus.UNVERIFIED
        assert "No validator" in result.message

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_validate_secret_verified(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        validator = SecretValidator(config={"validate_secrets": True})
        result = validator.validate_secret(
            "github-personal-token",
            "ghp_faketoken12345678901234567890123456",
        )
        assert result.status == ValidationStatus.VERIFIED
        assert result.elapsed_ms >= 0

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_validate_secret_inactive(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        validator = SecretValidator(config={"validate_secrets": True})
        result = validator.validate_secret(
            "github-personal-token",
            "ghp_revokedtoken123456789012345678901",
        )
        assert result.status == ValidationStatus.INACTIVE


class TestSecretValidatorBatch:
    """Test batch validation of multiple secrets."""

    def test_validate_secrets_disabled(self):
        validator = SecretValidator(config={"validate_secrets": False})
        secrets = [
            {"rule_id": "github-personal-token", "line_number": 1},
            {"rule_id": "openai-api-key", "line_number": 2},
        ]
        results = validator.validate_secrets(secrets, "line1\nline2")
        assert len(results) == 2
        assert all(r.status == ValidationStatus.UNVERIFIED for r in results)

    def test_validate_secrets_no_validators(self):
        validator = SecretValidator(config={"validate_secrets": True})
        secrets = [
            {"rule_id": "aws-access-key", "line_number": 1},
            {"rule_id": "hex-secret", "line_number": 2},
        ]
        results = validator.validate_secrets(secrets, "line1\nline2")
        assert len(results) == 2
        assert all(r.status == ValidationStatus.UNVERIFIED for r in results)

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_validate_secrets_mixed(self, mock_get):
        """Test batch with some validatable and some not."""
        mock_get.return_value = MagicMock(status_code=401)
        validator = SecretValidator(config={"validate_secrets": True})
        secrets = [
            {
                "rule_id": "github-personal-token",
                "line_number": 1,
                "secret": "ghp_fake123",
            },  # notsecret
            {"rule_id": "aws-access-key", "line_number": 2},
        ]
        results = validator.validate_secrets(
            secrets, "ghp_fake123\nAKIA1234"
        )  # notsecret
        assert len(results) == 2
        assert results[0].status == ValidationStatus.INACTIVE  # GitHub validated
        assert results[1].status == ValidationStatus.UNVERIFIED  # AWS no validator


class TestFilterInactive:
    """Test the filter_inactive method."""

    def test_all_active(self):
        validator = SecretValidator(config={"validate_secrets": True})
        secrets = [
            {"rule_id": "github-personal-token", "line_number": 1},
            {"rule_id": "openai-api-key", "line_number": 2},
        ]
        results = [
            ValidationResult(
                status=ValidationStatus.VERIFIED, rule_id="github-personal-token"
            ),
            ValidationResult(
                status=ValidationStatus.VERIFIED, rule_id="openai-api-key"
            ),
        ]
        active, inactive = validator.filter_inactive(secrets, results)
        assert len(active) == 2
        assert len(inactive) == 0

    def test_all_inactive(self):
        validator = SecretValidator(config={"validate_secrets": True})
        secrets = [
            {"rule_id": "github-personal-token", "line_number": 1},
            {"rule_id": "openai-api-key", "line_number": 2},
        ]
        results = [
            ValidationResult(
                status=ValidationStatus.INACTIVE, rule_id="github-personal-token"
            ),
            ValidationResult(
                status=ValidationStatus.INACTIVE, rule_id="openai-api-key"
            ),
        ]
        active, inactive = validator.filter_inactive(secrets, results)
        assert len(active) == 0
        assert len(inactive) == 2

    def test_mixed_active_and_inactive(self):
        validator = SecretValidator(config={"validate_secrets": True})
        secrets = [
            {"rule_id": "github-personal-token", "line_number": 1},
            {"rule_id": "openai-api-key", "line_number": 2},
        ]
        results = [
            ValidationResult(
                status=ValidationStatus.VERIFIED, rule_id="github-personal-token"
            ),
            ValidationResult(
                status=ValidationStatus.INACTIVE, rule_id="openai-api-key"
            ),
        ]
        active, inactive = validator.filter_inactive(secrets, results)
        assert len(active) == 1
        assert len(inactive) == 1
        assert active[0]["rule_id"] == "github-personal-token"
        assert inactive[0]["rule_id"] == "openai-api-key"

    def test_unverified_treated_as_active(self):
        validator = SecretValidator(config={"validate_secrets": True})
        secrets = [{"rule_id": "unknown", "line_number": 1}]
        results = [
            ValidationResult(status=ValidationStatus.UNVERIFIED, rule_id="unknown"),
        ]
        active, inactive = validator.filter_inactive(secrets, results)
        assert len(active) == 1
        assert len(inactive) == 0


class TestApplySecretValidation:
    """Test the _apply_secret_validation helper in hook_processing."""

    def test_disabled_returns_none(self):
        from ai_guardian.scanners.secret_scanning import _apply_secret_validation

        result = _apply_secret_validation(
            {"validate_secrets": False},
            [{"rule_id": "github-personal-token", "line_number": 1}],
            "ghp_fake123",
        )
        assert result is None

    def test_no_config_returns_none(self):
        from ai_guardian.scanners.secret_scanning import _apply_secret_validation

        result = _apply_secret_validation(None, [], "")
        assert result is None

    def test_no_secrets_returns_none(self):
        from ai_guardian.scanners.secret_scanning import _apply_secret_validation

        result = _apply_secret_validation(
            {"validate_secrets": True},
            [],
            "",
        )
        assert result is None

    def test_no_validators_returns_unverified(self):
        from ai_guardian.scanners.secret_scanning import _apply_secret_validation

        result = _apply_secret_validation(
            {"validate_secrets": True},
            [{"rule_id": "aws-access-key", "line_number": 1}],
            "AKIA1234567890123456",  # notsecret
        )
        assert result is not None
        assert result["skip_block"] is False
        assert result["validation_info"]["status"] == "unverified"

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_all_inactive_returns_skip_block(self, mock_get):
        from ai_guardian.scanners.secret_scanning import _apply_secret_validation

        mock_get.return_value = MagicMock(status_code=401)
        result = _apply_secret_validation(
            {"validate_secrets": True, "on_inactive": "warn"},
            [
                {
                    "rule_id": "github-personal-token",
                    "line_number": 1,
                    "secret": "ghp_revoked",
                }
            ],  # notsecret
            "ghp_revoked",
        )
        assert result is not None
        assert result["skip_block"] is True
        assert result["validation_info"]["status"] == "inactive"

    @patch("ai_guardian.scanners.secret_validator.requests.get")
    def test_active_secret_returns_no_skip(self, mock_get):
        from ai_guardian.scanners.secret_scanning import _apply_secret_validation

        mock_get.return_value = MagicMock(status_code=200)
        result = _apply_secret_validation(
            {"validate_secrets": True},
            [
                {
                    "rule_id": "github-personal-token",
                    "line_number": 1,
                    "secret": "ghp_active",
                }
            ],  # notsecret
            "ghp_active",
        )
        assert result is not None
        assert result["skip_block"] is False
        assert result["validation_info"]["status"] == "verified"


class TestSecretMatchValidationStatus:
    """Test the validation_status field on SecretMatch."""

    def test_default_is_unverified(self):
        from ai_guardian.scanners.strategies import SecretMatch

        match = SecretMatch(
            rule_id="test",
            description="test secret",
            file="test.py",
            line_number=1,
        )
        assert match.validation_status == "unverified"

    def test_can_set_verified(self):
        from ai_guardian.scanners.strategies import SecretMatch

        match = SecretMatch(
            rule_id="test",
            description="test secret",
            file="test.py",
            line_number=1,
            validation_status="verified",
        )
        assert match.validation_status == "verified"

    def test_can_set_inactive(self):
        from ai_guardian.scanners.strategies import SecretMatch

        match = SecretMatch(
            rule_id="test",
            description="test secret",
            file="test.py",
            line_number=1,
            validation_status="inactive",
        )
        assert match.validation_status == "inactive"
