"""Tests for TomlPatternsScanner — Scanner SDK engine."""

import pytest

from ai_guardian.scanners.sdk import Scanner, Finding
from ai_guardian.scanners.toml_patterns import TomlPatternsScanner


class TestTomlPatternsScanner:

    def test_is_scanner_subclass(self):
        scanner = TomlPatternsScanner()
        assert isinstance(scanner, Scanner)

    def test_name_and_version(self):
        scanner = TomlPatternsScanner()
        assert scanner.name == "toml-patterns"
        assert scanner.version == "1.0.0"

    def test_scan_finds_api_key(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert len(findings) >= 1
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_scan_returns_finding_objects(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789")  # notsecret
        for f in findings:
            assert isinstance(f, Finding)
            assert f.rule_id
            assert f.line_number >= 1
            assert f.matched_text
            assert f.severity == "warning"

    def test_scan_no_match(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Nothing sensitive here at all.")
        secret_findings = [f for f in findings if f.rule_id.startswith("openai") or f.rule_id.startswith("github")]
        assert len(secret_findings) == 0

    def test_scan_empty_content(self):
        scanner = TomlPatternsScanner()
        assert scanner.scan("") == []

    def test_has_rules_loaded(self):
        scanner = TomlPatternsScanner()
        assert scanner._cache.rule_count > 0

    def test_configure_additional_patterns(self):
        scanner = TomlPatternsScanner()
        initial_count = scanner._cache.rule_count
        scanner.configure({
            "additional_patterns": [
                {"id": "custom-1", "match_type": "regex", "regex": "custom-secret-[0-9]+"}
            ]
        })
        assert scanner._cache.rule_count == initial_count + 1


class TestTomlPatternsPiiFiltering:

    def test_scan_filters_pii_by_configured_types(self):
        """Email excluded from pii_types should not appear in findings."""
        scanner = TomlPatternsScanner()
        scanner.configure({"pii_types": ["ssn"]})
        findings = scanner.scan("Contact: user@example.com")
        assert not any(f.rule_id == "pii-email" for f in findings)

    def test_scan_includes_pii_when_in_configured_types(self):
        """Email included in pii_types should appear in findings."""
        scanner = TomlPatternsScanner()
        scanner.configure({"pii_types": ["email"]})
        findings = scanner.scan("Contact: user@example.com")
        assert any(f.rule_id == "pii-email" for f in findings)

    def test_scan_without_pii_types_config_includes_all(self):
        """Without configure(), all PII types should be returned."""
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Contact: user@example.com")
        assert any(f.rule_id == "pii-email" for f in findings)

    def test_scan_secrets_not_filtered_by_pii_types(self):
        """Secret findings must never be filtered by pii_types."""
        scanner = TomlPatternsScanner()
        scanner.configure({"pii_types": []})
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_default_pii_types_exclude_email(self):
        """Default pii_types from config_loaders excludes email."""
        from ai_guardian.config_loaders import _PII_DEFAULTS
        scanner = TomlPatternsScanner()
        scanner.configure({"pii_types": _PII_DEFAULTS["pii_types"]})
        findings = scanner.scan("Contact: user@example.com")
        assert not any(f.rule_id == "pii-email" for f in findings)


class TestTomlPatternsFindingCategory:
    """Tests for category propagation through Finding objects (Issue #984)."""

    def test_secret_finding_has_secrets_category(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        secret_findings = [f for f in findings if f.rule_id == "openai-api-key"]
        assert len(secret_findings) >= 1
        assert secret_findings[0].category == "secrets"

    def test_pii_finding_has_pii_category(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("SSN: 123-45-6789")
        pii_findings = [f for f in findings if f.rule_id == "pii-ssn"]
        assert len(pii_findings) >= 1
        assert pii_findings[0].category == "pii"

    def test_email_finding_has_pii_category(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"pii_types": ["email"]})
        findings = scanner.scan("Contact: user@example.com")
        email_findings = [f for f in findings if f.rule_id == "pii-email"]
        assert len(email_findings) >= 1
        assert email_findings[0].category == "pii"

    def test_finding_category_field_exists(self):
        """Finding dataclass has category attribute."""
        f = Finding(
            rule_id="test",
            line_number=1,
            matched_text="test",
            description="test",
            category="pii",
        )
        assert f.category == "pii"

    def test_finding_category_defaults_to_none(self):
        f = Finding(
            rule_id="test",
            line_number=1,
            matched_text="test",
            description="test",
        )
        assert f.category is None


class TestTomlPatternsGapFillingRules:
    """Tests for platform-specific gap-filling rules (Issue #972).

    These rules cover platforms NOT detected by gitleaks/leaktk engines.
    """

    def _find(self, text, rule_id):
        scanner = TomlPatternsScanner()
        findings = scanner.scan(text)
        return any(f.rule_id == rule_id for f in findings)

    # --- Payment / Financial ---

    def test_square_oauth_secret_detected(self):
        token = "sq0csp-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG"
        assert self._find(f"SECRET={token}", "square-oauth-secret")

    def test_square_oauth_secret_placeholder_skipped(self):
        token = "sq0csp-" + "X" * 43
        assert not self._find(f"SECRET={token}", "square-oauth-secret")

    def test_square_access_token_not_matched_as_oauth_secret(self):
        # sq0atp- is an access token (covered by gitleaks), not our rule
        token = "sq0atp-" + "A" * 43
        assert not self._find(f"TOKEN={token}", "square-oauth-secret")

    def test_paypal_braintree_production_token(self):
        text = "token=access_token$production$abc123def456abcd"
        assert self._find(text, "paypal-braintree-token")

    def test_paypal_braintree_sandbox_token(self):
        text = "token=access_token$sandbox$abc123def456abcdef01"
        assert self._find(text, "paypal-braintree-token")

    def test_paypal_braintree_short_value_not_matched(self):
        # Value after $production$ must be >= 16 chars
        text = "token=access_token$production$short"
        assert not self._find(text, "paypal-braintree-token")

    def test_paypal_client_secret_env_var(self):
        text = "PAYPAL_CLIENT_SECRET=AbCdEfGhIjKlMnOpQrStUvWx"
        assert self._find(text, "paypal-client-secret")

    def test_paypal_secret_case_insensitive(self):
        text = "paypal_secret = 'AbCdEfGhIjKlMnOpQrStUvWx'"
        assert self._find(text, "paypal-client-secret")

    def test_generic_secret_not_matched_as_paypal(self):
        text = "MY_SECRET=AbCdEfGhIjKlMnOpQrStUvWx"
        assert not self._find(text, "paypal-client-secret")

    # --- CI/CD ---

    def test_circleci_token_detected(self):
        text = "CIRCLE_TOKEN=" + "a1b2c3d4" * 5  # 40 hex chars
        assert self._find(text, "circleci-api-token")

    def test_circleci_ci_token_detected(self):
        text = "CIRCLECI_API_TOKEN=" + "abcdef01" * 5  # 40 hex chars
        assert self._find(text, "circleci-api-token")

    def test_circleci_non_hex_not_matched(self):
        text = "CIRCLE_TOKEN=not_a_real_hex_token_value_here"
        assert not self._find(text, "circleci-api-token")

    def test_jenkins_token_detected(self):
        text = "JENKINS_API_TOKEN=" + "a1b2c3d4" * 4 + "ab"  # 34 hex chars
        assert self._find(text, "jenkins-api-token")

    def test_jenkins_token_case_insensitive(self):
        text = "jenkins_token: " + "abcdef01" * 4  # 32 hex chars
        assert self._find(text, "jenkins-api-token")

    def test_jenkins_non_hex_not_matched(self):
        text = "JENKINS_TOKEN=not-hex-characters-here!"
        assert not self._find(text, "jenkins-api-token")

    # --- Database ---

    def test_mongodb_atlas_api_key_detected(self):
        text = "MONGODB_ATLAS_PRIVATE_KEY=abcd1234-ab12-cd34-ef56-abcdef123456"
        assert self._find(text, "mongodb-atlas-api-key")

    def test_mongo_atlas_key_variant(self):
        text = "MONGO_ATLAS_KEY: abcd1234-ab12-cd34-ef56-abcdef123456"
        assert self._find(text, "mongodb-atlas-api-key")

    def test_generic_uuid_without_atlas_context_not_matched(self):
        text = "REQUEST_ID=abcd1234-ab12-cd34-ef56-abcdef123456"
        assert not self._find(text, "mongodb-atlas-api-key")

    def test_supabase_service_role_key_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.M2d_0djnGBiRw1rXznITPA"
        text = f"SUPABASE_SERVICE_ROLE_KEY={jwt}"
        assert self._find(text, "supabase-service-role-key")

    def test_supabase_anon_key_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.ZopqoUt20nEV9cklpv9e3yw3PVyZLmKs5qLD6nGL1SI"
        text = f"SUPABASE_ANON_KEY={jwt}"
        assert self._find(text, "supabase-service-role-key")

    def test_generic_jwt_without_supabase_context_not_matched(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.ZopqoUt20nEV9cklpv9e3yw3PVyZLmKs5qLD6nGL1SI"
        text = f"AUTH_TOKEN={jwt}"
        assert not self._find(text, "supabase-service-role-key")

    # --- AI/ML ---

    def test_replicate_api_token_detected(self):
        token = "r8_" + "aBcDeFgHiJ" * 4  # 40 alphanumeric chars
        assert self._find(f"TOKEN={token}", "replicate-api-token")

    def test_replicate_placeholder_rejected(self):
        token = "r8_" + "X" * 40
        assert not self._find(f"TOKEN={token}", "replicate-api-token")

    def test_short_r8_prefix_not_matched(self):
        # r8_ followed by < 40 chars should not match
        text = "r8_shortvalue"
        assert not self._find(text, "replicate-api-token")


class TestTomlPatternsEngineBuilder:

    def test_select_toml_patterns_engine(self):
        from ai_guardian.scanners.engine_builder import _build_engine_config
        config = _build_engine_config("toml-patterns")
        assert config is not None
        assert config.type == "python"
        assert config.python_scanner is not None
        assert config.python_scanner.name == "toml-patterns"

    def test_select_toml_patterns_as_dict(self):
        from ai_guardian.scanners.engine_builder import _build_engine_config
        config = _build_engine_config({"type": "toml-patterns"})
        assert config is not None
        assert config.python_scanner.name == "toml-patterns"

    def test_select_engine_with_toml_patterns(self):
        from ai_guardian.scanners.engine_builder import select_engine
        config = select_engine(["toml-patterns"])
        assert config is not None
        assert config.python_scanner.name == "toml-patterns"
