"""Tests for TomlPatternsScanner — Scanner SDK engine."""

import pytest

from ai_guardian.patterns.validators import shannon_entropy
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


class TestTomlPatternsAllowlist:
    """Tests for scanner-level allowlist filtering (Issue #1093)."""

    def test_configure_allowlist_suppresses_matching_finding(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"allowlist_patterns": ["sk-abcdefghijklmnopqrstuvwxyz"]})
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert not any(f.rule_id == "openai-api-key" for f in findings)

    def test_allowlist_does_not_suppress_nonmatching(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"allowlist_patterns": ["some-other-pattern"]})
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_allowlist_empty_list_no_effect(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"allowlist_patterns": []})
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_allowlist_none_no_effect(self):
        scanner = TomlPatternsScanner()
        scanner.configure({})
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_allowlist_dangerous_pattern_blocked(self):
        """compile_allowlist strips catch-all patterns like '.*'."""
        scanner = TomlPatternsScanner()
        scanner.configure({"allowlist_patterns": [".*"]})
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(f.rule_id == "openai-api-key" for f in findings)


class TestTomlPatternsIgnoreFiles:
    """Tests for scanner-level ignore_files filtering (Issue #1093)."""

    def test_ignore_files_matching_path_returns_empty(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"ignore_files": ["**/tests/fixtures/**"]})
        findings = scanner.scan(
            "Config: sk-abcdefghijklmnopqrstuvwxyz",
            file_path="/project/tests/fixtures/creds.json",
        )
        assert findings == []

    def test_ignore_files_nonmatching_path_scans_normally(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"ignore_files": ["**/tests/fixtures/**"]})
        findings = scanner.scan(
            "Config: sk-abcdefghijklmnopqrstuvwxyz",
            file_path="/project/src/main.py",
        )
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_ignore_files_none_file_path_scans_normally(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"ignore_files": ["**/tests/**"]})
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_ignore_files_empty_list_scans_normally(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"ignore_files": []})
        findings = scanner.scan(
            "Config: sk-abcdefghijklmnopqrstuvwxyz",
            file_path="/project/src/main.py",
        )
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_ignore_files_basename_matching(self):
        scanner = TomlPatternsScanner()
        scanner.configure({"ignore_files": ["*.fixture"]})
        findings = scanner.scan(
            "Config: sk-abcdefghijklmnopqrstuvwxyz",
            file_path="/project/data/creds.fixture",
        )
        assert findings == []


class TestTomlPatternsAllowlistAndIgnoreInteraction:
    """Test interaction between allowlist and ignore_files (Issue #1093)."""

    def test_ignore_files_takes_precedence(self):
        """Ignored file returns [] without even checking allowlist."""
        scanner = TomlPatternsScanner()
        scanner.configure({
            "allowlist_patterns": ["some-pattern"],
            "ignore_files": ["**/fixtures/**"],
        })
        findings = scanner.scan(
            "Config: sk-abcdefghijklmnopqrstuvwxyz",
            file_path="/project/fixtures/test.json",
        )
        assert findings == []

    def test_allowlist_filters_when_not_ignored(self):
        scanner = TomlPatternsScanner()
        scanner.configure({
            "allowlist_patterns": ["sk-abcdefghijklmnopqrstuvwxyz"],
            "ignore_files": ["**/fixtures/**"],
        })
        findings = scanner.scan(
            "Config: sk-abcdefghijklmnopqrstuvwxyz",
            file_path="/project/src/main.py",
        )
        assert not any(f.rule_id == "openai-api-key" for f in findings)


class TestShannonEntropy:
    """Tests for the shannon_entropy utility (Issue #1091)."""

    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert shannon_entropy("a") == 0.0

    def test_repeated_chars_returns_zero(self):
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_two_distinct_chars_equal_frequency(self):
        result = shannon_entropy("abababab")
        assert abs(result - 1.0) < 0.01

    def test_random_alphanum_high_entropy(self):
        result = shannon_entropy("aB3kQ9xLm7Zy2pR4wE6t")
        assert result > 3.5

    def test_low_entropy_placeholder(self):
        result = shannon_entropy("XXXXXXXXXXXXXXXXXXXX")
        assert result == 0.0

    def test_moderate_entropy_string(self):
        result = shannon_entropy("password123")
        assert 2.0 < result < 4.0


class TestTomlPatternsKeywordPreFilter:
    """Tests for keyword pre-filtering in PatternCache (Issue #1091)."""

    def test_keyword_present_allows_match(self):
        """Rule with keywords fires when keyword is in content."""
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-keyword-rule",
            "match_type": "regex",
            "regex": r"sk-[a-z]{20,}",
            "keywords": ["sk-"],
        }], category="secrets")
        findings = cache.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert len(findings) >= 1

    def test_keyword_absent_skips_rule(self):
        """Rule with keywords does NOT fire when keyword is missing."""
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-keyword-rule",
            "match_type": "regex",
            "regex": r"sk-[a-z]{20,}",
            "keywords": ["sk-"],
        }], category="secrets")
        findings = cache.scan("This text has no relevant prefix")
        assert len(findings) == 0

    def test_keyword_case_insensitive(self):
        """Keyword matching is case-insensitive."""
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-keyword-rule",
            "match_type": "regex",
            "regex": r"(?i)token-[a-z0-9]{10,}",
            "keywords": ["TOKEN-"],
        }], category="secrets")
        findings = cache.scan("value: token-abc1234567890")
        assert len(findings) >= 1

    def test_no_keywords_fires_on_all_content(self):
        """Rules without keywords field fire on any matching content."""
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-no-keyword-rule",
            "match_type": "regex",
            "regex": r"secret-[a-z]{10,}",
        }], category="secrets")
        findings = cache.scan("found: secret-abcdefghijklmnop")
        assert len(findings) >= 1


class TestTomlPatternsEntropyFilter:
    """Tests for per-rule entropy filtering (Issue #1091)."""

    def test_high_entropy_match_passes(self):
        """Match with entropy above threshold is kept."""
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-entropy-rule",
            "match_type": "regex",
            "regex": r"key-[A-Za-z0-9]{20,}",
            "entropy": 3.0,
        }], category="secrets")
        findings = cache.scan("value: key-aB3kQ9xLm7Zy2pR4wE6tX")
        assert len(findings) >= 1

    def test_low_entropy_match_rejected(self):
        """Match with entropy below threshold is filtered out."""
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-entropy-rule",
            "match_type": "regex",
            "regex": r"key-[A-Za-z]{20,}",
            "entropy": 3.0,
        }], category="secrets")
        findings = cache.scan("value: key-aaaaaaaaaaaaaaaaaaaaaaa")
        assert len(findings) == 0

    def test_no_entropy_field_passes_all(self):
        """Rules without entropy field accept all matches."""
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-no-entropy",
            "match_type": "regex",
            "regex": r"key-[A-Za-z]{20,}",
        }], category="secrets")
        findings = cache.scan("value: key-aaaaaaaaaaaaaaaaaaaaaaa")
        assert len(findings) >= 1


class TestTomlPatternsStopwords:
    """Tests for stopword filtering (Issue #1091)."""

    def test_bundled_stopwords_loaded(self):
        scanner = TomlPatternsScanner()
        assert len(scanner._stopwords) > 0

    def test_stopword_suppresses_matching_finding(self):
        """A match containing a stopword is filtered out."""
        scanner = TomlPatternsScanner()
        assert "example" in scanner._stopwords
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-stop",
            "match_type": "regex",
            "regex": r"key-[a-z_]+",
        }], category="secrets")
        scanner._cache = cache
        findings = scanner.scan("value: key-example_value")
        assert not any(f.rule_id == "test-stop" for f in findings)

    def test_stopword_does_not_suppress_non_matching(self):
        """A match NOT containing a stopword is kept."""
        scanner = TomlPatternsScanner()
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-stop",
            "match_type": "regex",
            "regex": r"key-[a-z]{20,}",
        }], category="secrets")
        scanner._cache = cache
        findings = scanner.scan("value: key-abcdefghijklmnopqrstuvwxyz")
        assert any(f.rule_id == "test-stop" for f in findings)

    def test_user_stopwords_extend_bundled(self):
        scanner = TomlPatternsScanner()
        initial_count = len(scanner._stopwords)
        scanner.configure({"stopwords": ["mycompanystopword"]})
        assert len(scanner._stopwords) == initial_count + 1
        assert "mycompanystopword" in scanner._stopwords

    def test_short_stopwords_rejected(self):
        scanner = TomlPatternsScanner()
        initial_count = len(scanner._stopwords)
        scanner.configure({"stopwords": ["ab"]})
        assert len(scanner._stopwords) == initial_count

    def test_duplicate_stopwords_not_added(self):
        scanner = TomlPatternsScanner()
        initial_count = len(scanner._stopwords)
        scanner.configure({"stopwords": ["example"]})
        assert len(scanner._stopwords) == initial_count

    def test_stopwords_only_filter_secrets_not_pii(self):
        """Stopwords should NOT filter PII findings."""
        scanner = TomlPatternsScanner()
        scanner.configure({"pii_types": ["email"]})
        findings = scanner.scan("Contact: test@example.com")
        assert any(f.rule_id == "pii-email" for f in findings)
