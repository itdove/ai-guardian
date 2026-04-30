"""Tests for scanner execution strategies."""

import unittest
from ai_guardian.scanners.strategies import (
    FirstMatchStrategy,
    AnyMatchStrategy,
    ConsensusStrategy,
    SecretMatch,
    ScanResult,
    get_strategy,
    EXECUTION_STRATEGIES
)


class TestSecretMatch(unittest.TestCase):
    """Test SecretMatch dataclass."""

    def test_create_basic_match(self):
        """Test creating a basic secret match."""
        match = SecretMatch(
            rule_id="aws-key",
            description="AWS Access Key",
            file="test.txt",
            line_number=5
        )

        self.assertEqual(match.rule_id, "aws-key")
        self.assertEqual(match.description, "AWS Access Key")
        self.assertEqual(match.file, "test.txt")
        self.assertEqual(match.line_number, 5)
        self.assertIsNone(match.end_line)
        self.assertIsNone(match.commit)
        self.assertEqual(match.engine, "")
        self.assertEqual(match.confidence, 1.0)
        self.assertFalse(match.verified)

    def test_create_match_with_optional_fields(self):
        """Test creating a match with all optional fields."""
        match = SecretMatch(
            rule_id="github-token",
            description="GitHub Token",
            file="config.py",
            line_number=10,
            end_line=12,
            commit="abc123",
            secret="ghp_redacted",
            engine="trufflehog",
            confidence=0.9,
            verified=True
        )

        self.assertEqual(match.end_line, 12)
        self.assertEqual(match.commit, "abc123")
        self.assertEqual(match.secret, "ghp_redacted")
        self.assertEqual(match.engine, "trufflehog")
        self.assertEqual(match.confidence, 0.9)
        self.assertTrue(match.verified)


class TestScanResult(unittest.TestCase):
    """Test ScanResult dataclass."""

    def test_create_clean_result(self):
        """Test creating a scan result with no secrets."""
        result = ScanResult(
            has_secrets=False,
            secrets=[],
            engine="gitleaks"
        )

        self.assertFalse(result.has_secrets)
        self.assertEqual(len(result.secrets), 0)
        self.assertEqual(result.engine, "gitleaks")
        self.assertIsNone(result.error)
        self.assertEqual(result.scan_time_ms, 0.0)

    def test_create_result_with_secrets(self):
        """Test creating a scan result with secrets found."""
        match = SecretMatch(
            rule_id="aws-key",
            description="AWS Key",
            file="test.txt",
            line_number=5
        )

        result = ScanResult(
            has_secrets=True,
            secrets=[match],
            engine="trufflehog",
            scan_time_ms=125.5
        )

        self.assertTrue(result.has_secrets)
        self.assertEqual(len(result.secrets), 1)
        self.assertEqual(result.engine, "trufflehog")
        self.assertEqual(result.scan_time_ms, 125.5)


class TestAnyMatchStrategyDeduplication(unittest.TestCase):
    """Test AnyMatchStrategy deduplication logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.strategy = AnyMatchStrategy()

    def test_deduplicate_empty_list(self):
        """Test deduplicating empty list."""
        result = self.strategy._deduplicate([])
        self.assertEqual(len(result), 0)

    def test_deduplicate_single_secret(self):
        """Test deduplicating single secret."""
        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks"
            )
        ]

        result = self.strategy._deduplicate(secrets)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].engine, "gitleaks")

    def test_deduplicate_same_secret_different_engines(self):
        """Test deduplicating same secret found by multiple engines."""
        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks",
                confidence=1.0
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Access Key",
                file="test.txt",
                line_number=5,
                engine="trufflehog",
                confidence=0.9
            )
        ]

        result = self.strategy._deduplicate(secrets)

        # Should keep only one, with combined engine names
        self.assertEqual(len(result), 1)
        self.assertIn("gitleaks", result[0].engine)
        self.assertIn("trufflehog", result[0].engine)
        # Should keep the one with higher confidence
        self.assertEqual(result[0].confidence, 1.0)

    def test_deduplicate_prefers_verified(self):
        """Test that deduplication prefers verified secrets."""
        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks",
                confidence=1.0,
                verified=False
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key (verified)",
                file="test.txt",
                line_number=5,
                engine="trufflehog",
                confidence=0.8,
                verified=True
            )
        ]

        result = self.strategy._deduplicate(secrets)

        # Should prefer verified even if confidence is lower
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].verified)
        self.assertEqual(result[0].confidence, 0.8)

    def test_deduplicate_different_locations(self):
        """Test that secrets at different locations are not deduplicated."""
        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks"
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=10,  # Different line
                engine="gitleaks"
            )
        ]

        result = self.strategy._deduplicate(secrets)

        # Should keep both since they're at different lines
        self.assertEqual(len(result), 2)

    def test_deduplicate_different_files(self):
        """Test that secrets in different files are not deduplicated."""
        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test1.txt",
                line_number=5,
                engine="gitleaks"
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test2.txt",  # Different file
                line_number=5,
                engine="gitleaks"
            )
        ]

        result = self.strategy._deduplicate(secrets)

        # Should keep both since they're in different files
        self.assertEqual(len(result), 2)


class TestConsensusStrategyFindConsensus(unittest.TestCase):
    """Test ConsensusStrategy consensus finding logic."""

    def test_find_consensus_empty_list(self):
        """Test finding consensus in empty list."""
        strategy = ConsensusStrategy(threshold=2)
        result = strategy._find_consensus([])
        self.assertEqual(len(result), 0)

    def test_find_consensus_below_threshold(self):
        """Test that secrets below threshold are filtered out."""
        strategy = ConsensusStrategy(threshold=2)

        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks"
            )
            # Only one engine, threshold is 2
        ]

        result = strategy._find_consensus(secrets)
        self.assertEqual(len(result), 0)

    def test_find_consensus_meets_threshold(self):
        """Test that secrets meeting threshold are included."""
        strategy = ConsensusStrategy(threshold=2)

        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks",
                confidence=1.0
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Access Key",
                file="test.txt",
                line_number=5,
                engine="trufflehog",
                confidence=0.9
            )
        ]

        result = strategy._find_consensus(secrets)

        # Should include since 2 engines agree (meets threshold of 2)
        self.assertEqual(len(result), 1)
        self.assertIn("2 engines", result[0].engine)

    def test_find_consensus_exceeds_threshold(self):
        """Test that secrets exceeding threshold are included."""
        strategy = ConsensusStrategy(threshold=2)

        secrets = [
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks"
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="trufflehog"
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="detect-secrets"
            )
        ]

        result = strategy._find_consensus(secrets)

        # Should include since 3 engines agree (exceeds threshold of 2)
        self.assertEqual(len(result), 1)
        self.assertIn("3 engines", result[0].engine)

    def test_find_consensus_mixed_results(self):
        """Test consensus with mixed results."""
        strategy = ConsensusStrategy(threshold=2)

        secrets = [
            # Secret 1: 2 engines agree (should include)
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="gitleaks"
            ),
            SecretMatch(
                rule_id="aws-key",
                description="AWS Key",
                file="test.txt",
                line_number=5,
                engine="trufflehog"
            ),
            # Secret 2: only 1 engine (should exclude)
            SecretMatch(
                rule_id="github-token",
                description="GitHub Token",
                file="test.txt",
                line_number=10,
                engine="gitleaks"
            )
        ]

        result = strategy._find_consensus(secrets)

        # Should only include the first secret
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].line_number, 5)


class TestStrategyRegistry(unittest.TestCase):
    """Test strategy registry and factory."""

    def test_all_strategies_registered(self):
        """Test that all expected strategies are registered."""
        expected_strategies = {"first-match", "any-match", "consensus"}
        self.assertEqual(set(EXECUTION_STRATEGIES.keys()), expected_strategies)

    def test_get_first_match_strategy(self):
        """Test getting FirstMatchStrategy."""
        strategy = get_strategy("first-match")
        self.assertIsInstance(strategy, FirstMatchStrategy)

    def test_get_any_match_strategy(self):
        """Test getting AnyMatchStrategy."""
        strategy = get_strategy("any-match")
        self.assertIsInstance(strategy, AnyMatchStrategy)

    def test_get_consensus_strategy(self):
        """Test getting ConsensusStrategy with default threshold."""
        strategy = get_strategy("consensus")
        self.assertIsInstance(strategy, ConsensusStrategy)
        self.assertEqual(strategy.threshold, 2)

    def test_get_consensus_strategy_custom_threshold(self):
        """Test getting ConsensusStrategy with custom threshold."""
        strategy = get_strategy("consensus", threshold=3)
        self.assertIsInstance(strategy, ConsensusStrategy)
        self.assertEqual(strategy.threshold, 3)

    def test_get_unknown_strategy_raises_error(self):
        """Test that unknown strategy name raises ValueError."""
        with self.assertRaises(ValueError) as cm:
            get_strategy("unknown-strategy")

        self.assertIn("Unknown strategy", str(cm.exception))
        self.assertIn("unknown-strategy", str(cm.exception))


if __name__ == '__main__':
    unittest.main()
