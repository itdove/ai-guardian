"""
Tests for PII detection functionality (Issue #262).

Tests the SecretRedactor PII patterns, Luhn/IBAN validation,
and PII-specific redaction strategies.
"""

import time
import pytest
from ai_guardian.secret_redactor import SecretRedactor


PII_CONFIG = {
    'enabled': True,
    'pii_types': ['ssn', 'credit_card', 'phone', 'email', 'us_passport', 'iban', 'intl_phone'],
    'action': 'block',
}


class TestPIIDetection:
    """Test PII detection patterns."""

    def test_pii_disabled_by_default(self):
        """PII patterns are not loaded when no pii_config is provided."""
        redactor = SecretRedactor()
        text = "SSN: 123-45-6789"
        result = redactor.redact(text)
        assert result['redacted_text'] == text
        assert len(result['redactions']) == 0

    def test_pii_enabled_loads_patterns(self):
        """PII patterns are loaded when pii_config is provided and enabled."""
        redactor = SecretRedactor(pii_config=PII_CONFIG)
        assert len(redactor.compiled_patterns) > 0

    # --- SSN ---

    def test_ssn_detection(self):
        """Detect valid SSN format."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "My SSN is 123-45-6789"
        result = redactor.redact(text)
        assert "123-45-6789" not in result['redacted_text']
        assert "[HIDDEN SSN]" in result['redacted_text']
        assert len(result['redactions']) >= 1

    def test_ssn_invalid_area_000(self):
        """SSN with area number 000 should not be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Not a SSN: 000-12-3456"
        result = redactor.redact(text)
        assert "000-12-3456" in result['redacted_text']

    def test_ssn_invalid_area_666(self):
        """SSN with area number 666 should not be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Not a SSN: 666-12-3456"
        result = redactor.redact(text)
        assert "666-12-3456" in result['redacted_text']

    def test_ssn_invalid_area_9xx(self):
        """SSN with area number 900+ should not be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Not a SSN: 900-12-3456"
        result = redactor.redact(text)
        assert "900-12-3456" in result['redacted_text']

    def test_ssn_invalid_group_00(self):
        """SSN with group number 00 should not be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Not a SSN: 123-00-3456"
        result = redactor.redact(text)
        assert "123-00-3456" in result['redacted_text']

    def test_ssn_invalid_serial_0000(self):
        """SSN with serial number 0000 should not be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Not a SSN: 123-45-0000"
        result = redactor.redact(text)
        assert "123-45-0000" in result['redacted_text']

    # --- Credit Card ---

    def test_credit_card_visa_valid_luhn(self):
        """Detect valid Visa card number (passes Luhn)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        # 4532015112830366 passes Luhn
        text = "Card: 4532015112830366"
        result = redactor.redact(text)
        assert "4532015112830366" not in result['redacted_text']
        assert "****0366" in result['redacted_text']

    def test_credit_card_with_spaces(self):
        """Detect credit card with spaces."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        # 4532 0151 1283 0366 passes Luhn
        text = "Card: 4532 0151 1283 0366"
        result = redactor.redact(text)
        assert "4532 0151 1283 0366" not in result['redacted_text']

    def test_credit_card_with_dashes(self):
        """Detect credit card with dashes."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        # 4532-0151-1283-0366 passes Luhn
        text = "Card: 4532-0151-1283-0366"
        result = redactor.redact(text)
        assert "4532-0151-1283-0366" not in result['redacted_text']

    def test_credit_card_invalid_luhn(self):
        """Random 16-digit number failing Luhn should NOT be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Number: 1234567890123456"
        result = redactor.redact(text)
        # Should NOT be redacted (fails Luhn)
        assert "1234567890123456" in result['redacted_text']

    # --- Phone ---

    def test_phone_standard(self):
        """Detect standard US phone number."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Call me at 555-123-4567"
        result = redactor.redact(text)
        assert "555-123-4567" not in result['redacted_text']

    def test_phone_with_parens(self):
        """Detect phone with parentheses."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Phone: (555) 123-4567"
        result = redactor.redact(text)
        assert "(555) 123-4567" not in result['redacted_text']

    def test_phone_with_dots(self):
        """Detect phone with dots."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Phone: 555.123.4567"
        result = redactor.redact(text)
        assert "555.123.4567" not in result['redacted_text']

    def test_phone_with_plus1(self):
        """Detect phone with +1 prefix."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Phone: +1-555-123-4567"
        result = redactor.redact(text)
        assert "+1-555-123-4567" not in result['redacted_text']

    # --- Email ---

    def test_email_detection(self):
        """Detect standard email address."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Contact: john.doe@example.com for info"
        result = redactor.redact(text)
        assert "john.doe" not in result['redacted_text']
        assert "@example.com" in result['redacted_text']
        assert "[HIDDEN]@example.com" in result['redacted_text']

    def test_email_with_subdomain(self):
        """Detect email with subdomain."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Email: user@mail.company.co.uk"
        result = redactor.redact(text)
        assert "[HIDDEN]@mail.company.co.uk" in result['redacted_text']

    # --- US Passport ---

    def test_us_passport(self):
        """Detect US passport number (letter + 8 digits)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Passport: C12345678"
        result = redactor.redact(text)
        assert "C12345678" not in result['redacted_text']
        assert "[HIDDEN US PASSPORT NUMBER]" in result['redacted_text']

    # --- IBAN ---

    def test_iban_valid(self):
        """Detect valid IBAN (passes mod-97)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        # GB29NWBK60161331926819 is a valid IBAN
        text = "IBAN: GB29NWBK60161331926819"
        result = redactor.redact(text)
        assert "GB29NWBK60161331926819" not in result['redacted_text']
        assert "IBAN GB" in result['redacted_text']

    def test_iban_invalid(self):
        """Invalid IBAN should NOT be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Not IBAN: GB00XXXX12345678901234"
        result = redactor.redact(text)
        # Invalid mod-97 should not be redacted
        assert "GB00XXXX12345678901234" in result['redacted_text']

    # --- International Phone ---

    def test_intl_phone(self):
        """Detect international phone number."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Call: +442071234567"
        result = redactor.redact(text)
        assert "+442071234567" not in result['redacted_text']

    def test_intl_phone_too_short(self):
        """Too-short international number should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Code: +12345"
        result = redactor.redact(text)
        assert "+12345" in result['redacted_text']

    # --- Type Filtering ---

    def test_pii_type_filtering(self):
        """Only detect configured PII types."""
        config = {
            'enabled': True,
            'pii_types': ['ssn'],
            'action': 'block',
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config)
        text = "SSN: 123-45-6789, Email: user@example.com"
        result = redactor.redact(text)
        # SSN should be redacted
        assert "123-45-6789" not in result['redacted_text']
        # Email should NOT be redacted (not in pii_types)
        assert "user@example.com" in result['redacted_text']

    # --- Mixed Content ---

    def test_mixed_pii_and_secrets(self):
        """PII and secrets detected together."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = """
        SSN: 123-45-6789
        API Key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx
        Email: john@example.com
        """
        result = redactor.redact(text)
        assert "123-45-6789" not in result['redacted_text']
        assert "abc123def456" not in result['redacted_text']
        assert "john" not in result['redacted_text']
        assert len(result['redactions']) >= 3


class TestLuhnValidation:
    """Test Luhn checksum validation."""

    def test_luhn_valid_visa(self):
        assert SecretRedactor._luhn_check("4532015112830366") is True

    def test_luhn_valid_mastercard(self):
        assert SecretRedactor._luhn_check("5425233430109903") is True

    def test_luhn_invalid(self):
        assert SecretRedactor._luhn_check("1234567890123456") is False

    def test_luhn_too_short(self):
        assert SecretRedactor._luhn_check("123456") is False

    def test_luhn_too_long(self):
        assert SecretRedactor._luhn_check("1" * 20) is False

    def test_luhn_with_separators(self):
        assert SecretRedactor._luhn_check("4532-0151-1283-0366") is True


class TestIBANValidation:
    """Test IBAN mod-97 validation."""

    def test_iban_valid_gb(self):
        assert SecretRedactor._iban_check("GB29NWBK60161331926819") is True

    def test_iban_valid_de(self):
        assert SecretRedactor._iban_check("DE89370400440532013000") is True

    def test_iban_invalid(self):
        assert SecretRedactor._iban_check("GB00XXXX12345678901234") is False

    def test_iban_too_short(self):
        assert SecretRedactor._iban_check("GB29") is False


class TestPIIPerformance:
    """Test PII detection performance."""

    def test_performance_with_pii(self):
        """PII scanning should complete in under 50ms for 10KB."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = ("Normal text line. " * 100 +
                "SSN: 123-45-6789\nEmail: test@example.com\n" +
                "More normal text. " * 100) * 5

        start = time.time()
        result = redactor.redact(text)
        elapsed = (time.time() - start) * 1000

        assert elapsed < 50, f"PII scan took {elapsed}ms, expected <50ms"
        assert len(result['redactions']) > 0
