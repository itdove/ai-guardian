"""
Tests for PII detection functionality (Issue #262).

Tests the SecretRedactor PII patterns, Luhn/IBAN validation,
and PII-specific redaction strategies.
"""

import time
from datetime import datetime, timezone

import pytest
from ai_guardian.secret_redactor import SecretRedactor


PII_CONFIG = {
    'enabled': True,
    'pii_types': ['ssn', 'credit_card', 'phone', 'email', 'us_passport', 'iban', 'intl_phone',
                  'medical_id', 'passport', 'canada_sin', 'uk_nin', 'india_aadhaar', 'address'],
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

    def test_credit_card_all_zeros_not_detected(self):
        """All-zeros passes Luhn but has invalid prefix — should NOT be detected (issue #694)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "ID: 0000000000000000"
        result = redactor.redact(text)
        assert "0000000000000000" in result['redacted_text']

    def test_credit_card_invalid_prefix_not_detected(self):
        """16-digit number with prefix 9 — no card network uses this (issue #694)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Tracking: 9876543210987654"
        result = redactor.redact(text)
        assert "9876543210987654" in result['redacted_text']

    def test_credit_card_prefix_7_not_detected(self):
        """Numbers starting with 7 — no major card network (issue #694)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Reference: 7000000000000000"
        result = redactor.redact(text)
        assert "7000000000000000" in result['redacted_text']

    def test_credit_card_prefix_1_not_detected(self):
        """Numbers starting with 1 — no major card network (issue #694)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "ID: 1000000000000001"
        result = redactor.redact(text)
        assert "1000000000000001" in result['redacted_text']

    def test_credit_card_mastercard_detected(self):
        """Valid Mastercard prefix (51-55) with valid Luhn — should be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Card: 5425233430109903"
        result = redactor.redact(text)
        assert "5425233430109903" not in result['redacted_text']
        assert "****9903" in result['redacted_text']

    def test_credit_card_jcb_detected(self):
        """Valid JCB prefix (35) with valid Luhn — should be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Card: 3530111333300000"
        result = redactor.redact(text)
        assert "3530111333300000" not in result['redacted_text']
        assert "****0000" in result['redacted_text']

    def test_credit_card_discover_detected(self):
        """Valid Discover prefix (6011) with valid Luhn — should be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Card: 6011000990139424"
        result = redactor.redact(text)
        assert "6011000990139424" not in result['redacted_text']
        assert "****9424" in result['redacted_text']

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

    def test_iban_space_separated(self):
        """Detect valid IBAN in space-separated format (Issue #677)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "IBAN: GB29 NWBK 6016 1331 9268 19"
        result = redactor.redact(text)
        assert "GB29 NWBK 6016 1331 9268 19" not in result['redacted_text']
        assert len(result['redactions']) > 0

    def test_iban_space_separated_de(self):
        """Detect valid German IBAN in space-separated format (Issue #677)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "IBAN: DE89 3704 0044 0532 0130 00"
        result = redactor.redact(text)
        assert "DE89 3704 0044 0532 0130 00" not in result['redacted_text']
        assert len(result['redactions']) > 0

    def test_iban_space_separated_invalid(self):
        """Invalid space-separated IBAN should NOT be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Not IBAN: GB00 XXXX 1234 5678 9012 34"
        result = redactor.redact(text)
        assert "GB00 XXXX 1234 5678 9012 34" in result['redacted_text']

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


class TestEnhancedIntlPhone:
    """Test enhanced international phone detection with formatted numbers."""

    def test_intl_phone_formatted_uk(self):
        """Detect UK phone with spaces."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Call: +44 20 7946 0958"
        result = redactor.redact(text)
        assert "+44 20 7946 0958" not in result['redacted_text']

    def test_intl_phone_formatted_france(self):
        """Detect French phone with spaces."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Tel: +33 1 23 45 67 89"
        result = redactor.redact(text)
        assert "+33 1 23 45 67 89" not in result['redacted_text']

    def test_intl_phone_formatted_germany(self):
        """Detect German phone with spaces."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Nummer: +49 30 12345678"
        result = redactor.redact(text)
        assert "+49 30 12345678" not in result['redacted_text']

    def test_intl_phone_with_dashes(self):
        """Detect international phone with dashes."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Phone: +44-20-7946-0958"
        result = redactor.redact(text)
        assert "+44-20-7946-0958" not in result['redacted_text']

    def test_intl_phone_with_dots(self):
        """Detect international phone with dots."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Phone: +33.1.23.45.67.89"
        result = redactor.redact(text)
        assert "+33.1.23.45.67.89" not in result['redacted_text']

    def test_intl_phone_continuous_still_works(self):
        """Original continuous format still detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Call: +442071234567"
        result = redactor.redact(text)
        assert "+442071234567" not in result['redacted_text']

    def test_intl_phone_too_short(self):
        """Too-short international number should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Code: +1234"
        result = redactor.redact(text)
        assert "+1234" in result['redacted_text']


class TestMedicalIDDetection:
    """Test medical record number detection (Issue #329)."""

    def test_mrn_with_colon(self):
        """Detect MRN with colon separator."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "MRN: 12345678"
        result = redactor.redact(text)
        assert "12345678" not in result['redacted_text']
        assert "[HIDDEN" in result['redacted_text']

    def test_patient_id(self):
        """Detect Patient ID format."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Patient ID: 1234567890"
        result = redactor.redact(text)
        assert "1234567890" not in result['redacted_text']

    def test_medical_record_number(self):
        """Detect full Medical Record Number format."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Medical Record Number: 12345678"
        result = redactor.redact(text)
        assert "12345678" not in result['redacted_text']

    def test_patient_number(self):
        """Detect Patient Number format."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Patient Number 987654"
        result = redactor.redact(text)
        assert "987654" not in result['redacted_text']

    def test_mrn_case_insensitive(self):
        """MRN detection is case-insensitive."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "mrn: 12345678"
        result = redactor.redact(text)
        assert "12345678" not in result['redacted_text']

    def test_no_context_no_match(self):
        """Random number without context should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "The value is 12345678"
        result = redactor.redact(text)
        assert "12345678" in result['redacted_text']

    def test_too_short_number(self):
        """Number shorter than 6 digits should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "MRN: 12345"
        result = redactor.redact(text)
        assert "12345" in result['redacted_text']


class TestPassportDetection:
    """Test international passport number detection (Issue #329)."""

    def test_passport_with_context(self):
        """Detect passport number with context keyword."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Passport: AB1234567"
        result = redactor.redact(text)
        assert "AB1234567" not in result['redacted_text']

    def test_passport_number_keyword(self):
        """Detect with 'passport number' prefix."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "passport number: C12345678"
        result = redactor.redact(text)
        assert "C12345678" not in result['redacted_text']

    def test_passport_no_keyword(self):
        """Detect with 'passport no' prefix."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Passport No. XY123456"
        result = redactor.redact(text)
        assert "XY123456" not in result['redacted_text']

    def test_passport_hash_separator(self):
        """Detect with hash separator."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Passport# N12345678"
        result = redactor.redact(text)
        assert "N12345678" not in result['redacted_text']

    def test_no_passport_context(self):
        """Alphanumeric string without passport context should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Reference: AB1234567"
        result = redactor.redact(text)
        # us_passport pattern would catch this, but 'passport' type should not
        config = {
            'enabled': True,
            'pii_types': ['passport'],
            'action': 'block',
        }
        redactor2 = SecretRedactor(config={'enabled': True}, pii_config=config)
        result2 = redactor2.redact(text)
        assert "AB1234567" in result2['redacted_text']


class TestCanadaSINDetection:
    """Test Canadian Social Insurance Number detection (Issue #329)."""

    def test_sin_with_dashes(self):
        """Detect SIN with dashes (Luhn-valid)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        # 046-454-286 passes Luhn
        text = "SIN: 046-454-286"
        result = redactor.redact(text)
        assert "046-454-286" not in result['redacted_text']
        assert "[HIDDEN Canadian SIN]" in result['redacted_text']

    def test_sin_with_spaces(self):
        """Detect SIN with spaces (Luhn-valid)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "SIN: 046 454 286"
        result = redactor.redact(text)
        assert "046 454 286" not in result['redacted_text']

    def test_sin_invalid_luhn(self):
        """SIN failing Luhn should NOT be detected."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Number: 123-456-789"
        result = redactor.redact(text)
        assert "123-456-789" in result['redacted_text']

    def test_sin_not_part_of_longer_number(self):
        """SIN pattern should not match part of a longer digit sequence."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "ID: 1046-454-2861"
        result = redactor.redact(text)
        # Should not match because preceded by digit
        assert "046-454-286" in result['redacted_text'] or "1046-454-2861" in result['redacted_text']

    def test_sin_wrong_format(self):
        """Numbers in wrong format should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Number: 0464542861"
        result = redactor.redact(text)
        # Continuous digits without separators don't match SIN format
        assert "0464542861" in result['redacted_text']


class TestUKNINDetection:
    """Test UK National Insurance Number detection (Issue #329)."""

    def test_uk_nin_standard(self):
        """Detect standard UK NIN format."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "NIN: AB123456C"
        result = redactor.redact(text)
        assert "AB123456C" not in result['redacted_text']

    def test_uk_nin_suffix_d(self):
        """Detect UK NIN with suffix D."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "NI Number: XY987654D"
        result = redactor.redact(text)
        assert "XY987654D" not in result['redacted_text']

    def test_uk_nin_invalid_suffix(self):
        """UK NIN with invalid suffix (E-Z) should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Code: AB123456E"
        result = redactor.redact(text)
        assert "AB123456E" in result['redacted_text']

    def test_uk_nin_lowercase_not_matched(self):
        """Lowercase UK NIN should not match (uppercase required)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Code: ab123456c"
        result = redactor.redact(text)
        assert "ab123456c" in result['redacted_text']


class TestIndiaAadhaarDetection:
    """Test Indian Aadhaar number detection (Issue #329)."""

    def test_aadhaar_with_spaces(self):
        """Detect Aadhaar with spaces."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Aadhaar: 1234 5678 9012"
        result = redactor.redact(text)
        assert "1234 5678 9012" not in result['redacted_text']

    def test_aadhaar_with_dashes(self):
        """Detect Aadhaar with dashes."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Aadhaar: 1234-5678-9012"
        result = redactor.redact(text)
        assert "1234-5678-9012" not in result['redacted_text']

    def test_aadhaar_not_credit_card(self):
        """Aadhaar pattern should not match first 12 digits of a credit card."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Card: 4532 0151 1283 0366"
        result = redactor.redact(text)
        # Credit card pattern should match, but aadhaar should not trigger
        # because the pattern has (?![- ]\d) lookahead
        redactions = result['redactions']
        aadhaar_redactions = [r for r in redactions if r['type'] == 'Indian Aadhaar Number']
        assert len(aadhaar_redactions) == 0

    def test_aadhaar_continuous_not_matched(self):
        """Continuous 12-digit number should not match (needs separators)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Number: 123456789012"
        result = redactor.redact(text)
        # No separator = no aadhaar match
        aadhaar_redactions = [r for r in result['redactions'] if r['type'] == 'Indian Aadhaar Number']
        assert len(aadhaar_redactions) == 0


class TestAddressDetection:
    """Test street address detection (Issue #329)."""

    def test_address_street(self):
        """Detect address with Street suffix."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Address: 123 Main Street"
        result = redactor.redact(text)
        assert "123 Main Street" not in result['redacted_text']

    def test_address_ave(self):
        """Detect address with Ave suffix."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Lives at 456 Oak Ave"
        result = redactor.redact(text)
        assert "456 Oak Ave" not in result['redacted_text']

    def test_address_blvd(self):
        """Detect address with Blvd suffix."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Office: 789 Elm Boulevard"
        result = redactor.redact(text)
        assert "789 Elm Boulevard" not in result['redacted_text']

    def test_address_with_multiple_words(self):
        """Detect address with multiple words before suffix."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Located at 100 North Main St"
        result = redactor.redact(text)
        assert "100 North Main St" not in result['redacted_text']

    def test_address_rd_dr(self):
        """Detect address with Rd and Dr suffixes."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Home: 55 Pine Rd"
        result = redactor.redact(text)
        assert "55 Pine Rd" not in result['redacted_text']

    def test_no_number_no_match(self):
        """Text without leading number should not match."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "Main Street is busy"
        result = redactor.redact(text)
        assert "Main Street" in result['redacted_text']

    def test_code_not_address(self):
        """Code-like text should not be detected as address."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = "import sys"
        result = redactor.redact(text)
        assert "import sys" in result['redacted_text']


class TestPhase2TypeFiltering:
    """Test that Phase 2 types are opt-in only."""

    def test_phase2_types_not_in_defaults(self):
        """Phase 2 types should not be detected with default config."""
        from ai_guardian.config_loaders import _PII_DEFAULTS
        default_types = _PII_DEFAULTS['pii_types']
        phase2_types = ['medical_id', 'passport', 'canada_sin', 'uk_nin', 'india_aadhaar', 'address']
        for t in phase2_types:
            assert t not in default_types, f"{t} should not be in defaults"

    def test_phase2_type_selective_enable(self):
        """Only enabled Phase 2 types should detect PII."""
        config = {
            'enabled': True,
            'pii_types': ['medical_id'],
            'action': 'block',
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config)
        text = "MRN: 12345678 and NIN: AB123456C"
        result = redactor.redact(text)
        assert "12345678" not in result['redacted_text']
        assert "AB123456C" in result['redacted_text']


class TestSINLuhnValidation:
    """Test Luhn validation with 9-digit SIN length."""

    def test_sin_luhn_valid(self):
        """Valid SIN passes Luhn check."""
        assert SecretRedactor._luhn_check("046-454-286", 9, 9) is True

    def test_sin_luhn_valid_no_separators(self):
        """Valid SIN passes without separators."""
        assert SecretRedactor._luhn_check("046454286", 9, 9) is True

    def test_sin_luhn_invalid(self):
        """Invalid SIN fails Luhn check."""
        assert SecretRedactor._luhn_check("123-456-789", 9, 9) is False

    def test_sin_luhn_wrong_length(self):
        """Wrong length fails Luhn check."""
        assert SecretRedactor._luhn_check("12345", 9, 9) is False

    def test_sin_luhn_too_long(self):
        """Too long fails Luhn check."""
        assert SecretRedactor._luhn_check("0464542861", 9, 9) is False


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


class TestCreditCardIINValidation:
    """Test IIN/BIN prefix validation for credit card detection (issue #694)."""

    def test_valid_cc_prefixes_constant_exists(self):
        """VALID_CC_PREFIXES class constant is defined."""
        assert hasattr(SecretRedactor, 'VALID_CC_PREFIXES')
        assert isinstance(SecretRedactor.VALID_CC_PREFIXES, tuple)
        assert len(SecretRedactor.VALID_CC_PREFIXES) > 0

    def test_visa_prefix_accepted(self):
        """Visa prefix (4) is in valid prefixes."""
        assert any(p == '4' for p in SecretRedactor.VALID_CC_PREFIXES)

    def test_amex_prefixes_accepted(self):
        """Amex prefixes (34, 37) are in valid prefixes."""
        assert '34' in SecretRedactor.VALID_CC_PREFIXES
        assert '37' in SecretRedactor.VALID_CC_PREFIXES

    def test_prefix_0_rejected(self):
        """Prefix 0 is not a valid card network."""
        assert not '0'.startswith(SecretRedactor.VALID_CC_PREFIXES)

    def test_prefix_1_rejected(self):
        """Prefix 1 is not a valid card network."""
        assert not '1'.startswith(SecretRedactor.VALID_CC_PREFIXES)

    def test_prefix_7_rejected(self):
        """Prefix 7 is not a valid card network."""
        assert not '7000'.startswith(SecretRedactor.VALID_CC_PREFIXES)

    def test_prefix_8_rejected(self):
        """Prefix 8 is not a valid card network."""
        assert not '8000'.startswith(SecretRedactor.VALID_CC_PREFIXES)

    def test_prefix_9_rejected(self):
        """Prefix 9 is not a valid card network."""
        assert not '9000'.startswith(SecretRedactor.VALID_CC_PREFIXES)


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

    def test_iban_valid_with_spaces(self):
        """Validator strips spaces before validation (Issue #677)."""
        assert SecretRedactor._iban_check("GB29 NWBK 6016 1331 9268 19") is True

    def test_iban_valid_de_with_spaces(self):
        assert SecretRedactor._iban_check("DE89 3704 0044 0532 0130 00") is True


class TestPIIPerformance:
    """Test PII detection performance."""

    def test_performance_with_pii(self):
        """PII scanning should complete in under 50ms for 10KB (all Phase 1+2 patterns)."""
        redactor = SecretRedactor(config={'enabled': True}, pii_config=PII_CONFIG)
        text = ("Normal text line. " * 100 +
                "SSN: 123-45-6789\nEmail: test@example.com\n"
                "MRN: 12345678\nPassport: AB1234567\n" +
                "More normal text. " * 100) * 5

        start = time.time()
        result = redactor.redact(text)
        elapsed = (time.time() - start) * 1000

        assert elapsed < 50, f"PII scan took {elapsed}ms, expected <50ms"
        assert len(result['redactions']) > 0


class TestPIIAllowlistPatterns:
    """Test PII allowlist_patterns support (Issue #357)."""

    def test_email_allowlisted_not_redacted(self):
        """Email matching allowlist pattern should not be flagged."""
        config = {
            'enabled': True,
            'pii_types': ['email'],
            'action': 'block',
            'allowlist_patterns': [r'\b[\w.+-]+@anthropic\.com\b'],
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config, pii_only=True)
        text = "Contact noreply@anthropic.com for help"
        result = redactor.redact(text)
        assert result['redacted_text'] == text
        assert len(result['redactions']) == 0

    def test_non_allowlisted_email_still_redacted(self):
        """Email not matching allowlist should still be flagged."""
        config = {
            'enabled': True,
            'pii_types': ['email'],
            'action': 'block',
            'allowlist_patterns': [r'\b[\w.+-]+@anthropic\.com\b'],
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config, pii_only=True)
        text = "Contact secret@personal.com for help"
        result = redactor.redact(text)
        assert len(result['redactions']) == 1

    def test_multiple_allowlist_patterns(self):
        """Multiple allowlist patterns work together."""
        config = {
            'enabled': True,
            'pii_types': ['email'],
            'action': 'block',
            'allowlist_patterns': [
                r'\b[\w.+-]+@anthropic\.com\b',
                r'\b[\w.+-]+@example\.(com|org|net)\b',
            ],
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config, pii_only=True)
        text = "Emails: noreply@anthropic.com and user@example.org and secret@real.com"
        result = redactor.redact(text)
        assert len(result['redactions']) == 1
        assert 'secret@real.com' not in result['redacted_text']
        assert 'noreply@anthropic.com' in result['redacted_text']
        assert 'user@example.org' in result['redacted_text']

    def test_allowlist_with_no_patterns(self):
        """Empty allowlist has no effect — PII still detected."""
        config = {
            'enabled': True,
            'pii_types': ['email'],
            'action': 'block',
            'allowlist_patterns': [],
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config, pii_only=True)
        text = "Email: user@example.com"
        result = redactor.redact(text)
        assert len(result['redactions']) == 1

    def test_allowlist_dangerous_pattern_blocked(self):
        """Catch-all patterns like .* are blocked."""
        config = {
            'enabled': True,
            'pii_types': ['email'],
            'action': 'block',
            'allowlist_patterns': ['.*'],
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config, pii_only=True)
        text = "Email: user@example.com"
        result = redactor.redact(text)
        assert len(result['redactions']) == 1

    def test_allowlist_time_based_active(self):
        """Active time-based pattern suppresses PII detection."""
        from datetime import timedelta
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        config = {
            'enabled': True,
            'pii_types': ['email'],
            'action': 'block',
            'allowlist_patterns': [
                {'pattern': r'\b[\w.+-]+@anthropic\.com\b', 'valid_until': future}
            ],
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config, pii_only=True)
        text = "Email: noreply@anthropic.com"
        result = redactor.redact(text)
        assert len(result['redactions']) == 0

    def test_allowlist_time_based_expired(self):
        """Expired time-based pattern does not suppress detection."""
        from datetime import timedelta
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        config = {
            'enabled': True,
            'pii_types': ['email'],
            'action': 'block',
            'allowlist_patterns': [
                {'pattern': r'\b[\w.+-]+@anthropic\.com\b', 'valid_until': past}
            ],
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config, pii_only=True)
        text = "Email: noreply@anthropic.com"
        result = redactor.redact(text)
        assert len(result['redactions']) == 1


class TestPIIPatternLoader:
    """Test PIIPatternLoader class (Issue #644)."""

    def test_loader_loads_bundled_defaults(self):
        """PIIPatternLoader loads patterns from bundled pii.toml."""
        from ai_guardian.pattern_loader import PIIPatternLoader

        loader = PIIPatternLoader()
        result = loader.load_patterns()
        rules = result.get("rules", [])
        assert len(rules) > 0
        pii_types = {r.get("pii_type") for r in rules}
        assert "ssn" in pii_types
        assert "credit_card" in pii_types
        assert "email" in pii_types

    def test_loader_immutable_empty(self):
        """PIIPatternLoader has no immutable patterns."""
        from ai_guardian.pattern_loader import PIIPatternLoader

        loader = PIIPatternLoader()
        immutable = loader.get_immutable_patterns()
        assert immutable == {"rules": []}

    def test_loader_merge_extend_mode(self):
        """Server patterns extend defaults when override_mode is extend."""
        from ai_guardian.pattern_loader import PIIPatternLoader

        loader = PIIPatternLoader()
        immutable = {"rules": []}
        defaults = {"rules": [
            {"id": "pii-ssn", "pii_type": "ssn", "match_type": "regex", "regex": "test"},
        ]}
        server = {"rules": [
            {"id": "pii-custom", "pii_type": "custom_id", "match_type": "regex", "regex": "custom"},
        ]}
        merged = loader.merge_patterns(immutable, server, None)
        ids = [r["id"] for r in merged["rules"]]
        assert "pii-ssn" in ids
        assert "pii-custom" in ids

    def test_loader_merge_replace_mode(self):
        """Server patterns replace defaults when override_mode is replace."""
        from ai_guardian.pattern_loader import PIIPatternLoader

        loader = PIIPatternLoader()
        immutable = {"rules": []}
        server = {
            "metadata": {"override_mode": "replace"},
            "rules": [
                {"id": "pii-custom-only", "pii_type": "custom", "match_type": "regex", "regex": "custom"},
            ],
        }
        merged = loader.merge_patterns(immutable, server, None)
        ids = [r["id"] for r in merged["rules"]]
        assert "pii-custom-only" in ids
        assert len(merged["rules"]) == 1

    def test_loader_merge_server_overrides_by_id(self):
        """Server rules override defaults with matching id in extend mode."""
        from ai_guardian.pattern_loader import PIIPatternLoader

        loader = PIIPatternLoader()
        immutable = {"rules": []}
        defaults = {"rules": [
            {"id": "pii-ssn", "pii_type": "ssn", "regex": "old-pattern"},
            {"id": "pii-email", "pii_type": "email", "regex": "email-pattern"},
        ]}
        server = {"rules": [
            {"id": "pii-ssn", "pii_type": "ssn", "regex": "new-pattern"},
        ]}
        merged = loader.merge_patterns(immutable, server, None)
        ssn_rules = [r for r in merged["rules"] if r["id"] == "pii-ssn"]
        assert len(ssn_rules) == 1
        assert ssn_rules[0]["regex"] == "new-pattern"
        email_rules = [r for r in merged["rules"] if r["id"] == "pii-email"]
        assert len(email_rules) == 1

    def test_loader_merge_local_additions(self):
        """Local additional_pii_patterns are always additive."""
        from ai_guardian.pattern_loader import PIIPatternLoader

        loader = PIIPatternLoader()
        immutable = {"rules": []}
        defaults = {"rules": [
            {"id": "pii-ssn", "pii_type": "ssn", "regex": "ssn-pattern"},
        ]}
        local = {
            "additional_pii_patterns": [
                {"id": "pii-local", "pii_type": "local_id", "regex": "local-pattern"},
            ]
        }
        merged = loader.merge_patterns(immutable, defaults, local)
        ids = [r["id"] for r in merged["rules"]]
        assert "pii-ssn" in ids
        assert "pii-local" in ids

    def test_loader_pattern_type(self):
        """PIIPatternLoader has correct pattern_type for server API."""
        from ai_guardian.pattern_loader import PIIPatternLoader

        loader = PIIPatternLoader()
        assert loader.pattern_type == "pii"
        assert loader.feature_name == "PII Detection"


class TestPIIPatternServerWiring:
    """Test that SecretRedactor uses PIIPatternLoader when pattern_server configured (Issue #644)."""

    def test_pii_with_pattern_server_none_uses_bundled(self):
        """When pattern_server is None, bundled pii.toml is used (no regression)."""
        config = {
            'enabled': True,
            'pii_types': ['ssn', 'credit_card'],
            'action': 'block',
            'pattern_server': None,
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config)
        text = "SSN: 123-45-6789"
        result = redactor.redact(text)
        assert "123-45-6789" not in result['redacted_text']

    def test_pii_without_pattern_server_key_uses_bundled(self):
        """When pattern_server key is absent, bundled pii.toml is used."""
        config = {
            'enabled': True,
            'pii_types': ['ssn'],
            'action': 'block',
        }
        redactor = SecretRedactor(config={'enabled': True}, pii_config=config)
        text = "SSN: 123-45-6789"
        result = redactor.redact(text)
        assert "123-45-6789" not in result['redacted_text']

    def test_pii_defaults_include_pattern_server(self):
        """_PII_DEFAULTS includes pattern_server key."""
        from ai_guardian.config_loaders import _PII_DEFAULTS
        assert 'pattern_server' in _PII_DEFAULTS
        assert _PII_DEFAULTS['pattern_server'] is None
