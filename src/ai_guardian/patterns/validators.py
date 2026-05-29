"""
Validation functions for pattern matching results.

These validators run post-match to reduce false positives. A regex match
alone may be insufficient — for example, credit card numbers must pass
Luhn checksum, and IBANs must pass mod-97 validation.

Extracted from SecretRedactor for shared use by PatternCache.
"""

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def luhn_check(number_str: str, min_digits: int = 13, max_digits: int = 19) -> bool:
    """Validate a number string using the Luhn algorithm.

    Args:
        number_str: String containing digits to validate
        min_digits: Minimum digit count (default: 13 for credit cards)
        max_digits: Maximum digit count (default: 19)

    Returns:
        True if the number passes Luhn validation
    """
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < min_digits or len(digits) > max_digits:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def iban_check(iban_str: str) -> bool:
    """Validate an IBAN using the mod-97 algorithm.

    Args:
        iban_str: IBAN string to validate

    Returns:
        True if the IBAN passes mod-97 validation
    """
    iban = iban_str.replace(' ', '').upper()
    if len(iban) < 15 or len(iban) > 34:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = ''
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord('A') + 10)
        else:
            return False
    return int(numeric) % 97 == 1


VALID_CC_PREFIXES = (
    '4',
    '51', '52', '53', '54', '55',
    '2221', '2222', '2223', '2224', '2225', '2226', '2227', '2228', '2229',
    '223', '224', '225', '226', '227', '228', '229',
    '23', '24', '25', '26',
    '270', '271', '2720',
    '34', '37',
    '6011', '65', '644', '645', '646', '647', '648', '649',
    '35',
    '30', '36', '38', '39',
)


def credit_card_check(number_str: str) -> bool:
    """Validate a credit card number using Luhn + IIN/BIN prefix check.

    Args:
        number_str: String containing digits (may include spaces/dashes)

    Returns:
        True if passes both Luhn checksum AND has a valid card network prefix
    """
    import re
    digits_only = re.sub(r'[- ]', '', number_str)
    if not luhn_check(digits_only):
        return False
    if not digits_only.startswith(VALID_CC_PREFIXES):
        return False
    return True


def aadhaar_check(number_str: str) -> bool:
    """Validate an Indian Aadhaar number beyond the regex format check.

    Args:
        number_str: String containing digits with optional spaces/dashes

    Returns:
        True if the number looks like a plausible Aadhaar number
    """
    import re
    digits = re.sub(r'[- ]', '', number_str)
    if len(digits) != 12 or not digits.isdigit():
        return False
    if digits[0] in ('0', '1'):
        return False
    if len(set(digits)) == 1:
        return False
    return True


VALIDATOR_REGISTRY: dict = {
    "luhn": luhn_check,
    "iban": iban_check,
    "credit_card": credit_card_check,
    "aadhaar": aadhaar_check,
}


def get_validator(name: str) -> Optional[Callable]:
    """Look up a validator function by name.

    Args:
        name: Validator name as specified in TOML rules (e.g., "luhn", "iban")

    Returns:
        Validator callable, or None if not found
    """
    validator = VALIDATOR_REGISTRY.get(name)
    if validator is None:
        logger.warning(f"Unknown validator: {name}")
    return validator
