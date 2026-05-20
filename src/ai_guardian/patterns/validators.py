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


VALIDATOR_REGISTRY: dict = {
    "luhn": luhn_check,
    "iban": iban_check,
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
