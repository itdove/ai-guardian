"""
Validation functions for pattern matching results.

These validators run post-match to reduce false positives. A regex match
alone may be insufficient — for example, credit card numbers must pass
Luhn checksum, and IBANs must pass mod-97 validation.

Extracted from SecretRedactor for shared use by PatternCache.
"""

import logging
import re
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
    digits = re.sub(r'[- ]', '', number_str)
    if len(digits) != 12 or not digits.isdigit():
        return False
    if digits[0] in ('0', '1'):
        return False
    if len(set(digits)) == 1:
        return False
    return True


def _is_file_path(value: str) -> bool:
    """Check if a value looks like a filesystem path."""
    if value.startswith('/') and '/' in value[1:]:
        return _has_path_like_segments(value.split('/'))
    if len(value) >= 3 and value[0].isalpha() and value[1] == ':' and value[2] in ('/', '\\'):
        rest = value[2:].replace('\\', '/')
        return _has_path_like_segments(rest.split('/'))
    if value.startswith('./') or value.startswith('../'):
        return _has_path_like_segments(value.split('/'))
    return False


def _has_path_like_segments(parts: list) -> bool:
    """Check if split path segments look like directory/file names, not base64."""
    for p in parts:
        if p == '' or p in ('.', '..'):
            continue
        if not all(c.isalnum() or c in '-_.' for c in p):
            return False
    return True


_PLACEHOLDER_RE = re.compile(
    r'^(?:'
    r'(?:your|my|example|replace|insert|enter|put|test|fake|dummy|sample|placeholder|changeme)[-_]'
    r'|'
    r'.*[-_](?:here|placeholder|example|changeme)$'
    r')',
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    """Check if a value looks like a documentation placeholder."""
    return bool(_PLACEHOLDER_RE.search(value))


def env_not_file_path(matched_text: str) -> bool:
    """Return False (skip) if the env var value is a filesystem path,
    starts with underscore (Python identifier), or looks like a placeholder.
    """
    eq_pos = matched_text.find('=')
    if eq_pos < 0:
        return True
    value = matched_text[eq_pos + 1:].strip().strip("'\"")
    if not value:
        return True
    if value.startswith('_'):
        return False
    if _is_placeholder(value):
        return False
    return not _is_file_path(value)


_BRACKET_PLACEHOLDER_RE = re.compile(
    r'^\[(?:HIDDEN|REDACTED|PASSWORD|MASKED|REMOVED|SECRET|CENSORED)\]$',
    re.IGNORECASE,
)

_ANGLE_PLACEHOLDER_RE = re.compile(
    r'^<[a-z0-9_-]+>$',
    re.IGNORECASE,
)

_REPEATED_CHAR_RE = re.compile(r'^(.)\1{5,}$')

_CONNECTION_URI_RE = re.compile(
    r'(?:mongodb|mysql|postgres(?:ql)?|redis)://[^:]*:([^@]+)@',
    re.IGNORECASE,
)


def _is_connection_placeholder(password: str) -> bool:
    """Check if a connection string password is a documentation placeholder."""
    if _BRACKET_PLACEHOLDER_RE.match(password):
        return True
    if _ANGLE_PLACEHOLDER_RE.match(password):
        return True
    if _REPEATED_CHAR_RE.match(password):
        return True
    return _is_placeholder(password)


def connection_not_placeholder(matched_text: str) -> bool:
    """Return False (skip) if the connection string password is a placeholder."""
    m = _CONNECTION_URI_RE.search(matched_text)
    if not m:
        return True
    password = m.group(1)
    if _is_connection_placeholder(password):
        return False
    return True


_TOKEN_PREFIX_RE = re.compile(
    r'^(?:sk-(?:proj-|ant-)?|gh[pors]_|glpat-|xox[baprs]-)',
)

_REPEATED_CHAR_TOKEN_RE = re.compile(r'^(.)\1{7,}$')

_ALL_CAPS_UNDERSCORES_RE = re.compile(r'^[A-Z0-9]+(?:_[A-Z0-9]+)+$')

_TEMPLATE_SYNTAX_RE = re.compile(r'<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}')


def _is_token_placeholder(body: str) -> bool:
    """Check if a token body (after prefix) is a documentation placeholder."""
    if not body:
        return False
    if _REPEATED_CHAR_TOKEN_RE.match(body):
        return True
    if _is_placeholder(body):
        return True
    if _ALL_CAPS_UNDERSCORES_RE.match(body):
        return True
    if _TEMPLATE_SYNTAX_RE.search(body):
        return True
    return False


def token_not_placeholder(matched_text: str) -> bool:
    """Return False (skip) if the token value is a placeholder."""
    m = _TOKEN_PREFIX_RE.match(matched_text)
    if not m:
        return True
    body = matched_text[m.end():]
    if _is_token_placeholder(body):
        return False
    return True


VALIDATOR_REGISTRY: dict = {
    "luhn": luhn_check,
    "iban": iban_check,
    "credit_card": credit_card_check,
    "aadhaar": aadhaar_check,
    "env_not_file_path": env_not_file_path,
    "connection_not_placeholder": connection_not_placeholder,
    "token_not_placeholder": token_not_placeholder,
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
