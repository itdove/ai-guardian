"""
Sanitizer - Redacts secrets, PII, and threats from text.

Designed for cleaning transcripts before sharing with other agents.
Uses hardcoded maximum detection — ignores user config, no allowlists.

Part of Issue #443: ai-guardian sanitize command.
"""

import logging
import re
import sys
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def get_sanitize_config():
    """Config for sanitize command — scan everything, ignore nothing."""
    return {
        "secret_scanning": {"enabled": True},
        "scan_pii": {
            "enabled": True,
            "pii_types": ["ssn", "credit_card", "phone", "email",
                          "us_passport", "iban", "intl_phone"],
            "allowlist_patterns": [],
            "ignore_files": [],
            "ignore_tools": [],
        },
    }


def _sanitize_unicode(text: str) -> tuple:
    """
    Strip dangerous unicode characters and replace homoglyphs.

    Returns:
        Tuple of (sanitized_text, list of changes made)
    """
    from ai_guardian.prompt_injection import UnicodeAttackDetector

    changes = []

    zero_width_set = set(UnicodeAttackDetector.ZERO_WIDTH_CHARS)
    bidi_set = set(UnicodeAttackDetector.BIDI_OVERRIDE_CHARS)

    homoglyph_map = {lookalike: latin for lookalike, latin in UnicodeAttackDetector.HOMOGLYPH_PATTERNS}

    result = []
    for char in text:
        code_point = ord(char)

        if char in zero_width_set:
            changes.append({"type": "unicode_zero_width", "char": f"U+{code_point:04X}"})
            continue

        if char in bidi_set:
            changes.append({"type": "unicode_bidi_override", "char": f"U+{code_point:04X}"})
            continue

        if UnicodeAttackDetector.TAG_CHAR_START <= code_point <= UnicodeAttackDetector.TAG_CHAR_END:
            changes.append({"type": "unicode_tag_char", "char": f"U+{code_point:05X}"})
            continue

        if char in homoglyph_map:
            latin = homoglyph_map[char]
            changes.append({"type": "unicode_homoglyph", "char": f"U+{code_point:04X}", "replaced_with": latin})
            result.append(latin)
            continue

        result.append(char)

    return "".join(result), changes


def _sanitize_prompt_injection(text: str) -> tuple:
    """
    Detect and replace prompt injection patterns with [SANITIZED].

    Returns:
        Tuple of (sanitized_text, list of redactions)
    """
    from ai_guardian.prompt_injection import PromptInjectionDetector

    detector = PromptInjectionDetector({
        "enabled": True,
        "sensitivity": "high",
        "allowlist_patterns": [],
        "ignore_files": [],
        "ignore_tools": [],
    })

    redactions = []

    all_patterns = (
        detector._compiled_critical
        + detector._compiled_documentation
        + detector._compiled_jailbreak
        + detector._compiled_suspicious
    )

    redacted_regions = []
    replacements = []

    for pattern in all_patterns:
        for match in pattern.finditer(text):
            start, end = match.span()

            if any(rs <= start < re_ or rs < end <= re_
                   for rs, re_ in redacted_regions):
                continue

            redacted_regions.append((start, end))
            replacements.append((start, end, match.group(0)))
            redactions.append({
                "type": "prompt_injection",
                "matched_text": match.group(0)[:80],
                "pattern": pattern.pattern[:60],
            })

    for start, end, original in sorted(replacements, key=lambda x: x[0], reverse=True):
        text = text[:start] + "[SANITIZED]" + text[end:]

    return text, redactions


def sanitize_text(text: str, no_secrets: bool = False, no_pii: bool = False,
                  no_threats: bool = False) -> Dict:
    """
    Sanitize text by redacting secrets, PII, and threats.

    Args:
        text: Input text to sanitize
        no_secrets: Skip secret pattern redaction
        no_pii: Skip PII pattern redaction
        no_threats: Skip prompt injection and unicode attack neutralization

    Returns:
        Dict with sanitized_text, redactions list, and stats
    """
    if not text:
        return {"sanitized_text": "", "redactions": [], "stats": {
            "secrets": 0, "pii": 0, "prompt_injection": 0, "unicode": 0, "total": 0,
        }}

    sanitized = text
    all_redactions: List[Dict] = []
    stats = {"secrets": 0, "pii": 0, "prompt_injection": 0, "unicode": 0}

    # 1. Unicode attacks (strip invisible chars before pattern matching)
    if not no_threats:
        sanitized, unicode_changes = _sanitize_unicode(sanitized)
        stats["unicode"] = len(unicode_changes)
        all_redactions.extend(unicode_changes)

    # 2. Secrets + PII (via SecretRedactor)
    if not no_secrets or not no_pii:
        from ai_guardian.secret_redactor import SecretRedactor

        config = get_sanitize_config()

        pii_config = config["scan_pii"] if not no_pii else {"enabled": False}

        redactor = SecretRedactor(
            config={"enabled": True},
            pii_config=pii_config,
            pii_only=no_secrets,
        )

        result = redactor.redact(sanitized)
        sanitized = result["redacted_text"]

        for r in result.get("redactions", []):
            rtype = r.get("type", "")
            is_pii = rtype in (
                "SSN", "Credit Card Number", "US Phone Number",
                "Email Address", "US Passport Number", "IBAN",
                "International Phone Number",
            )
            if is_pii:
                stats["pii"] += 1
            else:
                stats["secrets"] += 1
            all_redactions.append(r)

    # 3. Prompt injection (detect and replace)
    if not no_threats:
        sanitized, pi_redactions = _sanitize_prompt_injection(sanitized)
        stats["prompt_injection"] = len(pi_redactions)
        all_redactions.extend(pi_redactions)

    stats["total"] = sum(stats.values())

    return {
        "sanitized_text": sanitized,
        "redactions": all_redactions,
        "stats": stats,
    }


def sanitize_command(args) -> int:
    """
    Handle the sanitize CLI command.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 = clean or redacted, 1 = redactions found with --exit-code)
    """
    # Suppress all logging — stdout must be only the sanitized text
    logging.disable(logging.CRITICAL)

    # Read input
    if hasattr(args, "input") and args.input:
        try:
            with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    else:
        if sys.stdin.isatty():
            print("Error: No input provided. Pipe text via stdin or provide a file argument.", file=sys.stderr)
            print("Usage: echo 'text' | ai-guardian sanitize", file=sys.stderr)
            print("   or: ai-guardian sanitize <file>", file=sys.stderr)
            return 1
        text = sys.stdin.read()

    result = sanitize_text(
        text,
        no_secrets=args.no_secrets,
        no_pii=args.no_pii,
        no_threats=args.no_threats,
    )

    # stdout: only the sanitized text
    sys.stdout.write(result["sanitized_text"])

    # stderr: optional summary
    if args.summary:
        stats = result["stats"]
        if stats["total"] > 0:
            parts = []
            if stats["secrets"]:
                parts.append(f"{stats['secrets']} secret(s)")
            if stats["pii"]:
                parts.append(f"{stats['pii']} PII item(s)")
            if stats["prompt_injection"]:
                parts.append(f"{stats['prompt_injection']} prompt injection(s)")
            if stats["unicode"]:
                parts.append(f"{stats['unicode']} unicode threat(s)")
            print(f"Sanitized: {', '.join(parts)}", file=sys.stderr)
        else:
            print("No redactions needed", file=sys.stderr)

    # exit code
    if args.exit_code and result["stats"]["total"] > 0:
        return 1

    return 0
