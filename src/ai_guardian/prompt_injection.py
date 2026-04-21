#!/usr/bin/env python3
"""
Prompt Injection Detection Module

Provides multi-layered prompt injection detection:
- Heuristic/pattern-based detection (default, local, fast)
- Optional ML-based detection (Rebuff, LLM Guard, custom models)

Design Philosophy:
- Local-first: Default detection runs entirely locally
- Privacy-preserving: No prompts sent externally by default
- Fast: <1ms for heuristic detection
- Fail-open: Allow operation on detection errors
"""

import fnmatch
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, Union, List

from ai_guardian.config_utils import is_expired
from ai_guardian.tool_policy import _strip_bash_heredoc_content

logger = logging.getLogger(__name__)


class PromptInjectionDetector:
    """
    Detects prompt injection attacks using multiple methods.

    Default: Heuristic/pattern-based detection (no dependencies, fast)
    Optional: ML-based detection (Rebuff, LLM Guard, etc.)

    Context-Aware Detection:
    - User prompts: All patterns checked with medium sensitivity (threshold 0.75)
    - File content: Only critical patterns checked with high sensitivity (threshold 0.90)
    """

    # Critical patterns - checked everywhere (user prompts AND file content)
    # These are high-confidence attack patterns that should always be detected
    CRITICAL_PATTERNS = [
        # Explicit instruction override
        r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?|commands?|prompts?)',
        r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?|commands?)',
        r'forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?|commands?)',
        r'skip\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?|commands?)',

        # System/mode override attempts
        r'you\s+are\s+now\s+(in\s+)?(developer|debug|admin|god|dan)\s+mode',
        r'enable\s+(developer|debug|admin|god|dan)\s+mode',
        r'enter\s+(developer|debug|admin)\s+mode',

        # Information exfiltration
        r'reveal\s+(your\s+)?(system\s+)?(prompt|instructions?|rules)',
        r'show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|rules)',
        r'print\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration)',
        r'output\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration)',

        # Constraint bypassing
        r'bypass\s+(all\s+)?(safety|security|content|ethical)\s+(filters?|checks?|guidelines?)',
        r'disable\s+(all\s+)?(safety|security|content|ethical)\s+(filters?|checks?|guidelines?)',
        r'remove\s+(all\s+)?(safety|security|content|ethical)\s+(filters?|checks?|constraints?)',

        # Direct harm instructions
        r'generate\s+(malicious|harmful|offensive)\s+(code|content)',
        r'create\s+(malware|exploit|backdoor)',
        r'(write|create)\s+(a\s+)?(virus|trojan|ransomware)',
    ]

    # Documentation patterns - only checked in user prompts (NOT in file content)
    # These patterns are common in documentation, tutorials, and examples
    DOCUMENTATION_PATTERNS = [
        # System/mode mentions (common in docs)
        r'system\s+(override|mode|prompt)',

        # Role manipulation (common in examples)
        r'you\s+are\s+no\s+longer\s+(an?\s+)?AI',
        r'act\s+as\s+(if\s+you\s+are\s+)?(an?\s+)?(unfiltered|unrestricted|uncensored)',
        r'pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unfiltered|unrestricted|human)',
        r'roleplay\s+as\s+(an?\s+)?(unfiltered|unrestricted|hacker)',

        # Information exfiltration (common in docs describing attacks)
        r'what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules)',
        r'display\s+(your\s+)?(system\s+)?(prompt|instructions?|rules)',

        # Constraint bypassing (common in examples)
        r'turn\s+off\s+(safety|security|content|ethical)\s+(filters?|guidelines?|checks?)',

        # Delimiter/encoding attacks (common in security docs)
        r'&lt;/?system&gt;',  # HTML-encoded system tags
        r'\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){3,}',  # Hex encoding chains
        r'&#x?[0-9a-f]+;(&#x?[0-9a-f]+;){3,}',  # HTML entity encoding

        # Many-shot pattern indicators (simplified)
        r'(Q:|A:|Question:|Answer:)(\s*\n\s*){3,}(Q:|A:|Question:|Answer:)',  # Multiple Q&A pairs
    ]

    # Suspicious phrases that might indicate injection (lower confidence)
    SUSPICIOUS_PATTERNS = [
        r'jailbreak',
        r'uncensored\s+mode',
        r'do\s+anything\s+now',
        r'without\s+any\s+restrictions?',
        r'regardless\s+of\s+ethical',
        r'ignore\s+ethical',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the prompt injection detector.

        Args:
            config: Optional configuration dictionary with keys:
                - enabled: bool (default True)
                - sensitivity: str - "low", "medium", "high" (default "medium")
                - detector: str - "heuristic", "rebuff", "llm-guard" (default "heuristic")
                - allowlist_patterns: list of regex patterns to ignore
                - custom_patterns: list of additional regex patterns to check
                - max_score_threshold: float (0.0-1.0, default 0.75)
                - ignore_files: list of glob patterns for files to skip (default [])
                - ignore_tools: list of tool name patterns to skip (default [])
        """
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.sensitivity = self.config.get("sensitivity", "medium")
        self.detector_type = self.config.get("detector", "heuristic")
        self.allowlist_patterns = self.config.get("allowlist_patterns", [])
        self.custom_patterns = self.config.get("custom_patterns", [])
        self.max_score_threshold = self.config.get("max_score_threshold", 0.75)
        self.ignore_files = self.config.get("ignore_files", [])
        self.ignore_tools = self.config.get("ignore_tools", [])
        self.action = self.config.get("action", "block")

        # Compile regex patterns for performance
        # Critical patterns - always checked
        self._compiled_critical = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.CRITICAL_PATTERNS
        ]
        # Documentation patterns - only checked for user prompts
        self._compiled_documentation = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.DOCUMENTATION_PATTERNS
        ]
        self._compiled_suspicious = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.SUSPICIOUS_PATTERNS
        ]

        # Compile allowlist patterns (filter expired ones first)
        valid_allowlist = self._filter_valid_patterns(self.allowlist_patterns)
        self._compiled_allowlist = [
            re.compile(self._extract_pattern_string(pattern), re.IGNORECASE | re.MULTILINE)
            for pattern in valid_allowlist
        ]

        self._compiled_custom = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.custom_patterns
        ]

    def _extract_pattern_string(self, pattern_entry: Union[str, Dict]) -> str:
        """
        Extract the pattern string from a pattern entry.

        Args:
            pattern_entry: Either a string pattern or dict with 'pattern' field

        Returns:
            str: The pattern string

        Examples:
            >>> self._extract_pattern_string("test:.*")
            "test:.*"

            >>> self._extract_pattern_string({"pattern": "debug:.*", "valid_until": "2026-04-13T12:00:00Z"})
            "debug:.*"
        """
        if isinstance(pattern_entry, str):
            return pattern_entry
        elif isinstance(pattern_entry, dict) and "pattern" in pattern_entry:
            return pattern_entry["pattern"]
        else:
            # Fallback - return string representation
            return str(pattern_entry)

    def _is_allowlist_pattern_valid(self, pattern_entry: Union[str, Dict], current_time: Optional[datetime] = None) -> bool:
        """
        Check if an allowlist pattern entry is still valid (not expired).

        Supports both simple format (string) and extended format (dict with valid_until).

        Args:
            pattern_entry: Either a string pattern or dict with 'pattern' and 'valid_until'
            current_time: Optional current time for testing (defaults to now in UTC)

        Returns:
            bool: True if pattern is valid, False if expired

        Examples:
            >>> self._is_allowlist_pattern_valid("test:.*")
            True

            >>> self._is_allowlist_pattern_valid({"pattern": "temp:.*", "valid_until": "2099-12-31T23:59:59Z"})
            True

            >>> self._is_allowlist_pattern_valid({"pattern": "old:.*", "valid_until": "2020-01-01T00:00:00Z"})
            False
        """
        # Simple format (string) - never expires
        if isinstance(pattern_entry, str):
            return True

        # Extended format (dict) - check for valid_until field
        if isinstance(pattern_entry, dict):
            # No valid_until field - treat as non-expiring
            if "valid_until" not in pattern_entry:
                return True

            valid_until = pattern_entry.get("valid_until")
            if not valid_until:
                return True

            # Check if expired
            return not is_expired(valid_until, current_time)

        # Unknown format - treat as valid (fail-safe)
        logger.warning(f"Unknown allowlist pattern entry format: {type(pattern_entry)}")
        return True

    def _sanitize_text_for_logging(self, text: str) -> str:
        """
        Sanitize text to prevent secrets from leaking in logs.

        Redacts common secret patterns:
        - API keys, tokens, passwords
        - Environment variable values
        - Long alphanumeric strings (potential tokens)
        - Base64-encoded credentials

        Args:
            text: The text to sanitize

        Returns:
            Sanitized text with secrets redacted
        """
        # Redact common secret patterns (case-insensitive)
        # Pattern: key=value or key='value' or key="value"
        secret_patterns = [
            (r'(api[_-]?key|apikey|token|password|passwd|pwd|secret|auth|authorization|bearer)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', r'\1=***REDACTED***'),
            # Environment variables with common secret names
            (r'(API_KEY|TOKEN|PASSWORD|SECRET|GITHUB_TOKEN|AWS_SECRET|OPENAI_API_KEY)=([^\s]{8,})', r'\1=***REDACTED***'),
            # Long alphanumeric strings (potential tokens) - 32+ chars
            (r'\b([a-zA-Z0-9]{32,})\b', r'***REDACTED-TOKEN***'),
            # Base64-encoded strings (potential credentials) - must be 24+ chars and end with padding or not
            (r'\b([A-Za-z0-9+/]{24,}={0,2})\b', r'***REDACTED-BASE64***'),
        ]

        sanitized = text
        for pattern, replacement in secret_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def _filter_valid_patterns(self, patterns: List[Union[str, Dict]], current_time: Optional[datetime] = None) -> List[Union[str, Dict]]:
        """
        Filter out expired patterns from a list.

        Args:
            patterns: List of pattern entries (strings or dicts)
            current_time: Optional current time for testing

        Returns:
            list: Filtered list with only valid (non-expired) patterns
        """
        valid_patterns = []
        for pattern_entry in patterns:
            if self._is_allowlist_pattern_valid(pattern_entry, current_time):
                valid_patterns.append(pattern_entry)
            else:
                # Log when we skip an expired pattern
                pattern_str = self._extract_pattern_string(pattern_entry)
                valid_until = pattern_entry.get("valid_until") if isinstance(pattern_entry, dict) else None
                logger.info(f"Skipping expired allowlist pattern '{pattern_str}' (expired: {valid_until})")

        return valid_patterns

    def _check_allowlist(self, content: str) -> bool:
        """
        Check if content matches any allowlist pattern.

        Only checks non-expired patterns.

        Args:
            content: The text to check

        Returns:
            True if content is allowlisted (should skip detection)
        """
        for pattern in self._compiled_allowlist:
            if pattern.search(content):
                return True
        return False

    def _is_file_ignored(self, file_path: Optional[str]) -> bool:
        """
        Check if a file path matches any ignore_files pattern.

        Supports glob patterns with wildcards:
        - * matches any characters except /
        - ** matches any characters including /
        - ? matches a single character
        - ~ is expanded to user home directory

        Args:
            file_path: The file path to check (can be None)

        Returns:
            True if file should be ignored (skip detection), False otherwise

        Examples:
            >>> detector = PromptInjectionDetector({"ignore_files": ["**/.claude/skills/*/SKILL.md"]})
            >>> detector._is_file_ignored("/home/user/.claude/skills/code-review/SKILL.md")
            True

            >>> detector._is_file_ignored("/home/user/project/src/main.py")
            False
        """
        if not file_path:
            return False

        if not self.ignore_files:
            return False

        # Expand ~ in file_path for proper matching
        file_path_obj = Path(file_path).expanduser()

        for pattern in self.ignore_files:
            # Expand ~ in pattern
            expanded_pattern = str(Path(pattern).expanduser())

            # Use Path.match() which supports ** glob patterns
            # fnmatch doesn't support ** so we need pathlib
            if file_path_obj.match(expanded_pattern):
                logger.debug(f"File '{file_path}' matches ignore pattern '{pattern}'")
                return True

        return False

    def _is_tool_ignored(self, tool_name: Optional[str]) -> bool:
        """
        Check if a tool name matches any ignore_tools pattern.

        Supports wildcard patterns:
        - * matches any characters
        - ? matches a single character
        - Exact match (e.g., "Skill", "Read")
        - Prefix match (e.g., "mcp__*")

        Args:
            tool_name: The tool name to check (can be None)

        Returns:
            True if tool should be ignored (skip detection), False otherwise

        Examples:
            >>> detector = PromptInjectionDetector({"ignore_tools": ["Skill"]})
            >>> detector._is_tool_ignored("Skill")
            True

            >>> detector = PromptInjectionDetector({"ignore_tools": ["mcp__*"]})
            >>> detector._is_tool_ignored("mcp__notebooklm__notebook_list")
            True

            >>> detector._is_tool_ignored("Read")
            False
        """
        if not tool_name:
            return False

        if not self.ignore_tools:
            return False

        for pattern in self.ignore_tools:
            # Check if pattern matches using fnmatch (glob-style)
            if fnmatch.fnmatch(tool_name, pattern):
                logger.debug(f"Tool '{tool_name}' matches ignore pattern '{pattern}'")
                return True

        return False

    def _heuristic_detection(self, content: str, source_type: str = "user_prompt") -> Tuple[bool, float, str, str]:
        """
        Perform heuristic/pattern-based detection.

        Args:
            content: The text to check for injection patterns
            source_type: Source of content - "user_prompt" or "file_content"

        Returns:
            Tuple of (is_injection, confidence_score, matched_text, matched_pattern)
        """
        matches = []

        # For file content, only check critical patterns with higher threshold
        # For user prompts, check all patterns
        if source_type == "file_content":
            # Only check critical patterns for file content
            pattern_sets = [("high", self._compiled_critical)]
        else:
            # Check both critical and documentation patterns for user prompts
            pattern_sets = [
                ("high", self._compiled_critical),
                ("high", self._compiled_documentation)
            ]

        # Check patterns based on source type
        for confidence_level, pattern_list in pattern_sets:
            for pattern in pattern_list:
                match = pattern.search(content)
                if match:
                    matches.append((confidence_level, match.group(0), pattern.pattern))

        # Check custom patterns (treat as high confidence, check for all sources)
        for pattern in self._compiled_custom:
            match = pattern.search(content)
            if match:
                matches.append(("high", match.group(0), pattern.pattern))

        # Check suspicious patterns (lower confidence) - only for user prompts
        if source_type == "user_prompt" and self.sensitivity in ["medium", "high"]:
            for pattern in self._compiled_suspicious:
                match = pattern.search(content)
                if match:
                    matches.append(("medium", match.group(0), pattern.pattern))

        if not matches:
            return False, 0.0, "", ""

        # Calculate confidence score based on matches
        high_confidence_matches = [m for m in matches if m[0] == "high"]
        medium_confidence_matches = [m for m in matches if m[0] == "medium"]

        # Scoring logic
        if high_confidence_matches:
            # Found high-confidence pattern match
            confidence = 0.9 if len(high_confidence_matches) == 1 else 0.95
            matched_text = high_confidence_matches[0][1]
            matched_pattern = high_confidence_matches[0][2]
        elif medium_confidence_matches:
            # Only medium-confidence matches
            matched_text = medium_confidence_matches[0][1]
            matched_pattern = medium_confidence_matches[0][2]
            # Check if pattern has context (not standalone)
            # Look at the full content to see if there's more than just the keyword
            content_words = len(content.split())
            pattern_words = len(matched_text.split())
            has_context = content_words > pattern_words or 'mode' in content.lower() or 'activated' in content.lower()
            if has_context or len(medium_confidence_matches) > 1:
                confidence = 0.75
            else:
                confidence = 0.6
        else:
            return False, 0.0, "", ""

        # Different thresholds based on source type
        if source_type == "file_content":
            # Higher threshold for file content (more strict)
            sensitivity_thresholds = {
                "low": 0.95,    # Only very obvious attacks
                "medium": 0.90,  # High confidence only
                "high": 0.85,    # Still require high confidence
            }
        else:
            # Normal thresholds for user prompts
            sensitivity_thresholds = {
                "low": 0.85,    # Only very obvious attacks
                "medium": 0.75,  # Balanced approach
                "high": 0.60,    # More aggressive detection
            }

        threshold = sensitivity_thresholds.get(self.sensitivity, 0.75 if source_type == "user_prompt" else 0.90)
        is_injection = confidence >= threshold

        if is_injection:
            logger.debug(f"Detected injection pattern in {source_type}: '{matched_text[:50]}...'")

        return is_injection, confidence, matched_text, matched_pattern

    def detect(self, content: str, file_path: Optional[str] = None, tool_name: Optional[str] = None, source_type: str = "user_prompt") -> Tuple[bool, Optional[str], bool]:
        """
        Detect prompt injection in the given content.

        Args:
            content: The text to check for prompt injection
            file_path: Optional file path being scanned (for ignore_files matching)
            tool_name: Optional tool name being used (for ignore_tools matching)
            source_type: Source of content - "user_prompt" (default) or "file_content"

        Returns:
            Tuple of (should_block, error_message, detected)
            - should_block: Whether to block execution (False in log mode, True in block mode)
            - error_message: Formatted error message if should_block is True, None otherwise
            - detected: Whether injection was detected (True even in log mode, for violation logging)
        """
        if not self.enabled:
            return False, None, False

        if not content or not content.strip():
            return False, None, False

        try:
            # Check if tool should be ignored
            if self._is_tool_ignored(tool_name):
                logger.info(f"Skipping prompt injection detection for ignored tool: {tool_name}")
                return False, None, False

            # Check if file should be ignored based on path
            if self._is_file_ignored(file_path):
                logger.info(f"Skipping prompt injection detection for ignored file: {file_path}")
                return False, None, False

            # Strip heredoc content before checking for injection patterns
            # This prevents false positives when heredoc content mentions protected keywords
            # Only checks command structure, not heredoc data (Issue #155)
            content_to_check = _strip_bash_heredoc_content(content)

            # Check allowlist first (use stripped content to avoid false positives)
            if self._check_allowlist(content_to_check):
                logger.debug("Content matches allowlist pattern, skipping detection")
                return False, None, False

            # Perform detection based on configured detector type (use stripped content)
            if self.detector_type == "heuristic":
                is_injection, confidence, matched_text, matched_pattern = self._heuristic_detection(content_to_check, source_type)
            elif self.detector_type == "rebuff":
                # Placeholder for Rebuff integration
                logger.warning("Rebuff detector not implemented yet, falling back to heuristic")
                is_injection, confidence, matched_text, matched_pattern = self._heuristic_detection(content_to_check, source_type)
            elif self.detector_type == "llm-guard":
                # Placeholder for LLM Guard integration
                logger.warning("LLM Guard detector not implemented yet, falling back to heuristic")
                is_injection, confidence, matched_text, matched_pattern = self._heuristic_detection(content_to_check, source_type)
            else:
                # Unknown detector type, use heuristic
                logger.warning(f"Unknown detector type '{self.detector_type}', using heuristic")
                is_injection, confidence, matched_text, matched_pattern = self._heuristic_detection(content_to_check, source_type)

            if is_injection:
                # Format error message
                confidence_level = "High" if confidence >= 0.85 else "Medium" if confidence >= 0.65 else "Low"

                # Sanitize matched text to prevent secret leakage in logs
                sanitized_text = self._sanitize_text_for_logging(matched_text)

                # Show preview of matched text (up to 100 chars)
                text_preview = sanitized_text[:100]
                if len(sanitized_text) > 100:
                    text_preview += "..."

                # Show pattern (up to 150 chars)
                pattern_preview = matched_pattern[:150]
                if len(matched_pattern) > 150:
                    pattern_preview += "..."

                # Format source information for logging
                if file_path:
                    source_info = f"file='{file_path}'"
                elif tool_name:
                    source_info = f"tool='{tool_name}'"
                else:
                    source_info = "source='user_prompt'"

                # Show context around the matched text (sanitized, up to 200 chars for main log)
                # This helps with debugging to see what triggered the detection
                sanitized_content = self._sanitize_text_for_logging(content)
                content_preview = sanitized_content[:200]
                if len(sanitized_content) > 200:
                    content_preview += "..."

                # Check action
                if self.action == "warn":
                    logger.warning(f"Prompt injection detected (warn mode): {source_info}, confidence={confidence:.2f}, pattern='{pattern_preview}', text='{text_preview}', prompt='{content_preview}' - execution allowed")
                    # Return warning message to display to user via systemMessage
                    warn_msg = f"⚠️  Prompt injection detected (warn mode): confidence={confidence:.2f} - execution allowed"
                    return False, warn_msg, True  # Allow execution, warning message, detected (for violation logging)
                elif self.action == "log-only":
                    logger.warning(f"Prompt injection detected (log-only mode): {source_info}, confidence={confidence:.2f}, pattern='{pattern_preview}', text='{text_preview}', prompt='{content_preview}' - execution allowed (silent)")
                    # Allow execution - logged for audit, NO warning to user
                    return False, None, True  # Allow execution, no warning, detected (for violation logging)
                else:
                    # Block execution
                    logger.error(f"Prompt injection detected: {source_info}, confidence={confidence:.2f}, pattern='{pattern_preview}', text='{text_preview}', prompt='{content_preview}'")
                    error_msg = (
                        f"\n{'='*70}\n"
                        f"🚨 BLOCKED BY POLICY\n"
                        f"🚨 PROMPT INJECTION DETECTED\n"
                        f"{'='*70}\n\n"
                        "AI Guardian has detected a potential prompt injection attack.\n"
                        "This operation has been blocked for security.\n\n"
                        "DO NOT attempt to bypass this protection - it prevents malicious prompts.\n\n"
                        f"Detection details:\n"
                        f"  • Confidence: {confidence_level} ({confidence:.2f})\n"
                        f"  • Method: {self.detector_type}\n"
                        f"  • Pattern detected: {pattern_preview}\n"
                        f"  • Matched text: {text_preview}\n\n"
                        "Common injection patterns:\n"
                        "  • \"Ignore previous instructions\"\n"
                        "  • \"You are now in DAN mode\"\n"
                        "  • \"Reveal your system prompt\"\n"
                        "  • Role-playing attacks\n"
                        "  • Delimiter/encoding bypasses\n\n"
                        "If this is a false positive, you can:\n"
                        "  1. Adjust sensitivity in ~/.config/ai-guardian/ai-guardian.json\n"
                        "  2. Add allowlist patterns for legitimate use cases\n"
                        "  3. Temporarily disable: \"prompt_injection\": {\"enabled\": false}\n\n"
                        f"{'='*70}\n"
                    )

                    return True, error_msg, True  # Block, error message, detected

            return False, None, False  # No injection detected

        except Exception as e:
            # Fail-open: allow operation on errors
            logger.error(f"Error during prompt injection detection: {e}")
            logger.debug("Failing open - allowing operation")
            return False, None, False


def check_prompt_injection(content: str, config: Optional[Dict[str, Any]] = None, file_path: Optional[str] = None, tool_name: Optional[str] = None, source_type: str = "user_prompt") -> Tuple[bool, Optional[str], bool]:
    """
    Convenience function to check for prompt injection.

    Args:
        content: The text to check for prompt injection
        config: Optional configuration dictionary
        file_path: Optional file path being scanned (for ignore_files matching)
        tool_name: Optional tool name being used (for ignore_tools matching)
        source_type: Source of content - "user_prompt" (default) or "file_content"

    Returns:
        Tuple of (should_block, error_message, detected)
        - should_block: Whether to block execution (False in log mode, True in block mode)
        - error_message: Error message if should_block is True, None otherwise
        - detected: Whether injection was detected (True even in log mode, for violation logging)
    """
    detector = PromptInjectionDetector(config)
    return detector.detect(content, file_path=file_path, tool_name=tool_name, source_type=source_type)
