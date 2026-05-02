"""
Secret Redactor - Redacts sensitive information from text while preserving context.

This module provides defense-in-depth secret redaction for tool outputs, allowing work
to continue while protecting credentials. Instead of blocking operations entirely when
secrets are detected, the redactor sanitizes outputs by masking sensitive data.

Part of Phase 4: Hermes Security Patterns Integration (Issue #197)
NEW in v1.5.0: Optional pattern server support for enterprise secret pattern management.
NEW in v1.6.0: PII detection for GDPR/CCPA compliance (Issue #262).
"""

import re
import logging
from typing import List, Dict, Tuple, Optional

from ai_guardian.config_utils import validate_regex_pattern
from ai_guardian import allowlist_utils

logger = logging.getLogger(__name__)


class SecretRedactor:
    """
    Redacts secrets from text using multiple masking strategies.

    Supports 35+ secret types including API keys, tokens, credentials, and private keys.
    Uses different masking strategies to preserve debugging context while hiding secrets.
    """

    # Pattern definitions: (regex, strategy, secret_type)
    # Strategy determines how the secret is masked
    PATTERNS = [
        # OpenAI API Keys
        (r'(sk-[A-Za-z0-9]{20,})', 'preserve_prefix_suffix', 'OpenAI API Key'),
        (r'(sk-proj-[A-Za-z0-9]{20,})', 'preserve_prefix_suffix', 'OpenAI Project Key'),

        # GitHub Tokens
        (r'(ghp_[A-Za-z0-9]{36,})', 'preserve_prefix_suffix', 'GitHub Personal Token'),
        (r'(gho_[A-Za-z0-9]{36,})', 'preserve_prefix_suffix', 'GitHub OAuth Token'),
        (r'(ghr_[A-Za-z0-9]{36,})', 'preserve_prefix_suffix', 'GitHub Refresh Token'),
        (r'(ghs_[A-Za-z0-9]{36,})', 'preserve_prefix_suffix', 'GitHub Secret Token'),

        # Anthropic API Keys
        (r'(sk-ant-[A-Za-z0-9\-_]{32,})', 'preserve_prefix_suffix', 'Anthropic API Key'),

        # GitLab Tokens
        (r'(glpat-[A-Za-z0-9\-_]{20,})', 'preserve_prefix_suffix', 'GitLab Personal Token'),

        # Slack Tokens
        (r'(xox[baprs]-[A-Za-z0-9\-]+)', 'preserve_prefix_suffix', 'Slack Token'),

        # AWS Access Keys (full redact - very sensitive)
        (r'\b(AKIA[A-Z0-9]{16})\b', 'full_redact', 'AWS Access Key'),

        # AWS Secret Access Keys (full redact)
        (r'(aws_secret_access_key\s*=\s*)([^\s]+)', 'aws_secret', 'AWS Secret Key'),

        # Google Tokens
        (r'(ya29\.[A-Za-z0-9\-_]+)', 'preserve_prefix_suffix', 'Google OAuth Token'),
        (r'(AIza[A-Za-z0-9\-_]{35})', 'preserve_prefix_suffix', 'Google API Key'),

        # Azure Client Secrets (requires context to avoid matching all UUIDs)
        (r'(?:client.?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'preserve_prefix_suffix', 'Azure Client Secret'),

        # npm Tokens
        (r'(npm_[A-Za-z0-9]{36})', 'preserve_prefix_suffix', 'npm Token'),

        # PyPI Tokens
        (r'(pypi-[A-Za-z0-9\-_]{43,})', 'preserve_prefix_suffix', 'PyPI Token'),

        # Stripe Keys
        (r'(sk_live_[A-Za-z0-9]{24,})', 'preserve_prefix_suffix', 'Stripe Secret Key'),
        (r'(sk_test_[A-Za-z0-9]{24,})', 'preserve_prefix_suffix', 'Stripe Test Secret Key'),
        (r'(pk_live_[A-Za-z0-9]{24,})', 'preserve_prefix_suffix', 'Stripe Public Key'),
        (r'(pk_test_[A-Za-z0-9]{24,})', 'preserve_prefix_suffix', 'Stripe Test Public Key'),
        (r'(rk_live_[A-Za-z0-9]{24,})', 'preserve_prefix_suffix', 'Stripe Restricted Key'),
        (r'(rk_test_[A-Za-z0-9]{24,})', 'preserve_prefix_suffix', 'Stripe Test Restricted Key'),

        # Twilio API Keys
        (r'(SK[A-Za-z0-9]{32})', 'preserve_prefix_suffix', 'Twilio API Key'),

        # SendGrid API Keys
        (r'(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})', 'preserve_prefix_suffix', 'SendGrid API Key'),

        # Mailgun API Keys
        (r'(key-[A-Za-z0-9]{32})', 'preserve_prefix_suffix', 'Mailgun API Key'),

        # Private Keys (full redact - very sensitive)
        (r'(-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----)', 'private_key', 'Private Key'),

        # Environment variable assignments (keeps variable name)
        (r'([A-Z_][A-Z0-9_]*)\s*=\s*(["\']?)([A-Za-z0-9\-_+/=]{16,})\2', 'env_assignment', 'Environment Variable'),
        (r'(export\s+[A-Z_][A-Z0-9_]*)\s*=\s*(["\']?)([A-Za-z0-9\-_+/=]{16,})\2', 'env_assignment', 'Exported Environment Variable'),

        # JSON fields (preserves structure)
        (r'"(api[_-]?key)"\s*:\s*"([^"]{16,})"', 'json_field', 'JSON API Key'),
        (r'"(token)"\s*:\s*"([^"]{16,})"', 'json_field', 'JSON Token'),
        (r'"(password)"\s*:\s*"([^"]{16,})"', 'json_field', 'JSON Password'),
        (r'"(secret)"\s*:\s*"([^"]{16,})"', 'json_field', 'JSON Secret'),

        # YAML/Config file passwords (password: value format)
        (r'(password:\s*)([^\s\n]{8,})', 'yaml_password', 'YAML Password'),

        # HTTP Authorization headers
        (r'(Authorization:\s*Bearer\s+)([A-Za-z0-9\-._~+/]+=*)', 'auth_header', 'Bearer Token'),
        (r'(X-API-Key:\s*)([^\s]+)', 'header_value', 'API Key Header'),
        (r'(X-Auth-Token:\s*)([^\s]+)', 'header_value', 'Auth Token Header'),

        # Database connection strings (preserves endpoint)
        (r'(mongodb://[^:]+:)([^@]+)(@[^\s]+)', 'connection_string', 'MongoDB Connection'),
        (r'(mysql://[^:]+:)([^@]+)(@[^\s]+)', 'connection_string', 'MySQL Connection'),
        (r'(postgres://[^:]+:)([^@]+)(@[^\s]+)', 'connection_string', 'PostgreSQL Connection'),
        (r'(redis://[^:]*:)([^@]+)(@[^\s]+)', 'connection_string', 'Redis Connection'),

        # Generic long hex strings (potential secrets)
        # Requires context (secret/key/token/password) OR very long (100+ chars to avoid git SHAs)
        (r'((?:secret|key|token|password|credential)[\s"\'=:]+)([a-f0-9]{40,})\b', 'context_secret', 'Hex Secret'),
        (r'\b([a-f0-9]{100,})\b', 'preserve_prefix_suffix', 'Very Long Hex Secret'),

        # Base64 encoded secrets (long strings)
        # Requires context (secret/key/token/password) OR very long (100+ chars)
        (r'((?:secret|key|token|password|credential)[\s"\'=:]+)([A-Za-z0-9+/]{40,}={0,2})\b', 'context_secret', 'Base64 Secret'),
        (r'\b([A-Za-z0-9+/]{100,}={0,2})\b', 'preserve_prefix_suffix', 'Very Long Base64 Secret'),
    ]

    # PII pattern definitions keyed by type for selective loading (Issue #262)
    PII_PATTERNS = {
        'ssn': (r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', 'full_redact', 'SSN'),
        'credit_card': (r'\b(?:\d{4}[- ]?){3}\d{4}\b', 'credit_card', 'Credit Card Number'),
        'phone': (r'(?<!\d)(?:\+1[- ]?)?\(?\d{3}\)?[- .]\d{3}[- .]\d{4}(?!\d)', 'full_redact', 'US Phone Number'),
        'email': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'pii_email', 'Email Address'),
        'us_passport': (r'\b[A-Z]\d{8}\b', 'full_redact', 'US Passport Number'),
        'iban': (r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b', 'iban', 'IBAN'),
        'intl_phone': (r'\+\d{7,15}\b', 'full_redact', 'International Phone Number'),
    }

    @staticmethod
    def _luhn_check(number_str: str) -> bool:
        """Validate a number string using the Luhn algorithm."""
        digits = [int(d) for d in number_str if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    @staticmethod
    def _iban_check(iban_str: str) -> bool:
        """Validate an IBAN using the mod-97 algorithm."""
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

    def __init__(self, config: Optional[Dict] = None, pii_config: Optional[Dict] = None, pii_only: bool = False):
        """
        Initialize the SecretRedactor.

        Args:
            config: Optional configuration dict with:
                - enabled: bool - whether redaction is enabled (default: True)
                - action: str - "log-only" or "warn" (default: "warn")
                - preserve_format: bool - whether to preserve format in redactions (default: True)
                - additional_patterns: List[Dict] - custom patterns to add
                - log_redactions: bool - whether to log redaction events (default: True)
                - pattern_server: Dict - pattern server configuration (NEW in v1.5.0)
            pii_config: Optional PII scanning configuration dict with:
                - enabled: bool - whether PII detection is enabled (default: True)
                - pii_types: List[str] - PII types to detect (default: all)
                - action: str - "redact", "log-only", or "block" (default: "redact")
        """
        self.config = config or {}
        self.pii_config = pii_config or {}
        self.enabled = self.config.get('enabled', True)
        self.action = self.config.get('action', 'warn')
        self.preserve_format = self.config.get('preserve_format', True)
        self.log_redactions = self.config.get('log_redactions', True)

        self.pii_only = pii_only

        # Load patterns using pattern loader if pattern_server configured
        pattern_server_config = self.config.get('pattern_server')
        if pii_only:
            # Skip all secret patterns, only PII patterns will be loaded below
            patterns_to_use = []
        elif pattern_server_config:
            logger.info("Secret Redaction: Loading patterns via pattern server")
            patterns_to_use = self._load_patterns_via_server(pattern_server_config)
        else:
            # Use hardcoded default patterns
            patterns_to_use = [(p, s, t) for p, s, t in self.PATTERNS]

        # Compile all patterns for performance
        self.compiled_patterns = []
        for pattern_info in patterns_to_use:
            try:
                # Handle both tuple format (hardcoded) and dict format (pattern server)
                if isinstance(pattern_info, tuple):
                    pattern, strategy, secret_type = pattern_info
                else:
                    pattern = pattern_info.get('regex') or pattern_info.get('pattern')
                    strategy = pattern_info.get('strategy', 'preserve_prefix_suffix')
                    secret_type = pattern_info.get('secret_type', 'Unknown Secret')

                # Validate pattern before compilation (protects against ReDoS from pattern server)
                if not validate_regex_pattern(pattern):
                    logger.error(f"Pattern validation failed for {secret_type} (potential ReDoS or invalid syntax) - skipping")
                    continue

                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                self.compiled_patterns.append((compiled, strategy, secret_type))
            except (re.error, KeyError, TypeError) as e:
                logger.warning(f"Failed to compile pattern for {secret_type if isinstance(pattern_info, tuple) else pattern_info.get('secret_type', 'unknown')}: {e}")

        # Add custom patterns from local config (always additive, skip in pii_only mode)
        additional = [] if pii_only else self.config.get('additional_patterns', [])
        for custom in additional:
            try:
                pattern = custom.get('pattern') or custom.get('regex')
                strategy = custom.get('strategy', 'preserve_prefix_suffix')
                secret_type = custom.get('type') or custom.get('secret_type', 'Custom Secret')

                # Validate pattern before compilation (protects against ReDoS)
                if not validate_regex_pattern(pattern):
                    logger.error(f"Custom pattern validation failed for {secret_type} (potential ReDoS or invalid syntax) - skipping")
                    continue

                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                self.compiled_patterns.append((compiled, strategy, secret_type))
                logger.debug(f"Added custom pattern: {secret_type}")
            except (re.error, KeyError, TypeError) as e:
                logger.warning(f"Failed to compile custom pattern: {e}")

        # Load PII patterns if enabled (Issue #262)
        if self.pii_config.get('enabled', False):
            pii_types = self.pii_config.get('pii_types',
                ['ssn', 'credit_card', 'phone', 'us_passport', 'iban', 'intl_phone'])
            for pii_type in pii_types:
                if pii_type in self.PII_PATTERNS:
                    pattern, strategy, label = self.PII_PATTERNS[pii_type]
                    try:
                        if not validate_regex_pattern(pattern):
                            logger.error(f"PII pattern validation failed for {label} - skipping")
                            continue
                        compiled = re.compile(pattern)
                        self.compiled_patterns.append((compiled, strategy, label))
                        logger.debug(f"Added PII pattern: {label}")
                    except re.error as e:
                        logger.warning(f"Failed to compile PII pattern for {label}: {e}")
            logger.info(f"PII Detection: Loaded patterns for {pii_types}")

        # Compile PII allowlist patterns (Issue #357)
        raw_allowlist = self.pii_config.get('allowlist_patterns', [])
        self._compiled_pii_allowlist = allowlist_utils.compile_allowlist(raw_allowlist)
        if self._compiled_pii_allowlist:
            logger.info(f"PII Allowlist: {len(self._compiled_pii_allowlist)} active patterns")

        logger.info(f"Secret Redaction: Loaded {len(self.compiled_patterns)} patterns")

    def _load_patterns_via_server(self, pattern_server_config: Dict) -> List:
        """
        Load patterns via pattern server with fallback to defaults.

        Args:
            pattern_server_config: Pattern server configuration

        Returns:
            List of patterns (either from server or defaults)
        """
        try:
            from ai_guardian.pattern_loader import SecretPatternLoader

            loader = SecretPatternLoader()
            merged_patterns = loader.load_patterns(
                pattern_server_config=pattern_server_config, local_config=self.config
            )

            # Convert pattern loader format to list of dicts
            server_patterns = merged_patterns.get('patterns', [])

            if server_patterns:
                logger.info(f"Loaded {len(server_patterns)} patterns from pattern server/cache/defaults")
                return server_patterns
            else:
                logger.warning("Pattern server returned no patterns, using hardcoded defaults")
                return [(p, s, t) for p, s, t in self.PATTERNS]

        except ImportError:
            logger.error("pattern_loader module not available, using hardcoded defaults")
            return [(p, s, t) for p, s, t in self.PATTERNS]
        except Exception as e:
            logger.error(f"Error loading patterns from pattern server: {e}")
            logger.info("Falling back to hardcoded default patterns")
            return [(p, s, t) for p, s, t in self.PATTERNS]

    def redact(self, text: str) -> Dict:
        """
        Redact secrets from text.

        Args:
            text: Input text that may contain secrets

        Returns:
            Dict with:
                - redacted_text: str - Text with secrets redacted
                - redactions: List[Dict] - List of redaction metadata
                - original_length: int - Length of original text
                - redacted_length: int - Length of redacted text
        """
        if not self.enabled or not text:
            return {
                'redacted_text': text,
                'redactions': [],
                'original_length': len(text) if text else 0,
                'redacted_length': len(text) if text else 0
            }

        redacted_text = text
        redactions = []

        # Track already redacted regions to avoid overlapping redactions
        redacted_regions = []

        # Process patterns in priority order (specific → generic)
        for compiled_pattern, strategy, secret_type in self.compiled_patterns:
            matches = list(compiled_pattern.finditer(redacted_text))

            for match in matches:
                start, end = match.span()

                # Skip if this region was already redacted
                if any(r_start <= start < r_end or r_start < end <= r_end
                       for r_start, r_end in redacted_regions):
                    continue

                # Apply redaction strategy
                original = match.group(0)

                # Skip if match is allowlisted (Issue #357)
                if self._compiled_pii_allowlist and allowlist_utils.check_allowlist(
                    original, self._compiled_pii_allowlist
                ):
                    logger.debug(f"PII match allowlisted: {secret_type}")
                    continue

                redacted, metadata = self._apply_strategy(match, strategy, secret_type)

                # Skip if strategy returned None (e.g., failed Luhn/IBAN validation)
                if redacted is None:
                    continue

                # Replace in text
                redacted_text = redacted_text[:start] + redacted + redacted_text[end:]

                # Track redacted region (adjust for length change)
                length_diff = len(redacted) - len(original)
                new_region = (start, start + len(redacted))

                # Adjust future regions for length change (BEFORE adding new region)
                redacted_regions = [
                    (s + length_diff if s > start else s,
                     e + length_diff if e > start else e)
                    for s, e in redacted_regions
                ]

                # Now append the new region (after adjustment to avoid self-corruption)
                redacted_regions.append(new_region)

                # Record redaction
                line_start = text.rfind('\n', 0, start) + 1
                redactions.append({
                    'type': secret_type,
                    'position': start,
                    'line_number': text[:start].count('\n') + 1,
                    'column': start - line_start + 1,
                    'original_length': len(original),
                    'redacted_length': len(redacted),
                    'strategy': strategy,
                    **metadata
                })

                if self.log_redactions:
                    logging.info(f"Redacted {secret_type} at position {start} using {strategy}")

        return {
            'redacted_text': redacted_text,
            'redactions': redactions,
            'original_length': len(text),
            'redacted_length': len(redacted_text)
        }

    def _apply_strategy(self, match: re.Match, strategy: str, secret_type: str) -> Tuple[str, Dict]:
        """
        Apply a masking strategy to a matched secret.

        Args:
            match: Regex match object
            strategy: Masking strategy name
            secret_type: Type of secret being redacted

        Returns:
            Tuple of (redacted_string, metadata_dict)
        """
        if strategy == 'preserve_prefix_suffix':
            return self._preserve_prefix_suffix(match)
        elif strategy == 'full_redact':
            return self._full_redact(secret_type)
        elif strategy == 'env_assignment':
            return self._redact_env_assignment(match)
        elif strategy == 'json_field':
            return self._redact_json_field(match)
        elif strategy == 'auth_header':
            return self._redact_auth_header(match)
        elif strategy == 'header_value':
            return self._redact_header_value(match)
        elif strategy == 'connection_string':
            return self._redact_connection_string(match)
        elif strategy == 'private_key':
            return ('[REDACTED PRIVATE KEY]', {'method': 'full'})
        elif strategy == 'aws_secret':
            return self._redact_aws_secret(match)
        elif strategy == 'yaml_password':
            return self._redact_yaml_password(match)
        elif strategy == 'context_secret':
            return self._redact_context_secret(match)
        elif strategy == 'credit_card':
            return self._redact_credit_card(match)
        elif strategy == 'pii_email':
            return self._redact_pii_email(match)
        elif strategy == 'iban':
            return self._redact_iban(match)
        else:
            # Default to preserve_prefix_suffix
            return self._preserve_prefix_suffix(match)

    def _preserve_prefix_suffix(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Preserve first 6 and last 4 characters, redact middle.

        Example: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx
                 -> sk-pro...1vwx
        """
        secret = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

        if len(secret) <= 18:
            # Too short to preserve format meaningfully
            return ('***', {'method': 'short'})

        # Preserve prefix and suffix - for debugging while hiding the secret
        prefix_len = min(6, len(secret) // 3)  # Max 6 chars, but not more than 1/3 of total
        suffix_len = min(4, len(secret) // 4)  # Max 4 chars, but not more than 1/4 of total

        prefix = secret[:prefix_len]
        suffix = secret[-suffix_len:]
        redacted = f"{prefix}...{suffix}"

        return (redacted, {'method': 'preserve_prefix_suffix', 'preserved_chars': prefix_len + suffix_len})

    def _full_redact(self, secret_type: str) -> Tuple[str, Dict]:
        """
        Completely redact the secret with a placeholder.

        Example: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                 -> [REDACTED AWS SECRET KEY]
        """
        placeholder = f"[HIDDEN {secret_type.upper()}]"
        return (placeholder, {'method': 'full'})

    def _redact_env_assignment(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact environment variable value but keep variable name.

        Example: AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                 -> AWS_SECRET_KEY=[HIDDEN]
        """
        var_name = match.group(1)
        # Check if there's a quote group
        if match.lastindex >= 3:
            # Has quote marks
            quote = match.group(2) if match.group(2) else ''
            redacted = f"{var_name}={quote}[HIDDEN]{quote}"
        else:
            redacted = f"{var_name}=[HIDDEN]"

        return (redacted, {'method': 'env_var', 'var_name': var_name})

    def _redact_json_field(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact JSON field value but preserve structure.

        Example: {"api_key": "sk-proj-abc123..."}
                 -> {"api_key": "[HIDDEN]"}
        """
        field_name = match.group(1)
        redacted = f'"{field_name}": "[HIDDEN]"'

        return (redacted, {'method': 'json', 'field_name': field_name})

    def _redact_auth_header(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact Authorization Bearer token but keep header name.

        Example: Authorization: Bearer sk-proj-abc123...
                 -> Authorization: Bearer [HIDDEN]
        """
        header_prefix = match.group(1)
        token = match.group(2)

        # For long tokens, preserve prefix/suffix
        if len(token) > 18:
            redacted_token = f"{token[:6]}...{token[-4:]}"
        else:
            redacted_token = "[HIDDEN]"

        redacted = f"{header_prefix}{redacted_token}"

        return (redacted, {'method': 'auth_header'})

    def _redact_header_value(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact HTTP header value but keep header name.

        Example: X-API-Key: abc123def456
                 -> X-API-Key: [HIDDEN]
        """
        header_name = match.group(1)
        redacted = f"{header_name}[HIDDEN]"

        return (redacted, {'method': 'header'})

    def _redact_connection_string(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact credentials in connection string but preserve endpoint.

        Example: mongodb://user:MySecretPass@db.example.com:27017/mydb
                 -> mongodb://user:[HIDDEN]@db.example.com:27017/mydb
        """
        prefix = match.group(1)  # protocol://user:
        # password is group(2)
        suffix = match.group(3)  # @host:port/db

        redacted = f"{prefix}[HIDDEN]{suffix}"

        return (redacted, {'method': 'connection_string'})

    def _redact_aws_secret(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact AWS secret access key.

        Example: aws_secret_access_key = wJalrXUtnFEMI...
                 -> aws_secret_access_key = [HIDDEN]
        """
        prefix = match.group(1)  # "aws_secret_access_key = "
        redacted = f"{prefix}[HIDDEN]"

        return (redacted, {'method': 'aws_secret'})

    def _redact_yaml_password(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact password in YAML/config format.

        Example: password: MySecretPass123
                 -> password: [HIDDEN]
        """
        prefix = match.group(1)  # "password: "
        redacted = f"{prefix}[HIDDEN]"

        return (redacted, {'method': 'yaml_password'})

    def _redact_context_secret(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact secret with context keyword prefix.

        Preserves the context keyword (secret, key, token, etc.) and separator,
        but redacts the secret value using prefix/suffix preservation.

        Example: api_secret: abcdef1234567890abcdef1234567890abcdef123456
                 -> api_secret: abcdef...123456
        """
        context_prefix = match.group(1)  # "secret: ", "key=", etc.
        secret = match.group(2)  # The actual secret value

        # Redact the secret part using prefix/suffix preservation
        if len(secret) <= 18:
            # Too short to preserve format meaningfully
            redacted_secret = '***'
        else:
            # Preserve prefix and suffix for debugging while hiding the secret
            prefix_len = min(6, len(secret) // 3)
            suffix_len = min(4, len(secret) // 4)
            prefix = secret[:prefix_len]
            suffix = secret[-suffix_len:]
            redacted_secret = f"{prefix}...{suffix}"

        redacted = f"{context_prefix}{redacted_secret}"

        return (redacted, {'method': 'context_secret', 'context': context_prefix.strip()})

    def _redact_credit_card(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact credit card number after Luhn validation.

        Returns (None, None) if the number fails Luhn check (not a real CC).
        """
        number = match.group(0)
        digits_only = re.sub(r'[- ]', '', number)
        if not self._luhn_check(digits_only):
            return (None, None)
        last_four = digits_only[-4:]
        return (f"[HIDDEN CREDIT CARD ****{last_four}]", {'method': 'credit_card', 'last_four': last_four})

    def _redact_pii_email(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact email address, preserving the domain.

        Example: john.doe@example.com -> [HIDDEN]@example.com
        """
        email = match.group(0)
        at_idx = email.rfind('@')
        domain = email[at_idx + 1:]
        return (f"[HIDDEN]@{domain}", {'method': 'pii_email', 'domain': domain})

    def _redact_iban(self, match: re.Match) -> Tuple[str, Dict]:
        """
        Redact IBAN after mod-97 validation.

        Returns (None, None) if the string fails IBAN check.
        """
        iban = match.group(0)
        if not self._iban_check(iban):
            return (None, None)
        country = iban[:2]
        last_four = iban[-4:]
        return (f"[HIDDEN IBAN {country}****{last_four}]", {'method': 'iban', 'country': country})
