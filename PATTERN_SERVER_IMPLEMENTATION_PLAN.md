# Pattern Server Support Implementation Plan

**Issue**: #206 - Add Pattern Server Support for SSRF, Unicode, Config Scanner, and Secret Redaction
**Parent Epic**: #186 - Integrate Hermes Security Patterns
**Prerequisites**: Issues #194-198 (all CLOSED ✅)

## Executive Summary

Extend the existing `PatternServerClient` (currently used only for Gitleaks) to support optional pattern server integration for four new security features. Uses a hybrid three-tier approach balancing security and flexibility.

## Current State Analysis

### 1. SSRFProtector (`ssrf_protector.py`)

**Immutable Patterns** (lines 44-77):
- `CORE_BLOCKED_IP_RANGES`: 8 IP ranges (RFC 1918, loopback, link-local, IPv6)
- `CORE_BLOCKED_DOMAINS`: 6 domains (cloud metadata endpoints)
- `DANGEROUS_SCHEMES`: 8 URL schemes (file://, gopher://, etc.)

**Configurable Patterns**:
- `additional_blocked_ips` (local config)
- `additional_blocked_domains` (local config)
- `allow_localhost` flag (local config override)

**Integration Point**: Constructor merges core + additional patterns into `_blocked_ip_networks` and `_blocked_domains`

### 2. SecretRedactor (`secret_redactor.py`)

**Current Patterns** (lines 26-100+):
- `PATTERNS` list with 35+ tuples: `(regex, strategy, secret_type)`
- All hardcoded, no tier separation

**Configurable Patterns**:
- `additional_patterns` (local config, lines in schema)

**Integration Point**: Class-level PATTERNS list, no current pattern server support

### 3. UnicodeAttackDetector (`prompt_injection.py`)

**Immutable Patterns** (lines 44-73):
- `ZERO_WIDTH_CHARS`: 9 characters (Unicode spec-based)
- `BIDI_OVERRIDE_CHARS`: 2 characters (Unicode spec-based)
- `TAG_CHAR_START/END`: Deprecated Unicode tag range

**Overridable Patterns** (lines 77-150+):
- `HOMOGLYPH_PATTERNS`: 80+ character pairs (Cyrillic, Greek, Math symbols → Latin)
- New scripts emerge regularly, should be updateable

**Integration Point**: Class-level constants, no current pattern server support

### 4. ConfigFileScanner (`config_scanner.py`)

**Immutable Patterns** (lines 47-104):
- `CORE_EXFIL_PATTERNS`: 8 patterns (curl/wget env vars, AWS S3, GCP storage)

**Configurable Patterns**:
- `additional_patterns` (local config)

**Integration Point**: Constructor merges core + additional patterns

## Design: Three-Tier Pattern System

### Tier 1: IMMUTABLE (Hardcoded - Always Active)

Core security baselines that **cannot be disabled** even by pattern server:

| Feature | Immutable Patterns | Rationale |
|---------|-------------------|-----------|
| SSRF | `169.254.169.254`, `metadata.google.internal`, `file://` scheme | Cloud metadata, dangerous schemes |
| Unicode | Zero-width chars, bidi overrides | Based on Unicode spec, fundamental attacks |
| Config Scanner | Core exfiltration (env\|curl, aws s3 cp) | Fundamental credential theft vectors |
| Secret Redaction | N/A (no immutable patterns needed) | All patterns can be enterprise-customized |

### Tier 2: OVERRIDABLE (Pattern Server Can Replace)

Security team has full control - can modify/remove these:

| Feature | Overridable Patterns | Use Case |
|---------|---------------------|----------|
| SSRF | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918) | Dev teams need Docker access |
| Unicode | Homoglyph patterns | New scripts discovered |
| Config Scanner | Additional exfiltration patterns | Emerging attack vectors |
| Secret Redaction | All 35+ secret types | New secret formats |

### Tier 3: ADDITIONS (Local Config - Always Additive)

Users can extend via local config:

| Feature | Local Config Field | Behavior |
|---------|-------------------|----------|
| SSRF | `additional_blocked_ips/domains` | Add to effective list |
| Unicode | `additional_homoglyphs` | Add to effective list |
| Config Scanner | `additional_patterns` | Add to effective list |
| Secret Redaction | `additional_patterns` | Add to effective list |

## Pattern File Format: TOML

**Why TOML over JSON**:
- ✅ Native comment support (document WHY patterns exist)
- ✅ More human-readable (like INI files)
- ✅ Multiline strings (no escaping `\n`)
- ✅ Compatible with existing Gitleaks pattern server (already uses TOML)

### Example: `ssrf-patterns.toml`

```toml
# SSRF Protection Patterns
# Version: 1.0.0
# Updated: 2026-04-22T10:00:00Z

[metadata]
version = "1.0.0"
updated_at = 2026-04-22T10:00:00Z
override_mode = "replace"
source = "patterns.security.company.com"

[[blocked_ip_ranges]]
cidr = "10.0.0.0/8"
description = "Private network Class A (RFC 1918)"
added = 2026-01-01

[[blocked_ip_ranges]]
cidr = "100.64.0.0/10"
description = "Shared address space (CGNAT)"
added = 2026-02-15
rationale = "Company policy: block CGNAT ranges"

[[blocked_domains]]
domain = "internal.company.com"
description = "Company internal services"
added = 2026-04-01
rationale = "Prevent AI from accessing internal HR/payroll"
```

### Example: `secrets-patterns.toml`

```toml
# Secret Redaction Patterns
# Version: 1.0.0

[metadata]
version = "1.0.0"
override_mode = "extend"

[[patterns]]
regex = '(new-api-v2-[A-Za-z0-9]{32})'
strategy = "preserve_prefix_suffix"
secret_type = "New API v2 Key"
added = 2026-04-22
rationale = "New secret format introduced in Q2 2026"

[[patterns]]
regex = '(acme-corp-token-[A-Za-z0-9\-_]{40})'
strategy = "preserve_prefix_suffix"
secret_type = "ACME Corp Internal Token"
```

## Implementation Architecture

### Phase 1: Core Infrastructure

#### 1.1 Extend `PatternServerClient` (`pattern_server.py`)

**New Methods**:
```python
def get_patterns_by_type(self, pattern_type: str) -> Optional[Dict[str, Any]]:
    """
    Get patterns for specific type (ssrf, unicode, config-exfil, secrets).
    
    Args:
        pattern_type: One of "ssrf", "unicode", "config-exfil", "secrets"
    
    Returns:
        Parsed TOML patterns dict, or None if unavailable
    """

def _get_patterns_endpoint_for_type(self, pattern_type: str) -> str:
    """
    Build endpoint path for pattern type.
    
    Examples:
        "ssrf" -> "/patterns/ssrf/v1"
        "secrets" -> "/patterns/secrets/v1"
    """
```

**Configuration Changes**:
```python
# Current: Single endpoint
{
    "pattern_server": {
        "url": "https://patterns.security.company.com",
        "patterns_endpoint": "/patterns/gitleaks/8.18.1"
    }
}

# New: Multiple endpoints per feature
{
    "ssrf_protection": {
        "pattern_server": {
            "url": "https://patterns.security.company.com",
            "patterns_endpoint": "/patterns/ssrf/v1",
            "allow_override": true,
            "validate_critical": true
        }
    }
}
```

#### 1.2 Create `PatternLoader` Base Class

```python
class PatternLoader(ABC):
    """Base class for loading patterns from pattern server."""
    
    @abstractmethod
    def load_from_server(self, client: PatternServerClient) -> Dict[str, Any]:
        """Load patterns from pattern server."""
        
    @abstractmethod
    def get_immutable_patterns(self) -> Dict[str, Any]:
        """Get patterns that cannot be overridden."""
        
    @abstractmethod
    def merge_patterns(self, 
                      immutable: Dict[str, Any],
                      server: Optional[Dict[str, Any]],
                      local: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge three tiers into effective configuration."""
```

**Implementations**:
- `SSRFPatternLoader`
- `UnicodePatternLoader`
- `ConfigExfilPatternLoader`
- `SecretPatternLoader`

### Phase 2: Feature Integration

#### 2.1 SSRFProtector Integration

**Changes**:
1. Split `CORE_BLOCKED_IP_RANGES` into:
   - `IMMUTABLE_IP_RANGES` (cannot override): `169.254.0.0/16`, metadata endpoints
   - `DEFAULT_IP_RANGES` (can override): RFC 1918 ranges

2. Add pattern loader initialization:
```python
def __init__(self, config: Optional[Dict[str, Any]] = None):
    self.config = config or {}
    
    # Load pattern server config if present
    pattern_server_config = self.config.get("pattern_server")
    if pattern_server_config:
        loader = SSRFPatternLoader()
        client = PatternServerClient(pattern_server_config)
        server_patterns = loader.load_from_server(client)
    else:
        server_patterns = None
    
    # Three-tier merge
    final_patterns = self._merge_patterns(
        immutable=self.IMMUTABLE_IP_RANGES,
        server=server_patterns,
        local=self.config.get("additional_blocked_ips", [])
    )
```

3. Add source attribution tracking:
```python
self._pattern_sources = {
    "169.254.169.254": "IMMUTABLE",
    "10.0.0.0/8": "SERVER" if from_server else "DEFAULT",
    "admin.company.com": "LOCAL_CONFIG"
}
```

#### 2.2 SecretRedactor Integration

**Changes**:
1. No immutable patterns needed (all can be enterprise-customized)

2. Pattern loader:
```python
def __init__(self, config: Optional[Dict[str, Any]] = None):
    # Load default patterns
    default_patterns = self.PATTERNS.copy()
    
    # Load from pattern server if configured
    pattern_server_config = self.config.get("pattern_server")
    if pattern_server_config:
        loader = SecretPatternLoader()
        client = PatternServerClient(pattern_server_config)
        server_patterns = loader.load_from_server(client)
        
        override_mode = server_patterns.get("metadata", {}).get("override_mode", "extend")
        if override_mode == "replace":
            final_patterns = server_patterns["patterns"]
        else:
            final_patterns = default_patterns + server_patterns["patterns"]
    else:
        final_patterns = default_patterns
    
    # Add local config patterns
    final_patterns += self.config.get("additional_patterns", [])
```

#### 2.3 UnicodeAttackDetector Integration

**Changes**:
1. Mark immutable patterns:
   - `ZERO_WIDTH_CHARS` → Immutable (Unicode spec)
   - `BIDI_OVERRIDE_CHARS` → Immutable (Unicode spec)
   - `HOMOGLYPH_PATTERNS` → Overridable (emerging scripts)

2. Pattern loader for homoglyphs only

#### 2.4 ConfigFileScanner Integration

**Changes**:
1. Keep `CORE_EXFIL_PATTERNS` as immutable
2. Pattern loader for additional patterns only

### Phase 3: Configuration Schema

#### 3.1 Schema Updates (`ai-guardian-config.schema.json`)

Add `pattern_server` section to each feature:

```json
{
  "ssrf_protection": {
    "properties": {
      "pattern_server": {
        "type": ["object", "null"],
        "description": "Optional pattern server for SSRF patterns",
        "properties": {
          "url": {"type": "string"},
          "patterns_endpoint": {"type": "string", "default": "/patterns/ssrf/v1"},
          "allow_override": {"type": "boolean", "default": true},
          "validate_critical": {"type": "boolean", "default": true},
          "auth": {...},
          "cache": {...}
        }
      }
    }
  }
}
```

#### 3.2 Setup.py Updates

Add pattern_server to default configs:

```python
"ssrf_protection": {
    "enabled": True,
    "action": "block",
    "_comment_pattern_server": "Optional: Fetch SSRF patterns from enterprise server",
    "pattern_server": None  # Disabled by default
}
```

### Phase 4: show-config Command

#### 4.1 ConfigInspector Class

```python
class ConfigInspector:
    """Inspects and displays effective configuration with source attribution."""
    
    def show_ssrf_config(self, show_sources: bool = False):
        """Display SSRF protection config with pattern sources."""
        
    def show_diff(self):
        """Show what pattern server changed from defaults."""
        
    def export_json(self) -> Dict[str, Any]:
        """Export effective config as JSON."""
```

#### 4.2 CLI Command

```bash
ai-guardian show-config --feature ssrf_protection
ai-guardian show-config --feature ssrf_protection --show-sources
ai-guardian show-config --feature ssrf_protection --diff
ai-guardian show-config --output json > final-config.json
```

**Example Output**:
```
SSRF Protection Configuration
==============================

Blocked IP Ranges (Total: 7):
  ┌──────────────────┬──────────────────────┬─────────────┐
  │ CIDR             │ Description          │ Source      │
  ├──────────────────┼──────────────────────┼─────────────┤
  │ 169.254.0.0/16   │ AWS metadata         │ IMMUTABLE   │
  │ 172.16.0.0/12    │ Private Class B      │ Server      │
  │ admin.company.com│ Admin portal         │ Local Config│
  └──────────────────┴──────────────────────┴─────────────┘
  
  ⚠️  REMOVED by pattern server:
    • 10.0.0.0/8 (Private network Class A)
      Reason: Development teams need Docker access
```

## Safeguards

### 1. Critical Immutable List

Patterns that CANNOT be disabled by pattern server:
- SSRF: `169.254.169.254`, cloud metadata endpoints, `file://` scheme
- Unicode: Zero-width chars, bidi overrides
- Config Scanner: Core exfiltration patterns

### 2. Pattern Validation

```python
def validate_critical_patterns_present(self, patterns: Dict[str, Any]) -> bool:
    """
    Ensure critical patterns are present in final config.
    Auto-add if missing from pattern server.
    """
    for critical in self.CRITICAL_PATTERNS:
        if critical not in patterns:
            logger.warning(f"Critical pattern missing: {critical}, auto-adding")
            patterns.append(critical)
```

### 3. Config Flag Requirement

```python
if pattern_server_config.get("allow_override", False):
    # Only allow override if explicitly enabled
    apply_server_patterns()
else:
    logger.info("Pattern override disabled, using defaults")
```

### 4. Audit Logging

```python
logger.info("Pattern override applied", extra={
    "source": "pattern_server",
    "url": pattern_server_url,
    "override_mode": "replace",
    "patterns_added": 5,
    "patterns_removed": 1
})
```

### 5. Fallback Chain

```
1. Pattern Server (network fetch)
   ├─ SUCCESS → Cache + Use
   └─ FAIL → Try cache...

2. Cached Patterns (local file)
   ├─ EXISTS + NOT EXPIRED (<168h) → Use cache
   └─ EXPIRED/MISSING → Fallback...

3. Hardcoded Defaults (Python code)
   └─ ALWAYS AVAILABLE → Use defaults
```

## Testing Strategy

### Unit Tests

1. **PatternLoader tests**:
   - Test three-tier merge
   - Test immutable enforcement
   - Test override modes (replace vs extend)

2. **Feature integration tests**:
   - SSRFProtector with pattern server
   - SecretRedactor with pattern server
   - Unicode with pattern server
   - Config scanner with pattern server

3. **Fallback tests**:
   - Server unreachable → use cache
   - Cache expired → use defaults
   - Invalid patterns → reject and fallback

### Integration Tests

1. **End-to-end pattern server fetch**
2. **Override mode semantics**
3. **Source attribution accuracy**
4. **Performance validation (<20ms overhead)**

## Migration Path

### Backward Compatibility

✅ Works without pattern server (uses hardcoded defaults)
✅ Existing configs continue to work unchanged
✅ Pattern server is opt-in (config presence = enabled)

### Rollout Strategy

**Phase 1**: Deploy with pattern server disabled (default)
**Phase 2**: Create example pattern files and documentation
**Phase 3**: Enterprise teams pilot pattern server
**Phase 4**: Recommend pattern server for secret redaction (highest value)

## Success Metrics

- ✅ Security teams update patterns without code releases
- ✅ Dev teams can allow Docker via pattern server
- ✅ New secret formats deployed in <24h
- ✅ Critical protections remain immutable
- ✅ Full transparency via `show-config`
- ✅ Zero breaking changes
- ✅ Performance: <20ms overhead per feature

## Implementation Timeline

- **Phase 1**: Core Infrastructure (3-4 days)
- **Phase 2**: Feature Integration (5-6 days)
- **Phase 3**: Configuration & CLI (3-4 days)
- **Phase 4**: Examples & Documentation (2-3 days)
- **Phase 5**: Testing (3-4 days)
- **Phase 6**: Migration & Polish (2 days)

**Total**: 18-24 days (3.5-5 weeks)

## References

- **Existing**: `src/ai_guardian/pattern_server.py` (Gitleaks)
- **Epic**: #186 - Integrate Hermes Security Patterns
- **Prerequisites**: #194 (SSRF), #195 (Unicode), #196 (Config Scanner), #197 (Secret Redaction), #198 (Integration)
- **Issue**: #206 - Pattern Server Support

## Priority Assessment

**MEDIUM** - Optional enhancement, implement AFTER #194-198 complete ✅

**Highest value**: Secret Redaction (new formats emerge frequently)
**Lower value**: SSRF/Unicode/Config Scanner (stable patterns)

Can be implemented incrementally:
1. Start with Secret Redaction (highest ROI)
2. Add SSRF (second priority)
3. Add Unicode and Config Scanner later
