# TOML Pattern Engine

AI Guardian ships with 267 built-in detection patterns stored in TOML files. These patterns are loaded automatically at startup — **no configuration required**. All detection features (secret redaction, PII scanning, prompt injection, unicode attacks, SSRF, config exfiltration) use the bundled TOML patterns as their primary source.

## Zero-Config Usage

The TOML patterns work out of the box. All detection modules load them automatically:
- **Secret redaction** (PostToolUse) — loads `secrets.toml`
- **PII detection** — loads `pii.toml`
- **Prompt injection** — loads `prompt-injection.toml`
- **Unicode attacks** — loads `unicode.toml`
- **Config exfiltration** — loads `config-exfil.toml`
- **SSRF protection** — loads `ssrf.toml`

## Scanner SDK Engine (Optional)

For the secret scanning PreToolUse pipeline, `toml-patterns` is also available as a Scanner SDK engine. This is useful if you want to run it instead of (or alongside) gitleaks:

```json
{
  "secret_scanning": {
    "engines": ["toml-patterns"]
  }
}
```

Or use alongside external scanners:

```json
{
  "secret_scanning": {
    "engines": ["toml-patterns", "gitleaks"]
  }
}
```

## Bundled Pattern Files

AI Guardian ships with 267 pre-compiled rules across 6 categories:

| File | Category | Rules | Description |
|------|----------|-------|-------------|
| `secrets.toml` | Secret detection | 44 | API keys, tokens, credentials, connection strings |
| `pii.toml` | PII detection | 13 | SSN, credit cards, phone numbers, email, passports |
| `prompt-injection.toml` | Prompt injection | 73 | Jailbreaks, instruction override, exfiltration |
| `unicode.toml` | Unicode attacks | 107 | Homoglyphs, zero-width chars, bidi overrides |
| `config-exfil.toml` | Config exfiltration | 8 | Credential theft via curl, wget, aws s3 |
| `ssrf.toml` | SSRF protection | 22 | Private IPs, cloud metadata, dangerous schemes |

## Match Types

TOML rules support five match types:

| Type | Use Case | Example |
|------|----------|---------|
| `regex` | Secrets, PII, prompt injection | `regex = '''(sk-[A-Za-z0-9]{20,})'''` |
| `literal` | Homoglyph character mappings | `source = "а"`, `target = "a"` |
| `cidr` | SSRF IP ranges | `cidr = "10.0.0.0/8"` |
| `range` | Unicode codepoint ranges | `start = 917504`, `end = 917631` |
| `glob` | File ignore patterns | `glob = "**/node_modules/**"` |

## TOML Rule Format

```toml
[[rules]]
id = "openai-api-key"
match_type = "regex"
regex = '''(sk-[A-Za-z0-9]{20,})'''
redaction_strategy = "preserve_prefix_suffix"
description = "OpenAI API Key"
keywords = ["sk-"]
```

### Common Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique rule identifier |
| `match_type` | Yes | One of: regex, literal, cidr, range, glob |
| `description` | No | Human-readable description |
| `tier` | No | `immutable` or `overridable` (for pattern server merge) |
| `redaction_strategy` | No | How to mask matched text (secrets/PII only) |
| `validation` | No | Post-match validator: `luhn` or `iban` |
| `pii_type` | No | PII category for `scan_pii.types` filtering |
| `group` | No | Confidence group for prompt injection rules |

## Pattern Servers

Each violation type can load patterns from one or more remote servers. Servers are configured per section and support different TOML formats:

```json
{
  "secret_scanning": {
    "pattern_servers": [
      {
        "url": "https://patterns.company.com/secrets",
        "format": "ai-guardian",
        "auth": { "token_env": "PATTERN_TOKEN" }
      },
      {
        "url": "https://gitleaks-patterns.company.com",
        "format": "gitleaks",
        "auth": { "token_env": "GITLEAKS_TOKEN" }
      }
    ]
  }
}
```

### Supported Formats

| Format | Description |
|--------|-------------|
| `ai-guardian` | Native format (same as bundled TOML files) |
| `gitleaks` | Gitleaks TOML format (Go RE2 regex, auto-converted) |

The existing singular `pattern_server` key continues to work (treated as a single-entry array with `gitleaks` format).

## How It Works

1. **Load**: TOML files are parsed at startup (or on config reload)
2. **Compile**: All patterns are compiled into Python objects (regex, IP networks, dict lookups)
3. **Cache**: Compiled matchers are held in memory via `PatternCache`
4. **Scan**: Each hook call uses the pre-compiled cache — no parsing or compilation per request

The same compiled cache serves detection (PreToolUse), redaction (PostToolUse), and prompt scanning (UserPromptSubmit).

## RE2 Compatibility

Patterns are validated for Go RE2 compatibility at load time. Patterns using Python-only regex features are rejected with a warning:

- `\p{L}` (Unicode property escapes) — not supported in RE2
- `(?<=...)` (lookbehinds) — not supported in RE2
- `(?>...)` (atomic groups) — not supported in RE2

Rules can opt out of RE2 validation with `re2_compat = false` (used by some PII patterns that require lookbehinds).

## Performance

| Metric | toml-patterns | External scanner (gitleaks) |
|--------|---------------|----------------------------|
| Scan latency | ~1-5ms | ~50-100ms |
| Binary required | No | Yes |
| Startup cost | One-time TOML parse + compile | None per scan |
| Memory | Compiled regex cache | None |

## Relationship to Other Engines

The `toml-patterns` engine is **additive** — it does not replace gitleaks or betterleaks:

- **gitleaks**: Subprocess-based, uses its own pattern server, unchanged
- **betterleaks**: Subprocess-based, uses built-in rules, unchanged
- **toml-patterns**: In-process Python, uses bundled TOML + optional pattern servers

All engines can be used together via the `engines` list. The scanning strategy (`first-match`, `any-match`, `consensus`) determines how results are combined.
