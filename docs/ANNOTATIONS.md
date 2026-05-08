# Inline Annotation Suppression

Suppress false positives on specific lines without disabling scanning for entire files.

## Quick Reference

```python
secret = "test_key"          # ai-guardian:allow       <- suppresses secrets + PII
api_key = "AKIA..."          # gitleaks:allow          <- suppresses secrets only

# ai-guardian:begin-allow
multi_line_secret = "..."    # <- suppressed (secrets + PII)
ssn = "123-45-6789"          # <- suppressed (secrets + PII)
# ai-guardian:end-allow
```

## Annotation Types

### Inline - single line

Add the marker anywhere on the line. Works with any comment syntax:

| Language | Example |
|---|---|
| Python/Ruby/YAML | `value = "..."  # ai-guardian:allow` |
| JavaScript/Go/Rust | `value = "..."  // ai-guardian:allow` |
| HTML/XML | `value="..."  <!-- ai-guardian:allow -->` |
| CSS | `value: ...  /* ai-guardian:allow */` |
| SQL/Lua | `value = '...'  -- ai-guardian:allow` |

### Block - multiple lines

```python
# ai-guardian:begin-allow
secret1 = "..."
secret2 = "..."
pii = "123-45-6789"
# ai-guardian:end-allow
```

Both the begin/end marker lines and all lines between them are suppressed.

## What Each Marker Suppresses

| Marker | Suppresses | Configurable? |
|---|---|---|
| `ai-guardian:allow` | Secrets + PII | No (hardcoded) |
| `ai-guardian:begin-allow` / `end-allow` | Secrets + PII in block | No (hardcoded) |
| `gitleaks:allow` | Secrets only | Yes (default alias) |

`gitleaks:allow` does **not** suppress PII. Add custom aliases (e.g., `notsecret`) via `inline_allow_secrets` config.

## Configuration

```json
{
  "annotations": {
    "enabled": true,
    "inline_allow": [],
    "inline_allow_secrets": ["gitleaks:allow"],
    "block_begin": [],
    "block_end": []
  }
}
```

| Field | Purpose | Default |
|---|---|---|
| `enabled` | Enable/disable all annotation processing | `true` |
| `inline_allow` | Custom aliases that suppress ALL violations | `[]` |
| `inline_allow_secrets` | Custom aliases that suppress secrets only | `["gitleaks:allow"]` |
| `block_begin` | Custom block-begin aliases | `[]` |
| `block_end` | Custom block-end aliases | `[]` |

User config **extends** defaults. Adding `"nosec"` to `inline_allow` doesn't remove `ai-guardian:allow`.

### Example: add Bandit and IntelliJ aliases

```json
{
  "annotations": {
    "inline_allow": ["nosec", "noinspection"]
  }
}
```

Now `# nosec` and `# noinspection` suppress secrets + PII alongside the built-in `# ai-guardian:allow`.

### Example: add custom secrets-only alias

```json
{
  "annotations": {
    "inline_allow_secrets": ["notsecret"]
  }
}
```

Now `# notsecret` suppresses secrets alongside the built-in `# gitleaks:allow`.

### Disable for strict compliance

```json
{
  "annotations": {
    "enabled": false
  }
}
```

All annotations are ignored and every line is scanned.

## What Gets Suppressed

Annotations suppress **secrets and PII** detection, including both blocking and redaction:

- **PreToolUse** (before file read): suppressed lines are not scanned for secrets/PII, so the read is allowed
- **PostToolUse** (after file read): secrets and PII on suppressed lines are not redacted -- original content passes through unchanged

Prompt injection, jailbreak, and config exfiltration detection **cannot be suppressed by annotations**. This is by design -- a malicious file could insert annotations next to injection patterns to bypass protection.

| Annotation | Secrets | PII | Prompt Injection | Jailbreak | Config Exfil |
|---|---|---|---|---|---|
| `ai-guardian:allow` / block | Suppressed | Suppressed | **Always scanned** | **Always scanned** | **Always scanned** |
| `gitleaks:allow` | Suppressed | **Scanned** | **Always scanned** | **Always scanned** | **Always scanned** |

## Security Notes

- Annotations only affect **secrets and PII** -- never prompt injection, jailbreak, or config exfiltration
- Review annotations in code reviews -- treat them like `// NOSONAR` or `# nosec`
- Use `annotations.enabled: false` in strict compliance environments
- Monitor `annotation_suppressed` entries in violation logs

## Safety

- **Unmatched `begin-allow`** (no `end-allow`) is **ignored entirely** -- nothing is suppressed. A warning is logged.
- **Unmatched `end-allow`** is silently ignored.
- **File content only** -- annotations in user prompts, tool output, and transcripts are never honored.
- **Audit trail** -- every suppression is logged via ViolationLogger (`annotation_suppressed` type).

## How It Differs from Other Mechanisms

| Mechanism | Scope | Applies to |
|---|---|---|
| `ignore_files` | Entire file | Secrets, PII |
| `allowlist_patterns` | Regex match on value | Secrets, PII |
| `ai-guardian:allow` | Single line or block | Secrets, PII |
| `gitleaks:allow` | Single line | Secrets only |

## Multi-line Strings

Inline annotations only suppress the line they're on. For multi-line strings, use block annotations:

```python
# ai-guardian:begin-allow
text = """
My SSN is 123-45-6789
and key is AKIA_EXAMPLE_KEY
"""
# ai-guardian:end-allow
```
