# Secret Scanning Configuration Guide

This guide explains how AI Guardian's secret scanning works, including configuration options, pattern server integration, and security measures for secret redaction.

## Table of Contents

- [Overview](#overview)
- [Scanner Engines](#scanner-engines)
- [Configuration](#configuration)
- [Pattern Server Integration](#pattern-server-integration)
- [Secret Redaction Security](#secret-redaction-security)
- [Troubleshooting](#troubleshooting)

---

## Overview

AI Guardian provides comprehensive secret scanning to prevent sensitive information from being exposed through AI interactions. The scanning system has two main components:

| Component | Purpose | Controls |
|-----------|---------|----------|
| **`secret_scanning`** | Enable/disable secret scanning | Whether to scan for secrets at all (always blocks when found) |
| **`pattern_server`** | Customize detection patterns | **Which patterns** to use when scanning (enterprise patterns vs defaults) |

**Think of it like this:**
- `secret_scanning` = "Should I scan?" (always blocks secrets when found)
- `pattern_server` = "What secrets should I look for?"

---

## Scanner Engines

**NEW in v1.4.0:** AI Guardian now supports multiple scanner engines with automatic fallback.

### Supported Scanners

| Scanner | Speed | Pattern Management | Output Format | Installation |
|---------|-------|-------------------|---------------|--------------|
| **Gitleaks** | Standard | Manual config | JSON | `brew install gitleaks` |
| **BetterLeaks** | 20-40% faster | Manual config | JSON (same as Gitleaks) | `brew install betterleaks` |
| **LeakTK** | Standard | Auto-managed | JSON (custom) | `brew install leaktk/tap/leaktk` |

### Configuration

**Default (Gitleaks):**
```json
{
  "secret_scanning": {
    "enabled": true
    // Defaults to gitleaks if not specified
  }
}
```

**Recommended (BetterLeaks with Gitleaks fallback):**
```json
{
  "secret_scanning": {
    "enabled": true,
    "engines": ["betterleaks", "gitleaks"]
  }
}
```

**Behavior:**
- Tries BetterLeaks first (if installed)
- Falls back to Gitleaks if BetterLeaks not found
- Works on any system (automatic detection)

**Three-Scanner Fallback:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "engines": ["leaktk", "betterleaks", "gitleaks"]
  }
}
```

### Advanced Configuration

**Custom Binary Path:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "engines": [
      {
        "type": "betterleaks",
        "binary": "/opt/betterleaks/bin/betterleaks",
        "extra_flags": ["--regex-engine=re2"]
      },
      "gitleaks"
    ]
  }
}
```

**Custom Scanner:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "engines": [
      {
        "type": "custom",
        "binary": "my-scanner",
        "command_template": [
          "{binary}", "scan",
          "--input", "{source_file}",
          "--output", "{report_file}",
          "--format", "json"
        ],
        "success_exit_code": 0,
        "secrets_found_exit_code": 1,
        "output_format": "gitleaks-compatible"
      }
    ]
  }
}
```

### Scanner Selection

AI Guardian automatically selects the first available scanner from your `engines` list:

1. **Defaults to gitleaks:** If no `engines` configured, uses `["gitleaks"]`
2. **Checks availability:** Tries each scanner binary in order
3. **Selects first found:** Uses the first scanner that exists in PATH
4. **Blocks if none found:** Shows error with installation instructions

**Example:**
```bash
# With config: "engines": ["betterleaks", "gitleaks"]

# If betterleaks installed:
$ which betterleaks
/usr/local/bin/betterleaks
# → Uses betterleaks

# If betterleaks NOT installed:
$ which betterleaks
# (not found)
$ which gitleaks
/usr/local/bin/gitleaks
# → Uses gitleaks (fallback)
```

### Error Messages

Error messages now show which scanner detected the secret:

```
======================================================================
🚨 BLOCKED BY POLICY
🔒 SECRET DETECTED
======================================================================

Betterleaks has detected sensitive information in your prompt/file.

Secret Type: aws-access-token
Location: config.py, line 5
Total findings: 1

Detection Source:
  Scanner: betterleaks
  Patterns: Built-in Defaults (100+ rules)

This operation has been blocked for security.
```

---

## Configuration

### Basic Secret Scanning

**Location:** `~/.config/ai-guardian/ai-guardian.json`

```json
{
  "secret_scanning": {
    "enabled": true,           // ← Turn scanning ON/OFF (always blocks when secrets found)
    "ignore_files": [           // ← Files to skip
      "**/tests/fixtures/**",
      "**/.env.example"
    ],
    "ignore_tools": [],         // ← Tools to skip (rarely needed)
    "pattern_server": {         // ← NEW in v1.7.0: Nested here!
      "url": "https://patterns.security.redhat.com",
      "auth": {...}
    }
  }
}
```

### What It Controls

✅ **Global enable/disable** - Turn secret scanning on or off (always blocks when enabled)
✅ **Ignore patterns** - Skip specific files or tools  
✅ **Scanner selection** - Which engine(s) to use (Gitleaks, BetterLeaks, LeakTK, or custom)

**Note:** Secret scanning **always blocks** when secrets are detected - no "log only" mode for security reasons.

### Action Modes

**Block mode** (`"action": "block"`, default):
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"  // ← Prevent execution when secrets found
  }
}
```
- Secrets found → Execution **blocked**
- Error message shown to user
- Violation logged at ERROR level

**Log mode** (`"action": "log"`):
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "log"  // ← Allow execution, log for audit
  }
}
```
- Secrets found → Execution **allowed**
- No message shown to user (hook limitation)
- Violation logged at WARNING level
- Visible in `ai-guardian tui`

### Common Configurations

#### Individual Developer (Recommended)

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  }
}
```

- Uses Gitleaks default patterns (comprehensive)
- Blocks on secret detection
- No external dependencies

#### Enterprise with Custom Patterns

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block",
    "pattern_server": {
      "url": "https://patterns.company.com",
      "auth": {
        "method": "bearer",
        "token_file": "~/.config/company/pattern-token"
      },
      "cache": {
        "refresh_interval_hours": 12
      }
    }
  }
}
```

- Fetches organization-specific patterns
- Caches patterns locally (refresh every 12h)
- Falls back to defaults if server unavailable

#### Gradual Rollout / Testing

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "log",  // ← Start with logging only
    "pattern_server": {
      "url": "https://patterns.company.com"
    }
  }
}
```

- Log violations without blocking users
- Monitor in TUI to identify false positives
- Switch to "block" after validation

---

## Pattern Server Integration

### Overview

**Purpose:** Fetch custom secret detection patterns from an enterprise pattern server instead of using Gitleaks default patterns.

**Location:** `~/.config/ai-guardian/ai-guardian.json`

**NEW in v1.7.0:** Nested under `secret_scanning` (was at root level)

### Configuration

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block",
    "pattern_server": {         // ← Nested under secret_scanning (v1.7.0+)
      "url": "https://patterns.security.redhat.com",  // ← Presence = enabled!
      "patterns_endpoint": "/patterns/gitleaks/8.18.1",
      "auth": {
        "method": "bearer",
        "token_env": "AI_GUARDIAN_PATTERN_TOKEN",
        "token_file": "~/.config/rh-gitleaks/auth.jwt"
      },
      "cache": {
        "path": "~/.cache/ai-guardian/patterns.toml",
        "refresh_interval_hours": 12,
        "expire_after_hours": 168
      }
    }
  }
}
```

**Simplified in v1.7.0:**
- ✅ **No `enabled` field needed** - presence of section = enabled
- ✅ **Logical nesting** - pattern_server clearly part of secret scanning
- ✅ **Easier to understand** - all secret scanning config in one place

### What It Controls

✅ **Pattern source** - Where to get detection patterns  
✅ **Enterprise patterns** - Organization-specific secret types  
✅ **Pattern caching** - Local cache with refresh intervals  
✅ **Authentication** - Token-based access to pattern server

### How to Enable/Disable

**Enable pattern server** (v1.7.0+ simplified):
```json
{
  "secret_scanning": {
    "pattern_server": {
      "url": "https://patterns.company.com"  // ← Presence = enabled
    }
  }
}
```

**Disable pattern server:**
```json
{
  "secret_scanning": {
    "pattern_server": null  // ← Explicit disable
  }
}
```

**Or simply don't configure it:**
```json
{
  "secret_scanning": {
    "enabled": true
    // No pattern_server = use defaults
  }
}
```

### Pattern Priority Order

When scanning for secrets, AI Guardian uses patterns in this priority:

```
1. Pattern Server (if configured and available)
   - Enterprise/organization-specific patterns
   - Cached for 7 days if server becomes unavailable
   ↓
2. Scanner Engines (first available from engines list)
   - Example: ["betterleaks", "gitleaks", "leaktk"]
   - Tries each scanner in order until one is found
   - Automatically uses .gitleaks.toml if scanner supports it
   ↓
3. BLOCK if no scanner is available
```

**Key Changes:**
- ✅ Always falls back to scanner engines when pattern server fails
- ✅ Scanner engines automatically detect and use `.gitleaks.toml` if present
- ✅ No configuration needed - fallback is automatic
- ✅ Clear logging at each fallback step

**Example Scenarios:**

**Scenario 1: Pattern server available**
```bash
# Your setup
~/.config/ai-guardian/ai-guardian.json  # pattern_server configured
/your/project/.gitleaks.toml            # exists

# Result: Uses Pattern Server patterns
# .gitleaks.toml is IGNORED (pattern server takes priority)
```

**Scenario 2: Pattern server down, gitleaks installed**
```bash
# Your setup
~/.config/ai-guardian/ai-guardian.json  # pattern_server configured
/your/project/.gitleaks.toml            # exists
$ which gitleaks
/usr/local/bin/gitleaks

# Result:
# 1. Pattern server unavailable (logged warning)
# 2. Falls back to gitleaks scanner
# 3. Gitleaks automatically uses .gitleaks.toml (if present)
# 4. Or uses built-in patterns (if .gitleaks.toml not found)
```

**Scenario 3: No pattern server, has .gitleaks.toml**
```bash
# Your setup
~/.config/ai-guardian/ai-guardian.json  # no pattern_server
/your/project/.gitleaks.toml            # exists

# Result:
# 1. Uses gitleaks scanner (no pattern server configured)
# 2. Gitleaks automatically detects and uses .gitleaks.toml
```

### Pattern Server Workflow

```
User triggers scan (prompt, file read, tool output)
    ↓
secret_scanning.enabled == true?
    YES ↓
        ↓
    pattern_server configured?
        YES ↓
            ↓
        Fetch patterns from server → Cache locally
            ↓
        Use server patterns for scanning
            ↓
        Find secret → Apply secret_scanning.action (block/log)
        
        NO ↓
            ↓
        Use .gitleaks.toml or defaults
            ↓
        Find secret → Apply secret_scanning.action (block/log)
```

### How secret_scanning and pattern_server Work Together

#### Example 1: Pattern Server with Block Mode

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block",  // ← Controls what happens when secret found
    "pattern_server": {  // ← Controls WHICH secrets to look for
      "url": "https://patterns.security.redhat.com"
    }
  }
}
```

**Behavior:**
1. User pastes content with AWS key
2. ai-guardian fetches patterns from Red Hat pattern server
3. Pattern server includes AWS key pattern
4. Secret detected → **BLOCKED** (secret_scanning.action = "block")
5. Error shown to user

#### Example 2: Pattern Server with Log Mode

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "log",  // ← Log only, don't block
    "pattern_server": {
      "url": "https://patterns.security.redhat.com"
    }
  }
}
```

**Behavior:**
1. User pastes content with AWS key
2. ai-guardian fetches patterns from Red Hat pattern server
3. Pattern server includes AWS key pattern
4. Secret detected → **ALLOWED** (secret_scanning.action = "log")
5. Violation logged (WARNING level)
6. Visible in `ai-guardian tui`

#### Example 3: No Pattern Server, Default Patterns

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  }
  // pattern_server not configured
}
```

**Behavior:**
1. User pastes content with AWS key
2. ai-guardian uses Gitleaks built-in patterns (no pattern server)
3. Built-in patterns include AWS key detection
4. Secret detected → **BLOCKED** (secret_scanning.action = "block")

### Important Notes

#### Pattern Server Never Had an `action` Field

⚠️ **Note:** Pattern server only provides detection patterns, not policy decisions.

**Only `secret_scanning.action` matters:**
```json
{
  "secret_scanning": {
    "action": "log",  // ← This controls block vs log
    "pattern_server": {
      "url": "https://patterns.company.com"
      // No action field - uses secret_scanning.action
    }
  }
}
```

**Why?** Pattern server provides WHICH secrets to detect. The `secret_scanning.action` determines WHAT TO DO when detected.

#### Pattern Completeness Warning

If pattern server returns fewer than 50 rules, you'll see:

```
WARNING: Pattern server returned only 12 rules. 
Standard Gitleaks has 100+ rules.
Your pattern server may be missing common secret types (AWS keys, RSA keys, etc.).
Ensure your pattern server includes both organization-specific AND default Gitleaks patterns.
```

**What to do:**
1. Check if pattern server includes default Gitleaks patterns
2. Contact pattern server administrator
3. Temporarily disable pattern server to use defaults

#### Pattern Server Unavailable

If pattern server fails:
```
WARNING: Pattern server configured at https://patterns.company.com but patterns unavailable.
Falling back to project config or gitleaks defaults.
Common causes: missing/invalid auth token, network error, server down.
Check token at ~/.config/company/token or see ~/.config/ai-guardian/ai-guardian.log
```

**Behavior:**
- Falls back to project `.gitleaks.toml` (if exists)
- Otherwise uses Gitleaks defaults
- Scanning continues (fail-safe)

---

## Secret Redaction Security

AI Guardian implements **defense-in-depth** for secret value redaction to ensure that actual secret values are **never** exposed in error messages, logs, or temporary files.

### Security Layers

#### Layer 1: Gitleaks `--redact` Flag

**Location**: `src/ai_guardian/__init__.py:1537`

```python
cmd = [
    'gitleaks',
    'detect',
    '--no-git',
    '--verbose',
    '--redact',        # Defense-in-depth: redact Match/Secret fields in JSON
    '--report-format', 'json',
    '--report-path', report_file,
    '--source', tmp_file_path,
]
```

**What it does**:
- Gitleaks replaces all secret values with `"REDACTED"` in its JSON output
- Both `Match` and `Secret` fields show `"REDACTED"` instead of actual values
- Prevents secrets from appearing in Gitleaks stdout/stderr

**Important Note**:
- ai-guardian **never extracts** the `Match` or `Secret` fields
- The `--redact` flag is **defense-in-depth** to safeguard against future code changes
- Even without `--redact`, current implementation wouldn't leak secrets
- We keep it as an extra security layer

**Verification**:
```python
# Gitleaks JSON output with --redact:
{
  "RuleID": "slack-bot-token",
  "Match": "REDACTED",      # ← Not the actual token (we don't use this field)
  "Secret": "REDACTED",     # ← Not the actual secret (we don't use this field)
  "File": "test.py",        # ← We extract this
  "StartLine": 2            # ← We extract this
}
```

#### Layer 2: Never Display or Log Secret Values

**What we extract** (safe metadata only):
- ✅ Rule ID (e.g., "slack-bot-token") - secret type, not value
- ✅ File path - where the secret was found
- ✅ Line numbers - location in file
- ✅ Total findings count - how many secrets

**What we DON'T extract** (fields that contain secret values):
- ❌ `Match` field - contains "REDACTED" (or actual secret without --redact flag)
- ❌ `Secret` field - contains "REDACTED" (or actual secret without --redact flag)
- ❌ Any actual secret value - we only use metadata for error messages

#### Layer 3: Error Messages Show Only Metadata

**Example error message** (user sees):
```
======================================================================
🚨 BLOCKED BY POLICY
🔒 SECRET DETECTED
======================================================================

Gitleaks has detected sensitive information in your prompt/file.

Secret Type: slack-bot-token
Location: test.py, line 2
Total findings: 1

This operation has been blocked for security.
Please remove the sensitive information and try again.
```

**Note**: No actual secret value is shown!

#### Layer 4: Logs Only Metadata

**Log output examples**:
```
2026-04-18 16:30:15 - ai_guardian - ERROR - Secret detected: slack-bot-token
2026-04-18 16:30:15 - ai_guardian - WARNING - Secret detected (log mode): aws-access-token - execution allowed
```

**Note**: Only rule_id logged, never the actual secret!

#### Layer 5: Sanitized Gitleaks stderr

**What's logged**:
- ✅ Length of stderr (for debugging)
- ✅ First line only, truncated to 200 chars
- ✅ Only logged at DEBUG level

**What's NOT logged**:
- ❌ Full Gitleaks stderr (could contain sensitive info in edge cases)

#### Layer 6: Violation Log Excludes Secrets

**Violation log entry** (JSONL):
```json
{
  "timestamp": "2026-04-18T16:30:15Z",
  "violation_type": "secret_detected",
  "blocked": {
    "file_path": "test.py",
    "source": "file",
    "secret_type": "slack-bot-token",
    "reason": "Gitleaks detected sensitive information",
    "line_number": 2,
    "total_findings": 1
  },
  "context": {...}
}
```

**Note**: No actual secret value in violation log!

#### Layer 7: KNOWN LIMITATION - UserPromptSubmit Terminal Display

**THE LIMITATION (Claude Code Behavior)**:

When ai-guardian blocks prompts containing secrets using `decision: "block"` in JSON response, Claude Code displays the original prompt in the terminal error message.

**What IS protected:**
- ✅ Secret does NOT reach Claude's API (hook blocks before submission)
- ✅ Secret does NOT appear in conversation history/session
- ✅ Secret does NOT get sent to Anthropic servers
- ✅ Only metadata in our error message (type, file, line)

**What is NOT protected:**
- ❌ Secret visible in user's terminal when blocking occurs
- This is the trade-off for blocking secrets from reaching Claude

**Why we accept this limitation:**
- Preventing secrets from reaching Claude's API is MORE IMPORTANT than hiding from terminal
- The terminal leak is local only (user's screen)
- The alternative (allowing secrets to Claude) is worse
- This is a Claude Code design decision we cannot work around

**IMPACT**:
- ❌ Secrets in direct prompts ARE LEAKED when blocked
- ✅ Secrets in tool outputs (PostToolUse) are NOT leaked (uses JSON)
- ✅ Secrets in file reads (PreToolUse) are NOT leaked (different flow)

**WORKAROUNDS**:
1. **Rely on other detection layers**:
   - PreToolUse hook scans files before reading (blocks file path, not content)
   - PostToolUse hook scans tool outputs (uses JSON, no leak)
   
2. **User education**:
   - Don't paste secrets directly in prompts
   - Use environment variables, config files, or secure vaults

#### Layer 8: Secure File Cleanup

**Content File (Scanned File)**:
```python
# Secure cleanup: overwrite file before deletion
if os.path.exists(tmp_file_path):
    # Make file writable
    os.chmod(tmp_file_path, 0o600)
    
    # Overwrite with zeros to prevent recovery
    file_size = os.path.getsize(tmp_file_path)
    with open(tmp_file_path, 'wb') as f:
        f.write(b'\x00' * file_size)
        f.flush()
        os.fsync(f.fileno())
    
    # Delete the file
    os.unlink(tmp_file_path)
```

**Report File (Gitleaks JSON Output)** - Now securely cleaned up:
```python
# Securely clean up report file (contains Gitleaks findings)
# Even though --redact is used, we securely overwrite as defense in depth
if report_file and os.path.exists(report_file):
    # Overwrite with zeros before deletion
    file_size = os.path.getsize(report_file)
    with open(report_file, 'wb') as f:
        f.write(b'\x00' * file_size)
        f.flush()
        os.fsync(f.fileno())
    
    # Delete the file
    os.unlink(report_file)
```

**Why this matters**:
- Even though Gitleaks redacts secrets, defense in depth requires secure cleanup
- Prevents forensic recovery of temporary files
- Both content and report files are overwritten with zeros before deletion
- Uses `os.fsync()` to ensure writes are committed to disk

### Summary: What Is/Isn't Exposed

**Secret values are NEVER exposed in**:
- ❌ Error messages shown to users
- ❌ Log files (`~/.config/ai-guardian/ai-guardian.log`)
- ❌ Violation logs (`~/.config/ai-guardian/violations.jsonl`)
- ❌ Gitleaks stdout/stderr output
- ❌ Gitleaks JSON report (shows "REDACTED")
- ❌ Temporary files (securely overwritten before deletion)

**What IS exposed** (safe metadata):
- ✅ Secret type (e.g., "slack-bot-token", "aws-access-key")
- ✅ File path where secret was found
- ✅ Line number(s) in file
- ✅ Total count of secrets found

**Defense-in-depth layers**:
1. Gitleaks `--redact` flag
2. Don't extract secret values from Gitleaks output
3. Error messages show only metadata
4. Logs show only rule IDs
5. Sanitized stderr logging
6. Violation logs exclude secrets
7. Secure file cleanup (overwrite + delete)

### Best Practices for Developers

When modifying secret scanning code:

1. **Never log `first_finding.get('Match')` or `first_finding.get('Secret')`**
   - These fields contain "REDACTED" but should never be logged anyway

2. **Never include `result.stdout` or `result.stderr` in user-facing messages**
   - Only use for internal debugging, with sanitization

3. **Always use secure cleanup for temporary files containing secrets**
   - Overwrite with zeros before deletion
   - Use `os.fsync()` to ensure write is committed

4. **Test with real secrets to verify redaction**
   - Use actual secret formats (Slack tokens, AWS keys, etc.)
   - Verify secrets don't appear in output, logs, or files

5. **Document any new fields extracted from Gitleaks output**
   - Ensure they don't contain secret values
   - Update this document with security analysis

---

## Troubleshooting

### Secret scanning doesn't work

**Check:**
```bash
# 1. Is secret_scanning enabled?
cat ~/.config/ai-guardian/ai-guardian.json | jq .secret_scanning.enabled

# 2. Is Gitleaks installed?
which gitleaks
gitleaks version

# 3. Check logs
tail -f ~/.config/ai-guardian/ai-guardian.log
```

### Pattern server not being used

**Check:**
```bash
# 1. Is pattern_server configured?
cat ~/.config/ai-guardian/ai-guardian.json | jq .secret_scanning.pattern_server

# 2. Check authentication
cat ~/.config/rh-gitleaks/auth.jwt  # Your token file

# 3. Test pattern server manually
curl -H "Authorization: Bearer $(cat ~/.config/rh-gitleaks/auth.jwt)" \
  https://patterns.security.redhat.com/patterns/gitleaks/8.18.1

# 4. Check cache
ls -la ~/.cache/ai-guardian/patterns.toml
cat ~/.cache/ai-guardian/patterns.toml | head -20
```

### Secrets not detected

**Possible causes:**
1. Pattern server missing default patterns
2. Custom `.gitleaks.toml` doesn't include pattern
3. Secret format not recognized by Gitleaks

**Test manually:**
```bash
# Test with default Gitleaks patterns
echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | gitleaks detect --no-git -v

# Test with your pattern server patterns
gitleaks detect --no-git -v --config ~/.cache/ai-guardian/patterns.toml
```

---

## Summary

### `secret_scanning` - The Scanner

- **Purpose:** Enable/disable scanning + action on detection
- **Controls:** ON/OFF switch and block vs log behavior
- **Scope:** Global across all hooks and files
- **Action:** `"block"` (prevent) or `"log"` (audit)

### `pattern_server` - The Pattern Source

- **Purpose:** Customize which secrets to detect
- **Controls:** Where patterns come from (enterprise vs defaults)
- **Scope:** Pattern definitions only
- **Action field:** N/A (uses `secret_scanning.action`)

### They Work Together

```
secret_scanning.enabled → Should we scan?
    ↓ YES
pattern_server configured? → Which patterns?
    ↓ YES
Fetch patterns from server
    ↓
Scan content with those patterns
    ↓
Secret found?
    ↓ YES
secret_scanning.action → Block or log?
```

---

## Related Documentation

- [HOOKS.md](HOOKS.md) - Why log mode doesn't show messages
- [TUI.md](TUI.md) - Using the TUI to view violations
- [README.md](../README.md) - Configuration examples
- [CHANGELOG.md](../CHANGELOG.md) - Feature history
- [Gitleaks --redact](https://github.com/gitleaks/gitleaks#redaction)
- [OWASP Secret Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

**Last Updated:** 2026-04-19  
**Version:** 1.4.0-dev
