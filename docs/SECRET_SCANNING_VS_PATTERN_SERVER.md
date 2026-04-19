# Secret Scanning vs Pattern Server - What's the Difference?

## Quick Answer

**`secret_scanning`** and **`pattern_server`** are **two different configuration sections** that work together for secret detection:

| Configuration | Purpose | Controls |
|--------------|---------|----------|
| **`secret_scanning`** | Enable/disable secret scanning | Whether to scan for secrets at all (always blocks when found) |
| **`pattern_server`** | Customize detection patterns | **Which patterns** to use when scanning (enterprise patterns vs defaults) |

**Think of it like this:**
- `secret_scanning` = "Should I scan?" (always blocks secrets when found)
- `pattern_server` = "What secrets should I look for?"

---

## `secret_scanning` Configuration

**Purpose:** Control whether secret scanning is enabled and what action to take when secrets are found.

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
✅ **Scanner selection** - Which engine to use (currently only Gitleaks)

**Note:** Secret scanning **always blocks** when secrets are detected - no "log only" mode for security reasons.

### ~~Action Modes~~ (REMOVED)

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

### Use Cases

**Enable scanning with blocking:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  }
}
```
Use for: Production environments, strict security

**Enable scanning with logging only:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "log"
  }
}
```
Use for: Gradual rollout, testing policies, audit-only mode

**Disable scanning completely:**
```json
{
  "secret_scanning": {
    "enabled": false
  }
}
```
Use for: Debugging, temporary bypass (not recommended)

---

## `pattern_server` Configuration

**Purpose:** Fetch custom secret detection patterns from an enterprise pattern server instead of using Gitleaks default patterns.

**Location:** `~/.config/ai-guardian/ai-guardian.json`

**NEW in v1.7.0:** Nested under `secret_scanning` (was at root level)

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

When scanning for secrets, ai-guardian uses patterns in this priority:

```
1. Pattern Server (if enabled and reachable)
   ↓
2. Project .gitleaks.toml (if exists in current directory)
   ↓
3. Gitleaks built-in patterns (always available, fallback)
```

**Example scenario:**
```bash
# Your setup
~/.config/ai-guardian/ai-guardian.json  # pattern_server enabled
/your/project/.gitleaks.toml            # exists

# Result:
# ai-guardian uses Pattern Server patterns (priority 1)
# .gitleaks.toml is IGNORED
```

### Pattern Server Workflow

```
User triggers scan (prompt, file read, tool output)
    ↓
secret_scanning.enabled == true?
    YES ↓
        ↓
    pattern_server.enabled == true?
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

### Use Cases

**Enterprise with custom patterns:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  },
  "pattern_server": {
    "enabled": true,
    "url": "https://patterns.company.com",
    "auth": {
      "token_file": "~/.config/company/token"
    }
  }
}
```
Use for: Organizations with custom secret formats, compliance requirements

**Standard Gitleaks patterns only:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  }
  // No pattern_server section = use defaults
}
```
Use for: Individual users, standard secret types (AWS, GitHub, etc.)

---

## How They Work Together

### Example 1: Pattern Server with Block Mode

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

### Example 2: Pattern Server with Log Mode

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

### Example 3: No Pattern Server, Default Patterns

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

### Example 4: Pattern Server Disabled

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block",
    "pattern_server": null  // ← Disabled (use defaults)
  }
}
```

**Or simply omit it:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
    // No pattern_server = use defaults
  }
}
```

**Behavior:**
1. Pattern server disabled → Use defaults
2. Falls back to project `.gitleaks.toml` or Gitleaks defaults
3. Scanning still happens (secret_scanning.enabled = true)

---

## Common Configurations

### Individual Developer (Recommended)

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

### Enterprise with Custom Patterns

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

### Gradual Rollout / Testing

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

## Important Notes

### Pattern Server Never Had an `action` Field

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

### Pattern Completeness Warning

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

### Pattern Server Unavailable

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
# 1. Is pattern_server enabled?
cat ~/.config/ai-guardian/ai-guardian.json | jq .pattern_server.enabled

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
- **Action field:** Ignored (use `secret_scanning.action`)

### They Work Together

```
secret_scanning.enabled → Should we scan?
    ↓ YES
pattern_server.enabled → Which patterns?
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

- [CLAUDE_CODE_HOOKS_LIMITATION.md](CLAUDE_CODE_HOOKS_LIMITATION.md) - Why log mode doesn't show messages
- [README.md](../README.md) - Configuration examples
- [CHANGELOG.md](../CHANGELOG.md) - Feature history

---

**Last Updated:** 2026-04-18  
**Version:** v1.7.0+ (nested pattern_server structure)

**Your Configuration (after migration):**
```json
{
  "secret_scanning": {
    "action": "log",
    "pattern_server": {
      "url": "https://patterns.security.redhat.com",
      "auth": {...}
    }
  }
}
```

**Result:** 
- Red Hat patterns used for detection
- Violations logged at WARNING level (action: log)
- Execution allowed
- Visible in `ai-guardian tui`
