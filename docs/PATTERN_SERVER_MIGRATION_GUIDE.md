# Pattern Server Migration Guide (v1.7.0)

## What Changed

In v1.7.0, we simplified pattern server configuration:

1. ✅ **Moved pattern_server under secret_scanning** - clearer scope
2. ✅ **Removed `enabled` field** - presence = enabled
3. ✅ **Backward compatible** - old configs still work (with deprecation warning)

## Quick Migration

### Before (v1.6.0 and earlier)

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  },
  "pattern_server": {
    "enabled": true,
    "url": "https://patterns.security.redhat.com",
    "patterns_endpoint": "/patterns/gitleaks/8.18.1",
    "auth": {
      "method": "bearer",
      "token_file": "~/.config/rh-gitleaks/auth.jwt"
    },
    "cache": {
      "refresh_interval_hours": 12,
      "expire_after_hours": 168
    }
  }
}
```

### After (v1.7.0+)

```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block",
    "pattern_server": {
      "url": "https://patterns.security.redhat.com",
      "patterns_endpoint": "/patterns/gitleaks/8.18.1",
      "auth": {
        "method": "bearer",
        "token_file": "~/.config/rh-gitleaks/auth.jwt"
      },
      "cache": {
        "refresh_interval_hours": 12,
        "expire_after_hours": 168
      }
    }
  }
}
```

**Changes:**
1. ❌ Remove `"enabled": true` from pattern_server
2. ⬆️ Move entire `pattern_server` section inside `secret_scanning`
3. ✅ Done!

## Step-by-Step Migration

### 1. Backup Your Config

```bash
cp ~/.config/ai-guardian/ai-guardian.json ~/.config/ai-guardian/ai-guardian.json.backup
```

### 2. Edit Your Config

Open `~/.config/ai-guardian/ai-guardian.json` in your editor:

```bash
vi ~/.config/ai-guardian/ai-guardian.json
```

### 3. Move pattern_server Section

**Find this:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  },
  "pattern_server": {    // ← At root level
    "enabled": true,     // ← Has enabled field
    "url": "..."
  }
}
```

**Change to this:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block",
    "pattern_server": {  // ← Nested under secret_scanning
      "url": "..."       // ← No enabled field
    }
  }
}
```

### 4. Remove `enabled` Field

Delete the `"enabled": true` line from pattern_server section.

### 5. Validate JSON

```bash
cat ~/.config/ai-guardian/ai-guardian.json | jq .
```

If you see JSON output (not an error), your config is valid!

### 6. Test

```bash
# Test that secret scanning still works
echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | ai-guardian

# You should see it blocked (or logged if action: log)
```

## Common Migration Scenarios

### Scenario 1: Pattern Server Enabled

**Before:**
```json
{
  "pattern_server": {
    "enabled": true,
    "url": "https://patterns.company.com"
  }
}
```

**After:**
```json
{
  "secret_scanning": {
    "pattern_server": {
      "url": "https://patterns.company.com"
    }
  }
}
```

### Scenario 2: Pattern Server Disabled

**Before:**
```json
{
  "pattern_server": {
    "enabled": false,
    "url": "https://patterns.company.com"
  }
}
```

**After (option 1 - explicit disable):**
```json
{
  "secret_scanning": {
    "pattern_server": null
  }
}
```

**After (option 2 - just remove it):**
```json
{
  "secret_scanning": {
    // No pattern_server = use defaults
  }
}
```

### Scenario 3: No Pattern Server

**Before:**
```json
{
  "secret_scanning": {
    "enabled": true
  }
  // No pattern_server configured
}
```

**After:**
```json
{
  "secret_scanning": {
    "enabled": true
  }
  // No pattern_server configured - no change needed!
}
```

## Backward Compatibility

### Old Config Still Works

Your v1.6.0 config will continue to work in v1.7.0:

```json
{
  "pattern_server": {
    "enabled": true,
    "url": "https://patterns.company.com"
  }
}
```

**You'll see a deprecation warning:**
```
WARNING: Root-level 'pattern_server' configuration.
Move to 'secret_scanning.pattern_server' instead.
Root-level support will be removed in v2.0.0.
```

**And if you have `enabled` field:**
```
WARNING: pattern_server.enabled field is no longer needed.
Use presence/absence of pattern_server section to enable/disable.
This field will be removed in v2.0.0.
```

### Deprecation Timeline

- **v1.7.0**: New nested structure introduced, old structure deprecated
- **v1.8.0 - v1.9.x**: Both structures supported (warnings shown)
- **v2.0.0**: Root-level `pattern_server` removed, only nested supported

**Recommendation:** Migrate now to avoid breaking changes in v2.0.0

## Automated Migration

### Option 1: Built-in Setup Command (Recommended)

Use the ai-guardian setup command with migration flag:

```bash
# Dry run - see what would change
ai-guardian setup --migrate-pattern-server --dry-run

# Interactive migration (prompts for confirmation)
ai-guardian setup --migrate-pattern-server

# Non-interactive migration
ai-guardian setup --migrate-pattern-server --yes
```

**Features:**
- ✅ Automatic backup creation
- ✅ Validates JSON structure
- ✅ Handles all migration scenarios
- ✅ Built into ai-guardian (no download needed)

### Option 2: Migration Script

Alternatively, use the standalone script:

```bash
# Download migration script
curl -O https://raw.githubusercontent.com/itdove/ai-guardian/main/scripts/migrate-pattern-server.py

# Run migration (creates backup automatically)
python migrate-pattern-server.py ~/.config/ai-guardian/ai-guardian.json

# Review changes
diff ~/.config/ai-guardian/ai-guardian.json.backup ~/.config/ai-guardian/ai-guardian.json
```

## Verification Checklist

After migration, verify:

- [ ] Config file is valid JSON (`jq` validates it)
- [ ] `pattern_server` is nested under `secret_scanning`
- [ ] No `enabled` field in `pattern_server`
- [ ] Secret scanning still works (test with example secret)
- [ ] No deprecation warnings in logs
- [ ] Pattern server patterns are being used (check logs)

### Check Logs

```bash
# Check for deprecation warnings
grep "DEPRECATED" ~/.config/ai-guardian/ai-guardian.log

# Should be empty after migration
```

### Verify Pattern Server Usage

```bash
# Check which patterns are being used
grep "Using pattern server" ~/.config/ai-guardian/ai-guardian.log

# Should show your pattern server URL
```

## Rollback

If you need to rollback:

```bash
# Restore backup
cp ~/.config/ai-guardian/ai-guardian.json.backup ~/.config/ai-guardian/ai-guardian.json

# Verify
cat ~/.config/ai-guardian/ai-guardian.json | jq .
```

## Need Help?

**Common issues:**

1. **"Invalid JSON" error**
   - Check for missing commas, trailing commas, or unbalanced braces
   - Use `jq` to find the syntax error

2. **Pattern server not working after migration**
   - Check URL is still present: `jq '.secret_scanning.pattern_server.url' ~/.config/ai-guardian/ai-guardian.json`
   - Check auth token: `cat ~/.config/rh-gitleaks/auth.jwt`

3. **Still seeing deprecation warnings**
   - Make sure you removed the root-level `pattern_server` section
   - Make sure you removed the `enabled` field from nested `pattern_server`

**Get support:**
- GitHub Issues: https://github.com/itdove/ai-guardian/issues
- Documentation: [SECRET_SCANNING_VS_PATTERN_SERVER.md](SECRET_SCANNING_VS_PATTERN_SERVER.md)

## Summary

**Old way (deprecated):**
```json
{
  "pattern_server": {
    "enabled": true,
    "url": "..."
  }
}
```

**New way (v1.7.0+):**
```json
{
  "secret_scanning": {
    "pattern_server": {
      "url": "..."
    }
  }
}
```

**Key benefits:**
- ✅ Clearer structure (pattern_server is part of secret scanning)
- ✅ Simpler config (no redundant `enabled` field)
- ✅ Easier to understand (all secret scanning config in one place)

---

**Last Updated:** 2026-04-18  
**Version:** v1.7.0
