# Claude Code Hooks Limitation: Why Warning Messages Aren't Displayed

## TL;DR

**Claude Code hooks don't display non-blocking messages to users.** When a hook exits with code 0 (success), Claude Code discards all stdout and stderr output. This is why ai-guardian uses **"log" mode** instead of "warn" mode - violations are logged for audit but never shown to users during execution.

## The Problem

When we initially implemented enforcement levels, we called it "warn mode" with the expectation that warning messages would be displayed to users. However, testing revealed that **Claude Code never shows these warnings**.

### What We Expected

```
User types a prompt
    ↓
Hook runs with "warn" mode
    ↓
Hook prints warning to stderr: "⚠️ POLICY VIOLATION (WARN MODE)"
    ↓
Hook exits with code 0 (allow execution)
    ↓
❌ EXPECTED: Claude Code shows warning to user
✅ ACTUAL: Claude Code discards all output, shows nothing
```

### What Actually Happens

**Claude Code Hook Behavior:**

| Exit Code | stdout/stderr | Behavior |
|-----------|---------------|----------|
| `0` | Any output | **Discarded** - User sees nothing |
| `!= 0` | stderr content | **Displayed** - User sees error message |

**Result:** Non-blocking warnings (exit 0) are invisible to users.

## Why This Matters

### 1. User Experience
Users never see policy violations in "warn mode":
- No visual feedback that a policy was violated
- No notification that activity is being logged
- Silent operation gives false sense that no policy applies

### 2. Naming Accuracy
"Warn mode" implies users are warned, but they aren't:
- ❌ "Warn" suggests user notification
- ✅ "Log" accurately describes behavior (logged but not shown)

### 3. Compliance & Audit
The actual value is in audit logging, not user warnings:
- All violations logged to ViolationLogger
- Visible in TUI (`ai-guardian tui`)
- Logged at WARNING level for audit
- Perfect for compliance tracking

## Our Solution: "Log Mode"

We renamed "warn" → "log" to accurately reflect what happens:

### Configuration (v1.7.0+)

```json
{
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["approved-skill"],
      "action": "log"  // ← Accurately named: logs but doesn't block
    }
  ]
}
```

### What "Log Mode" Does

✅ **Logs violation** at WARNING level  
✅ **Records to ViolationLogger** (visible in TUI)  
✅ **Allows execution** (exit 0)  
❌ **Does NOT show message to user** (Claude Code limitation)

### What "Block Mode" Does

✅ **Logs violation** at ERROR level  
✅ **Records to ViolationLogger** (visible in TUI)  
✅ **Shows error message to user** (exit != 0, stderr displayed)  
✅ **Prevents execution**

## Technical Details

### Hook Exit Code Behavior

**Success (exit 0):**
```python
# Hook code
print("⚠️ WARNING: Policy violation", file=sys.stderr)
sys.exit(0)  # Allow execution

# Result: Message printed but Claude Code discards it
# User sees: Nothing
```

**Failure (exit != 0):**
```python
# Hook code
print("🚨 BLOCKED BY POLICY: Violation detected", file=sys.stderr)
sys.exit(2)  # Block execution

# Result: Claude Code displays stderr to user
# User sees: Error message with details
```

### Code Implementation

**Before (v1.6.0 and earlier):**
```python
if enforcement == "warn":
    warn_msg = _format_warning_message(...)  # ← Wasted effort
    logger.warning("Policy violation")
    return True, warn_msg, tool_name  # Message never shown
```

**After (v1.7.0+):**
```python
if action == "log":
    logger.warning("Policy violation (log mode)")
    return True, None, tool_name  # No message generation - it's never shown
```

**Benefits:**
- No wasted string formatting
- Accurate naming ("log" not "warn")
- Clear expectation (audit logging, not user warnings)

## Verification Testing

We verified this behavior through testing:

### Test Setup
```json
{
  "permissions": [{
    "matcher": "Skill",
    "mode": "allow", 
    "patterns": ["approved"],
    "action": "log"
  }]
}
```

### Test Results
```
User loads unapproved skill
    ↓
Hook detects violation
    ↓
Hook prints warning message
    ↓
Hook logs at WARNING level ✅
    ↓
Hook logs to ViolationLogger ✅
    ↓
Hook exits 0 (allow)
    ↓
Claude Code UI shows: Nothing ❌
    ↓
Log file shows: WARNING level entry ✅
    ↓
TUI shows: Violation record ✅
```

**Conclusion:** Only logging mechanisms work; user messages don't.

## Use Cases for Log Mode

Since users won't see warnings, log mode is best for:

### 1. Gradual Policy Rollout
```json
{
  "permissions": [{
    "matcher": "Skill",
    "mode": "allow",
    "patterns": ["production-approved-*"],
    "action": "log"  // ← Monitor violations before enforcing
  }]
}
```

**Workflow:**
1. Deploy with `action: "log"`
2. Monitor violations in TUI
3. Identify false positives
4. Adjust patterns
5. Switch to `action: "block"`

### 2. Compliance Audit Mode
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "log"  // ← Track but don't disrupt workflow
  }
}
```

**Use Case:** Security team wants visibility without blocking developers.

### 3. Policy Testing
```json
{
  "prompt_injection": {
    "enabled": true,
    "action": "log"  // ← Test detection accuracy
  }
}
```

**Use Case:** Identify false positives before enforcing.

## Viewing Violations

Since users don't see warnings in Claude Code, use these methods:

### 1. TUI (Recommended)
```bash
ai-guardian tui
```

Shows all violations with:
- Timestamp
- Violation type
- Details (tool, pattern, file)
- Action taken (blocked/allowed)
- Suggested fixes

### 2. Log Files
```bash
# Python logging output
tail -f ~/.local/state/ai-guardian/ai-guardian.log

# Look for WARNING level entries
grep "WARNING" ~/.local/state/ai-guardian/ai-guardian.log
```

### 3. Violation Logger JSON
```bash
# Raw violation records
cat ~/.local/state/ai-guardian/violations.jsonl | jq .
```

## Comparison with Other IDEs

### Cursor IDE
**Status:** ❌ Does NOT support warning messages (tested and confirmed)

Cursor uses JSON response format:
```json
{
  "continue": true,  // allow execution
  "user_message": "Optional message to display"
}
```

**Testing Results (April 2026):**
- ✅ **Block mode** (`continue: false`): Message displayed correctly
- ❌ **Log mode** (`continue: true`): Message NOT displayed, even when `user_message` is included

**Cursor has the same limitation as Claude Code** - it only displays messages when blocking execution, not when allowing it.

**Test Configuration Used:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "log"  // ← Tested: message not shown
  }
}
```

**Hook Configuration:**
```json
{
  "hooks": {
    "beforeSubmitPrompt": [{"command": "ai-guardian"}],
    "beforeReadFile": [{"command": "ai-guardian"}],
    "preToolUse": [{"command": "ai-guardian"}]
  }
}
```

**Behavior observed:**
- Violations are logged (visible in `ai-guardian tui`)
- Execution is allowed
- No message shown to user in Cursor UI

**Conclusion:** Log mode in Cursor is for audit logging only, just like Claude Code.

### Aider
Aider hooks have similar limitations to Claude Code:
- Exit 0 = silent success
- Exit != 0 = error shown

### GitHub Copilot
GitHub Copilot pre-request hooks:
- Only blocking mode (no warnings)
- Binary: allow or deny (no informational messages)

## Future Considerations

### If Claude Code Adds Warning Support

If Claude Code adds support for non-blocking warnings in the future:

**Option 1: Keep "log" mode**
- Accurate name (violations are logged)
- Already clear behavior
- No breaking changes needed

**Option 2: Add "warn" mode separately**
```json
{
  "action": "warn"  // Display warning AND allow execution (if supported)
}
```

**Recommendation:** Keep "log" mode for consistency, even if warnings become displayable.

### Alternative Notification Methods

Potential workarounds (not currently implemented):

1. **Desktop notifications** (OS-level)
   - Pros: Visible to user
   - Cons: Intrusive, requires permissions

2. **Log file monitoring** (separate tool)
   - Pros: Real-time visibility
   - Cons: Requires separate terminal

3. **Periodic TUI summary**
   - Pros: Batch review
   - Cons: Not real-time

## Recommendations

### For Users

✅ **Use log mode for:**
- Gradual policy rollout
- Compliance auditing
- Testing new policies
- Development environments

✅ **Use block mode for:**
- Production enforcement
- Critical security policies
- Zero-trust environments

✅ **Monitor violations via:**
- `ai-guardian tui` (best UX)
- Log files (automation)
- ViolationLogger (programmatic access)

### For Developers

✅ **Do:**
- Use "log" terminology consistently
- Document that violations are logged, not shown
- Direct users to TUI for violation visibility

❌ **Don't:**
- Generate warning messages in log mode (wasted effort)
- Use "warn" terminology (misleading)
- Expect users to see violations in Claude Code UI

## Summary: Which IDEs Support Warning Messages?

| IDE | Block Mode Messages | Log Mode Messages | Notes |
|-----|-------------------|-------------------|-------|
| **Claude Code** | ✅ Displayed (exit != 0) | ❌ Not displayed (exit 0) | Logs only |
| **Cursor** | ✅ Displayed (`continue: false`) | ❌ Not displayed (`continue: true`) | Tested April 2026 |
| **Aider** | ✅ Displayed (exit != 0) | ❌ Not displayed (exit 0) | Same as Claude Code |
| **GitHub Copilot** | ✅ Displayed (deny) | ❌ No log mode support | Binary only |

**Conclusion:** No major IDE currently supports non-blocking warning messages to users. Log mode is for audit logging only.

## References

- [Claude Code Hooks Documentation](https://code.claude.com/docs/en/hooks)
- [Cursor Hooks Documentation](https://docs.cursor.com/context/rules-for-ai#hooks) (if available)
- [CHANGELOG.md](../CHANGELOG.md) - v1.7.0 enforcement → action refactoring

## Related Documentation

- [TUI.md](TUI.md) - Using the TUI to view violations
- [README.md](../README.md) - Action modes configuration
- [CHANGELOG.md](../CHANGELOG.md) - Version history

---

**Last Updated:** 2026-04-18  
**Version:** 1.7.0  
**Cursor Testing:** Completed - confirmed same limitation as Claude Code  
**Tester:** Community user with secret_scanning in log mode  
**Result:** Cursor does NOT display messages when allowing execution
