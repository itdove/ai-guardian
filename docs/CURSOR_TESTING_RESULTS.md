# Cursor IDE Testing Results - Log Mode Warning Messages

## Test Date
April 18, 2026

## Test Configuration

**Config:** `~/.config/ai-guardian/ai-guardian.json`
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "log"
  }
}
```

**Cursor Hooks:** `~/.cursor/hooks.json`
```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "ai-guardian",
        "statusMessage": "Checking tool policy..."
      }
    ],
    "beforeSubmitPrompt": [
      {
        "command": "ai-guardian"
      }
    ],
    "beforeReadFile": [
      {
        "command": "ai-guardian"
      }
    ]
  }
}
```

## Test Scenario
User pasted AWS credentials (matching AWS example key pattern) in chat.

## Test Results

### Block Mode (`"action": "block"`)
✅ **Message displayed to user**
- Cursor shows error message
- User sees the violation
- Execution blocked

### Log Mode (`"action": "log"`)
❌ **Message NOT displayed to user**
- No visual feedback in Cursor UI
- Violation logged silently
- Execution allowed
- Violation visible in `ai-guardian tui`

## Conclusion

**Cursor has the same limitation as Claude Code:**
- Only displays messages when blocking execution
- Does not display messages when allowing execution (log mode)

This confirms that the JSON response format:
```json
{
  "continue": true,
  "user_message": "Warning message here"
}
```

Does **not** result in the `user_message` being displayed when `continue: true`.

## Implications

1. **Log mode is for audit only** in Cursor (same as Claude Code)
2. **No IDE supports warning messages** in allow/log mode
3. **TUI is the only way** to view log mode violations
4. **Documentation updated** to reflect this finding
5. **Code changes reverted** - no point sending messages that aren't shown

## Updated Documentation

- `docs/CLAUDE_CODE_HOOKS_LIMITATION.md` - Added Cursor testing results
- Removed "untested" status for Cursor
- Confirmed same limitation as Claude Code
- Added comparison table showing no IDE supports log mode warnings

## Code Changes

**Reverted unnecessary changes:**
- Removed code that sent `user_message` in log mode for Cursor
- Updated docstrings to reflect tested behavior
- Added comments documenting April 2026 testing

**Final state:**
- Cursor only receives error messages when blocking
- No messages sent when allowing (log mode)
- Behavior now consistent with Claude Code

## Recommendations

For Cursor users:
- Use `"action": "block"` for policies where you want user visibility
- Use `"action": "log"` for audit-only policies
- Monitor violations with `ai-guardian tui`
- Review logs regularly for policy violations

## Future Considerations

If Cursor adds warning message support in the future:
1. Request feature from Cursor team
2. Test with updated Cursor version
3. Implement opt-in flag: `"enable_cursor_warnings": true`
4. Keep log mode working as-is for backward compatibility

## Testing Credits

Thank you to the community user who tested this with their Cursor installation and reported findings!

---

**Tested by:** Community user (dvernier)  
**Cursor Version:** Latest (April 2026)  
**OS:** macOS  
**ai-guardian Version:** 1.7.0-dev
