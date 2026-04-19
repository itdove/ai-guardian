# Hook Ordering and Multi-Hook Configuration

## Critical: ai-guardian Must Be First Hook (For Log Mode)

**When using multiple hooks in Claude Code with log mode (`action: "log"`), ai-guardian MUST be the first hook in each hook type's array.**

### Why This Matters

Claude Code's hook system runs hooks sequentially, but only the **first hook's `systemMessage`** is displayed to the user. Each hook type displays different log mode warnings via `systemMessage`:

- **PreToolUse**: Tool permissions, directory rules
- **UserPromptSubmit**: Prompt injection  
- **PostToolUse**: (No log mode warnings - secret scanning always blocks)

If another hook runs before ai-guardian, warnings are silently suppressed.

❌ **Wrong - Warnings Suppressed:**
```json
{
  "PreToolUse": [
    {
      "matcher": "*",
      "hooks": [
        {
          "command": "other-hook",
          "statusMessage": "Running other hook..."
        },
        {
          "command": "ai-guardian",
          "statusMessage": "🛡️ Checking tool permissions..."
        }
      ]
    }
  ]
}
```

**Result:** ai-guardian warnings are silently suppressed. Users won't see policy violations!

✅ **Correct - Warnings Visible:**
```json
{
  "PreToolUse": [
    {
      "matcher": "*",
      "hooks": [
        {
          "command": "ai-guardian",
          "statusMessage": "🛡️ Checking tool permissions..."
        },
        {
          "command": "other-hook",
          "statusMessage": "Running other hook..."
        }
      ]
    }
  ]
}
```

**Result:** ai-guardian warnings display correctly. Other hooks can still run.

## Hook Types and Warning Display

### 1. PreToolUse (Required first for log mode)

**Displays:** Tool permissions violations, directory access violations

**Must be first if:** Using `tool_permissions` or `directory_rules` with `action: "log"`

Checks tool permissions and directory rules before tools execute. In log mode, violations are displayed via `systemMessage`:

```json
"PreToolUse": [
  {
    "matcher": "*",
    "hooks": [
      { "command": "ai-guardian", "statusMessage": "🛡️ Checking tool permissions..." },
      { "command": "your-other-hook" }
    ]
  }
]
```

**Example warnings:**
```
PreToolUse:Skill says: ⚠️ Policy violation (log mode): Skill(database-migration) not in allow list - execution allowed

PreToolUse:Read says: ⚠️ Directory access violation (log mode): Directory rules matched '~/.claude/skills/unapproved/file.txt' - access allowed
```

### 2. UserPromptSubmit (Required first for prompt injection log mode)

**Displays:** Prompt injection detection warnings

**Must be first if:** Using `prompt_injection` with `action: "log"`

**Note:** Secret scanning always blocks (`decision: "block"`) and never uses `systemMessage`, so hook ordering doesn't affect secret detection.

```json
"UserPromptSubmit": [
  {
    "hooks": [
      { "command": "ai-guardian", "statusMessage": "🛡️ Scanning prompt..." },
      { "command": "your-other-hook" }
    ]
  }
]
```

**Example warning:**
```
UserPromptSubmit says: ⚠️ Prompt injection detected (log mode): confidence=0.95 - execution allowed
```

### 3. PostToolUse (Order doesn't matter for log mode)

**Displays:** No log mode warnings (secret scanning always blocks)

**Hook ordering doesn't matter** for log mode warnings because PostToolUse only scans tool outputs for secrets, which always blocks execution regardless of order.

```json
"PostToolUse": [
  {
    "matcher": "*",
    "hooks": [
      { "command": "ai-guardian", "statusMessage": "🛡️ Scanning tool output..." },
      { "command": "your-other-hook" }
    ]
  }
]
```

**Note:** Still recommended to keep ai-guardian first for consistency.

## Setup Command Behavior

The `ai-guardian setup` command automatically configures ai-guardian as the **only** hook for each hook type. This ensures correct ordering.

**If you manually add additional hooks:**
1. Always add them **after** ai-guardian in the array
2. Never insert hooks before ai-guardian in PreToolUse or UserPromptSubmit
3. Test that warnings still display by triggering a log mode violation

## Verification

To verify your hook ordering is correct:

1. Configure a feature in log mode (e.g., tool not in allowlist, directory with deny rule)
2. Trigger the violation (e.g., use the tool, read the file)
3. Check if you see the warning: `PreToolUse:ToolName says: ⚠️ ...` or `UserPromptSubmit says: ⚠️ ...`

**If you don't see warnings:**
- Check `~/.claude/settings.json` hook ordering
- Ensure ai-guardian is first in PreToolUse and UserPromptSubmit hooks arrays
- Restart Claude Code to reload configuration

## Alternative: Separate Matchers

If you need different hooks for different tools, use separate matchers:

```json
"PreToolUse": [
  {
    "matcher": "*",
    "hooks": [
      { "command": "ai-guardian" }
    ]
  },
  {
    "matcher": "SpecificTool",
    "hooks": [
      { "command": "other-hook" }
    ]
  }
]
```

This way each matcher has only one hook, avoiding conflicts.

## Summary

### Critical Requirements (Log Mode Only)
- **PreToolUse**: ai-guardian MUST be first (displays tool permissions & directory rules warnings)
- **UserPromptSubmit**: ai-guardian MUST be first if using prompt injection log mode (secret scanning blocks regardless of order)
- **PostToolUse**: Order doesn't matter for log mode (no warnings displayed, only blocks secrets)

### Best Practices
✅ **Do:**
- Run `ai-guardian setup` to configure hooks automatically
- Keep ai-guardian first in all hooks arrays for consistency
- Test warning visibility after adding new hooks
- Use separate matchers for different tools if needed

❌ **Don't:**
- Add other hooks before ai-guardian in PreToolUse or UserPromptSubmit when using log mode
- Assume warnings will display if ordering is wrong
- Skip testing after modifying hook configuration

**Security Impact:** Incorrect hook ordering can suppress log mode warnings, eliminating visibility into policy violations. Always verify warnings display correctly.

## Technical Details

Each hook type uses JSON responses with `systemMessage` to display warnings:

**PreToolUse response:**
```json
{
  "hookSpecificOutput": {
    "permissionDecision": "allow",
    "hookEventName": "PreToolUse"
  },
  "systemMessage": "⚠️ Policy violation (log mode): ..."
}
```

**UserPromptSubmit response:**
```json
{
  "systemMessage": "⚠️ Prompt injection detected (log mode): ..."
}
```

Claude Code displays the first hook's `systemMessage` to the user, which is why ordering matters.
