# GitHub Copilot Hook Format Research

**Research Date:** 2026-03-27
**Status:** ✅ Complete
**Finding:** **CODE CHANGES REQUIRED** - Configuration alone is insufficient

---

## Executive Summary

GitHub Copilot's hook system uses **incompatible JSON formats** compared to Claude Code and Cursor. Integration requires code changes to implement format adapters and response transformers.

**Key Differences:**
- Different field names (`toolName` vs `tool_use.name`)
- Different response format (JSON with `permissionDecision` vs exit codes)
- Tool arguments as JSON string (Copilot) vs object (Claude/Cursor)
- Three-level permission system (`allow`/`deny`/`ask`) vs binary

---

## 1. GitHub Copilot Hook Formats

### userPromptSubmitted Event

**Input Format:**
```json
{
  "timestamp": 1704614400000,
  "cwd": "/path/to/project",
  "prompt": "Create a new feature",
  "source": "user"
}
```

**Fields:**
- `timestamp`: Unix milliseconds (not seconds)
- `cwd`: Current working directory
- `prompt`: User's prompt text
- `source`: Origin of prompt (`"user"` or `"agent"`)

**Expected Response:**
- Exit code only (0=allow, non-zero=block)
- Optional stderr output for error messages

---

### preToolUse Event

**Input Format:**
```json
{
  "timestamp": 1704614600000,
  "cwd": "/path/to/project",
  "toolName": "bash",
  "toolArgs": "{\"command\":\"npm test\",\"description\":\"Run tests\"}"
}
```

**Fields:**
- `timestamp`: Unix milliseconds
- `cwd`: Current working directory
- `toolName`: Tool identifier (`"bash"`, `"read_file"`, `"write_file"`, etc.)
- `toolArgs`: **JSON string** (not object!) containing tool-specific arguments

**Expected Response (JSON on stdout):**
```json
{
  "permissionDecision": "allow",
  "permissionDecisionReason": "Tool is allowed"
}
```

**Permission Decisions:**
- `"allow"` - Execute the tool
- `"deny"` - Block the tool
- `"ask"` - Prompt user for confirmation (Copilot-specific)

---

## 2. Comparison with Existing Formats

### Claude Code Format

**UserPromptSubmit Input:**
```json
{
  "hook_event_name": "UserPromptSubmit",
  "prompt": "...",
  "session_id": "...",
  "tool_use": { ... }
}
```

**PreToolUse Input:**
```json
{
  "hook_event_name": "PreToolUse",
  "tool_use": {
    "name": "Skill|mcp__*|Read|Write|Bash",
    "input": {
      "skill": "...",
      "command": "...",
      "file_path": "..."
    }
  }
}
```

**Response:**
- Exit code 0 = allow
- Exit code 2 = block
- No JSON output required

---

### Cursor Format

**beforeSubmitPrompt Input:**
```json
{
  "hook_name": "beforeSubmitPrompt",
  "cursor_version": "0.43.0",
  "message": "User's prompt",
  "userMessage": "User's prompt"
}
```

**preToolUse Input:**
```json
{
  "hook_name": "preToolUse",
  "cursor_version": "0.43.0",
  "tool": {
    "name": "bash",
    "arguments": { "command": "npm test" }
  }
}
```

**Response (JSON on stdout):**
```json
{
  "continue": true,
  "user_message": "Optional message",
  "decision": "allow",
  "permission": "allow"
}
```

---

## 3. Compatibility Matrix

| Aspect | Claude Code | Cursor | GitHub Copilot | Compatible? |
|--------|------------|--------|----------------|-------------|
| **Event Detection Field** | `hook_event_name` | `hook_name` | None (detect by fields) | ❌ Different |
| **Timestamp** | None | None | `timestamp` (ms) | ⚠️ Copilot only |
| **Working Directory** | None | None | `cwd` | ⚠️ Copilot only |
| **Prompt Field** | `prompt` | `message`/`userMessage` | `prompt` | ⚠️ Mixed |
| **Tool Name** | `tool_use.name` | `tool.name` | `toolName` | ❌ Different structure |
| **Tool Arguments** | `tool_use.input` (object) | `tool.arguments` (object) | `toolArgs` (JSON string) | ❌ Different type |
| **Response Type** | Exit code only | JSON + exit code | JSON only | ❌ Incompatible |
| **Permission Levels** | Binary (0/2) | Binary (allow/deny) | Ternary (allow/deny/ask) | ❌ Different |

---

## 4. Code Changes Required

### 4.1 Detection Logic Updates

**Current detection (`detect_ide_type()` at line 59):**
```python
def detect_ide_type(hook_data):
    # Check for environment variable override
    ide_override = os.environ.get("AI_GUARDIAN_IDE_TYPE", "").lower()
    if ide_override == "cursor":
        return IDEType.CURSOR
    elif ide_override == "claude":
        return IDEType.CLAUDE_CODE

    # Auto-detect based on input structure
    if "cursor_version" in hook_data:
        return IDEType.CURSOR

    if "hook_name" in hook_data:
        return IDEType.CURSOR

    if "hook_event_name" in hook_data:
        return IDEType.CLAUDE_CODE

    # Default to Claude Code format
    return IDEType.CLAUDE_CODE
```

**Needs addition:**
```python
    # GitHub Copilot detection (add before defaults)
    if "toolName" in hook_data:
        return IDEType.GITHUB_COPILOT

    # More robust: timestamp (ms) + cwd + prompt/toolName pattern
    if ("timestamp" in hook_data and
        "cwd" in hook_data and
        ("toolName" in hook_data or "prompt" in hook_data)):
        return IDEType.GITHUB_COPILOT
```

### 4.2 New IDEType Enum Value

**Add to `IDEType` enum (line 52):**
```python
class IDEType(Enum):
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    GITHUB_COPILOT = "github_copilot"  # NEW
    UNKNOWN = "unknown"
```

### 4.3 Response Format Updates

**Current `format_response()` function (line 96):**
```python
def format_response(ide_type, has_secrets, error_message=None, hook_event="prompt"):
    if ide_type == IDEType.CURSOR:
        # Cursor expects JSON on stdout AND exit code 2 to block
        # ... existing Cursor logic ...
    else:
        # Claude Code (and unknown) use exit codes
        # ... existing Claude Code logic ...
```

**Needs addition:**
```python
def format_response(ide_type, has_secrets, error_message=None, hook_event="prompt"):
    if ide_type == IDEType.GITHUB_COPILOT:
        # GitHub Copilot expects JSON with permissionDecision field
        if hook_event == "pretooluse":
            response = {
                "permissionDecision": "deny" if has_secrets else "allow"
            }
            if has_secrets and error_message:
                response["permissionDecisionReason"] = error_message

            return {
                "output": json.dumps(response),
                "exit_code": 2 if has_secrets else 0
            }
        else:
            # userPromptSubmitted uses exit codes like Claude Code
            if has_secrets and error_message:
                print(error_message, file=sys.stderr)

            return {
                "output": None,
                "exit_code": 2 if has_secrets else 0
            }

    elif ide_type == IDEType.CURSOR:
        # ... existing Cursor logic ...
```

### 4.4 Tool Extraction Updates

**Current tool extraction (`extract_file_content_from_tool()` at line 235):**
```python
def extract_file_content_from_tool(hook_data):
    # Try to extract file path from different possible locations
    file_path = None

    # Claude Code format: tool_use.parameters.file_path
    if "tool_use" in hook_data:
        # ...

    # Cursor format: tool_input.file_path
    if not file_path and "tool_input" in hook_data:
        # ...
```

**Needs addition:**
```python
    # GitHub Copilot format: toolName + toolArgs (JSON string)
    if not file_path and "toolName" in hook_data and "toolArgs" in hook_data:
        try:
            # Parse toolArgs from JSON string
            tool_args = json.loads(hook_data["toolArgs"])
            file_path = tool_args.get("file_path") or tool_args.get("path")
        except json.JSONDecodeError:
            logging.warning("Could not parse Copilot toolArgs JSON")
```

### 4.5 Hook Event Detection Updates

**Current event detection (`detect_hook_event()` at line 149):**
```python
def detect_hook_event(hook_data):
    # Check hook_event_name for both Claude Code and Cursor
    event_name = hook_data.get("hook_event_name", "").lower()
    # ... existing logic ...
```

**Needs addition:**
```python
    # GitHub Copilot: detect by presence of toolName field
    if "toolName" in hook_data:
        return "pretooluse"

    # Copilot userPromptSubmitted: has prompt but no toolName
    if "prompt" in hook_data and "timestamp" in hook_data and "cwd" in hook_data:
        return "prompt"
```

---

## 5. Tool Policy Checker Updates

**File:** `src/ai_guardian/tool_policy.py`

The tool policy checker needs to understand Copilot's tool format:

**Current logic expects:**
- `tool_use.name` (Claude Code)
- `tool.name` (Cursor)

**Needs to support:**
- `toolName` (GitHub Copilot)
- `toolArgs` as JSON string (not object)

**Example change needed:**
```python
def check_tool_allowed(self, hook_data):
    # ... existing code ...

    # Extract tool name
    tool_name = None

    # GitHub Copilot format
    if "toolName" in hook_data:
        tool_name = hook_data["toolName"]

        # Parse toolArgs to get detailed input
        if "toolArgs" in hook_data:
            try:
                tool_input = json.loads(hook_data["toolArgs"])
            except:
                tool_input = {}

    # Claude Code format
    elif "tool_use" in hook_data:
        # ... existing logic ...
```

---

## 6. Implementation Estimate

**Effort:** 1-2 weeks (code changes required)

**Files to Modify:**
1. ✏️ `src/ai_guardian/__init__.py` - Core hook processing
   - Add `GITHUB_COPILOT` to `IDEType` enum
   - Update `detect_ide_type()` function
   - Update `format_response()` function
   - Update `extract_file_content_from_tool()` function
   - Update `detect_hook_event()` function

2. ✏️ `src/ai_guardian/tool_policy.py` - Tool permissions
   - Add Copilot `toolName` field support
   - Parse `toolArgs` JSON string

3. ✅ `tests/test_ai_guardian.py` - Add Copilot test cases
   - Test Copilot input detection
   - Test Copilot response formatting
   - Test toolArgs JSON string parsing

4. 📝 `README.md` - Document Copilot support
   - Add configuration example
   - Update IDE support table

5. 📝 `docs/GITHUB_COPILOT.md` - New integration guide
   - Hook configuration for `.github/hooks/hooks.json`
   - Setup instructions
   - Troubleshooting

**Testing Requirements:**
- Unit tests for format detection
- Unit tests for response formatting
- Integration tests with mock Copilot JSON payloads
- Manual testing with real GitHub Copilot (if available)

---

## 7. Alternative: Environment Variable Override

**Limited workaround:**
```bash
export AI_GUARDIAN_IDE_TYPE=github_copilot
```

**Problems:**
- Won't fix JSON format differences
- Won't handle response format requirements
- Won't parse `toolArgs` JSON strings correctly
- **Cannot work without code changes**

---

## 8. Conclusion

**Finding:** **Configuration-only approach is NOT viable**

**Reason:** GitHub Copilot uses fundamentally different JSON structures and response formats that cannot be handled by simple configuration or environment variables.

**Required Path:** Implement format adapter (Phase 1B from issue)

**Alternative Considered:** Using `AI_GUARDIAN_IDE_TYPE` environment variable
**Verdict:** Insufficient - still requires code changes to handle format differences

---

## 9. Next Steps

1. ✅ Document findings (this file)
2. ⏭️ Continue research for Aider and VS Code
3. ⏭️ Update implementation plan in issue #1
4. ⏭️ Begin Phase 1B implementation (code changes)

---

## 10. Sources

- [About hooks - GitHub Docs](https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-hooks)
- [Using hooks with GitHub Copilot agents](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks)
- [Hooks configuration reference](https://docs.github.com/en/copilot/reference/hooks-configuration)
- [Agent hooks in VS Code (Preview)](https://code.visualstudio.com/docs/copilot/customization/hooks)
- [GitHub Copilot Hooks Complete Guide - SmartScope](https://smartscope.blog/en/generative-ai/github-copilot/github-copilot-hooks-guide/)
- [ai-guardian source code analysis](../src/ai_guardian/__init__.py)

---

**Last Updated:** 2026-03-27
**Confidence Level:** High - Based on official GitHub documentation and source code analysis
