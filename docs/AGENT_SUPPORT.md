# Agent Support

AI Guardian protects multiple AI coding agents through a unified hook adapter architecture. Each agent gets a dedicated adapter that normalizes its hook format into a common internal model, so the core scanning pipeline stays agent-agnostic.

## Supported Agents

| Agent | Setup Command | Hooks | MCP | Status |
|-------|--------------|-------|-----|--------|
| Claude Code | `--ide claude` | Full | Full | **Complete** |
| Cursor | `--ide cursor` | Full | N/A | **Complete** |
| GitHub Copilot | `--ide copilot` | Full | N/A | **Complete** |
| OpenAI Codex | `--ide codex` | Full | N/A | **Complete** |
| Windsurf | `--ide windsurf` | Full | N/A | **Complete** |
| Gemini CLI | `--ide gemini` | Full | N/A | **Complete** |
| Cline / ZooCode | `--ide cline` | Full | N/A | **Complete** |
| Kiro (AWS) | `--ide kiro` | Full | N/A | **Complete** |
| Augment Code | `--ide augment` | Full | N/A | **Complete** |
| AiderDesk | `--ide aiderdesk` | Extension | N/A | **Complete** |
| OpenClaw | `--ide openclaw` | Plugin | N/A | **Complete** |
| Junie (JetBrains) | `--ide junie` | N/A | Full | **MCP-only** |

## Hook Capability Matrix

| Agent | UserPromptSubmit | PreToolUse | PostToolUse | BeforeReadFile |
|-------|-----------------|------------|-------------|----------------|
| Claude Code | Yes | Yes | Yes | N/A |
| Cursor | Yes | Yes | Yes | Yes |
| GitHub Copilot | Yes | Yes | N/A | N/A |
| OpenAI Codex | Yes | Yes | Yes | N/A |
| Windsurf | Yes | Yes | Yes | Yes |
| Gemini CLI | Yes (BeforeAgent) | Yes | Yes | N/A |
| Cline / ZooCode | Yes | Yes | Yes | N/A |
| Kiro | Yes | Yes | Yes | N/A |
| Augment Code | N/A | Yes | Yes | N/A |
| Junie | N/A | N/A | N/A | N/A |

## Protection Level by Hook Availability

| Hooks Available | AI Guardian Capabilities |
|----------------|------------------------|
| **Full hooks** (Prompt + Pre + Post) | Secret scanning, PII detection, prompt injection, SSRF, directory blocking, config scanning, redaction, tool permissions |
| **Pre + Post only** (no Prompt) | All above except prompt scanning and transcript scanning |
| **MCP only** (no hooks) | Advisory checks only — check_path, check_command, check_mcp_trust, sanitize_text. No enforcement (agent must cooperate) |
| **None** | No protection available |

## Hook Event Name Mapping

Each agent uses different event names. The adapter layer normalizes these.

| Concept | Claude Code | Copilot | Cursor | Windsurf | Gemini CLI | Cline | Kiro |
|---------|------------|---------|--------|----------|-----------|-------|------|
| Before tool | `PreToolUse` | `preToolUse` | `beforeShellExecution` | `pre_run_command` | `BeforeTool` | `PreToolUse` | `pre_tool_use` |
| After tool | `PostToolUse` | `postToolUse` | `postToolUse` | `post_run_command` | `AfterTool` | `PostToolUse` | `post_tool_use` |
| User prompt | `UserPromptSubmit` | `userPromptSubmitted` | `beforeSubmitPrompt` | `pre_user_prompt` | `BeforeAgent` | `UserPromptSubmit` | `prompt_submit` |

## Response Format Differences

| Agent | Blocking Mechanism | Block Response |
|-------|-------------------|----------------|
| Claude Code | JSON `hookSpecificOutput.permissionDecision` | `{"hookSpecificOutput": {"permissionDecision": "deny"}}` |
| Cursor | JSON `decision`/`permission` field | `{"decision": "deny", "reason": "..."}` |
| GitHub Copilot | JSON (PreToolUse) or exit code 2 | `{"permissionDecision": "deny"}` |
| Gemini CLI | JSON `decision` field | `{"decision": "deny", "reason": "..."}` |
| Cline | JSON `cancel` field | `{"cancel": true, "reason": "..."}` |
| Kiro | Exit code 1 + stderr | stderr = error message |
| Windsurf | Same as Claude Code | Same as Claude Code |
| Codex | Same as Claude Code | Same as Claude Code |

## Architecture

### Adapter Layer

Each agent has a dedicated adapter class in `src/ai_guardian/hook_adapters/`:

```
hook_adapters/
├── __init__.py          # Registry: detect_adapter(), get_adapter_by_ide_type()
├── base.py              # HookAdapter ABC + NormalizedHookInput dataclass
├── claude_code.py       # Claude Code (default fallback)
├── cursor.py            # Cursor IDE
├── copilot.py           # GitHub Copilot
├── codex.py             # OpenAI Codex (extends ClaudeCodeAdapter)
├── windsurf.py          # Windsurf (extends ClaudeCodeAdapter)
├── gemini.py            # Google Gemini CLI
├── cline.py             # Cline / ZooCode
├── kiro.py              # Kiro + AiderDesk + OpenClaw
├── augment.py           # Augment Code (extends ClaudeCodeAdapter)
└── junie.py             # Junie (MCP-only placeholder)
```

### How Detection Works

1. Check `AI_GUARDIAN_IDE_TYPE` environment variable (explicit override)
2. Try each adapter's `can_handle(hook_data)` method in priority order
3. Fall back to Claude Code adapter (handles PascalCase and all unknown formats)

Detection priority checks unique fields:
- `clineVersion` → Cline
- `transcript_path` → Gemini CLI
- `agent_action_name` → Windsurf
- `toolName` → GitHub Copilot
- `cursor_version` → Cursor
- `kiro_hook_type` → Kiro
- `is_mcp_tool` → Augment Code

### NormalizedHookInput

All adapters produce a `NormalizedHookInput` dataclass with consistent fields:

| Field | Type | Description |
|-------|------|-------------|
| `event` | `HookEvent` | Normalized event (PROMPT, PRE_TOOL_USE, POST_TOOL_USE) |
| `tool_name` | `str` | Canonical tool name (e.g., "Bash", "Read") |
| `tool_input` | `dict` | Tool parameters |
| `file_path` | `str` | File being accessed |
| `working_dir` | `str` | Working directory |
| `session_id` | `str` | Session correlation ID |
| `tool_use_id` | `str` | Tool use correlation ID |
| `prompt_text` | `str` | User prompt text |
| `tool_response` | `Any` | Tool output (PostToolUse) |
| `transcript_path` | `str` | Path to conversation transcript |
| `raw_data` | `dict` | Original hook data |

## Setup

Install hooks for any supported agent:

```bash
ai-guardian setup --ide <agent-name>
```

Agent names: `claude`, `cursor`, `copilot`, `codex`, `windsurf`, `gemini`, `cline`, `zoocode`, `kiro`, `augment`, `aiderdesk`, `openclaw`, `junie`

### Config File Locations

| Agent | Config Path |
|-------|------------|
| Claude Code | `~/.claude/settings.json` |
| Cursor | `~/.cursor/hooks.json` |
| GitHub Copilot | `~/.github/hooks/hooks.json` |
| OpenAI Codex | `~/.codex/hooks.json` |
| Windsurf | `~/.codeium/windsurf/hooks.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Cline / ZooCode | `.clinerules/hooks/` (scripts) |
| Kiro | `.kiro/hooks/` (scripts) |
| Augment Code | `~/.augment/settings.json` |
| Junie | `.junie/guidelines` (MCP only) |

## Per-Agent Deep-Dive Guides

| Agent | Guide | Description |
|-------|-------|-------------|
| GitHub Copilot | [GITHUB_COPILOT.md](GITHUB_COPILOT.md) | Detailed setup, troubleshooting, response format, enterprise deployment |
| Aider (CLI) | [AIDER.md](AIDER.md) | Git pre-commit hook integration (not hook adapter — scans at commit time) |
| AiderDesk | [AIDERDESK.md](AIDERDESK.md) | TypeScript extension setup, npm install, hot reload |

## Adding a New Agent

1. Create `src/ai_guardian/hook_adapters/<agent>.py` implementing `HookAdapter`
2. Add the adapter to `ADAPTER_CLASSES` in `hook_adapters/__init__.py`
3. Add setup config to `IDESetup.IDE_CONFIGS` in `setup.py`
4. Add tests in `tests/unit/test_<agent>_support.py`
5. Update this document
