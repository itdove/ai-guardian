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
| OpenCode | `--ide opencode` | Plugin | N/A | **Complete** |
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
| OpenCode | Yes (chat.message) | Yes | Yes | N/A |
| Junie | N/A | N/A | N/A | N/A |

## Protection Level by Hook Availability

| Hooks Available | AI Guardian Capabilities |
|----------------|------------------------|
| **Full hooks** (Prompt + Pre + Post) | Secret scanning, PII detection, prompt injection, SSRF, directory blocking, config scanning, redaction, tool permissions |
| **Pre + Post only** (no Prompt) | All above except prompt scanning and transcript scanning |
| **MCP only** (no hooks) | Advisory checks only — check_path, check_command, check_mcp_trust, sanitize_text. No enforcement (agent must cooperate) |
| **None** | No protection available |

## Violation Type Coverage Matrix

Coverage per agent depends on which hooks are available. This table shows representative agents across the enforcement spectrum: full hooks + MCP, full hooks only, partial hooks, and MCP-only.

Agents with full hook support not shown individually (Codex, Windsurf, Gemini CLI, Cline, Kiro, OpenCode) have the same coverage as Claude Code, minus MCP and minus UserPromptSubmit where applicable — see the [Hook Capability Matrix](#hook-capability-matrix) above.

| Violation Type | Requires | Claude Code | Cursor | Copilot | Junie (MCP) |
|---|---|---|---|---|---|
| secret_detected | Pre+Post | Enforce | Enforce | Enforce | Advisory |
| secret_redaction | Post | Enforce | Enforce | Enforce | No |
| pii_detected | Pre+Post+Prompt | Enforce | Enforce | Partial | Advisory |
| directory_blocking | Pre | Enforce | Enforce | Enforce | Advisory |
| tool_permission | Pre | Enforce | Enforce | Enforce | No |
| prompt_injection | Pre+Prompt | Enforce | Enforce | Partial | Advisory |
| jailbreak_detected | Pre+Prompt | Enforce | Enforce | Partial | Advisory |
| ssrf_blocked | Pre | Enforce | Enforce | Enforce | Advisory |
| config_file_exfil | Pre | Enforce | Enforce | Enforce | No |
| secret_in_transcript | Prompt | Enforce | No | No | No |
| pii_in_transcript | Prompt | Enforce | No | No | No |
| image_secret | Pre | Caution | Caution | Caution | No |
| image_pii | Pre | Caution | Caution | Caution | No |

**Legend:**

- **Enforce** — fully tested and working
- **Advisory** — MCP only, agent must cooperate (no enforcement)
- **Partial** — no UserPromptSubmit, only file content scanned
- **Caution** — known limitations (see [Image scanning](#image-scanning-all-agents) below)
- **No** — not supported

## Known Limitations

### Image scanning (all agents)

Claude Code binary file reads bypass hooks — image content may not pass through PreToolUse in a scannable format. Image scanning works best when images are base64-encoded in tool output, not when read as raw binary. See [#801](https://github.com/itdove/ai-guardian/issues/801) for tracking.

### Transcript scanning availability

Only Claude Code exposes the conversation transcript to hooks via `UserPromptSubmit`. Agents without this hook cannot scan for secrets or PII in the transcript, so `secret_in_transcript` and `pii_in_transcript` violations are Claude Code-only.

### MCP-only agents

Junie and any future MCP-only agents rely on the agent voluntarily calling ai-guardian's MCP tools. There is no enforcement mechanism — if the agent ignores the advisory, the violation is not blocked. MCP-only agents also cannot perform post-tool redaction or tool permission enforcement.

## Agent Confidence Levels

Testing depth varies by agent. Confidence reflects how thoroughly the hook adapter has been validated in real-world usage.

| Agent | Confidence | Reason |
|---|---|---|
| Claude Code | High | Extensively tested in production |
| Cursor | High | Extensively tested in production |
| Copilot | Medium | Tested but limited UserPromptSubmit |
| Gemini CLI | Low | Hook format implemented but limited testing |
| Codex | Low | Hook format implemented but limited testing |
| Windsurf | Low | Hook format implemented but limited testing |
| Cline / ZooCode | Low | Hook format implemented but limited testing |
| Augment Code | Low | Hook format implemented but limited testing |
| Kiro | Low | Hook format implemented but limited testing |
| Junie | Low | MCP only, no hook enforcement |
| AiderDesk | Low | Extension-based, limited testing |
| OpenClaw | Low | Plugin-based, limited testing |
| OpenCode | Low | Plugin-based, limited testing |

## Community Testing Feedback

For agents marked **Low confidence**, we implemented the hook adapter based on available documentation but could not fully test all scenarios. If you use ai-guardian with these agents, please report:

- Which violation types work correctly
- Which violation types fail or behave unexpectedly
- Any hook format differences from documentation

Report via [GitHub Discussions](https://github.com/itdove/ai-guardian/discussions) or [Issues](https://github.com/itdove/ai-guardian/issues).

## Hook Event Name Mapping

Each agent uses different event names. The adapter layer normalizes these.

| Concept | Claude Code | Copilot | Cursor | Windsurf | Gemini CLI | Cline | Kiro | OpenCode |
|---------|------------|---------|--------|----------|-----------|-------|------|----------|
| Before tool | `PreToolUse` | `preToolUse` | `beforeShellExecution` | `pre_run_command` | `BeforeTool` | `PreToolUse` | `pre_tool_use` | `tool.execute.before` |
| After tool | `PostToolUse` | `postToolUse` | `postToolUse` | `post_run_command` | `AfterTool` | `PostToolUse` | `post_tool_use` | `tool.execute.after` |
| User prompt | `UserPromptSubmit` | `userPromptSubmitted` | `beforeSubmitPrompt` | `pre_user_prompt` | `BeforeAgent` | `UserPromptSubmit` | `prompt_submit` | `message.submit` |

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
| OpenCode | Same as Claude Code | Same as Claude Code |

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
├── opencode.py          # OpenCode (extends ClaudeCodeAdapter)
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
- `opencode_version` → OpenCode

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

Agent names: `claude`, `cursor`, `copilot`, `codex`, `windsurf`, `gemini`, `cline`, `zoocode`, `kiro`, `augment`, `aiderdesk`, `openclaw`, `opencode`, `junie`

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
| OpenCode | `~/.config/opencode/plugins/ai-guardian.ts` (plugin) |
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
5. Update the tables in this document:
   - Supported Agents table
   - Hook Capability Matrix
   - Violation Type Coverage Matrix (or note coverage matches an existing agent)
   - Agent Confidence Levels table
   - Hook Event Name Mapping
   - Response Format Differences
   - Config File Locations

## Adding a New Violation Type

1. Implement the detector in the appropriate module
2. Add a row to the **Violation Type Coverage Matrix** with the required hooks and per-agent coverage
3. If the violation has agent-specific limitations, add a subsection under **Known Limitations**
4. Add tests covering the new violation type across adapters
