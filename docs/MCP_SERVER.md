# MCP Security Advisor Server

AI Guardian includes an MCP (Model Context Protocol) server that exposes read-only security tools to AI agents. The AI can check security **before** acting — instead of being blocked by hooks and retrying.

## Three-Layer Security Model

| Layer | Role | Trust |
|-------|------|-------|
| **MCP server** | Tools the AI *can* use | Advisory — AI chooses to use them |
| **Skill (instructions)** | Guidance for *when* to use them | Loaded automatically on MCP connect |
| **Hooks** | Enforcement if AI doesn't check | Mandatory — can't bypass |

## Setup

### Install with hooks

```bash
ai-guardian setup --ide claude --mcp
```

This adds the MCP server to your IDE config and enables it in `ai-guardian.json`.

### Manual setup

Add to `~/.claude.json` (or `~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "ai-guardian": {
      "command": "ai-guardian",
      "args": ["mcp-server"]
    }
  }
}
```

### Via uvx (no install needed)

```json
{
  "mcpServers": {
    "ai-guardian": {
      "command": "uvx",
      "args": ["ai-guardian", "mcp-server"]
    }
  }
}
```

### Multi-IDE support

| IDE | MCP config file |
|-----|----------------|
| Claude Code | `~/.claude/settings.json` or `~/.claude.json` → `mcpServers` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` |

## Enable / Disable

The MCP server is controlled by IDE config. Install/uninstall via:

```bash
ai-guardian setup --ide claude --mcp      # Install
ai-guardian setup --ide claude --no-mcp   # Uninstall
```

## Proactive Level

Controls how aggressively the AI uses proactive security checks. Higher levels add latency and token usage (each check adds tool call/result pairs to the conversation context).

| Level | Behavior | Best for |
|-------|----------|----------|
| **low** (default) | Check only when user asks or after a block | Most users — hooks enforce everything |
| **medium** | Also check unfamiliar paths and suspicious commands | Teams wanting fewer blocked-and-retry cycles |
| **high** | Check every file access and command | High-security environments |

Configure via:
- `ai-guardian.json`: `"mcp_server": {"proactive_level": "low"}`
- Tray menu: MCP submenu → Proactive radio buttons
- Console: MCP Servers panel → Proactive Level dropdown

## Tools

### Security Checks (Proactive)

| Tool | Parameters | Returns | Purpose |
|------|-----------|---------|---------|
| `check_path` | `path` | `allowed` / `denied` / `not_found` | Is this path protected? |
| `check_command` | `command` | `allowed` / `blocked` + reason | Would this command be blocked? |
| `check_mcp_trust` | `server_name` | `trusted` / `untrusted` | Is this MCP server allowed? |
| `sanitize_text` | `text` | sanitized text + redaction count | Redact secrets/PII from text |
| `check_annotations` | `file_path` | valid/invalid + warnings | Are annotation pairs matched? |

### Information (Query)

| Tool | Parameters | Returns | Purpose |
|------|-----------|---------|---------|
| `get_violations` | `violation_type?`, `limit?` | violation list with file:line | Recent security violations |
| `get_config` | — | feature enabled/disabled map | Current security posture |
| `get_scanner_status` | — | installed scanners + versions | Scanner inventory |
| `get_scanner_supported` | — | all available scanners | What can be installed |
| `get_patterns_list` | — | category names + counts | Active detection patterns |
| `get_metrics` | `since_days?` | stats by type/severity | Violation statistics |
| `doctor` | — | check results with fix hints | Health check |

### Support Bundle

| Tool | Parameters | Returns | Purpose |
|------|-----------|---------|---------|
| `prepare_support_bundle` | — | bundle_id, temp_path, file list | Create sanitized diagnostics |
| `send_support_bundle` | `bundle_id` | sent/error | Send after user review |

## Resources

| URI | Content |
|-----|---------|
| `ai-guardian://security-posture` | Feature status, action modes, scanner status |
| `ai-guardian://protected-paths` | Directories with `.ai-read-deny` markers |
| `ai-guardian://recent-violations` | Last 10 violations |

## Security Model

The MCP server is a **security advisor, not a security map**. It answers yes/no — it does not expose rules, patterns, or allowlists that could be used to find gaps.

| Tool | Exposes | Does NOT expose |
|------|---------|-----------------|
| `check_path` | allowed/denied | Which rule matched, full rules list |
| `check_command` | allowed/blocked + reason category | Which pattern matched, the deny list |
| `get_config` | Feature on/off, action mode | Allowlist patterns, regex, rule details |
| `get_violations` | Type, timestamp, file:line, action | Matched pattern internals |
| `get_patterns_list` | Category names and counts | Regex patterns |

### Self-protection

- ai-guardian's own MCP tools (`mcp__ai-guardian__*`) are auto-allowed — they don't need explicit permission rules
- All other MCP servers require explicit allow rules in the permissions config
- The MCP server process runs separately from the daemon — if the daemon is unavailable, MCP tools still work

## Support Bundle Flow

The support bundle uses a two-step process with user approval:

1. **Prepare**: `prepare_support_bundle()` creates a sanitized temp directory (protected by `.ai-read-deny`)
2. **Review**: AI shows the file list with redaction counts and the temp path — the user reviews and deletes unwanted files
3. **Send**: After user approval, `send_support_bundle(bundle_id)` sends remaining files to the configured destination

Sanitized files include: config (tokens redacted), violations (paths truncated), metrics (aggregate only), doctor results, system info, and full log (secrets/PII redacted).

Default destination: `~/.local/state/ai-guardian/support-bundles/`. Configure via `support.export_destination` (local path, `s3://bucket/prefix/`, or `gs://bucket-name/`).

### CLI Alternative

The same prepare/send workflow is available via the CLI for direct use without an AI agent:

```bash
ai-guardian support prepare                    # Prepare bundle, show file summary
ai-guardian support send                       # Send last prepared bundle (with confirmation)
ai-guardian support send --prepare --yes       # One-shot: prepare + send (for CI)
ai-guardian support status                     # Show destination, auth, pending bundles
ai-guardian support prepare --output ./bundle  # Save to specific directory
ai-guardian support prepare --no-log           # Exclude log file
```

Both interfaces share the same underlying logic — same sanitization, same destinations, same bundle format.

## Configuration

```json
{
  "mcp_server": {
    "proactive_level": "low"
  },
  "support": {
    "export_destination": "",
    "auth": {
      "method": "none",
      "token_env": ""
    },
    "bundle_ttl_minutes": 30
  }
}
```

## Requirements

- **Direct install** (`ai-guardian mcp-server`): Python >=3.10 (MCP SDK requirement). ai-guardian itself still supports Python 3.9 for all other features (hooks, CLI, Console, scanning).
- **Via uvx** (`uvx ai-guardian mcp-server`): No Python version requirement — uvx manages its own environment. This is the recommended method for users on Python 3.9.
- For S3 export: `pip install boto3`
- For GCS export: Google Application Default Credentials (`gcloud auth application-default login`) or `GOOGLE_APPLICATION_CREDENTIALS` env var. No extra packages needed.

## Skill Instructions

The MCP server automatically loads skill instructions (from the bundled `SKILL.md`) during the MCP initialize handshake. The AI receives these instructions when the server connects — no separate skill installation needed.

The instructions teach the AI:
- When to use each tool based on the proactive level
- How to handle annotation protection
- The support bundle review workflow
- That hooks are the enforcement layer — MCP is advisory
