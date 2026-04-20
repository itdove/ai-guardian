# AI Guardian

<p align="center">
  <img src="https://raw.githubusercontent.com/itdove/ai-guardian/main/images/ai-guardian-320.png" alt="AI Guardian Logo" width="320">
</p>

> AI IDE security hook: controls MCP/skill permissions, blocks directories, detects prompt injection, scans secrets

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/ai-guardian.svg)](https://pypi.org/project/ai-guardian/)

AI Guardian provides comprehensive protection for AI IDE interactions through multiple security layers.

## ⚠️ Security Disclaimer

**AI Guardian is not a silver bullet** and cannot guarantee detection of all security threats.

- **Prompt injection detection** may miss novel or obfuscated attacks
- **Secret scanning** depends on Gitleaks patterns and may miss custom secret formats
- **Attackers evolve continuously** - new bypass techniques emerge constantly
- **Fail-open by design** - prioritizes availability over security (errors allow operations)

**Use AI Guardian as ONE layer in a defense-in-depth security strategy, not as your only protection.**

Combine with:
- ✅ Code review processes
- ✅ Security testing and auditing
- ✅ Runtime monitoring
- ✅ Other security tools and best practices

**No warranty:** This software is provided "AS IS" under the Apache 2.0 License. See [LICENSE](LICENSE) for details.

---

## Quick Start

```bash
# 1. Install a secret scanner (macOS)
brew install gitleaks           # Standard (recommended)
# OR
brew install betterleaks        # Faster alternative (20-40% faster)
# OR
brew install leaktk/tap/leaktk  # Auto-pattern management

# 2. Install AI Guardian from PyPI
pip install ai-guardian

# 3. Setup IDE hooks (auto-detects Claude Code, Cursor, or GitHub Copilot)
ai-guardian setup

# 4. (Optional) Setup with remote configuration
ai-guardian setup --remote-config-url https://example.com/ai-guardian-policy.json

# 5. (Optional) Set up MCP/Skill permissions
mkdir -p ~/.config/ai-guardian
cp ai-guardian-example.json ~/.config/ai-guardian/ai-guardian.json
# Edit the file to allow your specific skills and MCP servers
```

## Setup Command

The `ai-guardian setup` command automatically configures IDE hooks for you.

**⚠️ IMPORTANT:** 
- Run `ai-guardian setup` after upgrading to get the latest security hooks. New versions may add additional hooks (e.g., PostToolUse for output scanning).
- If you manually add other hooks, **ai-guardian MUST be the first PostToolUse hook** (required for warn mode warnings). UserPromptSubmit ordering only matters if using prompt injection warn mode. See [Hook Ordering Documentation](docs/HOOK_ORDERING.md) for details.

### Basic Usage

```bash
# Auto-detect IDE and setup hooks
ai-guardian setup

# Specify IDE explicitly
ai-guardian setup --ide claude
ai-guardian setup --ide cursor

# Setup with remote configuration URL
ai-guardian setup --remote-config-url https://example.com/ai-guardian-policy.json

# Preview changes without applying
ai-guardian setup --dry-run

# Force overwrite existing hooks
ai-guardian setup --force

# Non-interactive mode (skip confirmations)
ai-guardian setup --yes
```

### What it Does

1. **IDE Detection**: Auto-detects Claude Code, Cursor, or GitHub Copilot based on config directories
2. **Hook Configuration**: Adds ai-guardian hooks to your IDE config
3. **Backup Creation**: Creates `.backup` file before modifying existing config
4. **Config Merging**: Preserves your existing IDE configuration
5. **Remote Config**: Optionally adds remote config URLs for centralized policies
6. **Environment Variables**: Respects IDE-specific env vars (e.g., `CLAUDE_CONFIG_DIR`)

### Examples

**Setup for Claude Code with confirmation:**
```bash
ai-guardian setup --ide claude
```

**Setup for Cursor without confirmation:**
```bash
ai-guardian setup --ide cursor --yes

**Setup for GitHub Copilot:**
```bash
ai-guardian setup --ide copilot
```

**Setup for Aider (git hooks):**
```bash
# Aider uses git pre-commit hooks instead of IDE hooks
# See docs/AIDER.md for setup instructions
cp examples/aider/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
cp examples/aider/.aider.conf.yml .aider.conf.yml
```
```

**Preview what would change:**
```bash
ai-guardian setup --dry-run
```

**Setup with enterprise remote config:**
```bash
# Setup IDE hooks and add remote policy URL
ai-guardian setup --remote-config-url https://company.com/ai-guardian-policy.json

# Just add remote config without IDE setup
ai-guardian setup --remote-config-url https://company.com/ai-guardian-policy.json --ide claude
```

### Remote Configuration

The `--remote-config-url` flag adds a remote configuration URL to `~/.config/ai-guardian/ai-guardian.json`:

- **New file**: Creates config with `remote_configs.urls` section
- **Existing file without remote_configs**: Adds the section
- **Existing file with remote_configs**: Appends to existing URLs list
- All existing configuration is preserved

**Example remote config structure:**
```json
{
  "remote_configs": {
    "urls": [
      {"url": "https://example.com/policy.json", "enabled": true}
    ]
  }
}
```

### Environment Variables

The setup command respects IDE-specific environment variables for custom config locations:

**Claude Code:**
- `CLAUDE_CONFIG_DIR` - Custom directory for Claude Code config files
- If set, `ai-guardian setup` will use `$CLAUDE_CONFIG_DIR/settings.json`
- Default: `~/.claude/settings.json`

Example:
```bash
# Use custom Claude config directory
export CLAUDE_CONFIG_DIR=~/my-custom-claude-config
ai-guardian setup --ide claude
# Will configure: ~/my-custom-claude-config/settings.json
```

**Cursor:**
- Default: `~/.cursor/hooks.json`
- No environment variable support currently (will add if Cursor implements one)

## Interactive TUI

Launch the interactive Text User Interface to manage AI Guardian configuration visually:

> **📖 Comprehensive Documentation**: See [docs/TUI.md](docs/TUI.md) for detailed TUI documentation including all 11 tabs, keyboard shortcuts, workflows, and troubleshooting.

```bash
ai-guardian tui
```

### Tab-Based Interface

The TUI uses a modern tab-based interface with separate tabs for each concern:

1. **⚙️ Global Settings** - Global security feature toggles (NEW)
   - Manage permissions enforcement (`permissions.enabled`) with time-based toggles
   - Manage `secret_scanning` with time-based toggles
   - Support for temporary disabling with expiration timestamps
   - Visual status indicators and auto re-enabling

2. **📋 Violations** - View all recent violations
   - See blocked operations from the violation log (all types)
   - One-click approval to automatically add permission rules
   - Smart rule merging (combines patterns with existing rules)
   - Filter by violation type (tool permissions, secrets, directories, prompt injection)
   - Mark violations as resolved

3. **🎯 Skills** - Manage Skill permissions
   - Add, edit, and delete Skill permission rules
   - Configure allow/deny patterns (e.g., daf-*, release, gh-cli)
   - Visual display of all Skill permissions

4. **🔌 MCP Servers** - Manage MCP server permissions
   - Add, edit, and delete MCP server permission rules
   - Configure allow/deny patterns for specific MCP servers
   - Supports wildcards (e.g., mcp__notebooklm-mcp__*, mcp__*)

5. **🔒 Secrets** - Secret detection settings
   - View secret detection configuration
   - See Gitleaks integration status
   - Pattern server configuration

6. **🛡️ Prompt Injection** - Prompt injection detection
   - View prompt injection detection settings
   - Configure sensitivity levels
   - Manage allowlist and custom patterns

7. **🌐 Remote Configs** - Remote policy management (NEW)
   - Manage remote config URLs for loading enterprise/team policies
   - Add/remove URL entries with enable/disable toggles
   - Configure refresh_interval_hours and expire_after_hours
   - Test connection to remote URLs

8. **🔍 Permissions Discovery** - Auto-discovery directories (NEW)
   - Manage permissions_directories.allow[] entries
   - Manage permissions_directories.deny[] entries
   - Add/remove directory entries (matcher, mode, url, token_env)
   - Support for both local paths and GitHub URLs

9. **🛡️ Directory Protection** - Directory exclusions (NEW)
   - Toggle directory_exclusions.enabled
   - Manage directory_exclusions.paths[] array
   - Add/remove exclusion paths
   - Scan and display active .ai-read-deny markers

10. **📄 Config** - View and export configuration
    - Display merged configuration from all sources
    - See which config files are loaded (user global, project local)
    - Export configuration

11. **📝 Logs** - View rotating file logs
    - Browse application logs
    - Filter by log level
    - Real-time log viewing

### Why Use the TUI?

- ✅ **User-friendly**: No need to remember JSON schema syntax
- ✅ **Validation**: Real-time validation prevents syntax errors
- ✅ **Discovery**: See all available configuration options
- ✅ **Safety**: Requires manual clicks - AI agents cannot modify config
- ✅ **One-click approval**: Quickly allow blocked operations from violation log

### Security Note

**The TUI is designed for manual, deliberate config changes only.**

Unlike command-line flags, the TUI requires you to physically see and click buttons to approve changes. This prevents an AI agent from sneakily modifying your configuration behind the scenes.

- ✅ **Manual approval required**: You must click "Approve & Add Rule" for each change
- ✅ **Human-in-the-loop**: Every config modification is visible in the UI
- ❌ **No automated changes**: No way for an agent to bypass the interactive interface

### Navigation

- `q` - Quit the TUI
- `Escape` - Go back to previous screen
- `r` - Refresh current screen
- `Arrow keys` / `Tab` - Navigate between buttons
- `Enter` - Select button/option

## Features

### 🛡️ Directory Blocking
Block AI access to sensitive directories using `.ai-read-deny` marker files:
- Recursive protection (blocks directory and all subdirectories)
- Fast performance (file existence check only)
- Clear error messages indicating protected paths

```bash
# Protect credentials
cd ~/.ssh && touch .ai-read-deny
cd ~/.aws && touch .ai-read-deny

# Protect secrets
cd ~/project/secrets && touch .ai-read-deny
```

#### Directory Exclusions (Config-Based)

**NEW in v1.5.0**: Optionally disable `.ai-read-deny` blocking for specific directories via configuration.

**CRITICAL**: `.ai-read-deny` markers **ALWAYS take precedence** over exclusions. This is hardcoded for security - there is NO configuration option to override it.

**Use cases:**
- Allow AI access to development workspace by default
- Exclude public repositories from blocking
- Corporate policies allowing approved project directories

**Configuration** (`~/.config/ai-guardian/ai-guardian.json`):

```json
{
  "directory_exclusions": {
    "enabled": true,
    "paths": [
      "~/development/workspace",
      "~/repos/public/**",
      "/opt/approved-projects/**"
    ]
  }
}
```

**Path formats supported:**
- `~/path` - Tilde expansion (user home directory)
- `/absolute/path` - Exact absolute path
- `~/repos/**` - Recursive wildcard (all subdirectories)
- `~/dev/*` - Single-level wildcard (direct children only)

**Precedence rules (SIMPLIFIED):**
1. **First**: `.ai-read-deny` marker → **BLOCKS** (always, no exceptions)
2. **Second**: If no `.ai-read-deny` and path matches exclusion → **ALLOWS**
3. **Otherwise**: **ALLOWS** (no `.ai-read-deny` found, not excluded)

**Security warning:**
- ⚠️ Directory exclusions reduce protection - use sparingly
- ✅ `.ai-read-deny` ALWAYS works (cannot be disabled)
- ✅ To remove protection, manually delete `.ai-read-deny` file
- ✅ Set exclusions in protected config files (not by AI)

**Example: Mixed markers and exclusions**
```
~/development/               # Excluded in config
├── public/
│   └── app.py              # ✓ ALLOWED (in excluded dir, no .ai-read-deny)
└── secrets/
    ├── .ai-read-deny       # 🚫 This marker ALWAYS blocks
    └── keys.txt            # 🚫 BLOCKED (marker takes precedence)
```

**Why config-based (not marker files):**
- ❌ `.ai-guardian-allow` marker files could be added by AI to bypass protection
- ✅ Config files are self-protected (AI cannot modify them)
- ✅ Centralized management (enterprise policies)
- ✅ Explicit, auditable configuration

### 🚨 Prompt Injection Detection
**NEW in v1.2.0**: Detects and blocks prompt injection attacks before they reach the AI:
- **Heuristic detection**: Fast, local pattern matching (<1ms, privacy-preserving)
- **Configurable sensitivity**: Low, medium, or high detection thresholds
- **Custom patterns**: Add your own detection rules
- **Allowlist support**: Handle false positives gracefully
- **Optional ML detectors**: Support for Rebuff, LLM Guard (future)

**Detection categories include**:
- Instruction override attempts
- System/mode manipulation
- Prompt exfiltration attempts
- Safety bypass attempts
- Role manipulation
- Encoding/delimiter attacks
- Many-shot injection patterns

> ⚠️ **Why we don't provide specific examples:**
> 
> We intentionally do not include actual prompt injection examples in this documentation for security reasons:
> - Publishing attack patterns makes them easier to copy and misuse
> - AI Guardian would block its own documentation if it contained these patterns
> - Specific examples can train AI agents on attack techniques
> 
> **To learn about prompt injection patterns:**
> - Research academic papers on LLM security (not via AI agents)
> - Review OWASP LLM Top 10 documentation (web browser only)
> - Consult security research from reputable sources
> 
> **For testing AI Guardian:** Use generic test strings prefixed with `test:` which are designed to trigger detection without being actual attack patterns.

**Configuration example** (`~/.config/ai-guardian/ai-guardian.json`):
```json
{
  "prompt_injection": {
    "enabled": true,
    "detector": "heuristic",
    "sensitivity": "medium",
    "allowlist_patterns": ["test:.*"],
    "ignore_tools": ["Skill:code-review"],
    "ignore_files": [
      "**/.claude/skills/*/SKILL.md",
      "**/.claude/projects/**/tool-results/**"
    ]
  }
}
```

**NEW in v1.4.0:**
- `ignore_tools` - Skip detection for specific tools (e.g., `"Skill:code-review"`, `"mcp__*"`)
- `ignore_files` - Skip detection for specific files (e.g., `"**/.claude/skills/*/SKILL.md"`, `"**/.claude/projects/**/tool-results/**"`)
- Recommended: Include both skill files AND tool-results to prevent false positives from cached outputs
- See [False Positives](#prompt-injection-false-positives) for detailed usage

### 🔒 Secret Scanning
Multi-layered secret detection before AI interactions:
- **Prompt scanning**: Check user prompts before sending to AI
- **File scanning**: Verify files before AI reads them
- **Tool output scanning**: Verify tool outputs before sending to AI (NEW in v1.4.0)
- Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) - industry-standard scanner
- Comprehensive pattern detection (API keys, tokens, private keys, etc.)

**Configuration example** (`~/.config/ai-guardian/ai-guardian.json`):
```json
{
  "secret_scanning": {
    "enabled": true,
    "ignore_files": [
      "**/tests/fixtures/**",
      "**/.env.example"
    ]
  }
}
```

**NEW in v1.4.0:**
- `ignore_files` - Skip scanning for test fixtures and example files
- `ignore_tools` - Skip scanning for specific tools (rarely needed)
- See [False Positives](#secret-scanning-false-positives) for detailed usage

### 📊 Action Modes: Log vs Block
**NEW in v1.7.0**: Configurable action for each security policy - choose between audit mode and blocking mode:

- **`"block"` mode** (default): Prevent execution when policy is violated - strict security
- **`"log"` mode**: Log violations but allow execution - audit/inform mode for gradual rollout

**Action Modes:**

AI Guardian supports three enforcement levels:

| Mode | Execution | User Warning | Logged | Use Case |
|------|-----------|--------------|--------|----------|
| `block` | ❌ Blocked | Error shown | ✅ ERROR | **Enforce** policy |
| `warn` | ✅ Allowed | ⚠️ Warning shown | ✅ WARNING | **Educate** user |
| `log-only` | ✅ Allowed | Silent | ✅ WARNING | **Monitor** silently |

**Use cases by mode:**

**`action="warn"`** (User-Facing):
- 🔄 **Gradual policy rollout**: Users see warnings, can adjust behavior
- 📊 **Policy testing**: Monitor violations WITH user awareness
- 🏢 **User education**: Teach users about policies before strict enforcement

**`action="log-only"`** (Silent Monitoring - NEW):
- 📈 **Baseline metrics**: Understand current violations without user disruption
- 🔬 **Impact analysis**: Measure policy impact before user communication
- 🤫 **Compliance audit**: Track violations silently for reporting
- 🎯 **Production monitoring**: Passive detection without workflow interruption

**Available for all detection areas:**

**Tool permissions** (per-rule):
```json
{
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["approved-skill"],
      "action": "warn"  // or "log-only" or "block" (default)
    }
  ]
}
```

**Prompt injection** (global):
```json
{
  "prompt_injection": {
    "enabled": true,
    "detector": "heuristic",
    "action": "warn"  // or "log-only" or "block" (default)
  }
}
```

**Directory rules** (global):
```json
{
  "directory_rules": {
    "action": "warn",  // or "log-only" or "block" (default)
    "rules": [
      {
        "mode": "deny",
        "paths": ["~/.claude/skills/**"]
      }
    ]
  }
}
```

**Logging levels:**
- `warn`/`log-only` mode: Violations logged at **WARNING** level
- `block` mode: Violations logged at **ERROR** level

**Violation tracking:**
- All violations are logged to ViolationLogger regardless of action mode
- View violations in TUI with `ai-guardian tui`
- Violations include timestamp, type, details, and suggested fixes
- Perfect for compliance auditing and security monitoring

### 🎛️ MCP Server & Skill Permissions
Control which MCP servers and skills Claude Code can use with fine-grained allow/deny lists:

**Security Model - Defense in Depth:**

ai-guardian provides **enterprise-level enforcement** that works alongside Claude Code's built-in [settings.json permissions](https://code.claude.com/docs/en/permissions):

| Layer | Controls | Can be bypassed? | Use case |
|-------|----------|------------------|----------|
| **settings.json** | Built-in tools, MCP, Subagents | Yes (user can edit) | User/project preferences |
| **ai-guardian** | Skills, MCP, Built-ins | No (remote policies) | Enterprise enforcement |

**Why use both:**
- ✅ **Remote enforcement** - Centrally managed policies that users can't bypass
- ✅ **Dynamic updates** - Change enterprise restrictions without touching local configs
- ✅ **Skills support** - Only place to control Skills (not in settings.json)
- ✅ **Auto-discovery** - GitHub/GitLab skill directories
- ✅ **Unified management** - One config for all tool types

**Default Security Posture:**
- ✅ **Built-in tools** (Read, Write, Bash): Managed by settings.json, can be restricted by ai-guardian
- ✅ **MCP Servers**: Managed by settings.json, can be restricted by ai-guardian
- 🚫 **Skills**: Blocked by default (must be explicitly allowed via ai-guardian)

**Features:**
- Matcher-based rules: Each tool type has its own allow/deny lists
- Pattern-based matching: `daf-*`, `mcp__notebooklm-mcp__notebook_*`
- Block dangerous patterns: `*rm -rf*`, `/etc/*`
- Auto-discover skills from GitHub/GitLab directories
- Local filesystem skill discovery
- Remote policy configuration (enterprise/team policies)
- Multi-level config: project → user → remote

**Example Configuration (`~/.config/ai-guardian/ai-guardian.json`):**

```json
{
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["daf-*", "gh-cli"]
    },
    {
      "matcher": "mcp__*",
      "mode": "allow",
      "patterns": ["mcp__notebooklm-mcp__notebook_*"]
    }
  ],
  "_comment": "Optional: Use permissions_directories for dynamic discovery (advanced)",
  "_comment2": "Recommended: Use remote_configs instead (see below)",
  "remote_configs": {
    "urls": [
      {
        "url": "https://example.com/enterprise-policy.json",
        "enabled": true
      }
    ]
  }
}
```

**Permission Rule Format:**
- Each rule has a `matcher` (which tools it applies to)
- A `mode` ("allow" or "deny")
- A list of `patterns` to match
- Precedence: All "deny" rules checked first (from any config source), then "allow" rules

**Defense in Depth:**

Claude Code's [settings.json permissions](https://code.claude.com/docs/en/permissions) provide user-level control for built-in tools and MCP servers. ai-guardian adds **enterprise-level enforcement** on top:

- **settings.json**: User/project preferences (can be edited locally)
- **ai-guardian remote policies**: Enterprise restrictions (cannot be bypassed)
- **Skills**: Only controlled by ai-guardian (not in settings.json)

Use ai-guardian to add Bash/Write/MCP matchers for centrally managed restrictions that complement settings.json permissions.

**Setup:** See [Configuration → MCP Server & Skill Permissions](#mcp-server--skill-permissions-optional) section below for detailed setup instructions.

**Managing Permissions:**
- ✅ **Recommended**: Use `remote_configs` to fetch complete policy from URL (easier to manage)
- ⚠️ **Advanced**: Use `permissions_directories` for dynamic discovery from GitHub/GitLab (local dev only)

See [ai-guardian-example.json](ai-guardian-example.json) for full documentation and more examples.

### 🎯 Multi-IDE Support

| IDE | Prompt Scanning | File Scanning | Tool Output Scanning | Status |
|-----|----------------|---------------|---------------------|--------|
| Claude Code CLI | ✅ | ✅ | ⚠️ PostToolUse (ready, not firing yet) | Full support |
| VS Code Claude | ✅ | ✅ | ⚠️ PostToolUse (ready, not firing yet) | Full support |
| Cursor IDE | ✅ | ✅ | ✅ postToolUse, afterShellExecution | Full support |
| GitHub Copilot | ✅ | ✅ | ⏭️ Planned | Full support |
| Aider | ❌ | ✅ (commit-time) | ❌ | Git hook integration |

Auto-detects IDE type and uses the appropriate response format.

**See documentation**: [GitHub Copilot Setup](docs/GITHUB_COPILOT.md) | [Aider Setup](docs/AIDER.md)


**Note on PostToolUse (Claude Code):** ai-guardian includes PostToolUse hook support to scan tool outputs (e.g., Bash command results) before they reach the AI. However, as of v1.3.0, Claude Code does not consistently fire this hook. The implementation is ready and will automatically activate when Claude Code enables it. Cursor IDE's equivalent hooks (postToolUse, afterShellExecution) work as expected.

## Requirements

- **Python 3.9 or higher**
- **Gitleaks 8.x** - Open-source secret scanner (currently the only supported engine)

> **Note**: Multi-engine support (TruffleHog, detect-secrets, etc.) is planned for v2.0.0. See [docs/MULTI_ENGINE_SUPPORT.md](docs/MULTI_ENGINE_SUPPORT.md) for details.

### Installing Gitleaks

**macOS:**
```bash
brew install gitleaks
```

**Linux:**
```bash
VERSION=8.18.1
wget "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_linux_x64.tar.gz"
tar -xzf "gitleaks_${VERSION}_linux_x64.tar.gz"
sudo mv gitleaks /usr/local/bin/
```

**Windows:**
```bash
choco install gitleaks
# Or download from: https://github.com/gitleaks/gitleaks/releases
```

**Verify:**
```bash
gitleaks version
```

## Installation

**Basic Installation:**
```bash
git clone https://github.com/itdove/ai-guardian.git
cd ai-guardian
pip install -e .
```

**With Skill Discovery (Optional):**

For auto-discovering skills from GitHub/GitLab directories:

```bash
pip install -e ".[skill-discovery]"
```

This installs the optional `requests` library for fetching remote skill directories.

## When to Use ai-guardian vs settings.json

| Scenario | Use settings.json | Use ai-guardian | Why |
|----------|-------------------|-----------------|-----|
| **Control Skills** | ❌ Not supported | ✅ Required | Skills not available in settings.json |
| **User MCP preferences** | ✅ Recommended | ❌ Optional | User can manage locally |
| **Enterprise MCP restrictions** | ⚠️ User can bypass | ✅ Required | Remote policies cannot be bypassed |
| **Built-in tool restrictions** | ✅ First choice | ⚠️ For extras | settings.json is the standard way |
| **Enterprise built-in restrictions** | ⚠️ User can bypass | ✅ Required | Add restrictions beyond settings.json |
| **Auto-discover skills** | ❌ Not supported | ✅ Use this | GitHub/GitLab directory discovery |
| **Dynamic enterprise policies** | ❌ Static files | ✅ Use this | Remote configs auto-refresh |

**Recommended Architecture:**
```
settings.json: User/project preferences for MCP and built-in tools
      ↓
ai-guardian: Skills (required) + enterprise enforcement layer
      ↓
Remote policies: Centrally managed, cannot be bypassed
```

## Configuration

**💡 Recommended**: Use `ai-guardian setup` to automatically configure your IDE (see [Setup Command](#setup-command) above).

The following manual configuration is provided for reference or advanced use cases.

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "ai-guardian",
            "statusMessage": "🛡️ Scanning prompt..."
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "ai-guardian",
            "statusMessage": "🛡️ Checking tool permissions..."
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "ai-guardian",
            "statusMessage": "🛡️ Scanning tool output..."
          }
        ]
      }
    ]
  }
}
```

**Matcher Configuration:**
- `"matcher": "*"` scans all tool outputs (**recommended** for full coverage)
- Specific matchers like `"Bash|Read|Grep"` can be used for optimization, but may miss new tools

**Note:** PostToolUse hook is configured but may not fire consistently in current Claude Code versions. The hook is ready and will activate automatically when Claude Code enables it.

### Cursor IDE

Create `~/.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "beforeSubmitPrompt": [
      {
        "command": "ai-guardian"
      }
    ],
    "beforeReadFile": [
      {
        "command": "ai-guardian"
      }
    ],
    "beforeShellExecution": [
      {
        "command": "ai-guardian"
      }
    ],
    "afterShellExecution": [
      {
        "command": "ai-guardian"
      }
    ],
    "postToolUse": [
      {
        "command": "ai-guardian"
      }
    ]
  }
}
```

**Hook Coverage:**
- `beforeSubmitPrompt`: Scans prompts before sending to AI
- `beforeReadFile`: Scans files before AI reads them
- `beforeShellExecution`: Scans shell commands before execution
- `afterShellExecution`: Scans shell command output after execution
- `postToolUse`: Scans all tool outputs (Read, Grep, WebFetch, etc.)

### MCP Server & Skill Permissions (Optional)

Control which MCP servers and skills Claude Code can access. **This is optional** - by default, built-in tools are allowed and Skills/MCP are blocked.

#### Step 1: Create Configuration Directory

```bash
mkdir -p ~/.config/ai-guardian
```

#### Step 2: Create Configuration File

Create `~/.config/ai-guardian/ai-guardian.json`:

```bash
# Copy the example configuration
curl -o ~/.config/ai-guardian/ai-guardian.json \
  https://raw.githubusercontent.com/itdove/ai-guardian/main/ai-guardian-example.json

# Or create manually with your editor
vi ~/.config/ai-guardian/ai-guardian.json
```

#### Step 3: Configure Permissions

**Basic Configuration (Skills and Optional MCP Restrictions):**

Essential for Skills (required), optional for adding enterprise-level MCP restrictions beyond settings.json:

```json
{
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["daf-*", "gh-cli"]
    },
    {
      "_comment": "Optional: Enterprise MCP restrictions (complements settings.json)",
      "matcher": "mcp__*",
      "mode": "allow",
      "patterns": ["mcp__notebooklm-mcp__notebook_*"]
    }
  ]
}
```

**Note:** MCP and built-in tools can be controlled via [settings.json permissions](https://code.claude.com/docs/en/permissions). Add them to ai-guardian for enterprise enforcement via remote policies.

**Enterprise Configuration (with additional restrictions and auto-discovery):**

Enterprise policies can add extra restrictions on built-in tools beyond what `settings.json` provides.

```json
{
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["daf-*", "gh-cli", "git-cli"]
    },
    {
      "matcher": "mcp__*",
      "mode": "allow",
      "patterns": [
        "mcp__notebooklm-mcp__notebook_list",
        "mcp__notebooklm-mcp__notebook_get",
        "mcp__atlassian__getJiraIssue"
      ]
    },
    {
      "_comment": "Enterprise-level restrictions (optional)",
      "matcher": "Bash",
      "mode": "deny",
      "patterns": ["*rm -rf*", "*dd *"]
    },
    {
      "matcher": "Write",
      "mode": "deny",
      "patterns": ["/etc/*", "/sys/*"]
    }
  ],
  "permissions_directories": {
    "allow": [
      {
        "url": "https://github.com/your-org/skills/tree/main/skills",
        "category": "Skill",
        "token_env": "GITHUB_TOKEN"
      }
    ]
  }
}
```

#### When a Tool is Blocked

When ai-guardian blocks a skill or MCP tool, it shows a helpful error message with the exact configuration to add:

```
======================================================================
🚫 TOOL ACCESS DENIED
======================================================================

Tool: Skill
Blocked by: not in allow list

To allow this tool, add to ~/.config/ai-guardian/ai-guardian.json:

  {
    "permissions": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "patterns": [
          "*"  # Allow all skills
        ]
      }
    ]
  }

Or ask your administrator to update the enterprise policy.
======================================================================
```

**Quick fix:** Copy the suggested configuration from the error message and add it to your `ai-guardian.json` file.

#### Configuration Locations (Precedence Order)

1. **Project config** (highest priority): `./.ai-guardian.json` in project root
2. **User config**: `~/.config/ai-guardian/ai-guardian.json`
3. **Remote configs**: Fetched from URLs in `remote_configs`
4. **Defaults**: Built-in defaults (allow all built-ins, block skills/MCP)

#### JSON Schema for IDE Support

AI Guardian provides a [JSON Schema](src/ai_guardian/schemas/ai-guardian-config.schema.json) for configuration validation and IDE autocomplete, with **runtime validation** that blocks operations if the config is invalid.

**Benefits:**
- ✅ **Runtime Validation** - Invalid configs are rejected at load time with clear error messages
- ✅ **Fail-Fast** - Blocks operations if config is broken (no silent failures)
- ✅ **IDE Autocomplete** - Get suggestions while editing config files
- ✅ **Real-time Validation** - Catch errors before running ai-guardian
- ✅ **Inline Documentation** - See descriptions for all configuration options
- ✅ **Type Checking** - Validates enums, data types, and required fields

**Usage:**

Add the `$schema` property to your configuration file:

```json
{
  "$schema": "https://raw.githubusercontent.com/itdove/ai-guardian/main/src/ai_guardian/schemas/ai-guardian-config.schema.json",
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["daf-*", "gh-cli"]
    }
  ]
}
```

**IDE Setup:**

Most modern editors (VSCode, JetBrains, etc.) automatically recognize the `$schema` property. For VSCode, you can also add to your `.vscode/settings.json`:

```json
{
  "json.schemas": [
    {
      "fileMatch": ["*ai-guardian.json", ".ai-guardian.json"],
      "url": "https://raw.githubusercontent.com/itdove/ai-guardian/main/src/ai_guardian/schemas/ai-guardian-config.schema.json"
    }
  ]
}
```

**See also:** [ai-guardian-example.json](ai-guardian-example.json) for a complete configuration example with detailed comments.

#### Immutable Remote Configurations (Enterprise Policy Enforcement)

**NEW in Issue #67**: Remote configurations can mark sections and permission rules as `immutable` to prevent local configs from overriding them.

**Use Cases:**
- ✅ **Enterprise Security Compliance**: Enforce mandatory skill allowlists that users cannot extend
- ✅ **Regulatory Requirements**: Ensure prompt injection detection cannot be weakened or disabled
- ✅ **Zero-Trust Environments**: Centrally managed pattern servers that cannot be overridden
- ✅ **Audit & Compliance**: Provable policy enforcement with immutable remote rules

**Per-Matcher Immutability:**

Mark specific permission rules as immutable by matcher:

```json
{
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["daf-*", "gh-cli"],
      "immutable": true
    }
  ]
}
```

When `immutable: true`, local configs **cannot add or modify rules** for that matcher. Users can still add rules for other matchers.

**Section Immutability:**

Mark entire sections as immutable:

```json
{
  "prompt_injection": {
    "enabled": true,
    "sensitivity": "high",
    "detector": "heuristic",
    "immutable": true
  },
  "pattern_server": {
    "enabled": true,
    "url": "https://company.com/patterns",
    "immutable": true
  }
}
```

When `immutable: true`, the **entire section** from local configs is ignored.

**Complete Enterprise Example:**

```json
{
  "permissions": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "patterns": ["daf-*", "gh-cli", "git-cli"],
      "immutable": true
    },
    {
      "matcher": "Bash",
      "mode": "deny",
      "patterns": ["*rm -rf*", "*dd if=*"],
      "immutable": true
    }
  ],
  "prompt_injection": {
    "enabled": true,
    "sensitivity": "high",
    "detector": "heuristic",
    "immutable": true
  },
  "pattern_server": {
    "enabled": true,
    "url": "https://company.com/patterns",
    "auth": {
      "method": "bearer",
      "token_env": "COMPANY_PATTERN_TOKEN"
    },
    "immutable": true
  }
}
```

With this remote config:
- ✅ Local can add MCP, Write, Read permission rules (not immutable)
- ❌ Local cannot add/modify Skill or Bash rules (immutable)
- ❌ Local cannot change prompt_injection settings (immutable)
- ❌ Local cannot override pattern_server config (immutable)

**Benefits:**
- **Security**: Enterprise policies cannot be weakened by local overrides
- **Compliance**: Auditable, provable policy enforcement
- **Flexibility**: Granular control - only lock what needs locking
- **Backward Compatible**: Existing configs work unchanged (immutable defaults to false)

#### Remote Configs vs Directory Discovery

**Use `remote_configs` (Recommended):**
```json
{
  "remote_configs": {
    "urls": [{
      "url": "https://your-org.com/ai-guardian-policy.json",
      "enabled": true
    }]
  }
}
```

**Benefits:**
- ✅ Complete control - permissions, deny rules, everything in one place
- ✅ Easier to audit - clear list of what's allowed
- ✅ Faster - no GitHub API calls or directory scanning
- ✅ Works for all tool types - not just Skills
- ✅ Better for production/enterprise

**Use `permissions_directories` (Advanced/Local Dev):**
```json
{
  "permissions_directories": [
    {
      "matcher": "Skill",
      "mode": "allow",
      "url": "https://github.com/your-org/skills/tree/main/skills",
      "token_env": "GITHUB_TOKEN"
    }
  ]
}
```

**Use cases:**
- ⚠️ Local development with file-based skill directories
- ⚠️ Dynamic environments where you can't pre-list skills
- ⚠️ Prototyping before creating a formal remote policy

**For most users:** Use `remote_configs` and maintain a complete policy file.

#### Pattern Matching Examples

| Matcher | Pattern | Matches | Description |
|---------|---------|---------|-------------|
| `Skill` | `gh-cli` | Exactly `gh-cli` skill | Exact skill name |
| `Skill` | `daf-*` | `daf-active`, `daf-status`, etc. | All skills starting with `daf-` |
| `mcp__*` | `mcp__notebooklm-mcp__notebook_*` | All notebook tools | Wildcard MCP tools |
| `Bash` | `*rm -rf*` | Any bash command containing `rm -rf` | Dangerous command patterns |
| `Write` | `/etc/*` | Any write to /etc directory | Path-based blocking |

**How matching works:**
- `Skill` matcher checks patterns against `input.skill` value
- `Bash` matcher checks patterns against `input.command` value
- `Write`/`Read` matchers check patterns against `input.file_path` value
- `mcp__*` matcher checks patterns against full tool name

#### Verify Configuration

Test that your configuration is loaded correctly:

```bash
# This will be blocked if Skills are not in your allow list
echo '{"hook_event_name": "PreToolUse", "tool_use": {"name": "Skill:unknown-skill"}}' | ai-guardian

# This should be allowed (built-in tool)
echo '{"hook_event_name": "PreToolUse", "tool_use": {"name": "Read"}}' | ai-guardian
```

## Usage

### Test the Hook

```bash
# Test clean prompt (should pass)
echo '{"prompt": "Hello world"}' | ai-guardian
# Output: ✓ No secrets detected

# Test with a GitHub token (should block)
echo '{"prompt": "token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"}' | ai-guardian  #notsecret
# Output: 🔒 SECRET DETECTED (exit code 2)
```

### Protect Directories

```bash
# Protect your configuration
cd ~/.config && touch .ai-read-deny

# Protect project secrets
cd ~/my-project/secrets && touch .ai-read-deny

# Protect dependencies
cd ~/my-project/node_modules && touch .ai-read-deny
```

### Handling False Positives

#### Secret Scanning False Positives

**Method 1: Ignore Files/Tools (Recommended for Test Fixtures)**

**NEW in v1.4.0**: Skip scanning specific files or tools. Perfect for test fixtures with fake credentials.

```json
{
  "secret_scanning": {
    "enabled": true,
    "ignore_files": [
      "**/tests/fixtures/**",           // All test fixture files
      "**/tests/**/*.fixture.json",     // Fixture JSON files
      "**/examples/**/*.example.*",     // Example config files
      "**/.env.example",                // Example env files
      "**/.gitleaks.toml"               // Gitleaks config files
    ],
    "ignore_tools": []                  // Usually not needed for secrets
  }
}
```

**File patterns** (glob syntax):
- `**/tests/fixtures/**` - All files under any tests/fixtures directory
- `**/*.example.*` - All .example files (config.example.json, .env.example)
- `**/README.md` - Documentation files that may contain example credentials
- `~/Documents/test-*.json` - Files in home directory (~ expands)

**Tool patterns:**
- Typically not needed for secret scanning (most secrets are in files)
- Could be useful if a specific tool always reads test data

**Example: Skip test fixtures but still scan production configs:**
```json
{
  "secret_scanning": {
    "ignore_files": [
      "**/tests/**",
      "**/examples/**",
      "**/.env.example"
    ]
  }
}
```

**Method 2: Inline Comments (Quick Fix)**

Add `gitleaks:allow` anywhere on the line to mark it as a false positive:

```python
# Example API key for testing
api_key = "ghp_exampleTokenForDocs12345678901234567890"  # gitleaks:allow

# Works in any language
const token = "sk_test_fake_token_123";  // gitleaks:allow
password = "example_password"  # gitleaks:allow
```

**Method 3: Project Configuration File**

Create `.gitleaks.toml` in your project root for project-wide allowlists:

```toml
# Allow specific patterns
[allowlist]
description = "Allowed patterns"
regexes = [
    '''example-api-key-12345''',
    '''test_.*_token''',  # Allow all test tokens
]
paths = [
    '''tests/fixtures/.*''',     # All files in test fixtures
    '''docs/examples/.*''',      # Documentation examples
]

# Add custom patterns
[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''mycompany_[0-9a-f]{32}'''
```

See [Gitleaks Configuration](https://github.com/gitleaks/gitleaks#configuration) for more options.

#### Prompt Injection False Positives

If legitimate prompts are being blocked, you have several options:

**Method 1: Ignore Specific Tools (Recommended for Skills/Documentation)**

**NEW in v1.4.0**: Skip detection for specific tools or files. Perfect for Skill documentation that contains example attack patterns.

```json
{
  "prompt_injection": {
    "enabled": true,
    "ignore_tools": [
      "Skill:code-review",              // Ignore specific skill
      "Skill:security-review",           // Another specific skill
      "Skill:*"                          // Or ignore all skills
    ],
    "ignore_files": [
      "**/.claude/skills/*/SKILL.md",   // All skill documentation
      "**/.claude/projects/**/tool-results/**",  // Cached tool results
      "**/CLAUDE.md",                    // Project instructions
      "**/AGENTS.md"                     // Agent instructions
    ]
  }
}
```

**Tool patterns:**
- `"Skill:code-review"` - Ignore only the code-review skill (both input and output)
- `"Skill:*"` or `"Skill"` - Ignore all skills
- `"mcp__notebooklm__*"` - Ignore all NotebookLM MCP tools
- `"Read"` - Ignore the Read tool

**How ignore_tools works (NEW in v1.4.0):**
- **PreToolUse**: Scans tool inputs (e.g., file content before tool reads it)
- **PostToolUse**: Scans tool outputs (e.g., skill execution results)
- **Correlation**: Skill tools automatically correlate input and output
  - Example: `"Skill:code-review"` ignores:
    - ✅ Reading code-review SKILL.md documentation (PreToolUse)
    - ✅ Code-review skill execution results (PostToolUse)
  - Prevents false positives from educational attack patterns in skill docs

**File patterns** (glob syntax):
- `**/.claude/skills/*/SKILL.md` - All SKILL.md files in any skill directory
- `**/.claude/projects/**/tool-results/**` - Cached tool outputs (prevents re-scanning)
- `**/tests/**/*.md` - All markdown files in test directories
- `~/Documents/security-*.md` - Files in home directory (~ expands)
- `*` matches any characters except `/`
- `**` matches any characters including `/`
- `?` matches a single character

**Defense in depth:** Use both `ignore_tools` AND `ignore_files` for comprehensive coverage:
```json
{
  "prompt_injection": {
    "ignore_tools": ["Skill:code-review"],
    "ignore_files": [
      "**/.claude/skills/code-review/**",        // Skill files
      "**/.claude/projects/**/tool-results/**"   // Cached tool outputs
    ]
  }
}
```

**Why both are needed:**
- `ignore_tools` covers skill execution (PreToolUse + PostToolUse)
- `ignore_files` covers direct file access (Read tool, not skill execution)
- Together they handle all access patterns:
  - ✅ Skill:code-review execution → `ignore_tools` handles it
  - ✅ Read tool accessing SKILL.md → `ignore_files` handles it
  - ✅ Read tool accessing cached tool results → `ignore_files` handles it
  - ✅ Bash cat SKILL.md → `ignore_files` doesn't help (no file_path), but rare edge case

**Method 2: Allowlist Patterns (Content-Based)**

If you need to allow specific content patterns regardless of tool/file:

```json
{
  "prompt_injection": {
    "enabled": true,
    "detector": "heuristic",
    "sensitivity": "medium",
    "allowlist_patterns": [
      "test:.*",                    
      ".*example.*ignore.*previous.*",  
      "documentation.*system.*prompt"   
    ]
  }
}
```

**How allowlist patterns work:**
- Patterns are regex (case-insensitive)
- If ANY pattern matches, detection is skipped for that prompt
- Use `.*` for wildcards: `test:.*` matches any string starting with "test:"
- Escape special regex characters: `\.` for literal dots

**Common use cases:**

```json
{
  "prompt_injection": {
    "allowlist_patterns": [
      "^test:",                         
      "example.*",                      
      "tutorial about.*prompt.*",       
      "documentation:.*",               
      "learning.*about.*injection"      
    ]
  }
}
```

**Adjusting sensitivity:**

If you get too many false positives, lower the sensitivity:

```json
{
  "prompt_injection": {
    "sensitivity": "low"    
  }
}
```

- `"high"`: Strictest, detects more potential attacks (more false positives)
- `"medium"`: Balanced (default, recommended)
- `"low"`: Permissive, only catches obvious attacks (fewer false positives)

### Pattern Server (Advanced)

**Optional enterprise feature** for fetching custom secret detection patterns from a centralized server instead of using Gitleaks' built-in patterns.

**Purpose:** Organizations can maintain custom pattern definitions for:
- Organization-specific secret formats
- Internal API key patterns  
- Custom token formats
- Compliance-specific detection rules

**When to use:**
- ✅ Enterprise environments with custom secret types
- ✅ Compliance requirements for specific pattern coverage
- ✅ Centralized pattern management across teams

**When NOT needed:**
- ✅ Individual developers (Gitleaks defaults are comprehensive)
- ✅ Standard secret types (AWS, GitHub, RSA keys - already in Gitleaks)

⚠️ **Warning:** Pattern servers must include default Gitleaks patterns AND custom patterns. Organization-only patterns may miss common secrets.

**Configuration (`~/.config/ai-guardian/ai-guardian.json`):**

**NEW in v1.7.0:** `pattern_server` is now nested under `secret_scanning` for clearer scoping.

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
        "token_env": "AI_GUARDIAN_PATTERN_TOKEN",
        "token_file": "~/.config/ai-guardian/pattern-token"
      },
      "cache": {
        "path": "~/.cache/ai-guardian/patterns.toml",
        "refresh_interval_hours": 12,
        "expire_after_hours": 168
      },
      "warn_on_failure": true
    }
  }
}
```

**Simplified configuration:**
- ✅ **No `enabled` field needed** - presence of section = enabled
- ✅ **To disable**: Set `pattern_server` to `null` or remove section
- ✅ **Backward compatible**: Old root-level config still works (with deprecation warning)

**How it works:**
1. Patterns fetched from server on first use
2. Cached locally for 12 hours (configurable)
3. Auto-refreshed when cache expires
4. Falls back to defaults if server unavailable

**Migrating from v1.6.0:**

If you have old root-level `pattern_server` config, migrate to new nested structure:

```bash
# Dry run - see what would change
ai-guardian setup --migrate-pattern-server --dry-run

# Migrate (interactive - prompts for confirmation)
ai-guardian setup --migrate-pattern-server

# Migrate (non-interactive)
ai-guardian setup --migrate-pattern-server --yes
```

**See:**
- [docs/SECRET_SCANNING_VS_PATTERN_SERVER.md](docs/SECRET_SCANNING_VS_PATTERN_SERVER.md) - Detailed explanation
- [docs/PATTERN_SERVER_MIGRATION_GUIDE.md](docs/PATTERN_SERVER_MIGRATION_GUIDE.md) - Step-by-step migration guide

### Gitleaks Pattern Priority

**Pattern source priority (highest to lowest):**
1. **Pattern Server** (if enabled and reachable) - Enterprise patterns
2. **Project `.gitleaks.toml`** (if exists in current directory) - Project overrides
3. **Gitleaks built-in patterns** - Default fallback (100+ rules)

#### Error Handling and Fallback Behavior

AI Guardian handles Gitleaks errors gracefully with different behaviors based on the error type:

**Missing Gitleaks Binary:**
- **Behavior:** ⚠️ Warns (prints to stderr) but allows operation to continue
- **Rationale:** User may not be able to install immediately
- **Warning shown:** Clear message with installation instructions for macOS, Linux, Windows
- **Setup check:** `ai-guardian setup` verifies Gitleaks is installed and warns during IDE hook setup

**Authentication Errors (401/403):**
- **Behavior:** 🔒 **BLOCKS operation** with visible error message
- **Rationale:** User can fix by updating credentials/token
- **Error shown:** Detailed authentication error with troubleshooting steps
- **Guidance:** Instructions for updating `AI_GUARDIAN_PATTERN_TOKEN` or disabling pattern servers

**Network/Server Errors (timeout, connection):**
- **Behavior:** ⚠️ Warns (prints to stderr) but allows operation to continue
- **Rationale:** User cannot control server being down (fail-open for availability)
- **Warning shown:** Network issue detected with pattern server disable instructions
- **Fallback:** Continues with default Gitleaks patterns

**Other Errors:**
- **Behavior:** ⚠️ Warns (prints to stderr) but allows operation to continue
- **Rationale:** Fail-open for availability
- **Warning shown:** Generic error with troubleshooting steps

**Example Error Messages:**

```
======================================================================
⚠️  SECRET SCANNING DISABLED
======================================================================

Gitleaks binary not found - secret scanning is currently disabled.

AI Guardian requires Gitleaks to scan for sensitive information like:
  • API keys and tokens
  • Private keys (SSH, RSA, PGP)
  • Database credentials
  • Cloud provider keys (AWS, GCP, Azure)

Install Gitleaks:
  macOS:   brew install gitleaks
  Linux:   See https://github.com/gitleaks/gitleaks#installing
  Windows: See https://github.com/gitleaks/gitleaks#installing

Operation will continue, but secrets will NOT be detected.
After installation, restart your IDE.
======================================================================
```

```
======================================================================
🔒 AUTHENTICATION ERROR
======================================================================

Gitleaks authentication failed (exit code 2).

Error: 401 Unauthorized - authentication failed

This operation has been blocked for security.

If using pattern-servers:
  1. Check your authentication token is valid
  2. Update token: export AI_GUARDIAN_PATTERN_TOKEN='your-token'
  3. Or disable pattern-servers in ~/.config/ai-guardian/ai-guardian.json

If NOT using pattern-servers:
  1. Check ~/.gitleaks.toml configuration
  2. Try: gitleaks version (to verify installation)
======================================================================
```

#### Verifying Gitleaks Installation

During setup, AI Guardian automatically checks if Gitleaks is installed:

```bash
$ ai-guardian setup --ide claude
✓ Gitleaks is installed: gitleaks version 8.18.0
✓ Successfully configured Claude Code hooks at ~/.claude/settings.json

Next steps:
  1. Restart Claude Code for changes to take effect
  2. Test with: echo '{"prompt": "test"}' | ai-guardian
```

If Gitleaks is missing, you'll see:

```bash
$ ai-guardian setup --ide claude
❌ Gitleaks not found
   Install from: https://github.com/gitleaks/gitleaks#installing
   Or use: brew install gitleaks (macOS)

⚠️  WARNING: Secret scanning will be disabled without Gitleaks!
    AI Guardian requires Gitleaks for secret detection.

Next steps:
  1. Install Gitleaks (see above)
  2. Restart Claude Code for changes to take effect
  3. Test with: echo '{"prompt": "test"}' | ai-guardian
```

### Environment Variables

Configure ai-guardian behavior with environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AI_GUARDIAN_CONFIG_DIR` | Custom configuration directory location | `~/.config/ai-guardian` (or `$XDG_CONFIG_HOME/ai-guardian`) |
| `AI_GUARDIAN_IDE_TYPE` | Override IDE auto-detection (`claude` or `cursor`) | Auto-detect |
| `AI_GUARDIAN_SKILL_CACHE_TTL_HOURS` | Skill directory cache TTL in hours | `24` |
| `AI_GUARDIAN_REFRESH_INTERVAL_HOURS` | Remote config refresh interval | `12` |
| `AI_GUARDIAN_EXPIRE_AFTER_HOURS` | Remote config expiration time | `168` (7 days) |
| `AI_GUARDIAN_PATTERN_TOKEN` | Bearer token for pattern server authentication | None |

**Configuration Directory Priority:**
1. `AI_GUARDIAN_CONFIG_DIR` (if set) - direct override
2. `$XDG_CONFIG_HOME/ai-guardian` (if `XDG_CONFIG_HOME` is set)
3. `~/.config/ai-guardian` - default fallback

**Example:**
```bash
# Use custom config directory
export AI_GUARDIAN_CONFIG_DIR=/opt/company/ai-guardian
ai-guardian setup --ide claude

# Other environment variables
export AI_GUARDIAN_IDE_TYPE=claude
export AI_GUARDIAN_SKILL_CACHE_TTL_HOURS=48
```

## How It Works

### Before Tool Execution (UserPromptSubmit, PreToolUse)
```
User types prompt / Uses tool
       ↓
[AI Guardian Hook]
       ↓
   MCP/Skill check ──→ Not allowed? ──→ BLOCK ❌
       ↓ (allowed)
   Directory check? ──→ .ai-read-deny exists? ──→ BLOCK ❌
       ↓ (no marker)
   Prompt Injection check ──→ Injection detected? ──→ BLOCK ❌  [v1.2.0]
       ↓ (clean)
   Scan with Gitleaks
       ↓
   Secret found? ──→ Yes ──→ BLOCK ❌
       ↓ (no)
   ALLOW ✅ ──→ Send to AI / Execute tool
```

### After Tool Execution (PostToolUse, afterShellExecution)
```
Tool completes (Bash, Read, Grep, etc.)
       ↓
[AI Guardian PostToolUse Hook]  [NEW in v1.3.0]
       ↓
   Extract tool output
       ↓
   Scan output with Gitleaks
       ↓
   Secret found? ──→ Yes ──→ BLOCK ❌ (output hidden from AI)
       ↓ (no)
   ALLOW ✅ ──→ Send output to AI
```

**Note:** PostToolUse works in Cursor IDE. Claude Code support is implemented but awaiting IDE activation.

## Security Design

### Architecture Principles

- ✅ **Defense in Depth**: One layer in a multi-layered security strategy
- ✅ **Fail-open**: If scanning errors occur, allows operation (availability over security)
- ✅ **In-memory scanning**: Uses `/dev/shm` on Linux for performance
- ✅ **Secure cleanup**: Overwrites temp files before deletion
- ✅ **No logging**: Secrets are never logged or stored
- ✅ **Privacy-first**: Heuristic detection runs locally, no external calls

### Self-Protecting Security Architecture

AI Guardian uses **hardcoded deny patterns** that protect its own critical files from being modified by AI agents. This prevents AI from disabling security features or bypassing protection.

**Protected Files:**

1. **Configuration files** - Prevents AI from disabling security features
   - `~/.config/ai-guardian/ai-guardian.json`
   - `./.ai-guardian.json`
   - Any file matching `*ai-guardian.json`

2. **IDE hook files** - Prevents AI from removing ai-guardian hooks
   - `~/.claude/settings.json` (Claude Code)
   - `~/.cursor/hooks.json` (Cursor IDE)

3. **Package source code** - Prevents AI from editing protection logic
   - `*/ai_guardian/*` (all package files)
   - `*/site-packages/ai_guardian/*`

4. **Directory protection markers** - Prevents AI from removing `.ai-read-deny` files
   - `*/.ai-read-deny` (all directory markers)
   - `**/.ai-read-deny` (recursive protection)

**How Self-Protection Works:**

The protection works through an **unbreakable loop**:

1. Deny patterns are checked in the PreToolUse hook **BEFORE** any tool executes
2. If a tool tries to modify a protected file, the operation is **BLOCKED**
3. The tool never executes, so the file is never modified
4. AI cannot edit the source code to remove the protection because editing is blocked by the same protection

**Example Attack Scenarios (All Blocked):**

```bash
# Try 1: Edit config file
Edit(file_path="~/.config/ai-guardian/ai-guardian.json")
# ❌ BLOCKED by "*ai-guardian.json" pattern

# Try 2: Remove Claude hooks
Edit(file_path="~/.claude/settings.json")
# ❌ BLOCKED by "*/.claude/settings.json" pattern

# Try 3: Edit source code to disable protection
Edit(file_path="~/.local/lib/.../ai_guardian/tool_policy.py")
# ❌ BLOCKED by "*/ai_guardian/*" pattern

# Try 4: Use sed to bypass
Bash(command="sed -i 's/IMMUTABLE/DISABLED/' ~/.local/lib/.../ai_guardian/tool_policy.py")
# ❌ BLOCKED by "*sed*ai_guardian*" pattern

# Try 5: Use echo redirect to overwrite
Bash(command="echo '{}' > ~/.config/ai-guardian/ai-guardian.json")
# ❌ BLOCKED by "*>*ai-guardian*" pattern

# Try 6: Delete config file
Bash(command="rm ~/.config/ai-guardian/ai-guardian.json")
# ❌ BLOCKED by "*rm*ai-guardian.json*" pattern

# Try 7: Bypass directory protection by removing marker
Bash(command="rm ~/secrets/.ai-read-deny")
# ❌ BLOCKED by "*rm*.ai-read-deny*" pattern

# Try 8: Rename directory protection marker
Bash(command="mv .ai-read-deny .ai-read-deny.bak")
# ❌ BLOCKED by "*mv*.ai-read-deny*" pattern
```

All bypass attempts are blocked before execution! 🛡️

**Why Filesystem Permissions Don't Work:**

AI Guardian's config directory is **always in the user's HOME directory**:
- Default: `~/.config/ai-guardian/`
- XDG: `$XDG_CONFIG_HOME/ai-guardian/`
- Custom: `$AI_GUARDIAN_CONFIG_DIR`

All paths resolve to the HOME directory, which is **always writable by the user** (and therefore by AI agents). Filesystem permissions cannot protect these files.

**Solution:** Hardcoded protection at the tool invocation level is the only cross-platform approach that works reliably.

**What Happens When Protection Triggers:**

```
======================================================================
🔒 CRITICAL FILE PROTECTED
======================================================================

This file is protected by ai-guardian and cannot be modified.

File: ~/.claude/settings.json
Tool: Edit
Reason: Critical security configuration

Protected files:
  • ai-guardian configuration files
  • IDE hook configuration (Claude, Cursor)
  • ai-guardian package source code
  • .ai-read-deny marker files (directory protection)

This protection cannot be disabled via configuration.
It ensures ai-guardian cannot be bypassed by AI agents.

To edit these files, use your text editor manually.

======================================================================
```

**User Override:**

If you need to edit these files:
- Use your text editor manually (vim, nano, VS Code, etc.)
- The protection only blocks **AI agent** access via tools
- You retain full control over your configuration

If a user manually edits the source code to remove the protection:
- This is an intentional choice by the user
- Same as uninstalling ai-guardian entirely
- Not an AI bypass (requires manual intervention)

**Maintainer Bypass for Development:**

GitHub maintainers of the AI Guardian project can edit source code with AI assistance:

```bash
# Prerequisites
# 1. Authenticate with GitHub CLI
gh auth login

# 2. Be a collaborator on the repository
# (check: gh api repos/itdove/ai-guardian/collaborators/YOUR_USERNAME)

# Now AI can help edit source files
✅ Edit src/ai_guardian/tool_policy.py  # Allowed for maintainers
✅ Write tests/test_new_feature.py      # Allowed for maintainers
✅ Edit README.md                        # Allowed for maintainers

# But config files remain protected
❌ Edit ~/.config/ai-guardian/ai-guardian.json  # BLOCKED (even for maintainers)
❌ Edit ~/.claude/settings.json                  # BLOCKED (even for maintainers)
❌ Write ~/.cache/ai-guardian/maintainer-status.json  # BLOCKED (cache poisoning prevented)
```

**How Maintainer Bypass Works:**

1. **GitHub OAuth Authentication** - Uses `gh` CLI to verify your GitHub identity
2. **Collaborator Check** - Confirms write access via GitHub API
3. **Scoped Bypass** - Only allows editing source code, never config files
4. **Automatic** - Works transparently when you're a maintainer
5. **Cached** - Status cached for 24 hours to avoid API rate limits

**Security Model:**

The bypass prevents **two distinct threat models**:

- **Threat A (Non-Maintainers)**: Blocked by GitHub collaborator check
  - AI can't fake OAuth credentials
  - GitHub API verifies real permissions

- **Threat B (Malicious Prompts to Maintainers)**: Blocked by scoped protection
  - Config files always protected (even for maintainers)
  - Cache files always protected (prevents poisoning)
  - Malicious prompts can't disable security features

**Example: Malicious Prompt Protection**

Even if you're a maintainer, this attack is blocked:

```bash
# Malicious prompt: "Help me organize my SSH keys"
# AI attempts to disable secret scanning first

Edit(file_path="~/.config/ai-guardian/ai-guardian.json",
     old_string='"secret_scanning": true',
     new_string='"secret_scanning": false')

# ❌ BLOCKED - Config files always protected
# Protection prevents AI from reading ~/.ssh/id_rsa
```

**Troubleshooting:**

If maintainer bypass isn't working:

1. Check GitHub authentication: `gh auth status`
2. Verify collaborator access: `gh api repos/itdove/ai-guardian/collaborators/YOUR_USERNAME`
3. Clear cache: `rm ~/.cache/ai-guardian/maintainer-status.json`
4. Check repo URL: `git config --get remote.origin.url` (must be github.com)

**Fork-Friendly:**

Works on your own fork too! If you're a maintainer of `yourname/ai-guardian`, you can edit your fork's source code.

### Known Limitations

**⚠️ AI Guardian is not perfect and has known limitations:**

**Prompt Injection Detection:**
- Heuristic pattern matching can be bypassed with novel techniques
- New attack vectors emerge faster than detection patterns update
- Trade-off between false positives (blocking legitimate text) and false negatives (missing attacks)

**Secret Scanning:**
- Depends on Gitleaks community-maintained patterns
- May miss organization-specific or custom secret formats
- Requires regular updates to detect new secret types

**Fail-Open Design:**
- Prioritizes availability over absolute security
- Detection errors allow operations to proceed (won't block legitimate work)
- Not suitable for zero-trust environments requiring fail-closed behavior

### What AI Guardian Protects Against

✅ **Common threats it catches:**
- Known prompt injection patterns (instruction override, role manipulation, etc.)
- Standard secret formats (GitHub tokens, AWS keys, API keys, etc.)
- Accidental exposure of sensitive directories
- Unauthorized MCP server and skill access

❌ **Threats it may miss:**
- Novel or zero-day prompt injection techniques
- Custom/proprietary secret formats
- Obfuscated or encoded attacks
- Social engineering attacks
- Compromised AI models

**Bottom line: Use AI Guardian as part of a comprehensive security strategy, not as sole protection.**

## Future Plans

- [ ] Integration with [leaktk](https://github.com/leaktk/leaktk) project
- [ ] Web UI for managing policies and blocked directories
- [ ] Policy audit logging and compliance reporting
- [ ] Enhanced pattern matching with regex support

## License

Apache 2.0 - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection engine
- [Claude Code](https://claude.ai/code) - AI-powered IDE
- [Cursor](https://cursor.sh) - AI code editor

## FAQ

### Q: Why doesn't this documentation include examples of prompt injection attacks?

**A:** For security reasons, we intentionally do not publish specific prompt injection examples:
- Publishing attack patterns makes them easier to copy and misuse
- Specific examples can inadvertently train AI agents on attack techniques
- Including actual attack patterns would cause AI Guardian to block its own documentation

Instead, we recommend researching prompt injection through:
- Academic papers on LLM security (use a web browser, not AI agents)
- OWASP LLM Top 10 documentation
- Security research from reputable sources

For testing AI Guardian, use generic `test:` prefixed strings rather than actual attack patterns.

## Contributing

We welcome contributions! This project uses a **fork-based workflow**.

### Quick Start

```bash
# 1. Fork the repository
gh repo fork itdove/ai-guardian --clone

# 2. Create a feature branch
cd ai-guardian
git checkout -b feature-name

# 3. Make changes and commit
git add .
git commit -m "feat: your change description"

# 4. Push to your fork
git push origin feature-name

# 5. Create pull request
gh pr create --web
```

### Important Notes

- ✅ **All contributions** must come from forks
- ✅ **Update CHANGELOG.md** for notable changes
- ✅ **Add tests** for new features/fixes
- ✅ **Follow coding standards** in [AGENTS.md](AGENTS.md)
- ❌ **Do NOT create release tags** (maintainers only)

### Detailed Guidelines

See [CONTRIBUTING.md](CONTRIBUTING.md) for complete contributing guidelines including:
- Fork setup and configuration
- Branch naming conventions
- Commit message format
- Testing requirements
- Code review process
- Release process (maintainers only)

### Reporting Issues

Found a bug or have a feature request?

1. Check [existing issues](https://github.com/itdove/ai-guardian/issues)
2. Open a new issue with:
   - Clear description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Getting Help

- 📖 Read the [documentation](README.md)
- 🐛 Open an [issue](https://github.com/itdove/ai-guardian/issues)
- 💬 Ask in your PR

---

🔒 **Private Repository** - Will be made public after testing
