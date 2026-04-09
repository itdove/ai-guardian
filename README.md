# AI Guardian

<p align="center">
  <img src="https://raw.githubusercontent.com/itdove/ai-guardian/main/images/ai-guardian-320.png" alt="AI Guardian Logo" width="320">
</p>

> AI IDE security hook: controls MCP/skill permissions, blocks directories, detects prompt injection, scans secrets

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/ai-guardian.svg)](https://pypi.org/project/ai-guardian/)

AI Guardian provides comprehensive protection for AI IDE interactions through multiple security layers.

## Quick Start

```bash
# 1. Install Gitleaks (macOS)
brew install gitleaks

# 2. Install AI Guardian from PyPI
pip install ai-guardian

# 3. Setup IDE hooks (auto-detects Claude Code or Cursor)
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

**⚠️ IMPORTANT:** Run `ai-guardian setup` after upgrading to get the latest security hooks. New versions may add additional hooks (e.g., PostToolUse for output scanning).

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

1. **IDE Detection**: Auto-detects Claude Code or Cursor based on config directories
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

### 🚨 Prompt Injection Detection
**NEW in v1.2.0**: Detects and blocks prompt injection attacks before they reach the AI:
- **Heuristic detection**: Fast, local pattern matching (<1ms, privacy-preserving)
- **Configurable sensitivity**: Low, medium, or high detection thresholds
- **Custom patterns**: Add your own detection rules
- **Allowlist support**: Handle false positives gracefully
- **Optional ML detectors**: Support for Rebuff, LLM Guard (future)

**Detection patterns include**:
- Instruction override attempts ("ignore previous instructions")
- System/mode manipulation ("you are now in developer mode")
- Prompt exfiltration ("reveal your system prompt")
- Safety bypass attempts ("disable ethical guidelines")
- Role manipulation ("act as unfiltered AI")
- Encoding/delimiter attacks
- Many-shot injection patterns

**Configuration example** (`~/.config/ai-guardian/ai-guardian.json`):
```json
{
  "prompt_injection": {
    "enabled": true,
    "detector": "heuristic",
    "sensitivity": "medium",
    "allowlist_patterns": ["test:.*"]
  }
}
```

### 🔒 Secret Scanning
Multi-layered secret detection before AI interactions:
- **Prompt scanning**: Check user prompts before sending to AI
- **File scanning**: Verify files before AI reads them
- Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) - industry-standard scanner
- Comprehensive pattern detection (API keys, tokens, private keys, etc.)

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

Auto-detects IDE type and uses the appropriate response format.

**Note on PostToolUse (Claude Code):** ai-guardian includes PostToolUse hook support to scan tool outputs (e.g., Bash command results) before they reach the AI. However, as of v1.3.0, Claude Code does not consistently fire this hook. The implementation is ready and will automatically activate when Claude Code enables it. Cursor IDE's equivalent hooks (postToolUse, afterShellExecution) work as expected.

## Requirements

- **Python 3.9 or higher**
- **Gitleaks 8.x** - Open-source secret scanner

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

### Custom Secret Patterns

Create `.gitleaks.toml` in your project:

```toml
# Allow specific patterns
[allowlist]
description = "Allowed patterns"
regexes = [
    '''example-api-key-12345''',
]
paths = [
    '''tests/fixtures/.*''',
]

# Add custom patterns
[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''mycompany_[0-9a-f]{32}'''
```

See [Gitleaks Configuration](https://github.com/gitleaks/gitleaks#configuration) for more options.

### Pattern Server (Advanced)

**Optional:** Integrate with a custom pattern server for enhanced, auto-updating secret detection rules.

**Note:** This is an advanced enterprise feature. Most users should use the default Gitleaks patterns or project-specific `.gitleaks.toml` files.

**Configuration (`~/.config/ai-guardian/ai-guardian.json`):**

```json
{
  "pattern_server": {
    "enabled": true,
    "url": "https://your-pattern-server.example.com",
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
    }
  }
}
```

**Setup:**

```bash
# 1. Get your Bearer token from your pattern server's web interface
#    Example: Visit https://your-pattern-server.example.com/token
#    Copy the JWT token provided

# 2. Provide the token (choose ONE method):

# Option A: Environment variable (temporary, session-only)
export AI_GUARDIAN_PATTERN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Option B: Token file (persistent, recommended)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." > ~/.config/ai-guardian/pattern-token
chmod 600 ~/.config/ai-guardian/pattern-token

# 3. Enable pattern server in config (see above)

# 4. Patterns will auto-download on first scan
```

**How it works:**
1. AI Guardian checks if patterns need refresh (every 12 hours)
2. Looks up Bearer token (tries `token_env` first, then `token_file`)
3. Downloads latest patterns from your pattern server using Bearer auth
4. Caches patterns locally for 7 days
5. Uses cached patterns if pattern server is unavailable (fail-safe)

**Configuration Priority:**
1. **Pattern Server** (if enabled and available) - highest priority
2. **Project `.gitleaks.toml`** - overrides for specific projects
3. **Default Gitleaks patterns** - built-in fallback

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

- ✅ **Fail-open**: If scanning errors occur, allows operation (availability over security)
- ✅ **In-memory scanning**: Uses `/dev/shm` on Linux for performance
- ✅ **Secure cleanup**: Overwrites temp files before deletion
- ✅ **No logging**: Secrets are never logged or stored

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
