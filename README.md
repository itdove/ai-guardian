# AI Guardian

> AI IDE security hook: controls MCP/skill permissions, blocks directories, scans secrets

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**Status:** 🔒 Private Development

AI Guardian provides comprehensive protection for AI IDE interactions through multiple security layers.

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

### 🔒 Secret Scanning
Multi-layered secret detection before AI interactions:
- **Prompt scanning**: Check user prompts before sending to AI
- **File scanning**: Verify files before AI reads them
- Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) - industry-standard scanner
- Comprehensive pattern detection (API keys, tokens, private keys, etc.)

### 🎛️ MCP Server & Skill Permissions
Control which MCP servers and skills Claude Code can use with fine-grained allow/deny lists:

**Default Security Posture:**
- ✅ **Built-in tools** (Read, Write, Bash, etc.): Allowed by default
- 🚫 **Skills**: Blocked by default (must be explicitly allowed)
- 🚫 **MCP Servers**: Blocked by default (must be explicitly allowed)

**Features:**
- Pattern-based matching: `Skill(daf-*)`, `mcp__notebooklm-mcp__notebook_*`
- Block dangerous patterns: `Bash(*rm -rf*)`, `Write(/etc/*)`
- Auto-discover skills from GitHub/GitLab directories
- Local filesystem skill discovery
- Remote policy configuration (enterprise/team policies)
- Multi-level config: enterprise → user → project

**Example Configuration:**

```json
{
  "permissions": {
    "deny": [
      "Bash(*rm -rf*)",
      "Write(/etc/*)"
    ],
    "allow": [
      "mcp__notebooklm-mcp__notebook_*",
      "Skill(daf-*)",
      "Skill(gh-cli)"
    ]
  },
  "permissions_directories": {
    "allow": [
      {
        "url": "https://github.com/your-org/skills/tree/main/skills",
        "category": "Skill"
      }
    ]
  }
}
```

Place configuration at `~/.config/ai-guardian/ai-guardian.json`. See [config-example.json](config-example.json) for full documentation.

### 🎯 Multi-IDE Support

| IDE | Prompt Scanning | File Scanning | Status |
|-----|----------------|---------------|--------|
| Claude Code CLI | ✅ | ✅ | Full support |
| VS Code Claude | ✅ | ✅ | Full support |
| Cursor IDE | ✅ | ✅ | Full support |

Auto-detects IDE type and uses the appropriate response format.

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

## Configuration

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
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "ai-guardian",
            "statusMessage": "🛡️ Checking file access..."
          }
        ]
      }
    ]
  }
}
```

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
    ]
  }
}
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

### Environment Variables

Configure ai-guardian behavior with environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AI_GUARDIAN_IDE_TYPE` | Override IDE auto-detection (`claude` or `cursor`) | Auto-detect |
| `AI_GUARDIAN_SKILL_CACHE_TTL_HOURS` | Skill directory cache TTL in hours | `24` |
| `AI_GUARDIAN_REFRESH_INTERVAL_HOURS` | Remote config refresh interval | `12` |
| `AI_GUARDIAN_EXPIRE_AFTER_HOURS` | Remote config expiration time | `168` (7 days) |

**Example:**
```bash
export AI_GUARDIAN_IDE_TYPE=claude
export AI_GUARDIAN_SKILL_CACHE_TTL_HOURS=48
```

## How It Works

```
User types prompt / Uses tool
       ↓
[AI Guardian Hook]
       ↓
   MCP/Skill check ──→ Not allowed? ──→ BLOCK ❌
       ↓ (allowed)
   Directory check? ──→ .ai-read-deny exists? ──→ BLOCK ❌
       ↓ (no marker)
   Scan with Gitleaks
       ↓
   Secret found? ──→ Yes ──→ BLOCK ❌
       ↓ (no)
   ALLOW ✅ ──→ Send to AI
```

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

---

🔒 **Private Repository** - Will be made public after testing
