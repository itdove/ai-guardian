# AI Guardian vs settings.json: Permission Systems Comparison

This document explains the differences between setting permissions in `ai-guardian.json` versus `.claude/settings.json` (or similar IDE configuration files). Both files have permission systems that serve different but complementary purposes.

## Table of Contents

- [Overview](#overview)
- [Architecture: Defense-in-Depth Model](#architecture-defense-in-depth-model)
- [Capabilities Comparison](#capabilities-comparison)
- [Enforcement Differences](#enforcement-differences)
- [When to Use Each System](#when-to-use-each-system)
- [Skills Are Special](#skills-are-special)
- [Additional AI Guardian Features](#additional-ai-guardian-features)
- [Example Configurations](#example-configurations)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

---

## Overview

AI IDEs like Claude Code support two permission layers:

1. **settings.json** - Built-in IDE permissions (Claude Code, Cursor, etc.)
   - User/project-level preferences
   - Controls built-in tools (Read, Write, Bash) and MCP servers
   - User can edit locally (no enforcement)
   - Standard IDE feature

2. **ai-guardian.json** - AI Guardian security layer
   - Enterprise-level enforcement
   - Controls Skills, MCP servers, built-in tools, and more
   - Remote policies cannot be bypassed
   - Additional security features (secret scanning, prompt injection, SSRF)

**Both work together** in a defense-in-depth model - they are not alternatives, they complement each other.

---

## Architecture: Defense-in-Depth Model

```
┌────────────────────────────────────────────────────────┐
│                    User Request                        │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│          Layer 1: AI Guardian (Hook-Based)             │
│  • Prompt injection detection                          │
│  • Secret scanning                                     │
│  • Config file exfiltration prevention                 │
│  • SSRF protection                                     │
│  • Tool permissions (Skills, MCP, Bash, Write)         │
│  • Directory access rules                              │
│  • Remote policy enforcement                           │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│       Layer 2: settings.json (Built-in Permissions)    │
│  • Built-in tools (Read, Write, Bash, etc.)            │
│  • MCP server permissions                              │
│  • Subagent permissions                                │
│  • User/project preferences                            │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│                    Tool Execution                      │
└────────────────────────────────────────────────────────┘
```

**Flow:**

1. User submits prompt → AI Guardian checks for prompt injection/secrets
2. AI invokes tool → AI Guardian checks permissions, directory rules
3. Tool executes → settings.json checks built-in permissions
4. Tool outputs → AI Guardian scans for leaked secrets

**Key Points:**

- AI Guardian runs **first** via hooks (PreToolUse, UserPromptSubmit, PostToolUse)
- settings.json permissions apply **after** AI Guardian allows the tool
- Both layers can independently block operations
- Defense-in-depth: If one layer is bypassed, the other provides protection

---

## Capabilities Comparison

| Capability | settings.json | ai-guardian.json | Notes |
|------------|---------------|------------------|-------|
| **Built-in Tools** (Read, Write, Bash, etc.) | ✅ Primary control | ✅ Extra restrictions | settings.json is the standard way |
| **MCP Servers** | ✅ Primary control | ✅ Extra restrictions | settings.json for user prefs, ai-guardian for enterprise |
| **Skills** | ❌ **NOT supported** | ✅ **ONLY here** | Skills cannot be controlled via settings.json |
| **Subagents** | ✅ Supported | ❌ Not applicable | Subagents use parent permissions |
| **Remote Enforcement** | ❌ User can edit locally | ✅ Cannot be bypassed | Remote policies enforced via hooks |
| **Pattern Matching** | ✅ Basic glob patterns | ✅ Advanced wildcards | ai-guardian: `*`, `?`, `{a,b}`, `**` |
| **Auto-Discovery** | ❌ Not supported | ✅ GitHub/GitLab scanning | Discover skills from repos automatically |
| **Secret Scanning** | ❌ Not supported | ✅ Gitleaks integration | Detect leaked secrets in prompts/outputs |
| **Prompt Injection** | ❌ Not supported | ✅ Detection engine | Heuristic + Unicode attack detection |
| **SSRF Protection** | ❌ Not supported | ✅ IP/domain blocking | Block private IPs, metadata endpoints |
| **Config Exfiltration** | ❌ Not supported | ✅ Detection patterns | Prevent config file leaks |
| **Directory Rules** | ❌ Not supported | ✅ Path-based control | Block `~/.ssh`, `~/.aws`, etc. |
| **Immutable Protection** | ❌ Not enforced | ✅ Hardcoded | Protects IDE config, ai-guardian files |
| **Violation Logging** | ❌ No audit trail | ✅ JSON logs + TUI | View violations in `ai-guardian tui` |
| **Action Modes** | Binary (allow/deny) | Block, Log, Redact | Flexible enforcement |

---

## Enforcement Differences

### settings.json: User-Editable Preferences

**Location:** `~/.claude/settings.json` (Claude Code), `.cursor/config.json` (Cursor), etc.

**Enforcement:**
- ❌ **User can edit** the file locally
- ❌ **No remote enforcement** - changes only affect local machine
- ❌ **No audit trail** of permission violations
- ✅ **Respected by IDE** - but only as strong as user cooperation

**Use Case:** User/project preferences where trust is assumed

**Example:**
```json
{
  "permissions": {
    "allow": [
      "Bash:npm *",
      "Read:**/*.py",
      "mcp__github__*"
    ],
    "deny": [
      "Write:/etc/*"
    ]
  }
}
```

### ai-guardian.json: Enterprise Enforcement

**Location:** `~/.config/ai-guardian/ai-guardian.json` (local) or remote URL

**Enforcement:**
- ✅ **Remote policies cannot be bypassed** - enforced via hooks
- ✅ **Immutable protections** - hardcoded in ai-guardian source
- ✅ **Violation logging** - audit trail in `violations.jsonl`
- ✅ **Multiple action modes** - block, log, redact

**Use Case:** Enterprise enforcement, security policies, compliance

**Example:**
```json
{
  "permissions": {
    "enabled": true,
    "rules": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "patterns": ["approved-*"],
        "action": "block"
      }
    ]
  },
  "remote_configs": [
    {
      "url": "https://example.com/company-policy.json",
      "refresh_interval": 3600
    }
  ]
}
```

**Remote Config Enforcement:**

1. User cannot remove `remote_configs` from local file (ai-guardian detects tampering)
2. Remote policies merge with local config (remote takes precedence)
3. Policies auto-refresh from remote URL (cannot be stale)
4. Hooks enforce policies before IDE permissions run

---

## When to Use Each System

| Scenario | Use settings.json | Use ai-guardian.json | Why |
|----------|-------------------|----------------------|-----|
| **Control Skills** | ❌ Not supported | ✅ **Required** | Skills only exist in ai-guardian |
| **User MCP preferences** | ✅ Recommended | ⚠️ Optional | User can manage locally in settings.json |
| **Enterprise MCP restrictions** | ⚠️ User can bypass | ✅ **Required** | Remote policies cannot be bypassed |
| **Built-in tool restrictions** | ✅ First choice | ⚠️ For extras | settings.json is the standard way |
| **Enterprise built-in restrictions** | ⚠️ User can bypass | ✅ **Required** | Add restrictions beyond settings.json |
| **Auto-discover skills/MCP** | ❌ Not supported | ✅ Use this | GitHub/GitLab directory scanning |
| **Dynamic enterprise policies** | ❌ Static files | ✅ Use this | Remote configs auto-refresh |
| **Secret scanning** | ❌ Not supported | ✅ **Required** | Detect leaked credentials |
| **Prompt injection detection** | ❌ Not supported | ✅ Use this | Security layer |
| **Directory access control** | ❌ Not supported | ✅ Use this | Block `~/.ssh`, `~/.aws` |
| **Compliance audit trail** | ❌ No logging | ✅ **Required** | View violations in TUI |

**Recommended Decision Tree:**

1. **Do you need to control Skills?** → Use ai-guardian.json (required)
2. **Do you need enterprise enforcement?** → Use ai-guardian.json (remote policies)
3. **Do you need security features?** → Use ai-guardian.json (secrets, prompt injection, SSRF)
4. **Just user preferences for built-in tools?** → Use settings.json (simpler)
5. **Defense-in-depth?** → **Use both** (recommended)

---

## Skills Are Special

**Skills can ONLY be controlled via ai-guardian.json** - they are not available in settings.json.

### Why Skills Require ai-guardian

1. **Skills are external code** - not built into the IDE
2. **Skills have no IDE integration** - IDE doesn't know they exist
3. **Skills invoked via Skill tool** - ai-guardian intercepts via hooks
4. **Enterprise needs control** - Skills can be organization-specific

### Controlling Skills

**In ai-guardian.json:**
```json
{
  "permissions": {
    "enabled": true,
    "rules": [
      {
        "_comment": "Only allow approved skills",
        "matcher": "Skill",
        "mode": "allow",
        "patterns": [
          "daf-*",
          "gh-cli",
          "git-cli",
          "claude-api"
        ],
        "action": "block"
      }
    ]
  }
}
```

**NOT in settings.json:**
```json
{
  "permissions": {
    "allow": [
      "Skill:daf-*"  // ❌ DOES NOT WORK - Skills not supported
    ]
  }
}
```

**Auto-Discovery from GitHub:**
```json
{
  "permissions_directories": {
    "allow": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "url": "https://github.com/your-org/approved-skills/tree/main/skills",
        "token_env": "GITHUB_TOKEN"
      }
    ]
  }
}
```

This scans the GitHub repo, discovers all skills, and automatically adds them to the allowlist.

---

## Additional AI Guardian Features

Beyond permissions, ai-guardian provides security features not available in settings.json:

### 1. Secret Scanning (Gitleaks)

**Detects leaked secrets in:**
- User prompts (UserPromptSubmit hook)
- Tool outputs (PostToolUse hook)
- File contents being read

**Supported scanners:**
- Gitleaks (recommended)
- Betterleaks (20-40% faster)
- LeakTK (auto-pattern management)

**Configuration:**
```json
{
  "secret_scanning": {
    "enabled": true,
    "action": "block",
    "gitleaks": {
      "enabled": true,
      "config_path": null  // Uses built-in patterns
    }
  }
}
```

**Action on detection:**
- `block`: Prevents execution, shows error to user
- `redact`: Redacts secrets from output (output scanning only)

### 2. Prompt Injection Detection

**Detects adversarial prompts attempting to:**
- Override instructions ("Ignore previous instructions")
- Exfiltrate data ("Print your system prompt")
- Execute commands ("Run this shell script")

**Detection methods:**
- Heuristic patterns (keyword matching)
- Unicode attacks (homoglyphs, zero-width characters)

**Configuration:**
```json
{
  "prompt_injection": {
    "enabled": true,
    "action": "log",  // or "block"
    "heuristic_detector": {
      "enabled": true,
      "threshold": 0.5
    },
    "unicode_detection": {
      "enabled": true,
      "check_homoglyphs": true,
      "check_zero_width": true
    }
  }
}
```

### 3. SSRF Protection

**Blocks requests to:**
- Private IP addresses (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Localhost (127.0.0.1, ::1)
- Link-local addresses (169.254.0.0/16)
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal)

**Configuration:**
```json
{
  "ssrf_protection": {
    "enabled": true,
    "action": "block",
    "block_private_ips": true,
    "block_metadata_endpoints": true,
    "allowed_domains": [],
    "blocked_domains": []
  }
}
```

### 4. Config File Exfiltration Prevention

**Detects attempts to read sensitive config files:**
- `.env`, `credentials`, `secrets.yml`
- `~/.aws/credentials`, `~/.ssh/id_rsa`
- Database config files

**Configuration:**
```json
{
  "config_file_scanning": {
    "enabled": true,
    "action": "log"
  }
}
```

### 5. Directory Access Rules

**Path-based access control independent of permissions:**

```json
{
  "directory_rules": {
    "deny": [
      "~/.ssh/*",
      "~/.aws/*",
      "~/.gnupg/*",
      "**/secrets/*"
    ],
    "allow": [
      "~/projects/**"
    ]
  }
}
```

### 6. Immutable File Protection

**Hardcoded protections that cannot be disabled:**

- AI Guardian config: `~/.config/ai-guardian/ai-guardian.json`
- IDE hooks: `~/.claude/settings.json`, `.cursor/hooks.json`
- AI Guardian source: `**/ai_guardian/**/*.py`
- Read-deny markers: `**/.ai-read-deny`

**These files cannot be:**
- Written by Write tool
- Modified by Edit tool
- Deleted by Bash commands

### 7. Violation Logging

**All violations logged to:**
- `~/.config/ai-guardian/violations.jsonl` (JSON format)
- Python logs: `~/.local/state/ai-guardian/ai-guardian.log`

**View violations:**
```bash
ai-guardian tui  # Interactive TUI
```

**TUI features:**
- Filter by type (permissions, secrets, directories)
- One-click approval (add to allowlist)
- Violation statistics
- Suggested fixes

---

## Example Configurations

### Example 1: User Preferences Only (settings.json)

**Scenario:** Developer wants simple MCP/Bash restrictions, no enterprise enforcement

**~/.claude/settings.json:**
```json
{
  "permissions": {
    "allow": [
      "Bash:npm *",
      "Bash:pytest *",
      "Bash:git *",
      "Read:**/*.{py,js,ts,md}",
      "Write:src/**",
      "mcp__github__*",
      "mcp__linear__*"
    ],
    "deny": [
      "Bash:rm -rf*",
      "Write:/etc/*",
      "Write:~/.ssh/*"
    ]
  }
}
```

**No ai-guardian.json needed** - built-in permissions are sufficient.

### Example 2: Enterprise Enforcement (ai-guardian.json)

**Scenario:** Company requires Skills control + security features + remote policies

**~/.config/ai-guardian/ai-guardian.json:**
```json
{
  "permissions": {
    "enabled": true,
    "rules": [
      {
        "_comment": "Only approved skills allowed",
        "matcher": "Skill",
        "mode": "allow",
        "patterns": [
          "company-approved-*",
          "daf-*",
          "gh-cli",
          "git-cli"
        ],
        "action": "block"
      },
      {
        "_comment": "Block dangerous Bash commands",
        "matcher": "Bash",
        "mode": "deny",
        "patterns": [
          "*rm -rf /*",
          "*mkfs*",
          "*dd if=*"
        ],
        "action": "block"
      }
    ]
  },
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  },
  "prompt_injection": {
    "enabled": true,
    "action": "log"
  },
  "directory_rules": {
    "deny": [
      "~/.ssh/*",
      "~/.aws/*",
      "~/.gnupg/*"
    ]
  },
  "remote_configs": [
    {
      "url": "https://policies.company.com/ai-guardian-enterprise.json",
      "refresh_interval": 3600
    }
  ]
}
```

**Also have settings.json** for user MCP preferences (both files work together).

### Example 3: Defense-in-Depth (Both Files)

**Scenario:** User preferences + enterprise enforcement + security features

**~/.claude/settings.json (User layer):**
```json
{
  "permissions": {
    "allow": [
      "Bash:npm *",
      "Bash:pytest *",
      "Read:**/*.py",
      "Write:src/**",
      "mcp__github__*"
    ]
  }
}
```

**~/.config/ai-guardian/ai-guardian.json (Enterprise layer):**
```json
{
  "permissions": {
    "enabled": true,
    "rules": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "patterns": ["approved-*"],
        "action": "block"
      },
      {
        "_comment": "Extra enterprise restrictions on Bash",
        "matcher": "Bash",
        "mode": "deny",
        "patterns": ["*rm -rf /*"],
        "action": "block"
      }
    ]
  },
  "secret_scanning": {
    "enabled": true,
    "action": "block"
  },
  "directory_rules": {
    "deny": ["~/.ssh/*", "~/.aws/*"]
  },
  "remote_configs": [
    {
      "url": "https://policies.company.com/ai-guardian.json",
      "refresh_interval": 3600
    }
  ]
}
```

**Result:**
1. AI Guardian hook runs first (secrets, prompt injection, Skills, Bash restrictions, directory rules)
2. settings.json permissions apply (MCP, additional Bash/Read/Write restrictions)
3. Both layers enforce independently (defense-in-depth)

---

## Best Practices

### 1. Use Both Systems (Recommended)

**settings.json:** User/project preferences for built-in tools and MCP servers
- Simple, standard IDE feature
- User can customize per project
- No external dependencies

**ai-guardian.json:** Enterprise enforcement + security features
- Skills control (required if using Skills)
- Remote policies (cannot be bypassed)
- Security layers (secrets, prompt injection, SSRF)

### 2. Start Permissive, Tighten Gradually

**Phase 1: Monitoring** (Log mode)
```json
{
  "permissions": {
    "rules": [
      {"matcher": "Skill", "mode": "allow", "patterns": ["*"], "action": "log"}
    ]
  }
}
```

**Phase 2: Identify Violations**
```bash
ai-guardian tui  # Review violations
```

**Phase 3: Allowlist** (Block mode)
```json
{
  "permissions": {
    "rules": [
      {"matcher": "Skill", "mode": "allow", "patterns": ["approved-*"], "action": "block"}
    ]
  }
}
```

### 3. Use Remote Policies for Enterprise

**Central policy server:**
```
https://policies.company.com/
├── ai-guardian-base.json       # Base policy (all users)
├── ai-guardian-engineering.json # Engineering team
└── ai-guardian-security.json    # Security team
```

**User config references remote:**
```json
{
  "remote_configs": [
    {
      "url": "https://policies.company.com/ai-guardian-base.json",
      "refresh_interval": 3600
    },
    {
      "url": "https://policies.company.com/ai-guardian-engineering.json",
      "refresh_interval": 3600
    }
  ]
}
```

**Benefits:**
- ✅ Centralized management
- ✅ Instant updates (auto-refresh)
- ✅ Cannot be bypassed (enforced via hooks)
- ✅ Different policies per team

### 4. Auto-Discover Skills from GitHub

**Instead of manual lists:**
```json
{
  "permissions": {
    "rules": [
      {"matcher": "Skill", "mode": "allow", "patterns": ["skill-a", "skill-b", "skill-c"]}
    ]
  }
}
```

**Use auto-discovery:**
```json
{
  "permissions_directories": {
    "allow": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "url": "https://github.com/company/approved-skills/tree/main/skills",
        "token_env": "GITHUB_TOKEN"
      }
    ]
  }
}
```

**Benefits:**
- ✅ No manual updates needed
- ✅ New skills auto-approved
- ✅ Removed skills auto-blocked

### 5. Enable All Security Features

**Minimal ai-guardian config (security only):**
```json
{
  "secret_scanning": {"enabled": true, "action": "block"},
  "prompt_injection": {"enabled": true, "action": "log"},
  "ssrf_protection": {"enabled": true, "action": "block"},
  "config_file_scanning": {"enabled": true, "action": "log"}
}
```

**No permissions needed** if only using security features.

### 6. Separate User and Enterprise Concerns

**Don't mix in settings.json:**
```json
{
  "permissions": {
    "allow": [
      "Bash:npm *",            // ✅ User preference
      "Skill:company-only-*"   // ❌ Should be in ai-guardian.json (Skills not supported here anyway)
    ]
  }
}
```

**Proper separation:**

**settings.json (User):**
```json
{
  "permissions": {
    "allow": ["Bash:npm *", "mcp__github__*"]
  }
}
```

**ai-guardian.json (Enterprise):**
```json
{
  "permissions": {
    "rules": [
      {"matcher": "Skill", "mode": "allow", "patterns": ["company-*"]}
    ]
  }
}
```

---

## Related Documentation

- [README.md](../README.md) - Main AI Guardian documentation
- [HOOKS.md](HOOKS.md) - Hook integration architecture and ordering
- [TUI.md](TUI.md) - Using the TUI to view violations
- [SECRET_SCANNING.md](SECRET_SCANNING.md) - Secret detection details
- [SSRF_PROTECTION.md](SSRF_PROTECTION.md) - SSRF protection configuration
- [Claude Code Permissions](https://code.claude.com/docs/en/permissions) - Official settings.json docs

---

**Last Updated:** 2026-04-24  
**Version:** 1.4.0-dev
