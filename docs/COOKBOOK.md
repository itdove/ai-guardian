# Configuration Cookbook

Practical Q&A pairs for common AI Guardian configuration tasks. Each entry shows the question, the JSON snippet to add to your `~/.config/ai-guardian/ai-guardian.json`, and a brief explanation.

For full configuration reference, see [CONFIGURATION.md](CONFIGURATION.md). For the annotated example config, see [ai-guardian-example.json](../ai-guardian-example.json).

---

## Table of Contents

- [SSRF Protection](#ssrf-protection)
- [PII Detection](#pii-detection)
- [Secret Scanning](#secret-scanning)
- [Prompt Injection](#prompt-injection)
- [Permissions](#permissions)
- [Directory Rules](#directory-rules)
- [Annotations](#annotations)
- [Project-Level Config](#project-level-config)
- [Daemon](#daemon)
- [Scanner Engines](#scanner-engines)
- [Pattern Server](#pattern-server)
- [Image Scanning](#image-scanning)
- [Tray Plugins](#tray-plugins)
- [Profiles](#profiles)
- [MCP Server](#mcp-server)

---

## SSRF Protection

### How do I allow localhost for local development?

```json
{
  "ssrf_protection": {
    "allow_localhost": true
  }
}
```

Sets `allow_localhost` to `true`. Only enable this in development — never in production. This allows tools to access `127.0.0.1`, `localhost`, and `::1`.

### How do I allow a specific internal domain?

```json
{
  "ssrf_protection": {
    "allowed_domains": [
      "api.corp.internal",
      "public.staging.company.com"
    ]
  }
}
```

The `allowed_domains` list overrides `additional_blocked_domains`. It cannot override immutable protections (cloud metadata endpoints, private IPs, dangerous URL schemes).

### How do I block additional internal domains?

```json
{
  "ssrf_protection": {
    "additional_blocked_domains": [
      "internal.example.com",
      "*.corp.company.com",
      "admin.*"
    ]
  }
}
```

Supports exact domains, subdomain matching, and wildcard patterns (`*` and `?`).

### How do I allow only specific paths on a blocked domain?

```json
{
  "ssrf_protection": {
    "additional_blocked_domains": ["internal.api.com"],
    "path_based_rules": [
      {
        "domain": "internal.api.com",
        "allowed_paths": ["/health", "/metrics", "/api/v1/*"],
        "blocked_paths": []
      }
    ]
  }
}
```

The domain is blocked by default, but `/health`, `/metrics`, and `/api/v1/*` are allowed. Path rules are evaluated after domain-level checks.

### How do I disable SSRF protection entirely?

```json
{
  "ssrf_protection": {
    "enabled": false
  }
}
```

Not recommended. Use `"action": "warn"` or `"action": "log-only"` instead to keep visibility without blocking.

### How do I set SSRF to warn instead of block?

```json
{
  "ssrf_protection": {
    "enabled": true,
    "action": "warn"
  }
}
```

Options: `"block"` (default), `"warn"` (show warning but allow), `"log-only"` (silent logging).

---

## PII Detection

### How do I enable PII detection?

```json
{
  "scan_pii": {
    "enabled": true,
    "pii_types": ["ssn", "credit_card", "phone", "us_passport", "iban", "intl_phone"],
    "action": "block"
  }
}
```

PII detection is enabled by default. The `pii_types` list controls which types are scanned.

### How do I add email PII detection?

```json
{
  "scan_pii": {
    "pii_types": ["ssn", "credit_card", "phone", "us_passport", "iban", "intl_phone", "email"]
  }
}
```

Email detection is available but not enabled by default because it can be noisy in codebases with email addresses in source code.

### How do I add Phase 2 PII types (medical, passport, etc.)?

```json
{
  "scan_pii": {
    "pii_types": [
      "ssn", "credit_card", "phone", "us_passport", "iban", "intl_phone",
      "medical_id", "passport", "canada_sin", "uk_nin", "india_aadhaar", "address"
    ]
  }
}
```

Phase 2 types (v1.8.0+) are all opt-in. Add any combination to your `pii_types` array.

### How do I change the PII action to redact instead of block?

```json
{
  "scan_pii": {
    "action": "redact"
  }
}
```

Options: `"block"` (default, blocks in all hooks), `"redact"` (replaces PII with masked text in PostToolUse), `"warn"` (log and warn but allow), `"log-only"` (silent logging).

### How do I ignore test files for PII scanning?

```json
{
  "scan_pii": {
    "ignore_files": [
      "tests/fixtures/**",
      "tests/test_pii_*.py"
    ]
  }
}
```

Glob patterns for files to skip entirely during PII scanning.

### How do I skip PII scanning for specific tools?

```json
{
  "scan_pii": {
    "ignore_tools": [
      "mcp__*",
      "Skill:*"
    ]
  }
}
```

Supports wildcards: `*` (any chars), `?` (single char). Examples: `"mcp__*"` skips all MCP tools, `"Bash"` skips the Bash tool.

### How do I allowlist known-safe PII patterns (false positives)?

```json
{
  "scan_pii": {
    "allowlist_patterns": [
      "\\b[\\w.+-]+@example\\.(com|org|net)\\b",
      "\\b555-0[0-9]{3}\\b"
    ]
  }
}
```

Regex patterns for known-safe values. Unlike `ignore_files` (which skips entire files), allowlist patterns let you keep scanning but exclude specific values.

---

## Secret Scanning

### How do I skip specific tools for secret scanning?

```json
{
  "secret_scanning": {
    "ignore_tools": [
      "mcp__*",
      "Skill:code-review"
    ]
  }
}
```

Supports wildcards: `*` (any chars), `?` (single char). Use for tools that legitimately read test data or documentation containing example secrets.

### How do I skip specific files for secret scanning?

```json
{
  "secret_scanning": {
    "ignore_files": [
      "tests/fixtures/**",
      "**/examples/**/*.example.*"
    ]
  }
}
```

Glob patterns applied globally across all engines. You can also use per-engine `ignore_files` inside the engine object (see [Scanner Engines](#scanner-engines)), or `.aiguardignore.toml` at the project root.

### How do I add allowlist patterns for known-safe secrets?

```json
{
  "secret_scanning": {
    "allowlist_patterns": [
      "pk_test_[A-Za-z0-9]{24,}",
      "EXAMPLE_API_KEY_[A-Z0-9]+"
    ]
  }
}
```

Regex patterns for known-safe secret values. Use this for test keys, example tokens, and false positives.

### How do I add a time-limited allowlist pattern?

```json
{
  "secret_scanning": {
    "allowlist_patterns": [
      {"pattern": "sk_test_temp_[A-Za-z0-9]+", "valid_until": "2026-06-01T00:00:00Z"}
    ]
  }
}
```

The pattern auto-expires on the given date. Mix strings and objects in the same array.

### How do I temporarily disable secret scanning?

```json
{
  "secret_scanning": {
    "enabled": {
      "value": false,
      "disabled_until": "2026-04-13T16:00:00Z",
      "reason": "Testing with known-safe example secrets"
    }
  }
}
```

Time-based disabling automatically re-enables scanning after the specified time.

---

## Prompt Injection

### How do I change the prompt injection action?

```json
{
  "prompt_injection": {
    "action": "warn"
  }
}
```

Options: `"block"` (default, prevents execution), `"warn"` (logs and warns but allows), `"log-only"` (silent logging).

### How do I skip specific tools for prompt injection scanning?

```json
{
  "prompt_injection": {
    "ignore_tools": [
      "Skill:code-review",
      "mcp__*"
    ]
  }
}
```

Useful for tools that legitimately read documentation containing example attack patterns. Supports wildcards.

### How do I skip specific files for prompt injection scanning?

```json
{
  "prompt_injection": {
    "ignore_files": [
      "**/.claude/skills/*/SKILL.md",
      "**/docs/security-examples.md"
    ]
  }
}
```

Glob patterns for files to skip. Useful for skill documentation files that describe attack patterns.

### How do I change prompt injection sensitivity?

```json
{
  "prompt_injection": {
    "sensitivity": "high"
  }
}
```

Options: `"low"` (obvious attacks only), `"medium"` (balanced, default), `"high"` (more aggressive).

### How do I change the detection threshold?

```json
{
  "prompt_injection": {
    "max_score_threshold": 0.5
  }
}
```

Lower threshold = more detections (more false positives). Higher = fewer detections (may miss subtle attacks). Default is `0.75`.

### How do I add custom detection patterns?

```json
{
  "prompt_injection": {
    "custom_patterns": [
      "company_secret_.*",
      "bypass_security_.*"
    ]
  }
}
```

Regex patterns checked in addition to built-in patterns.

### How do I add jailbreak-specific patterns?

```json
{
  "prompt_injection": {
    "jailbreak_patterns": [
      "custom_jailbreak_\\w+",
      "my_company_bypass_attempt"
    ]
  }
}
```

Extends the 13 built-in jailbreak patterns. Checked against user prompts only.

### How do I allowlist false positives?

```json
{
  "prompt_injection": {
    "allowlist_patterns": [
      "test:.*",
      {"pattern": "experimental:.*", "valid_until": "2026-04-14T00:00:00Z"}
    ]
  }
}
```

Supports permanent strings and time-limited objects.

### How do I disable prompt injection detection temporarily?

```json
{
  "prompt_injection": {
    "enabled": {
      "value": false,
      "disabled_until": "2026-04-13T18:00:00Z",
      "reason": "Testing documentation with prompt injection examples"
    }
  }
}
```

Auto-re-enables after the specified time.

---

## Permissions

### How do I allow a specific skill?

```json
{
  "permissions": {
    "enabled": true,
    "rules": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "patterns": ["my-custom-skill", "team-*"]
      }
    ]
  }
}
```

Skills are blocked by default. Add patterns to the allow list. Wildcards supported: `"daf-*"` allows all skills starting with `daf-`.

### How do I allow specific MCP server tools?

```json
{
  "permissions": {
    "rules": [
      {
        "matcher": "mcp__*",
        "mode": "allow",
        "patterns": [
          "mcp__notebooklm-mcp__notebook_list",
          "mcp__notebooklm-mcp__notebook_get",
          "mcp__atlassian__jira_get_issue"
        ]
      }
    ]
  }
}
```

MCP tools are blocked by default. Allowlist specific tool names using the full `mcp__<server>__<tool>` format.

### How do I block dangerous Bash commands?

```json
{
  "permissions": {
    "rules": [
      {
        "matcher": "Bash",
        "mode": "deny",
        "patterns": [
          "*rm -rf*",
          "*mkfs*",
          "*dd if=*"
        ]
      }
    ]
  }
}
```

Deny patterns match against the full command string. Use wildcards to catch variations.

### How do I block writes to system directories?

```json
{
  "permissions": {
    "rules": [
      {
        "matcher": "Write",
        "mode": "deny",
        "patterns": ["/etc/*", "/sys/*", "/proc/*"]
      }
    ]
  }
}
```

Matches against the `file_path` parameter of Write operations.

### How do multiple rules interact (last-match-wins)?

```json
{
  "permissions": {
    "rules": [
      {"matcher": "Skill", "mode": "allow", "patterns": ["team-*"]},
      {"matcher": "Skill", "mode": "deny", "patterns": ["team-dangerous"]}
    ]
  }
}
```

Rules are evaluated in order. The **last matching rule wins**. Here, `team-dangerous` is denied even though `team-*` allows it, because the deny rule comes last.

### How do I auto-generate directory rules from skill permissions?

```json
{
  "permissions": {
    "auto_directory_rules": {
      "enabled": true,
      "allow_symlinks": true
    }
  }
}
```

Automatically creates directory access rules based on which skill directories are permitted. Set `allow_symlinks` to `true` for container environments where skills are installed as symlinks.

---

## Directory Rules

### How do I block access to sensitive directories?

```json
{
  "directory_rules": {
    "action": "block",
    "rules": [
      {
        "mode": "deny",
        "paths": [
          "~/.ssh/**",
          "~/.aws/**",
          "~/.gnupg/**",
          "/etc/passwd",
          "/etc/shadow"
        ]
      }
    ]
  }
}
```

Blocks AI access to SSH keys, AWS credentials, GPG keys, and system password files.

### How do I deny-all then allow a workspace?

```json
{
  "directory_rules": {
    "rules": [
      {"mode": "deny", "paths": ["~/**"]},
      {"mode": "allow", "paths": ["~/development/workspace/**"]}
    ]
  }
}
```

Rules are evaluated sequentially — the **last matching rule wins**. First rule denies everything under home, second re-allows the workspace.

### How do I restrict skill directory access?

```json
{
  "directory_rules": {
    "rules": [
      {"mode": "deny", "paths": ["~/.claude/skills/**"]},
      {"mode": "allow", "paths": ["~/.claude/skills/approved/**"]}
    ]
  }
}
```

Blocks all skill directories, then re-allows only approved ones.

### What path patterns are supported?

| Pattern | Meaning |
|---------|---------|
| `~` | User home directory |
| `**` | Matches all subdirectories recursively |
| `*` | Matches single directory level |
| Absolute paths | Use for system directories (`/etc/passwd`) |

---

## Annotations

### How do I suppress a false positive on a single line?

Add an inline comment to the line in your source file:

```python
API_KEY = "pk_test_example123456789012"  # ai-guardian:allow
```

The `ai-guardian:allow` marker suppresses both secret and PII scanning for that line. The `gitleaks:allow` marker suppresses secrets only (not PII).

### How do I suppress multiple lines?

```python
# ai-guardian:begin-allow
TEST_DATA = {
    "ssn": "123-45-6789",
    "card": "4111111111111111",
}
# ai-guardian:end-allow
```

Block annotations suppress all lines between the begin and end markers.

### How do I add custom suppression keywords?

```json
{
  "annotations": {
    "enabled": true,
    "inline_allow": ["nosec"],
    "inline_allow_secrets": ["gitleaks:allow", "notsecret"],
    "block_begin": ["security:begin-ignore"],
    "block_end": ["security:end-ignore"]
  }
}
```

User config extends the built-in markers (`ai-guardian:allow`, `ai-guardian:begin-allow`, `ai-guardian:end-allow`). You add custom aliases without losing built-in ones.

### How do I disable annotations for strict compliance?

```json
{
  "annotations": {
    "enabled": false
  }
}
```

Disabling annotations means no inline suppressions are allowed — all detections are enforced.

### What can annotations suppress?

Annotations suppress **secrets and PII only**. Prompt injection, jailbreak, and config file exfiltration are **always scanned** regardless of annotations.

---

## Project-Level Config

### How do I create a project-level config overlay?

Create `.ai-guardian/ai-guardian.json` at your repository root:

```json
{
  "secret_scanning": {
    "allowlist_patterns": ["PROJECT_SPECIFIC_TOKEN_[A-Z]+"]
  },
  "scan_pii": {
    "ignore_files": ["tests/fixtures/**"]
  }
}
```

This merges on top of the global config (`~/.config/ai-guardian/ai-guardian.json`). Commit the `.ai-guardian/` directory to version control so the team shares scanning rules.

### What can project config override?

Project config can override: `prompt_injection`, `secret_scanning`, `scan_pii`, `ssrf_protection`, `permissions`, `directory_rules`, `annotations`, `image_scanning`, `config_file_scanning`, `transcript_scanning`.

Project config **cannot** override: `daemon`, `mcp_server`, `support`, `security_instructions`, `on_scan_error`, `remote_configs`.

### How do I prevent projects from disabling a security feature?

In your global config, use the `immutable` array:

```json
{
  "secret_scanning": {
    "enabled": true,
    "immutable": ["enabled"]
  }
}
```

Projects can change other fields (like `allowlist_patterns`) but cannot set `enabled` to `false`.

### What's the config merge order?

Configurations are merged in this order (later overrides earlier):

1. **Built-in defaults** (lowest priority)
2. **Project local config** (`.ai-guardian/ai-guardian.json` or legacy `.ai-guardian.json`)
3. **User global config** (`~/.config/ai-guardian/ai-guardian.json`)
4. **Remote configs** (enterprise policies, highest priority)

Exception: fields marked `"immutable": true` in remote configs cannot be overridden by any lower-priority source. Global-only sections (`daemon`, `mcp_server`, `support`, `security_instructions`, `on_scan_error`, `remote_configs`) cannot be overridden by project config.

### How do I use .aiguardignore.toml for project-level ignores?

Create `.aiguardignore.toml` at the project root:

```toml
# Global allowlist — applies to ALL scanners
[allowlist]
    paths = [
        "tests/fixtures/**",
        "tests/unit/test_ai_guardian.py",
    ]

# Per-scanner allowlists
[secret_scanning.allowlist]
    paths = ["tests/integration/test_scanner.py"]

[scan_pii.allowlist]
    paths = ["tests/unit/test_pii_detection.py"]

[prompt_injection.allowlist]
    paths = ["docs/security-patterns.md"]
```

Commit to version control. Paths are additive with JSON config `ignore_files`.

---

## Daemon

### How do I change the daemon REST API port?

```json
{
  "daemon": {
    "rest_port": 63200
  }
}
```

Default is `63152`. Set `0` for OS-assigned port. Container daemons should use a fixed port.

### How do I change the idle timeout?

```json
{
  "daemon": {
    "idle_timeout_minutes": 60
  }
}
```

Default is `30` minutes. The daemon shuts down after this idle period and auto-starts on the next command.

### How do I restart or reload the daemon?

```bash
# Reload config without restart
ai-guardian daemon reload

# Stop and let it auto-start on next command
ai-guardian daemon stop

# Check daemon status
ai-guardian daemon status
```

### How do I disable the system tray icon?

```json
{
  "daemon": {
    "tray": {
      "enabled": false
    }
  }
}
```

Disable on headless servers or when the tray icon is not needed.

### How do I fix the browser staying minimized on Linux?

On KDE and GNOME, clicking **Web Console**, **Violations**, or **Metrics & Audit** in the tray opens the URL but the browser window may stay minimized. Install one of these tools:

```bash
# KDE Wayland (recommended for modern KDE)
sudo dnf install kdotool    # Fedora / RHEL
sudo apt install kdotool    # Ubuntu / Debian

# X11 (any desktop)
sudo dnf install xdotool    # Fedora / RHEL
sudo apt install xdotool    # Ubuntu / Debian
```

AI Guardian tries `kdotool`, then `xdotool`, then `wmctrl` — whichever is found first. If none is installed the URL still opens normally.

### How do I enable Kubernetes daemon discovery?

```json
{
  "daemon": {
    "tray": {
      "discover_kubernetes": true,
      "kubernetes": {
        "namespace": "ai-sdlc",
        "label_selector": "app=ai-guardian"
      }
    }
  }
}
```

Discovers ai-guardian daemons running in Kubernetes pods matching the label selector.

---

## Scanner Engines

### How do I install a scanner engine?

```bash
# Install gitleaks (default)
ai-guardian scanner install gitleaks

# Install a specific version
ai-guardian scanner install gitleaks --version 8.24.3

# Install multiple scanners
ai-guardian scanner install gitleaks betterleaks

# List installed scanners
ai-guardian scanner list
```

### How do I configure multiple scanner engines?

```json
{
  "secret_scanning": {
    "engines": ["gitleaks", "betterleaks"],
    "execution_strategy": "any-match"
  }
}
```

Options for `execution_strategy`: `"first-match"` (default, backward compatible), `"any-match"` (block if ANY engine finds secrets), `"consensus"` (block only if N engines agree).

### How do I use the consensus strategy?

```json
{
  "secret_scanning": {
    "engines": ["gitleaks", "betterleaks", "leaktk"],
    "execution_strategy": "consensus",
    "consensus_threshold": 2
  }
}
```

Blocks only when at least 2 engines agree on a finding. Reduces false positives when using multiple engines.

### How do I configure per-engine settings?

```json
{
  "secret_scanning": {
    "engines": [
      "gitleaks",
      {
        "type": "trufflehog",
        "binary": "trufflehog",
        "ignore_files": ["**/test/**", "**/fixtures/**"],
        "file_patterns": ["*.env*", "*.yaml", "*.json"]
      }
    ]
  }
}
```

Mix simple strings and objects with per-engine settings in the same array.

### How do I enable scan result caching?

```json
{
  "secret_scanning": {
    "cache_results": true,
    "cache_ttl_hours": 24
  }
}
```

Caches scan results per content hash to avoid re-scanning unchanged content.

### How do I enable incremental scanning?

```json
{
  "secret_scanning": {
    "incremental": true
  }
}
```

Only scans files whose content changed since the last scan. Automatically enables `cache_results`.

---

## Pattern Server

### How do I configure the LeakTK community pattern server?

```json
{
  "secret_scanning": {
    "engines": [
      {
        "type": "gitleaks",
        "pattern_server": {
          "url": "https://raw.githubusercontent.com",
          "patterns_endpoint": "/leaktk/patterns/main/target/patterns/gitleaks/8.27.0",
          "cache": {
            "refresh_interval_hours": 12,
            "expire_after_hours": 168
          }
        }
      }
    ]
  }
}
```

LeakTK is free, public (no auth required), and community-maintained with 104+ detection rules.

### How do I configure an enterprise pattern server?

```json
{
  "secret_scanning": {
    "engines": [
      {
        "type": "gitleaks",
        "pattern_server": {
          "url": "https://patterns.security.company.com",
          "patterns_endpoint": "/patterns/gitleaks/latest",
          "auth": {
            "method": "bearer",
            "token_env": "AI_GUARDIAN_PATTERN_TOKEN"
          },
          "cache": {
            "refresh_interval_hours": 12,
            "expire_after_hours": 168
          }
        }
      }
    ]
  }
}
```

Set `AI_GUARDIAN_PATTERN_TOKEN` in your environment. Patterns auto-refresh every 12 hours and expire after 7 days.

### How do I force a pattern cache refresh?

```bash
# Clear the cache and re-fetch
rm -f ~/.cache/ai-guardian/patterns.toml
ai-guardian daemon reload
```

The daemon re-fetches patterns from the server on next scan after the cache file is removed.

### How do I disable the pattern server?

Remove the `pattern_server` section from the engine config, or set `"url": null`:

```json
{
  "secret_scanning": {
    "engines": [
      {
        "type": "gitleaks",
        "pattern_server": null
      }
    ]
  }
}
```

Without a pattern server, gitleaks uses its default built-in patterns (or a project-level `.gitleaks.toml` if present).

---

## Image Scanning

### How do I enable image scanning?

```json
{
  "image_scanning": {
    "enabled": true,
    "action": "block",
    "scan_types": ["secrets", "pii"]
  }
}
```

Image scanning is enabled by default (v1.10.0+). It uses OCR to scan images for secrets and PII.

### How do I enable QR code scanning?

```json
{
  "image_scanning": {
    "qr_scanning": true
  }
}
```

Requires `pyzbar`: `pip install pyzbar`.

### How do I enable face detection?

```json
{
  "image_scanning": {
    "face_detection": true
  }
}
```

Requires `opencv-python-headless`: `pip install opencv-python-headless`.

### How do I adjust the performance timeout?

```json
{
  "image_scanning": {
    "max_processing_ms": 2000,
    "min_confidence": 0.7
  }
}
```

Default processing timeout is `1500ms`. Higher `min_confidence` reduces false positives but may miss low-quality text.

### How do I ignore specific image files?

```json
{
  "image_scanning": {
    "ignore_files": ["docs/screenshots/**", "assets/logos/**"],
    "ignore_tools": ["Skill:*"],
    "max_image_size_mb": 5
  }
}
```

---

## Tray Plugins

Tray plugins add custom menu items to the system tray. Place `.json` files in either location:

- **User-level**: `~/.config/ai-guardian/tray-plugins/` — personal plugins, available on all projects
- **Project-level**: `.ai-guardian/tray-plugins/` at the repository root — shared via version control, project plugins override user-level plugins with the same name

Each `.json` file becomes a submenu. For full documentation, see [MULTI_DAEMON_TRAY.md](MULTI_DAEMON_TRAY.md#tray-plugins).

### How do I create a basic tray plugin?

Create `~/.config/ai-guardian/tray-plugins/my-tools.json`:

```json
{
  "name": "My Tools",
  "items": [
    {
      "label": "Run Tests",
      "command": "cd ~/projects/my-app && pytest",
      "type": "terminal"
    },
    {
      "label": "Check Status",
      "command": "ai-guardian daemon status",
      "type": "notification"
    }
  ]
}
```

Each file needs `name` (submenu title) and `items` (array of menu entries, max 12).

### What command types are available?

```json
{
  "name": "Command Types",
  "items": [
    {"label": "Opens terminal",      "command": "htop",                        "type": "terminal"},
    {"label": "Runs silently",       "command": "make build",                  "type": "background"},
    {"label": "Shows notification",  "command": "kubectl get pods | wc -l",    "type": "notification"},
    {"label": "Copies to clipboard", "command": "date +%Y-%m-%d",             "type": "clipboard"},
    {"label": "Shows in dialog",     "command": "ai-guardian doctor --json",   "type": "modal"}
  ]
}
```

Options: `"terminal"` (default), `"background"`, `"notification"`, `"clipboard"`, `"modal"`.

### How do I add user-prompted parameters?

```json
{
  "name": "Deploy",
  "items": [
    {
      "label": "Deploy Branch",
      "command": "make deploy BRANCH={tray.branch} ENV={tray.environment}",
      "type": "terminal",
      "params": [
        {"name": "branch", "hint": "Git branch", "default": "main"},
        {"name": "environment", "default": "dev", "options": ["dev", "staging", "prod"]}
      ]
    }
  ]
}
```

Parameters show a form before running. Values substitute into `{tray.param_name}` placeholders. Use `options` for a dropdown, or omit for free-text input.

### How do I use typed parameters with validation?

```json
{
  "name": "Scale",
  "items": [
    {
      "label": "Scale Replicas",
      "command": "kubectl scale deployment my-app --replicas={tray.count}",
      "type": "notification",
      "params": [
        {
          "name": "count",
          "hint": "Number of replicas",
          "type": "int",
          "default": "3",
          "min": 1,
          "max": 10,
          "required": true
        }
      ]
    }
  ]
}
```

Parameter types: `"string"` (default, text input), `"int"`/`"number"` (numeric with min/max), `"boolean"` (checkbox), `"choice"` (dropdown), `"combobox"` (editable input with suggestions). Use `pattern` for regex validation on strings.

### How do I use platform-specific commands?

```json
{
  "name": "Terminals",
  "items": [
    {
      "label": "Open Shell",
      "command": {
        "darwin": "open -a Terminal",
        "linux": "gnome-terminal",
        "windows": "cmd.exe /k",
        "default": "bash"
      },
      "type": "terminal"
    }
  ]
}
```

Replace the command string with an object keyed by `"darwin"`, `"linux"`, `"windows"`, or `"default"` (fallback). If no key matches and no default, the item is hidden on that platform.

### How do I run a command inside a container or Kubernetes target?

Set `"run_on_target": true` — the tray automatically wraps the command for the daemon's runtime:

```json
{
  "name": "Remote Ops",
  "items": [
    {
      "label": "Doctor",
      "command": "ai-guardian doctor",
      "run_on_target": true,
      "type": "terminal"
    },
    {
      "label": "Show Config",
      "command": "ai-guardian show-config",
      "run_on_target": true,
      "type": "modal"
    }
  ]
}
```

Write the command as if running locally inside the target. The tray handles the wrapping:

| Runtime | What actually runs |
|---------|-------------------|
| Container | `podman exec -it <container_id> ai-guardian doctor` |
| Kubernetes | `oc exec <pod> -n <namespace> -- ai-guardian doctor` |
| Local | `ai-guardian doctor` (no wrapping) |

**Key distinction**: `run_on_target` runs *inside* the target. Target variables (`{container_id}`, etc.) run *on the host* referencing the target. Both can coexist in the same plugin but not in the same item.

### How do I use target variables in commands?

```json
{
  "name": "Container Tools",
  "items": [
    {
      "label": "Container Logs",
      "command": "{container_engine} logs --tail 50 {container_id}",
      "type": "terminal"
    },
    {
      "label": "Restart Container",
      "command": "{container_engine} restart {container_id}",
      "type": "notification"
    }
  ]
}
```

Available variables: `{container_id}`, `{container_engine}`, `{host}`, `{port}`, `{name}`, `{container_name}`, `{pod_name}`, `{namespace}`. These run on the host and reference the target — unlike `run_on_target` which runs inside the target.

### How do I run a command on multiple targets at once?

```json
{
  "name": "Fleet Ops",
  "items": [
    {
      "label": "Doctor (select targets)",
      "command": "ai-guardian doctor",
      "run_on_target": true,
      "type": "terminal",
      "target": "select"
    },
    {
      "label": "Reload All",
      "command": "ai-guardian daemon reload",
      "run_on_target": true,
      "type": "notification",
      "target": "all"
    },
    {
      "label": "Restart All Containers",
      "command": "{container_engine} restart {container_id}",
      "type": "notification",
      "target": "containers"
    }
  ]
}
```

The `target` field controls multi-target execution:

| Value | Behavior |
|-------|----------|
| *(omitted)* | Default — runs on the single daemon this menu item belongs to |
| `"select"` | Shows an interactive multi-select picker listing all discovered daemons |
| `"all"` | Runs on every discovered target without prompting |
| `"containers"` | Runs on all container-runtime targets without prompting |

When combined with `params`, the parameter form shows once and the same values are applied to all targets.

### How do I add project-level tray plugins?

Create `.ai-guardian/tray-plugins/` at your repository root and add plugin JSON files there:

```json
{
  "name": "Project Build",
  "items": [
    {"label": "Build",     "command": "make build",      "type": "terminal"},
    {"label": "Test",      "command": "make test",       "type": "terminal"},
    {"label": "Lint",      "command": "make lint",       "type": "notification"}
  ]
}
```

Commit the `.ai-guardian/tray-plugins/` directory to version control. Project plugins with the same `name` as a user-level plugin override the user-level one.

### How do I filter a plugin to specific daemons?

```json
{
  "name": "Carbonite",
  "tags": ["carbonite"],
  "items": [
    {
      "label": "Rebuild Container",
      "command": "{container_engine} restart {container_id}",
      "type": "notification"
    }
  ]
}
```

The plugin only appears on daemons that have `"menu_tags": ["carbonite"]` in their `ai-guardian.json`. Untagged plugins appear on all daemons.

### What is the difference between global and per-daemon plugins?

The `scope` field controls where a plugin appears in the tray menu:

**Per-daemon** (default) — plugin appears inside each daemon's submenu, filtered by `tags`:

```json
{
  "name": "Container Ops",
  "scope": "daemon",
  "tags": ["container"],
  "items": [
    {"label": "Logs", "command": "{container_engine} logs {container_id}", "type": "terminal"}
  ]
}
```

Per-daemon plugins have access to target variables (`{container_id}`, `{host}`, `{port}`, etc.) and `run_on_target`. They appear once per matching daemon.

**Global** — plugin appears at the tray top level, not inside any daemon submenu:

```json
{
  "name": "Global Tools",
  "scope": "global",
  "items": [
    {"label": "Open Dashboard", "command": "open http://localhost:63152", "type": "background"},
    {"label": "System Status",  "command": "ai-guardian daemon status",   "type": "notification"}
  ]
}
```

Global plugins are not associated with any daemon, so they don't have target variables or `run_on_target`. Use for host-level tools, dashboards, and utilities that aren't specific to a daemon instance.

### How do I create nested submenus?

```json
{
  "name": "DevOps",
  "items": [
    {
      "label": "Kubernetes",
      "items": [
        {"label": "Get Pods",      "command": "kubectl get pods",      "type": "terminal"},
        {"label": "Get Services",  "command": "kubectl get svc",       "type": "terminal"},
        {"label": "Get Nodes",     "command": "kubectl get nodes",     "type": "terminal"}
      ]
    },
    {
      "label": "Docker",
      "items": [
        {"label": "Running Containers", "command": "docker ps",        "type": "terminal"},
        {"label": "Disk Usage",         "command": "docker system df", "type": "notification"}
      ]
    }
  ]
}
```

An item with `label` + `items` (instead of `command`) creates a nested submenu. Nesting supports all item types including further submenus.

### How do I import items from another file?

```json
{
  "name": "Team Tools",
  "items": [
    {
      "label": "Shared Scripts",
      "import": "shared-scripts.json"
    },
    {
      "label": "Local Build",
      "command": "make build",
      "type": "terminal"
    }
  ]
}
```

The `import` field references another JSON file in `tray-plugins/`. The imported file must contain an `items` array (and optionally `tags` for filtering):

```json
{
  "tags": ["team-a"],
  "items": [
    {"label": "Deploy Staging", "command": "make deploy-staging", "type": "terminal"},
    {"label": "Run Smoke Tests", "command": "make smoke", "type": "notification"}
  ]
}
```

---

## Profiles

### What profiles are available?

```bash
# List all available profiles
ai-guardian setup --list-profiles

# Create config with a specific profile
ai-guardian setup --create-config --profile @minimal
ai-guardian setup --create-config --profile @standard
ai-guardian setup --create-config --profile @strict
```

### What's the difference between profiles?

| Feature | @minimal | @standard | @strict |
|---------|----------|-----------|---------|
| Use case | Personal, low friction | Team, moderate security | Enterprise, SOC2/compliance |
| Secret scanning | Enabled | Enabled | Enabled |
| PII detection | Enabled | Enabled | Enabled |
| Prompt injection | Enabled (low) | Enabled (medium) | Enabled (high) |
| SSRF protection | Enabled | Enabled | Enabled |
| Permissions | Disabled | Enabled | Enabled |
| Directory rules | None | Basic | Comprehensive |
| Annotations | Enabled | Enabled | May be disabled |

### How do I switch profiles?

Regenerate your config with a different profile:

```bash
ai-guardian setup --create-config --profile @strict
```

This overwrites `~/.config/ai-guardian/ai-guardian.json`. Back up your existing config first if you have customizations.

---

## MCP Server

### How do I install the MCP security advisor server?

```bash
# Install hooks + MCP server for your IDE
ai-guardian setup --ide claude
ai-guardian setup --ide cursor
ai-guardian setup --ide copilot

# Skip MCP installation (hooks only)
ai-guardian setup --ide claude --no-mcp
```

Since v1.10.0, `ai-guardian setup` installs the MCP server by default.

### How do I change the proactive check level?

```json
{
  "mcp_server": {
    "proactive_level": "medium"
  }
}
```

Options:
- `"low"` (default) — Only check when user asks about security, when a hook blocks something, or before outputting text with secrets.
- `"medium"` — Also check paths outside the project, commands with credentials/URLs, and unfamiliar MCP servers.
- `"high"` — Check every file access, every command, and sanitize all output. Adds latency and token usage.

### What MCP tools are available?

| Tool | Purpose |
|------|---------|
| `check_path` | Check if a file path is protected |
| `check_command` | Check if a command would be blocked |
| `check_mcp_trust` | Check if an MCP server is trusted |
| `sanitize_text` | Redact secrets and PII from text |
| `get_config` | Get current security posture |
| `get_violations` | Get recent security violations |
| `get_metrics` | Get violation statistics |
| `get_scanner_status` | Get installed scanner engines |
| `get_patterns_list` | Get active detection patterns |
| `doctor` | Run health check |
| `scan_directory` | Scan project for security issues |

---

## Global Settings

### How do I set the behavior when a scanner errors?

```json
{
  "on_scan_error": "block"
}
```

Options: `"allow"` (default, fail-open for productivity), `"block"` (fail-closed for strict compliance).

### How do I give my instance a name?

```json
{
  "name": "my-workstation",
  "menu_tags": ["workstation"]
}
```

The name appears in the Console banner, tray, REST API, and MCP responses. Tags filter tray plugin visibility.

### How do I enable audit logging for compliance?

```json
{
  "secret_scanning": {
    "audit_logging": true
  }
}
```

Logs all scan operations to `~/.local/state/ai-guardian/scan-audit.jsonl`.

### How do I enable transcript scanning?

```json
{
  "transcript_scanning": {
    "enabled": true
  }
}
```

Enabled by default. Scans conversation transcripts for threats that bypassed hooks (e.g., `!` shell commands in Claude Code).

### How do I get native tray plugin popups?

Install tkinter for your platform for the best experience (native OS dialogs). Without it, AI Guardian uses a three-tier fallback:

1. **tkinter** (native popup, no browser/terminal needed)
2. **NiceGUI** (browser-based form, Python 3.10+ only)
3. **Textual** (terminal prompt, all Python versions)

**Installing tkinter:**

- **macOS (pyenv):** `brew install tcl-tk` then rebuild Python with `pyenv install <version> --force`
- **macOS (system):** included by default in `/usr/bin/python3`
- **RHEL/Fedora:** `dnf install python3-tkinter`
- **Debian/Ubuntu:** `apt install python3-tk`
- **Windows:** included by default in the python.org installer

tkinter is optional — the installer does not install it automatically. Use `install.sh --tkinter` to attempt automatic installation.

**Override the cascade with environment variables:**

```bash
# Force NiceGUI browser form (skip tkinter even if installed)
AI_GUARDIAN_NO_TKINTER=1 ai-guardian tray start

# Force Textual terminal prompt (skip both tkinter and NiceGUI)
AI_GUARDIAN_NO_TKINTER=1 AI_GUARDIAN_NO_NICEGUI=1 ai-guardian tray start
```
