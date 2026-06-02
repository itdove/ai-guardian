# AI Guardian

<p align="center">
  <img src="https://raw.githubusercontent.com/itdove/ai-guardian/main/images/ai-guardian-320.png" alt="AI Guardian Logo" width="320">
</p>

> AI IDE security hook: controls MCP/skill permissions, blocks directories, detects prompt injection, scans secrets

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/ai-guardian.svg)](https://pypi.org/project/ai-guardian/)

AI Guardian provides comprehensive protection for AI IDE interactions through multiple security layers.

## Security Disclaimer

**AI Guardian is not a silver bullet** and cannot guarantee detection of all security threats.

- **Prompt injection detection** may miss novel or obfuscated attacks
- **Secret scanning** depends on scanner patterns and may miss custom secret formats
- **Attackers evolve continuously** — new bypass techniques emerge constantly
- **Fail-open by design** — prioritizes availability over security (errors allow operations)

**Use AI Guardian as ONE layer in a defense-in-depth security strategy, not as your only protection.**

Combine with:
- Code review processes
- CI/CD security scanning
- Network security (firewalls, egress rules)
- Secret management (Vault, AWS Secrets Manager)

See [Security Design](https://github.com/itdove/ai-guardian/blob/main/docs/SECURITY_DESIGN.md) for limitations and architecture.

## Quick Start

**One-line install** (creates config, installs scanner, sets up hooks):

```bash
curl -fsSL https://raw.githubusercontent.com/itdove/ai-guardian/main/install.sh | bash -s -- --ide claude
```

Or install manually:

```bash
pip install ai-guardian
ai-guardian setup --ide claude --create-config --install-scanner
```

This:
- Installs a scanner engine (gitleaks)
- Creates `ai-guardian.json` config with secure defaults
- Installs IDE hooks (PreToolUse, PostToolUse, UserPromptSubmit)
- Sets up the MCP security advisor for AI-aware protection

> **MCP servers and Skills are blocked by default.** Built-in tools (Bash, Read, Write, Edit) are allowed and scanned by hooks, but MCP servers and Skills require explicit allow rules. See [Tool Policy](https://github.com/itdove/ai-guardian/blob/main/docs/TOOL_POLICY.md#default-security-posture) for why and how to allow them.

### Daemon & Tray

The daemon provides faster hook processing. The tray is a separate process that discovers and manages daemons across local, Podman/Docker containers, and Kubernetes pods:

```bash
ai-guardian daemon start          # Start headless daemon (background: -b)
ai-guardian tray start -b         # Start system tray in background
ai-guardian tray stop             # Stop the tray
ai-guardian tray --install --autostart  # Add desktop shortcut + launch on login
```

The tray auto-discovers running daemons and shows per-daemon submenus with Statistics, Console, Pause/Resume, and Start/Stop controls. On first launch, the tray will offer to create a desktop shortcut automatically. See [Multi-Daemon Tray](https://github.com/itdove/ai-guardian/blob/main/docs/MULTI_DAEMON_TRAY.md) for full documentation.

> **Breaking change in v1.8.0**: `daemon start` no longer launches the tray automatically. Run `ai-guardian tray start -b` separately, or use `ai-guardian tray --install --autostart` for a permanent desktop shortcut with login startup.

### Security Profiles

Choose a profile that matches your environment:

```bash
ai-guardian setup --ide claude --create-config --profile @minimal --install-scanner
ai-guardian setup --ide claude --create-config --profile @strict --install-scanner
```

| Profile | Secrets | PII | Prompt Injection | SSRF |
|---------|---------|-----|------------------|------|
| @minimal | block | warn | low | warn |
| @standard (default) | block | block | medium | block |
| @strict | block | block | high | block |

## Features

| Feature | Description | Docs |
|---------|-------------|------|
| Secret Scanning | Multi-layered detection of API keys, tokens, passwords | [docs/security/SECRET_SCANNING.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/SECRET_SCANNING.md) |
| PII Detection | Detect personally identifiable information | [docs/security/SECRET_SCANNING.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/SECRET_SCANNING.md) |
| Prompt Injection | Language-aware detection with tree-sitter AST parsing and configurable sensitivity | [docs/security/PROMPT_INJECTION.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/PROMPT_INJECTION.md) |
| Image Scanning | OCR-based secret and PII detection in screenshots and images | [docs/security/IMAGE_SCANNING.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/IMAGE_SCANNING.md) |
| Unicode Attack Detection | Zero-width chars, bidi override, homoglyphs | [docs/security/UNICODE_ATTACKS.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/UNICODE_ATTACKS.md) |
| SSRF Protection | Block private IPs, cloud metadata, dangerous schemes | [docs/security/SSRF_PROTECTION.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/SSRF_PROTECTION.md) |
| Config File Scanning | Detect exfiltration of sensitive config files | [docs/security/CREDENTIAL_EXFILTRATION.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/CREDENTIAL_EXFILTRATION.md) |
| Directory Blocking | `.ai-read-deny` markers + config-based rules | [docs/security/DIRECTORY_RULES.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/DIRECTORY_RULES.md) |
| Tool Permissions | Allow/deny lists for Skills, MCP, Bash, Write | [docs/TOOL_POLICY.md](https://github.com/itdove/ai-guardian/blob/main/docs/TOOL_POLICY.md) |
| Violation Logging | JSON audit trail of all blocked operations | [docs/VIOLATION_LOGGING.md](https://github.com/itdove/ai-guardian/blob/main/docs/VIOLATION_LOGGING.md) |
| Sanitize Command | Clean sensitive data from files | [docs/security/SECRET_REDACTION.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/SECRET_REDACTION.md) |
| Interactive Console | TUI for managing configuration visually | [docs/CONSOLE.md](https://github.com/itdove/ai-guardian/blob/main/docs/CONSOLE.md) |
| Scanner Management | Install and manage 8 scanner engines (including built-in toml-patterns) | [docs/SCANNER_INSTALLATION.md](https://github.com/itdove/ai-guardian/blob/main/docs/SCANNER_INSTALLATION.md) |
| Pre-commit Hook | Scan staged files for secrets before commit | [docs/PRE_COMMIT.md](https://github.com/itdove/ai-guardian/blob/main/docs/PRE_COMMIT.md) |
| Inline Annotations | Suppress false positives with `ai-guardian:allow` and block annotations | [docs/ANNOTATIONS.md](https://github.com/itdove/ai-guardian/blob/main/docs/ANNOTATIONS.md) |
| Self-Protection | Prevents AI from disabling its own security controls | [docs/SECURITY_DESIGN.md](https://github.com/itdove/ai-guardian/blob/main/docs/SECURITY_DESIGN.md) |
| MCP Security Advisor | Read-only security tools for AI agents (proactive checks) | [docs/MCP_SERVER.md](https://github.com/itdove/ai-guardian/blob/main/docs/MCP_SERVER.md) |
| MCP Security Scanning | Audit MCP server configs and source code for supply chain risks | [docs/MCP_SERVER.md](https://github.com/itdove/ai-guardian/blob/main/docs/MCP_SERVER.md#mcp-security-scanning) |
| Project Config Overlay | Per-repo config with immutable fields and global-only section protection | [docs/CONFIGURATION.md](https://github.com/itdove/ai-guardian/blob/main/docs/CONFIGURATION.md#2-project-level-config-overlay-new-in-v180) |
| Multi-Daemon Tray | Discover and manage daemons across local, Podman/Docker, and Kubernetes | [docs/MULTI_DAEMON_TRAY.md](https://github.com/itdove/ai-guardian/blob/main/docs/MULTI_DAEMON_TRAY.md) |
| Desktop Shortcut & Autostart | Install tray as desktop app with optional login startup | [docs/MULTI_DAEMON_TRAY.md](https://github.com/itdove/ai-guardian/blob/main/docs/MULTI_DAEMON_TRAY.md#desktop-shortcuts) |
| Tray Plugins | Custom menu items with native tkinter popup forms (Textual terminal fallback), platform-aware commands | [docs/MULTI_DAEMON_TRAY.md](https://github.com/itdove/ai-guardian/blob/main/docs/MULTI_DAEMON_TRAY.md#tray-plugins) |
| TOML Pattern Engine | Built-in Python scanner with 267 pre-compiled patterns, no binary required | [docs/TOML_PATTERNS.md](https://github.com/itdove/ai-guardian/blob/main/docs/TOML_PATTERNS.md) |
| Multi-Agent Support | Hook adapters for 12 AI coding agents with normalized input/output | [docs/AGENT_SUPPORT.md](https://github.com/itdove/ai-guardian/blob/main/docs/AGENT_SUPPORT.md) |

## Default Behavior (No Configuration File)

ai-guardian provides protection **immediately** with zero configuration:

| Feature | Default | Notes |
|---------|---------|-------|
| Secret scanning | Enabled | Requires gitleaks/scanner installed |
| Prompt injection detection | Enabled | Heuristic detector |
| Config file scanning | Enabled | Detects exfiltration patterns |
| SSRF protection | Enabled | Blocks private IPs, metadata endpoints |
| Immutable file protection | Enabled | Cannot be disabled |
| `.ai-read-deny` markers | Enabled | Always respected |
| Violation logging | Enabled | Logs to `~/.local/state/ai-guardian/violations.jsonl` |
| Built-in tool permissions | Allowed | Bash, Read, Write, Edit — protected by hooks |
| MCP server permissions | **Blocked** | Require explicit allow rules (third-party code) |
| Skill permissions | **Blocked** | Require explicit allow rules (can override AI behavior) |
| Directory rules | Allow all | Configure `directory_rules` to restrict |

## Configuration

Config file: `~/.config/ai-guardian/ai-guardian.json` (or `$XDG_CONFIG_HOME/ai-guardian/`)

```bash
ai-guardian setup --create-config                          # Secure defaults (Skills/MCP blocked)
ai-guardian setup --create-config --permissive              # Permissive (all tools allowed)
ai-guardian setup --create-config --profile @minimal        # Personal projects, low friction
ai-guardian setup --create-config --profile @strict         # Enterprise SOC2/compliance
ai-guardian setup --list-profiles                           # List available profiles
```

- **Example config**: [ai-guardian-example.json](https://github.com/itdove/ai-guardian/blob/main/ai-guardian-example.json)
- **JSON Schema**: [ai-guardian-config.schema.json](https://github.com/itdove/ai-guardian/blob/main/src/ai_guardian/schemas/ai-guardian-config.schema.json) (IDE autocomplete + runtime validation)
- **Full reference**: [docs/CONFIGURATION.md](https://github.com/itdove/ai-guardian/blob/main/docs/CONFIGURATION.md)

### Configuration Locations (Precedence Order)

1. **User config**: `~/.config/ai-guardian/ai-guardian.json` (base)
2. **Project config**: `.ai-guardian/ai-guardian.json` (merged on top of user config, see [docs](https://github.com/itdove/ai-guardian/blob/main/docs/CONFIGURATION.md#2-project-level-config-overlay-new-in-v180))
3. **Remote configs** (highest, permissions only): Fetched from URLs in `remote_configs`
4. **Defaults**: Built-in defaults when no config exists

## Setup Command

```bash
ai-guardian setup                    # Auto-detect IDE
ai-guardian setup --ide claude       # Claude Code
ai-guardian setup --ide cursor       # Cursor IDE
ai-guardian setup --ide copilot      # GitHub Copilot
ai-guardian setup --dry-run          # Preview changes
ai-guardian setup --ide claude --mcp # Enable MCP security advisor (opt-in)
ai-guardian setup --remote-config-url https://example.com/policy.json
```

Run `ai-guardian setup` after upgrading to get the latest hooks. Use `--mcp` to enable the MCP security advisor server — the AI can then check security proactively before acting. See [docs/MCP_SERVER.md](https://github.com/itdove/ai-guardian/blob/main/docs/MCP_SERVER.md) for details and [docs/CONFIGURATION.md](https://github.com/itdove/ai-guardian/blob/main/docs/CONFIGURATION.md) for other setup options.

## Action Modes

Each security policy supports three enforcement levels:

| Mode | Execution | User Warning | Use Case |
|------|-----------|--------------|----------|
| `block` | Blocked | Error shown | **Enforce** policy (default) |
| `warn` | Allowed | Warning shown | **Educate** during rollout |
| `log-only` | Allowed | Silent | **Monitor** silently |

See [docs/CONFIGURATION.md](https://github.com/itdove/ai-guardian/blob/main/docs/CONFIGURATION.md) for per-feature action mode configuration.

## Integration

| IDE | Prompt Scanning | File Scanning | Output Scanning | Status |
|-----|----------------|---------------|-----------------|--------|
| Claude Code CLI | Yes | Yes | PostToolUse (ready) | Full support |
| VS Code Claude | Yes | Yes | PostToolUse (ready) | Full support |
| Cursor IDE | Yes | Yes | Yes | Full support |
| GitHub Copilot | Yes | Yes | Planned | Full support |
| Aider | No | Yes (commit-time) | No | Git hook |

- [GitHub Copilot Setup](https://github.com/itdove/ai-guardian/blob/main/docs/GITHUB_COPILOT.md)
- [Aider Setup](https://github.com/itdove/ai-guardian/blob/main/docs/AIDER.md)
- [Multi-Engine Support](https://github.com/itdove/ai-guardian/blob/main/docs/MULTI_ENGINE_SUPPORT.md)
- [Hook Ordering](https://github.com/itdove/ai-guardian/blob/main/docs/HOOKS.md)

## How It Works

```
User prompt / Tool use
       |
  [MCP Advisor] -----> AI checks proactively (optional)
       |
  [AI Guardian Hook] -- Enforcement (mandatory)
       |
  MCP/Skill check --> Not allowed? --> BLOCK
       |
  Directory check --> .ai-read-deny? --> BLOCK
       |
  Prompt injection --> Detected? -----> BLOCK
       |
  Secret scan ------> Found? --------> BLOCK
       |
  ALLOW --> Send to AI / Execute tool
```

The MCP advisor lets the AI check *before* acting (advisory). Hooks enforce *during* execution (mandatory). PostToolUse hooks scan tool outputs using the same pipeline. See [docs/MCP_SERVER.md](https://github.com/itdove/ai-guardian/blob/main/docs/MCP_SERVER.md) for the MCP server and [docs/SECURITY_DESIGN.md](https://github.com/itdove/ai-guardian/blob/main/docs/SECURITY_DESIGN.md) for full architecture.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AI_GUARDIAN_CONFIG_DIR` | Custom config directory | `~/.config/ai-guardian` |
| `AI_GUARDIAN_STATE_DIR` | State directory (logs, violations) | `~/.local/state/ai-guardian` |
| `AI_GUARDIAN_CACHE_DIR` | Cache directory (patterns) | `~/.cache/ai-guardian` |
| `AI_GUARDIAN_IDE_TYPE` | Override IDE auto-detection | Auto-detect |
| `AI_GUARDIAN_PATTERN_TOKEN` | Default pattern server auth token (all sections) | None |

Each detection feature (`secret_scanning`, `secret_redaction`, `ssrf_protection`, `config_file_scanning`) can use its own pattern server with independent auth via `token_env` or `token_file`. See [docs/PATTERN_SERVER.md](https://github.com/itdove/ai-guardian/blob/main/docs/PATTERN_SERVER.md#per-section-auth-for-multiple-servers).

## Requirements

- **Python 3.9+** (3.10+ highly recommended — several features including AST-aware scanning, MCP server, and web console require Python 3.10+)
- **Scanner engine**: gitleaks, betterleaks, leaktk, trufflehog, detect-secrets, secretlint, or gitguardian
- **GNOME Linux**: AppIndicator extension for system tray icon ([setup steps](https://github.com/itdove/ai-guardian/blob/main/docs/CONSOLE.md#getting-started))

See [docs/SCANNER_INSTALLATION.md](https://github.com/itdove/ai-guardian/blob/main/docs/SCANNER_INSTALLATION.md) for installation instructions.

## Installation

```bash
pip install ai-guardian                   # Stable release from PyPI
pip install ai-guardian[skill-discovery]  # With auto-discovery from GitHub/GitLab
# Optional: tkinter for native tray plugin popup dialogs (see docs/MULTI_DAEMON_TRAY.md)
# RHEL/Fedora: dnf install python3-tkinter | Debian: apt install python3-tk
# macOS: included with system Python; pyenv users need tcl-tk (brew install tcl-tk)
```

> **Warning:** The `main` branch contains unreleased development code. Always install stable releases from PyPI (`pip install ai-guardian`). Do not `git clone` + `pip install -e .` for production use — development builds may contain breaking changes, incomplete features, or experimental code that has not been release-tested.

For development and contributing:

```bash
git clone https://github.com/itdove/ai-guardian.git
cd ai-guardian && pip install -e .
```

> **Dev builds:** CI builds a wheel on every PR and merge. Download from the [Actions tab](https://github.com/itdove/ai-guardian/actions/workflows/build-wheel.yml) for testing only; use PyPI for stable releases.

## Testing

```bash
pip install ai-guardian[dev]                     # Install test dependencies
pytest                                          # Run all tests
pytest --cov=ai_guardian --cov-report=term      # With coverage
```

Or using [uv](https://docs.astral.sh/uv/):

```bash
uv run --extra dev python -m pytest             # Run all tests
uv run --extra dev python -m pytest --cov=ai_guardian --cov-report=term  # With coverage
```

See [AGENTS.md](https://github.com/itdove/ai-guardian/blob/main/AGENTS.md) for testing guidelines and CI/CD details.

## Contributing

We welcome contributions! This repo uses interaction limits, so:

- **Bug reports & feature requests** -- use [GitHub Discussions](https://github.com/itdove/ai-guardian/discussions)
- **Code contributions** -- fork + PR (not affected by interaction limits)

```bash
gh repo fork itdove/ai-guardian --clone
cd ai-guardian
git checkout -b feature-name
# Make changes, commit, push
gh pr create --web
```

See [CONTRIBUTING.md](https://github.com/itdove/ai-guardian/blob/main/CONTRIBUTING.md) for complete guidelines.

## Documentation

Full documentation is available in the [docs/](https://github.com/itdove/ai-guardian/blob/main/docs/) folder:

- [Configuration Guide](https://github.com/itdove/ai-guardian/blob/main/docs/CONFIGURATION.md)
- [Security Documentation](https://github.com/itdove/ai-guardian/blob/main/docs/security/)
- [Console Guide](https://github.com/itdove/ai-guardian/blob/main/docs/CONSOLE.md)
- [Tool Policy](https://github.com/itdove/ai-guardian/blob/main/docs/TOOL_POLICY.md)
- [Scanner Installation](https://github.com/itdove/ai-guardian/blob/main/docs/SCANNER_INSTALLATION.md)
- [Security Design](https://github.com/itdove/ai-guardian/blob/main/docs/SECURITY_DESIGN.md)
- [All Documentation](https://github.com/itdove/ai-guardian/blob/main/docs/README.md)

## FAQ

**Q: Why no prompt injection examples in the docs?**
Publishing attack patterns makes them easier to misuse and would cause ai-guardian to block its own documentation. Use `test:` prefixed strings for testing. See OWASP LLM Top 10 for research.

**Q: What's `permissions` vs `permissions_directories` vs `directory_rules`?**
`permissions` = which **tools** can run. `permissions_directories` = auto-discover tool permissions from repos. `directory_rules` = which **paths** can be accessed. See [docs/TOOL_POLICY.md](https://github.com/itdove/ai-guardian/blob/main/docs/TOOL_POLICY.md) and [docs/security/DIRECTORY_RULES.md](https://github.com/itdove/ai-guardian/blob/main/docs/security/DIRECTORY_RULES.md).

## License

Apache 2.0 - see [LICENSE](https://github.com/itdove/ai-guardian/blob/main/LICENSE) file for details.

## Acknowledgments

- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection engine
- [Claude Code](https://claude.ai/code) - AI-powered IDE
- [Cursor](https://cursor.sh) - AI code editor
- [LeakTK](https://github.com/leaktk/patterns) - Community secret detection patterns
- [Hermes Security Patterns](https://github.com/fullsend-ai/experiments/tree/main/hermes-security-patterns) - Security research

