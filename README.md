# AI Guardian

<p align="center">
  <img src="https://raw.githubusercontent.com/itdove/ai-guardian/main/images/ai-guardian-320.png" alt="AI Guardian Logo" width="320">
</p>

> AI IDE security hook: controls MCP/skill permissions, blocks directories, detects prompt injection, scans secrets

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/ai-guardian.svg)](https://pypi.org/project/ai-guardian/)

AI Guardian provides comprehensive protection for AI IDE interactions through multiple security layers. **It is not a silver bullet** — use it as one layer in a defense-in-depth strategy. See [Security Design](docs/SECURITY_DESIGN.md) for limitations and architecture.

## Quick Start

```bash
pip install ai-guardian
ai-guardian setup --install-scanner --ide claude
ai-guardian scanner list
```

You're done! ai-guardian now protects against secrets, prompt injection, SSRF, and config exfiltration.

## Features

| Feature | Description | Docs |
|---------|-------------|------|
| Secret Scanning | Multi-layered detection of API keys, tokens, passwords | [docs/security/SECRET_SCANNING.md](docs/security/SECRET_SCANNING.md) |
| PII Detection | Detect personally identifiable information | [docs/security/SECRET_SCANNING.md](docs/security/SECRET_SCANNING.md) |
| Prompt Injection | Heuristic detection with configurable sensitivity | [docs/security/PROMPT_INJECTION.md](docs/security/PROMPT_INJECTION.md) |
| Unicode Attack Detection | Zero-width chars, bidi override, homoglyphs | [docs/security/UNICODE_ATTACKS.md](docs/security/UNICODE_ATTACKS.md) |
| SSRF Protection | Block private IPs, cloud metadata, dangerous schemes | [docs/security/SSRF_PROTECTION.md](docs/security/SSRF_PROTECTION.md) |
| Config File Scanning | Detect exfiltration of sensitive config files | [docs/security/CREDENTIAL_EXFILTRATION.md](docs/security/CREDENTIAL_EXFILTRATION.md) |
| Directory Blocking | `.ai-read-deny` markers + config-based rules | [docs/security/DIRECTORY_RULES.md](docs/security/DIRECTORY_RULES.md) |
| Tool Permissions | Allow/deny lists for Skills, MCP, Bash, Write | [docs/TOOL_POLICY.md](docs/TOOL_POLICY.md) |
| Violation Logging | JSON audit trail of all blocked operations | [docs/VIOLATION_LOGGING.md](docs/VIOLATION_LOGGING.md) |
| Sanitize Command | Clean sensitive data from files | [docs/security/SECRET_REDACTION.md](docs/security/SECRET_REDACTION.md) |
| Interactive Console | TUI for managing configuration visually | [docs/CONSOLE.md](docs/CONSOLE.md) |
| Scanner Management | Install and manage 7 scanner engines | [docs/SCANNER_INSTALLATION.md](docs/SCANNER_INSTALLATION.md) |
| Self-Protection | Prevents AI from disabling its own security controls | [docs/SECURITY_DESIGN.md](docs/SECURITY_DESIGN.md) |
| Daemon & Proxy | Background daemon with opt-in HTTP proxy for API traffic scanning | [docs/DAEMON.md](docs/DAEMON.md) |

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
| Tool/Skill permissions | Allow all | Configure `permissions` to restrict |
| Directory rules | Allow all | Configure `directory_rules` to restrict |

## Configuration

Config file: `~/.config/ai-guardian/ai-guardian.json` (or `$XDG_CONFIG_HOME/ai-guardian/`)

```bash
ai-guardian setup --create-config              # Secure defaults (Skills/MCP blocked)
ai-guardian setup --create-config --permissive  # Permissive (all tools allowed)
ai-guardian setup --create-config --dry-run     # Preview without creating
```

- **Example config**: [ai-guardian-example.json](ai-guardian-example.json)
- **JSON Schema**: [ai-guardian-config.schema.json](src/ai_guardian/schemas/ai-guardian-config.schema.json) (IDE autocomplete + runtime validation)
- **Full reference**: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

### Configuration Locations (Precedence Order)

1. **Project config** (highest): `./.ai-guardian.json`
2. **User config**: `~/.config/ai-guardian/ai-guardian.json`
3. **Remote configs**: Fetched from URLs in `remote_configs`
4. **Defaults**: Built-in defaults

## Setup Command

```bash
ai-guardian setup                    # Auto-detect IDE
ai-guardian setup --ide claude       # Claude Code
ai-guardian setup --ide cursor       # Cursor IDE
ai-guardian setup --ide copilot      # GitHub Copilot
ai-guardian setup --dry-run          # Preview changes
ai-guardian setup --remote-config-url https://example.com/policy.json
```

Run `ai-guardian setup` after upgrading to get the latest hooks. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for detailed setup options including remote configuration and hook ordering.

## Action Modes

Each security policy supports three enforcement levels:

| Mode | Execution | User Warning | Use Case |
|------|-----------|--------------|----------|
| `block` | Blocked | Error shown | **Enforce** policy (default) |
| `warn` | Allowed | Warning shown | **Educate** during rollout |
| `log-only` | Allowed | Silent | **Monitor** silently |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for per-feature action mode configuration.

## Integration

| IDE | Prompt Scanning | File Scanning | Output Scanning | Status |
|-----|----------------|---------------|-----------------|--------|
| Claude Code CLI | Yes | Yes | PostToolUse (ready) | Full support |
| VS Code Claude | Yes | Yes | PostToolUse (ready) | Full support |
| Cursor IDE | Yes | Yes | Yes | Full support |
| GitHub Copilot | Yes | Yes | Planned | Full support |
| Aider | No | Yes (commit-time) | No | Git hook |

- [GitHub Copilot Setup](docs/GITHUB_COPILOT.md)
- [Aider Setup](docs/AIDER.md)
- [Multi-Engine Support](docs/MULTI_ENGINE_SUPPORT.md)
- [Hook Ordering](docs/HOOKS.md)

## How It Works

```
User prompt / Tool use
       |
  [AI Guardian Hook]
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

PostToolUse hooks scan tool outputs using the same pipeline. See [docs/SECURITY_DESIGN.md](docs/SECURITY_DESIGN.md) for full architecture.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AI_GUARDIAN_CONFIG_DIR` | Custom config directory | `~/.config/ai-guardian` |
| `AI_GUARDIAN_STATE_DIR` | State directory (logs, violations) | `~/.local/state/ai-guardian` |
| `AI_GUARDIAN_CACHE_DIR` | Cache directory (patterns) | `~/.cache/ai-guardian` |
| `AI_GUARDIAN_IDE_TYPE` | Override IDE auto-detection | Auto-detect |
| `AI_GUARDIAN_PATTERN_TOKEN` | Default pattern server auth token (all sections) | None |

Each detection feature (`secret_scanning`, `secret_redaction`, `ssrf_protection`, `config_file_scanning`) can use its own pattern server with independent auth via `token_env` or `token_file`. See [docs/PATTERN_SERVER.md](docs/PATTERN_SERVER.md#per-section-auth-for-multiple-servers).

## Requirements

- **Python 3.9+**
- **Scanner engine**: gitleaks, betterleaks, leaktk, trufflehog, detect-secrets, secretlint, or gitguardian

See [docs/SCANNER_INSTALLATION.md](docs/SCANNER_INSTALLATION.md) for installation instructions.

## Installation

```bash
pip install ai-guardian                   # Basic
pip install ai-guardian[skill-discovery]  # With auto-discovery from GitHub/GitLab
```

Or from source:

```bash
git clone https://github.com/itdove/ai-guardian.git
cd ai-guardian && pip install -e .
```

## Testing

```bash
pytest                                          # Run all tests
pytest --cov=ai_guardian --cov-report=term      # With coverage
```

See [AGENTS.md](AGENTS.md) for testing guidelines and CI/CD details.

## Contributing

We welcome contributions via a **fork-based workflow**:

```bash
gh repo fork itdove/ai-guardian --clone
cd ai-guardian
git checkout -b feature-name
# Make changes, commit, push
gh pr create --web
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for complete guidelines.

## Documentation

Full documentation is available in the [docs/](docs/) folder:

- [Configuration Guide](docs/CONFIGURATION.md)
- [Security Documentation](docs/security/)
- [Console Guide](docs/CONSOLE.md)
- [Tool Policy](docs/TOOL_POLICY.md)
- [Scanner Installation](docs/SCANNER_INSTALLATION.md)
- [Security Design](docs/SECURITY_DESIGN.md)
- [All Documentation](docs/README.md)

## FAQ

**Q: Why no prompt injection examples in the docs?**
Publishing attack patterns makes them easier to misuse and would cause ai-guardian to block its own documentation. Use `test:` prefixed strings for testing. See OWASP LLM Top 10 for research.

**Q: What's `permissions` vs `permissions_directories` vs `directory_rules`?**
`permissions` = which **tools** can run. `permissions_directories` = auto-discover tool permissions from repos. `directory_rules` = which **paths** can be accessed. See [docs/TOOL_POLICY.md](docs/TOOL_POLICY.md) and [docs/security/DIRECTORY_RULES.md](docs/security/DIRECTORY_RULES.md).

## License

Apache 2.0 - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection engine
- [Claude Code](https://claude.ai/code) - AI-powered IDE
- [Cursor](https://cursor.sh) - AI code editor
- [LeakTK](https://github.com/leaktk/patterns) - Community secret detection patterns
- [Hermes Security Patterns](https://github.com/fullsend-ai/experiments/tree/main/hermes-security-patterns) - Security research

---

Private Repository - Will be made public after testing
