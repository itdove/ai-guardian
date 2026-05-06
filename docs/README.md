# AI Guardian Documentation

This directory contains detailed documentation for AI Guardian. The main [README.md](../README.md) provides a quick overview; these docs cover configuration, features, and architecture in depth.

## Getting Started

| Document | Description |
|----------|-------------|
| [Configuration Guide](CONFIGURATION.md) | Config file locations, options, precedence, and remote configs |
| [Scanner Installation](SCANNER_INSTALLATION.md) | Install and manage gitleaks, betterleaks, leaktk |
| [Console Guide](CONSOLE.md) | Interactive TUI for managing configuration |
| [Hook Ordering](HOOKS.md) | How hooks work and ordering requirements |

## Security Features

| Document | Description |
|----------|-------------|
| [Security Overview](security/) | Index of all security feature documentation |
| [Secret Scanning](security/SECRET_SCANNING.md) | Secret detection, pattern server, false positives |
| [Prompt Injection](security/PROMPT_INJECTION.md) | Heuristic detection, sensitivity, allowlists |
| [SSRF Protection](security/SSRF_PROTECTION.md) | Private IP blocking, metadata endpoints, limitations |
| [Unicode Attacks](security/UNICODE_ATTACKS.md) | Zero-width chars, bidi override, homoglyphs |
| [Directory Rules](security/DIRECTORY_RULES.md) | `.ai-read-deny` markers and config-based rules |
| [Credential Exfiltration](security/CREDENTIAL_EXFILTRATION.md) | Config file scanning for exfiltration patterns |
| [Secret Redaction](security/SECRET_REDACTION.md) | Masking secrets in tool outputs |

## Daemon & Proxy

| Document | Description |
|----------|-------------|
| [Daemon & Proxy](DAEMON.md) | Background daemon service and opt-in HTTP proxy for API traffic scanning |

## Architecture & Policy

| Document | Description |
|----------|-------------|
| [Security Design](SECURITY_DESIGN.md) | Architecture principles, self-protection, known limitations |
| [Tool Policy](TOOL_POLICY.md) | Allow/deny lists for Skills, MCP, Bash, Write |
| [Permissions Comparison](PERMISSIONS_COMPARISON.md) | ai-guardian vs settings.json permissions |
| [Violation Logging](VIOLATION_LOGGING.md) | JSON audit trail of blocked operations |

## IDE Integration

| Document | Description |
|----------|-------------|
| [GitHub Copilot Setup](GITHUB_COPILOT.md) | Setup guide for GitHub Copilot |
| [Aider Setup](AIDER.md) | Git hook integration for Aider |
| [Multi-Engine Support](MULTI_ENGINE_SUPPORT.md) | Scanner engine options and future plans |
| [Pattern Server](PATTERN_SERVER.md) | Enterprise pattern server configuration |

## Development

| Document | Description |
|----------|-------------|
| [Contributing](../CONTRIBUTING.md) | Fork workflow, PR guidelines |
| [Agent Instructions](../AGENTS.md) | Development guidelines, testing, CI/CD |
| [Releasing](../RELEASING.md) | Release process and version management |
| [Changelog](../CHANGELOG.md) | Version history |

## Research

| Document | Description |
|----------|-------------|
| [Prompt Injection Analysis](research/open-prompt-injection-analysis.md) | Research on open prompt injection techniques |
