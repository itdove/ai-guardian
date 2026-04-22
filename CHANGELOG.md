# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **SSRF (Server-Side Request Forgery) Protection** (Issue #194, Phase 1 of #186)
  - Prevents AI agents from accessing private networks, cloud metadata endpoints, and dangerous URL schemes
  - Immutable core protections (cannot be disabled):
    - Private IP ranges (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
    - IPv6 private ranges: ::1/128, fc00::/7, fe80::/10
    - Cloud metadata endpoints: 169.254.169.254 (AWS/Azure), metadata.google.internal (GCP), fd00:ec2::254 (AWS IPv6)
    - Dangerous URL schemes: file://, gopher://, ftp://, data://, dict://, ldap://
  - Fast performance: <1ms overhead per Bash command
  - No false positives: Public AWS services (s3.amazonaws.com) are NOT blocked
  - Full IPv6 support for all blocking rules
  - Configurable features:
    - `action` modes: block (default), warn, log-only
    - `additional_blocked_ips`: Add custom IP ranges to block
    - `additional_blocked_domains`: Add custom domains to block
    - `allow_localhost`: Enable for local development (default: false)
  - Comprehensive test suite: 73 tests including 2 validated Hermes Security Framework SSRF payloads
  - Inspired by Hermes Security Framework patterns
  - Documentation: [docs/SSRF_PROTECTION.md](docs/SSRF_PROTECTION.md)

- **Unicode Attack Detection for Prompt Injection** (Issue #195, Phase 2: Hermes Security Patterns)
  - Detects Unicode-based attacks that bypass pattern matching via invisible or look-alike characters
  - **Zero-width character detection** (9 types): U+200B (zero-width space), U+200C (non-joiner), U+200D (joiner), U+FEFF (BOM), U+2060 (word joiner), and 4 more invisible characters
  - **Bidirectional override detection** (2 types): U+202E (RTL override), U+202D (LTR override) for visual deception attacks
  - **Unicode tag character detection**: Deprecated tags (U+E0000 - U+E007F) used for hidden data encoding
  - **Homoglyph detection** (80+ pairs): Cyrillic/Greek/Mathematical look-alikes (e.g., Cyrillic 'е' U+0435 vs Latin 'e' U+0065)
  - **Smart false positive prevention**:
    - Allows emoji with zero-width joiners (e.g., 👨‍👩‍👧‍👦 family emoji) when `allow_emoji: true`
    - Allows RTL languages (Arabic, Hebrew) with legitimate bidi marks when `allow_rtl_languages: true`
    - Context-aware detection using surrounding character analysis
  - **Configuration options** under `prompt_injection.unicode_detection`:
    - `enabled`: Enable/disable all Unicode detection (default: true)
    - `detect_zero_width`: Toggle zero-width character detection (default: true)
    - `detect_bidi_override`: Toggle bidi override detection (default: true)
    - `detect_tag_chars`: Toggle tag character detection (default: true)
    - `detect_homoglyphs`: Toggle homoglyph detection (default: true)
    - `allow_rtl_languages`: Allow legitimate RTL text (default: true)
    - `allow_emoji`: Allow emoji with zero-width joiners (default: true)
  - **Performance**: <5ms overhead per prompt with early exit on first detection
  - **Integration**: Works with existing action modes (block/warn/log-only)
  - **Testing**: 40 comprehensive test cases covering all attack types and false positive scenarios
  - Validates 3/3 Hermes unicode attack payloads (zero-width, bidi override, tag characters)
  - Based on Tirith CLI patterns and Hermes Security Framework
  - New `UnicodeAttackDetector` class in `src/ai_guardian/prompt_injection.py`
  - Updated JSON schema with `unicode_detection` configuration section
  - Updated `setup.py` to include `unicode_detection` in default config template (ensures `ai-guardian setup --create-config` includes new options)

- **Config File Scanner** (Issue #196, Phase 3: Hermes Security Patterns)
  - Detects credential exfiltration commands in AI configuration files that could cause persistent credential theft across ALL AI sessions
  - **The Threat**: Malicious instructions in CLAUDE.md, AGENTS.md, or .cursorrules execute in every AI session, exfiltrating credentials from all developers on the project
  - **Persistence Multiplier**: 1 malicious config file × N developers × M sessions = N×M credential thefts
  - **8 Core Exfiltration Patterns** (immutable, cannot be disabled):
    1. `curl.*\$\{?[A-Z_][A-Z0-9_]*\}?` - curl with environment variables
    2. `wget.*\$\{?[A-Z_][A-Z0-9_]*\}?` - wget with environment variables
    3. `\benv\s*\|.*\bcurl\b` - env piped to curl (credential exfiltration)
    4. `\bprintenv\b.*\|.*\bcurl\b` - printenv exfiltration
    5. `\bcat\s+(?:/etc/|~/\.ssh/|~/\.aws/).*\|.*\bcurl\b` - file exfiltration
    6. `\bbase64\b.*\|.*\bcurl\b` - base64 encoded exfiltration
    7. `\baws\s+s3\s+(?:cp|sync)\b` - AWS S3 upload command
    8. `\bgcloud\s+storage\s+cp\b` - GCP Cloud Storage upload command
  - **Standard Config Files Scanned**: CLAUDE.md, AGENTS.md, .cursorrules, .aider.conf.yml, .github/CLAUDE.md
  - **Context-Aware Detection**: Ignores documentation examples with keywords (example, warning, don't, avoid, dangerous, attack, threat, security)
  - **Configurable Options** under `config_file_scanning`:
    - `enabled`: Enable/disable config file scanning (default: true)
    - `action`: "block" (default), "warn", or "log-only"
    - `additional_files`: Add more config file patterns to scan
    - `ignore_files`: Glob patterns for files to skip (e.g., "**/examples/**", "**/docs/**")
    - `additional_patterns`: Add custom regex patterns to detect
  - **Performance**: <10ms overhead per config file scan with early exit on first match
  - **Testing**: 37 comprehensive test cases including all 3 Hermes config file payloads
  - **Integration**: Runs after prompt injection detection, before secret scanning in PreToolUse hook
  - New `ConfigFileScanner` class in `src/ai_guardian/config_scanner.py`
  - Updated JSON schema with `config_file_scanning` configuration section
  - Updated `setup.py` to include `config_file_scanning` in default config template
  - Inspired by Hermes Security Framework patterns

- **Documented `--create-config` and `--permissive` flags in README** (Issue #199)
  - Quick Start section now shows `ai-guardian setup --create-config` as the recommended way to create config files
  - Explains difference between secure mode (default) and permissive mode (`--permissive` flag)
  - Setup Command section includes `--create-config` examples in Basic Usage
  - Includes dry-run preview example (`--create-config --dry-run`)
  - Makes onboarding easier by highlighting the automated config creation introduced in v1.4.0

- **Version information in all log entries** (Issue #190)
  - Every log line now includes AI Guardian version (e.g., `v1.5.0`)
  - New log format: `YYYY-MM-DD HH:MM:SS - v{VERSION} - logger - LEVEL - message`
  - Version logged explicitly at startup with Python version and platform information
  - Helps correlate bugs with specific releases and verify fixes
  - No manual version strings needed in log statements - automatically injected via custom LogRecord factory
  - Example log output:
    ```
    2026-04-21 18:49:20 - v1.5.0 - root - INFO - AI Guardian v1.5.0 initialized
    2026-04-21 18:49:20 - v1.5.0 - root - INFO - Python 3.12.11
    2026-04-21 18:49:20 - v1.5.0 - root - INFO - Platform: Darwin-25.4.0-arm64
    ```

### Changed

### Fixed
- **Overly aggressive self-protection heuristic no longer blocks legitimate content** (Issue #188)
  - Fixed false positives where commands mentioning "ai-guardian" in content were blocked
  - Self-protection patterns are now path-specific, only blocking when targeting actual protected files:
    - Config files: `*ai-guardian.json`, `*/.config/ai-guardian/*`
    - IDE hooks: `*/.claude/settings.json`, `*/.cursor/hooks.json`
    - Package code: `*/site-packages/ai_guardian/*`, `*/ai-guardian/src/ai_guardian/*`
    - Cache files: `*/.cache/ai-guardian/*`
    - Directory markers: `*/.ai-read-deny`
  - Now allows legitimate use cases:
    - Writing code reviews mentioning "ai-guardian" (e.g., `echo "Review mentions ai-guardian" > /tmp/review.md`)
    - Creating documentation about ai-guardian (e.g., `echo "Install ai-guardian using pip" > docs/README.md`)
    - Writing bug reports containing "ai-guardian" text
  - Protection remains strong for actual config/hook files - only the heuristic is more precise
  - Added 9 new test cases to prevent regression

## [1.4.0] - 2026-04-21

### Added
- **Default config creation in setup command** (Issue #178)
  - New `--create-config` flag for `ai-guardian setup` command to create default `ai-guardian.json` config file
  - Two configuration modes:
    - Default (secure): Secret scanning and prompt injection enabled, Skills/MCP blocked by default
    - Permissive (`--permissive`): Same security features, but all tools allowed (permissions disabled)
  - `--dry-run` flag shows config preview without creating file
  - Improves onboarding experience - no manual config file copying required
  - Example usage:
    - `ai-guardian setup --create-config` - Create secure default config
    - `ai-guardian setup --create-config --permissive` - Create permissive config
    - `ai-guardian setup --create-config --dry-run` - Preview config without creating
  - Config includes:
    - Secret scanning with LeakTK patterns
    - Prompt injection detection (medium sensitivity)
    - Permission rules (Skills/MCP blocked by default in secure mode)
    - Empty directory rules (no restrictions)
    - Remote configs section for enterprise policies

- **Improved logging for skill and prompt injection violations** (Issue #168)
  - Tool permission violations now include tool-specific details in logs:
    - Skill tool: Shows skill name and args parameter (e.g., `(skill='daf-jira', args='view PROJ-12345')`)
    - Bash tool: Shows command preview (first 100 chars, e.g., `(command='rm -rf /path/to/file...')`)
    - Read/Write/Edit tools: Shows full file path (e.g., `(file_path='/etc/passwd')`)
  - Prompt injection detection now logs comprehensive details:
    - Source information (file path, tool name, or "user_prompt")
    - Confidence score (e.g., `confidence=0.90`)
    - Matched regex pattern (e.g., `pattern='ignore\s+(all\s+)?(previous|prior|above)...'`)
    - Matched text substring (e.g., `text='Ignore all previous instructions'`)
    - Full prompt context (e.g., `prompt='Please ignore all previous...'`) - up to 200 chars, sanitized
  - **Secret sanitization**: All logged tool parameters and matched text are sanitized to prevent secrets from leaking in logs
    - Redacts API keys, tokens, passwords, and other sensitive values
    - Replaces secrets with `***REDACTED***` or similar placeholders
    - Protects against credential leakage in audit logs
  - All logging modes include full details (block, warn, log-only)
  - Enables faster debugging and better audit trail for security violations

- **Documentation: Clarified configuration section differences** (Issue #150)
  - Added comparison table and FAQ explaining differences between `permissions`, `permissions_directories`, and `directory_rules`
  - Key clarification: `permissions_directories` discovers tool permissions; `directory_rules` blocks filesystem paths

- **Action levels for audit mode and gradual policy rollout** (Issues #84, #88, #159)
  - `action="warn"` - Logs violation + shows warning to user + allows execution
  - `action="log-only"` - Logs violation silently without user warning + allows execution (NEW in #159)
  - `action="block"` - Prevents execution (default)
  - Available for: tool permissions (per-rule), prompt injection (global), directory rules (global)
  - Secret scanning always blocks (no action field for security)
  - Useful for baseline metrics, impact analysis, compliance audits, and passive monitoring
  - All violations logged to TUI and violation log regardless of action

- **Flexible scanner engine support** (Issues #153, #154)
  - Support for BetterLeaks (20-40% faster than Gitleaks) and LeakTK (auto-pattern management)
  - Automatic fallback to available scanners via `engines` configuration
  - Custom scanner support with configurable commands and output parsers
  - Enhanced error messages showing scanner type and pattern source
  - Includes fixes for betterleaks command template and validation flags

- **Directory rules system** (Issue #82, #172)
  - Order-based access control with last-match-wins precedence
  - Each rule has `mode: "allow"|"deny"` and `paths: [...]`
  - Supports `action: "warn"|"log-only"|"block"` for audit mode
  - Wildcard support: `**` (recursive), `*` (single-level), combined patterns including leading `**`
  - Can override .ai-read-deny markers with allow rules
  - Backward compatible: `directory_exclusions` auto-converted to allow rules
  - Consistent glob pattern matching with `ignore_files`

- **Ignore patterns for false positive handling** (Issue #84)
  - `ignore_tools`: Skip detection for specific tools (e.g., `"Skill:code-review"`, `"mcp__*"`)
  - `ignore_files`: Skip detection for specific files (e.g., `"**/.claude/skills/*/SKILL.md"`)
  - Works for both prompt injection and secret scanning

- **Pattern server test coverage** (Issue #101)
  - Added 12 comprehensive tests for `warn_on_failure` configuration
  - Pattern server module now has 57% code coverage

- **User-friendly error handling for malformed configuration**
  - Clear JSON parsing errors with file path, line number, column number
  - Fail-open with warning: continues with default configuration when config has errors

- **Enable contributor workflow** (Issue #105)
  - Contributors can now use AI assistance to edit ai-guardian source code in development repos
  - Enables standard fork + PR workflow for external contributors
  - Config/hooks/cache/pip-installed always protected; development source allowed via Edit/Write/Read

### Changed
- **Smart hook ordering in setup command**
  - `ai-guardian setup` ensures ai-guardian is first in all hooks arrays
  - Critical for log mode warning visibility (only first hook's systemMessage is displayed)
  - Preserves existing hooks after ai-guardian

### Fixed
- **Bug #183**: Hardcoded pattern blocks legitimate user scripts
  - Fixed overly broad protection pattern from `*mv*ai-guardian*` to `*mv*ai-guardian.json*`
  - Users can now organize scripts with 'ai-guardian' in filename
  - Config files remain protected

- **Bug #165**: Pattern server silently falls back to defaults when unavailable
  - **SECURITY FIX**: Operations now blocked when pattern server is configured but unavailable
  - Pattern server unavailable + cache expired → BLOCKS operation
  - Pattern server unavailable + cache valid → Uses cached patterns
  - Security impact: **High** - prevents organization-specific secrets from leaking

- **Bug #162**: Pattern server requires authentication for public URLs
  - Pattern server now makes authentication optional for public URLs
  - Only adds Authorization header when token is available
  - Better error messages distinguishing public vs private URL failures

- **Bug #155**: False positives in prompt injection detection for heredoc content
  - Heredoc content is now stripped before pattern matching
  - Prevents false positives when writing security documentation or test fixtures
  - Real injection attempts outside heredocs still detected

- **Bug #113**: Self-protection bypass when file_path parameter is missing
  - File-path tools (Edit, Write, Read, NotebookEdit) now fail-closed when file_path is missing

- **Bug #174**: Misleading warnings when Glob tool is used
  - Removed Glob from FILE_READING_TOOLS list
  - Glob uses `pattern` parameter, not `file_path`
  - Eliminates false warnings about missing file paths

## [1.3.0] - 2026-04-09

### Added
- **Tool output scanning** with PostToolUse hook for Claude Code and Cursor
  - Scans Bash command outputs before sending to AI
  - Scans Read/Grep/WebFetch results for secrets
  - Prevents secrets in tool responses from reaching AI context
  - Claude Code: Hook configured but not firing yet (awaiting IDE activation)
  - Cursor: Full support via `postToolUse` and `afterShellExecution` hooks

- **Maintainer bypass for source code editing**
  - GitHub repository maintainers can edit ai-guardian source files
  - Verified via GitHub CLI and collaborator API check
  - Status cached for 24 hours to avoid rate limits
  - Config files remain protected even for maintainers
  - Prevents cache poisoning attacks

### Changed
- **Tool policy deny patterns** now protect maintainer status cache
  - `*maintainer-status.json` pattern prevents cache manipulation
  - Blocks attempts to fake maintainer status via cache poisoning
  - Config files and hooks remain fully protected

### Fixed
- Removed `.github/ISSUE_TEMPLATE/` from self-protection deny patterns
  - Only protects actual config and source files
  - Allows editing issue templates for project maintenance

## [1.2.0] - 2026-04-02

### Added
- **Prompt injection detection** with heuristic pattern matching
  - Fast, local detection (<1ms, privacy-preserving)
  - Configurable sensitivity levels (low, medium, high)
  - Custom pattern support for organization-specific threats
  - Allowlist patterns for handling false positives
  - Detection categories: instruction override, system manipulation, exfiltration attempts
  - Optional integration points for ML detectors (Rebuff, LLM Guard)

### Changed
- **Enhanced violation logging**
  - All violations logged to rotating file (`~/.config/ai-guardian/violations.log`)
  - Structured JSON format for easy parsing and analysis
  - Includes violation type, timestamp, details, and suggested fixes
  - Perfect for compliance auditing and security monitoring

## [1.1.0] - 2026-03-15

### Added
- **MCP Server & Skill Permissions** system for granular access control
  - Pattern-based allow/deny lists for Skills and MCP servers
  - Wildcard matching support (e.g., `daf-*`, `mcp__notebooklm__*`)
  - Block dangerous command patterns (e.g., `*rm -rf*`)
  - Auto-discovery from GitHub/GitLab skill directories
  - Remote policy configuration for enterprise/team policies
  - Multi-level config: project → user → remote

- **Interactive TUI** for managing configuration
  - Tab-based interface for all security features
  - One-click approval of blocked operations from violation log
  - Visual configuration management with validation
  - Prevents AI agents from modifying config (requires manual clicks)

### Changed
- **Self-protecting security architecture** with hardcoded deny patterns
  - AI cannot modify ai-guardian config files
  - AI cannot remove IDE hooks (Claude Code, Cursor)
  - AI cannot edit package source code
  - AI cannot remove directory protection markers (.ai-read-deny)
  - Unbreakable protection loop - tools blocked before execution

## [1.0.0] - 2026-03-01

### Added
- **Secret scanning** with Gitleaks integration
  - Prompt scanning before AI interaction
  - File scanning before AI reads files
  - Comprehensive pattern detection (API keys, tokens, private keys, etc.)
  - Configurable ignore patterns for false positives

- **Directory blocking** with .ai-read-deny markers
  - Recursive protection (blocks directory and all subdirectories)
  - Fast performance (file existence check only)
  - Clear error messages for protected paths

- **Multi-IDE support** with auto-detection
  - Claude Code CLI and VS Code Claude extension
  - Cursor IDE
  - GitHub Copilot
  - Aider (via git hooks)

- **Setup command** for automated IDE configuration
  - Auto-detects IDE type
  - Creates backup before modifying config
  - Preserves existing configuration
  - Interactive and non-interactive modes

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/itdove/ai-guardian/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/itdove/ai-guardian/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/itdove/ai-guardian/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/itdove/ai-guardian/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
