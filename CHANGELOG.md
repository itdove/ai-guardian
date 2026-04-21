# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Improved logging for skill and prompt injection violations** (Issue #168)
  - Tool permission violations now include tool-specific details in logs:
    - Skill tool: Shows skill name and args parameter (e.g., `(skill='daf-jira', args='view AAP-12345')`)
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
  - Added "Configuration Concepts" section to README explaining the three main config areas
  - New comparison table showing differences between `permissions`, `permissions_directories`, and `directory_rules`
  - Expanded FAQ with three new questions addressing common configuration confusion:
    - Q: What's the difference between `permissions` and `permissions_directories`?
    - Q: What's the difference between `permissions_directories` and `directory_rules`?
    - Q: When should I use `permissions_directories`?
  - Improved comments in `ai-guardian-example.json`:
    - `permissions`: Clarified as "WHERE THE RULES LIVE" (tool execution control)
    - `permissions_directories`: Clarified as "HOW TO AUTO-POPULATE RULES" (auto-discovery feeds INTO permissions.rules)
    - `directory_exclusions`/`directory_rules`: Clarified as completely separate from permissions (filesystem path access control)
  - Updated `docs/TUI.md` to explain tab relationships:
    - Tabs 3-4 (Skills, MCP Servers) work together for tool permissions
    - Tab 8 (Permissions Discovery) feeds INTO tabs 3-4
    - Tab 9 (Directory Protection) is separate (filesystem access, not tool permissions)
  - Enhanced schema descriptions in `ai-guardian-config.schema.json` for all three sections
  - Key clarification: `permissions_directories` discovers TOOL permissions; `directory_rules` blocks filesystem PATHS

### Changed
- **BREAKING**: Replaced `action="log"` with `action="warn"` for clearer semantics (Issue #159)
  - Old behavior: `action="log"` logged violations and showed warning to user
  - New behavior: `action="warn"` logs violations and shows warning to user (same behavior, clearer name)
  - Migration: Replace all `"action": "log"` with `"action": "warn"` in your configuration
  - Affects: tool permissions, prompt injection, directory rules

### Added
- **New `action="log-only"` mode** for silent monitoring without user warnings (Issue #159)
  - Logs violations for audit purposes but does NOT show warnings to users
  - Useful for baseline metrics, impact analysis, compliance audits, and passive monitoring
  - Available for: tool permissions, prompt injection, directory rules
  - Action modes summary:
    - `action="block"` - Prevents execution (default)
    - `action="warn"` - Logs violation + shows warning to user + allows execution
    - `action="log-only"` - Logs violation silently without user warning + allows execution

- **Flexible Scanner Engine Support** - Multi-scanner support for secret detection (Issue #154)
  - Support for BetterLeaks (20-40% faster than Gitleaks)
  - Support for LeakTK (auto-pattern management)
  - Automatic fallback to available scanners via `engines` configuration
  - Custom scanner support with configurable commands and output parsers
  - Enhanced error messages showing scanner type and pattern source (Issue #153)
  - New modules: `scanners/engine_builder.py` and `scanners/output_parsers.py`

- **Directory Rules System** - Order-based access control (Issue #82)
  - Replaces `directory_exclusions` with more flexible `directory_rules`
  - Rules evaluated in order with last-match-wins precedence
  - Each rule has `mode: "allow"|"deny"` and `paths: [...]`
  - Supports `action: "warn"|"log-only"|"block"` for audit mode and gradual rollout
  - Wildcard support: `**` (recursive), `*` (single-level), combined patterns (e.g., `daf-*/**`)
  - Can override .ai-read-deny markers with allow rules
  - Backward compatible: `directory_exclusions` auto-converted to allow rules

- **Action levels** for audit mode and gradual policy rollout (Issues #84, #88, #159)
  - Configure `action: "warn"` to show warning to user but allow execution
  - Configure `action: "log-only"` to log silently without user warning (NEW in #159)
  - Configure `action: "block"` to enforce policies (default)
  - Available for: tool permissions (per-rule), prompt injection (global), directory rules (global)
  - Secret scanning always blocks (no action field for security)
  - Warn mode warnings displayed via JSON systemMessage in PreToolUse/UserPromptSubmit hooks
  - All violations logged to TUI and violation log regardless of action

- **Ignore patterns** for false positive handling (Issue #84)
  - `ignore_tools`: Skip detection for specific tools (e.g., `"Skill:code-review"`, `"mcp__*"`)
  - `ignore_files`: Skip detection for specific files (e.g., `"**/.claude/skills/*/SKILL.md"`)
  - Works for both prompt injection and secret scanning

- **Pattern server test coverage** (Issue #101)
  - Added 12 comprehensive tests for `warn_on_failure` configuration
  - Tests cover auth errors, network errors, timeouts, and fallback behavior
  - Pattern server module now has 57% code coverage

- **User-friendly error handling** for malformed configuration files
  - Clear JSON parsing errors with file path, line number, column number
  - Fail-open with warning: continues with default configuration when config has errors
  - Prevents silent failures when configuration JSON is malformed

### Changed
- **Enable contributor workflow** for open-source development (Issue #105)
  - Contributors can now use AI assistance to edit ai-guardian source code in development repos
  - Enables standard fork + PR workflow for external contributors
  - Security model: Config/hooks/cache/pip-installed always protected; development source allowed via Edit/Write/Read only
  - Updated error messages to distinguish pip-installed vs development source code

- **Smart hook ordering** in setup command
  - `ai-guardian setup` ensures ai-guardian is first in all hooks arrays
  - Critical for log mode warning visibility (only first hook's systemMessage is displayed)
  - Preserves existing hooks after ai-guardian

### Fixed
- **Bug #172**: Inconsistent glob pattern matching between `directory_rules` and `ignore_files`
  - Fixed `directory_rules.paths` to support leading `**` patterns (e.g., `**/.claude/skills/**`, `**/skills/daf-*/**`)
  - Previously, patterns starting with `**` were converted to absolute paths, making them relative to current working directory
  - Now both `directory_rules` and `ignore_files` support the same glob patterns consistently
  - Enterprise use case: Single pattern `**/skills/daf-*/**` now works across all skill locations (home, daf-sessions, projects)
  - Implementation: Added custom `_match_leading_doublestar_pattern()` function for proper `**` support
  - Updated both `directory_rules` and `ignore_files` to use the same pattern matching logic

- **Bug #165**: Pattern server silently falls back to defaults instead of blocking when unavailable
  - **SECURITY FIX**: Operations are now blocked when pattern server is configured but unavailable
  - Previously, AI Guardian silently fell back to gitleaks defaults, defeating organization-specific secret detection
  - New behavior: If pattern server is configured, those specific patterns are **required**
  - Pattern server unavailable + cache expired → **BLOCKS operation** with detailed error message
  - Pattern server unavailable + cache still valid → Uses cached patterns (graceful degradation)
  - Breaking change: `warn_on_failure` flag no longer controls fallback behavior (always blocks for security)
  - Updated README.md "Error Handling and Fallback Behavior" section to reflect blocking behavior
  - Updated tests to verify blocking instead of fallback
  - Security impact: **High** - prevents organization-specific secrets from leaking when pattern server is down

- **Bug #162**: Pattern server requires authentication for public URLs on first run
  - Pattern server now makes authentication optional for public URLs
  - Only adds Authorization header when token is available
  - Allows fetching patterns from public repositories (GitHub raw content, etc.)
  - Better error messages distinguishing public vs private URL failures
  - Backward compatible: authenticated endpoints still work as before
  - Added 5 comprehensive tests covering public/private URL scenarios

- **Bug #155**: False positives in prompt injection detection for heredoc content
  - Heredoc content is now stripped before prompt injection pattern matching
  - Prevents false positives when writing security documentation or test fixtures
  - Reuses `_strip_bash_heredoc_content()` function from tool_policy.py (PR #152)
  - Example: `cat > doc.md <<EOF\n"Ignore previous instructions"\nEOF` now allowed
  - Real injection attempts outside heredocs still detected and blocked
  - Added 20 comprehensive tests in `tests/test_prompt_injection_heredoc.py`

- **Bug #113**: Self-protection bypass when file_path parameter is missing
  - File-path tools (Edit, Write, Read, NotebookEdit) now fail-closed when file_path is missing
  - Previously, malformed tool_input could bypass IMMUTABLE pattern checks

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

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/itdove/ai-guardian/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/itdove/ai-guardian/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/itdove/ai-guardian/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
