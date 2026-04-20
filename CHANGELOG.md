# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Issue #105: Enable contributor workflow for open-source development**
  - Contributors can now use AI assistance to edit ai-guardian source code in development repos
  - Removes maintainer-only restriction for editing development source files
  - Enables standard fork + PR workflow for external contributors
  - Security model:
    - Config/hooks/cache files: ALWAYS protected (even for repo owners)
    - Pip-installed code: ALWAYS protected (production deployments)
    - Development source code: ALLOWED for all users (relies on PR review process)
  - Bash/PowerShell commands on source files still blocked (rm, Remove-Item, etc.)
  - Only Edit/Write/Read tools can modify development source files
  - Added comprehensive test coverage in `tests/test_contributor_workflow.py`
  - Updated error messages to distinguish pip-installed vs development source code

### Security
- **Issue #105: Confirmed self-protection is immune to action=log bypass**
  - Self-protection patterns ALWAYS block, regardless of `action="log"` configuration
  - User's `directory_rules.action="log"` setting does NOT bypass config/hooks protection
  - User's permission rules with `action="log"` do NOT bypass critical file protection
  - Immutable patterns are checked FIRST (PRIORITY 1) before user permissions
  - No action parameter in immutable deny logic - hardcoded to block
  - Added verification tests in `tests/test_issue_105_log_bypass.py`
  - Issue #105 was filed as preventive security measure - vulnerability never existed

### Fixed
- **Bug #113: Self-protection bypass when file_path parameter is missing**
  - File-path tools (Edit, Write, Read, NotebookEdit) now fail-closed when file_path is missing
  - Previously, malformed tool_input with missing file_path would bypass IMMUTABLE pattern checks
  - AI could potentially bypass config/hooks protection by sending empty tool parameters
  - Fixed by requiring file_path parameter for security checks on file-path tools
  - Added comprehensive test coverage in `tests/test_self_protection.py`
  - Affects: Edit, Write, Read, NotebookEdit tools with empty or malformed input

- **Bug #102: Directory rules don't support combined wildcards (e.g., daf-*/**)**
  - Patterns combining single-level (`*`) and recursive (`**`) wildcards now work correctly
  - Example: `~/.claude/skills/daf-*/**` now matches all files under daf-git/, daf-jira/, etc.
  - Previously treated the `*` as a literal character after stripping `**`
  - Fixed by using fnmatch to match directory patterns when wildcards remain in base path
  - Added comprehensive test coverage in `tests/test_combined_wildcards.py`
  - Users can now use concise patterns instead of listing each directory explicitly

- **Bug #93: Directory rules ignore action=log setting and block instead**
  - When `directory_rules.action` was set to "log", .ai-read-deny markers still blocked access
  - Global action setting was not applied when no specific rule matched the path
  - Fixed by returning global action even when no rules match (applies to .ai-read-deny markers)
  - Now correctly allows access with warnings in log mode as intended
  - Added comprehensive test coverage in `tests/test_directory_rules_log_mode_bug.py`

- **Bug #94: Directory rules incorrectly parse Bash command text as file paths**
  - Bash commands were incorrectly treated as file paths in PreToolUse hooks
  - Error messages incorrectly showed "File: daf git create enhancement..." for Bash commands
  - Fixed by only checking file paths for file-reading tools (Read, Grep, Glob, etc.)
  - Bash error messages now correctly show "Command:" instead of "File:"
  - Added comprehensive test coverage in `tests/test_bash_directory_rules.py`

### Added
- **User-friendly error handling for malformed configuration files**
  - Clear JSON parsing errors displayed via systemMessage in all hook types
  - Error messages include file path, line number, column number, and problem description
  - Fail-open with warning: continues with default configuration when config has errors
  - Centralized config loading with `_load_config_file()` function
  - Comprehensive test coverage in `tests/test_config_error_handling.py`
  - Prevents silent failures when configuration JSON is malformed

- **Action levels (log vs block)** for audit mode and gradual policy rollout (Issues #84, #88)
  - Configure `action: "log"` to audit violations without blocking
  - Configure `action: "block"` to enforce policies
  - Available for: tool permissions (per-rule), prompt injection (global), directory rules (global)
  - Secret scanning always blocks (no action field for security)
  - Log mode displays clear warnings: `PreToolUse:ToolName says: ⚠️ Policy violation (log mode): ...`

- **ignore_tools and ignore_files** for false positive handling (Issue #84)
  - Skip detection for specific tools: `"Skill:code-review"`, `"Skill:*"`, `"mcp__*"`
  - Skip detection for specific files: `"**/.claude/skills/*/SKILL.md"`
  - Works for both prompt injection and secret scanning

- **Smart hook ordering in setup command**
  - `ai-guardian setup` ensures ai-guardian is first in all hooks arrays
  - Preserves existing hooks after ai-guardian
  - Warns if multiple hooks detected
  - Critical for log mode warning visibility - see `docs/HOOK_ORDERING.md`

- **Directory Rules System** - Order-based access control (Issue #82)
  - Replaces `directory_exclusions` with more flexible `directory_rules`
  - Rules evaluated in order with last-match-wins precedence
  - Each rule has `mode: "allow"|"deny"` and `paths: [...]`
  - Wildcard support: `**` (recursive), `*` (single-level)
  - Can override .ai-read-deny markers with allow rules
  - Backward compatible: `directory_exclusions` auto-converted to allow rules
  - See `tests/test_directory_rules.py` for complete examples

## [1.3.0] - 2024-04-09

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

## [1.2.0] - 2024-04-02

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

## [1.1.0] - 2024-03-15

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

## [1.0.0] - 2024-03-01

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
