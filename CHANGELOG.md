# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **ignore_tools** configuration for prompt injection and secret scanning (Issue #84)
  - Skip detection for specific tools using patterns: `"Skill:code-review"`, `"Skill:*"`, `"mcp__*"`
  - Granular control: ignore specific skills (e.g., `"Skill:code-review"`) or all skills (`"Skill"` or `"Skill:*"`)
  - Composite tool identifiers: automatically created for Skill tools (e.g., `"Skill:code-review"`)
  - **PreToolUse + PostToolUse correlation**: ignore_tools patterns now work on BOTH:
    - PreToolUse: tool inputs (e.g., Skill reading SKILL.md documentation)
    - PostToolUse: tool outputs (e.g., Skill execution results)
    - Correlation ensures cached tool results inherit ignore from original invocation
  - Supports wildcards: `*` (any chars), `?` (single char)
  - Use case: Skill documentation with example attack patterns no longer triggers false positives
  - Available in both `prompt_injection` and `secret_scanning` configuration sections
- **ignore_files** configuration for prompt injection and secret scanning (Issue #84)
  - Skip detection for specific files using glob patterns
  - Supports glob wildcards: `*` (any chars except /), `**` (any chars including /), `?` (single char)
  - Supports tilde expansion: `~` expands to home directory
  - Examples: `"**/.claude/skills/*/SKILL.md"`, `"**/tests/fixtures/**"`, `"**/.env.example"`
  - Use cases: SKILL.md files, test fixtures with fake credentials, example configuration files
  - Available in both `prompt_injection` and `secret_scanning` configuration sections
- **Defense in depth**: Use both `ignore_tools` and `ignore_files` together for comprehensive false positive handling
- Comprehensive test coverage: 10 new tests for `ignore_tools`, 9 new tests for `ignore_files`
- Example configuration files: `examples/ignore-tools-config.json`, `examples/secret-scanning-ignore-config.json`

### Changed
- **Improved logging for debugging false positives**
  - Log messages now include full file paths (not just filenames)
  - Before: `"Scanning file 'SKILL.md' for secrets..."`
  - After: `"Scanning file 'SKILL.md' (/home/user/.claude/skills/foo/SKILL.md) for secrets..."`
  - Prompt injection warnings now include file path: `"Prompt injection detected in /path/to/file, blocking operation"`
  - Makes it easy to identify which specific file triggered detection
  - Helps users quickly add files to `ignore_files` configuration

### Fixed
- **CRITICAL: Bash tool bypass vulnerability** (discovered during code review)
  - Root cause: PostToolUse hook checked `output`, `content`, `result` fields but NOT `stdout`/`stderr`
  - Impact: Bash tool could read secrets/injections without detection (e.g., `Bash(command="cat ~/.aws/credentials")`)
  - Fix: Added `stdout` and `stderr` extraction in `extract_tool_result()`
  - Both streams now combined and scanned for secrets and prompt injections
  - 12 new tests covering Bash output scanning
  - All tool outputs now scanned equally (Read, Bash, Grep, etc.)

## [1.3.0] - 2026-04-16

### Added
- Gitleaks prerequisite verification and improved error handling (Issue #73)
- Pattern server re-enabled with strict priority and graceful fallback (Issue #79)
  - **Priority order**: Pattern server → Project config → Gitleaks defaults
  - **Enterprise enforcement**: Pattern servers can now enforce organization-wide security policies
  - **Graceful fallback**: Automatically falls back to project config or defaults if pattern server is unreachable, authentication fails, or returns errors
  - **Enhanced logging**: Clear visibility into which configuration source is being used (pattern server, project config, or defaults)
  - **Pattern validation**: Warns if pattern server returns fewer than 50 rules (standard Gitleaks has 100+ rules)
  - **Fallback triggers**: Network errors, authentication errors (401/403), pattern server disabled, or fetch failures
  - **Documentation**: Pattern servers must include both organization-specific AND default Gitleaks patterns for complete coverage
  - Restores original implementation from commit aed4db0 with improved error handling and observability
  - **Setup verification**: `ai-guardian setup` now checks if Gitleaks is installed and displays warning
  - **Pattern server failure warnings**: New `warn_on_failure` config option (default: true) to control visibility of pattern server errors
  - **Generic branding**: Removed organization-specific references from TUI and defaults (pattern server URLs, token paths)


  - **Visible warnings**: Missing Gitleaks shows clear warning message (previously silent)
  - **Smart error handling**: Authentication errors block operation (user can fix), network errors warn but allow (fail-open)
  - **Installation guidance**: Clear instructions for macOS, Linux, and Windows
  - **Pattern server support**: Detects and provides specific guidance for pattern server auth/network issues
  - **Documentation**: Clarified that pattern server is not used for Gitleaks scanning (uses built-in patterns)
  - Prevents users from unknowingly operating without secret scanning protection
- Workaround suggestion in error messages for documentation files (Issue #65)
  - **Smart detection**: Identifies when users try to write ABOUT ai - guardian (not modify it)
  - **Helpful tip**: Suggests using "ai - guardian" (with spaces) to avoid triggering protection patterns
  - **Context-aware**: Only shown for documentation files (.md, .txt, /docs/, README) mentioning the tool
  - **Pattern explanation**: Explains why the workaround works (literal string matching)
  - **No security impact**: Workaround only affects text content, not actual protected file paths
  - Applies to Write and Edit tools on protected documentation files
- Comprehensive TUI documentation (Issue #57)
  - **New docs/TUI.md**: Complete guide to Text User Interface with 11 tabs
  - **Getting started**: Installation, launching, and navigation
  - **Tab reference**: Detailed documentation for all 11 tabs (Global Settings, Violations, Skills, MCP Servers, Secrets, Prompt Injection, Remote Configs, Permissions Discovery, Directory Protection, Config, Logs)
  - **Keyboard shortcuts**: Complete reference for keyboard navigation
  - **Common workflows**: 6 detailed workflow examples (allowing blocked tools, temporary disabling, team permissions, directory protection, secret investigation, config debugging)
  - **Advanced features**: Time-based permissions, smart rule merging, nested tabs, custom themes
  - **Troubleshooting**: Solutions for common TUI issues
  - **Technical details**: Architecture, data flow, Textual framework usage, performance considerations
  - Linked from README.md for easy discovery
- GitHub maintainer bypass for source code editing (Issue #60)
  - **Scoped bypass**: Maintainers can edit ai-guardian source code with AI assistance
  - **Config protection**: Config files always protected (even for maintainers)
  - **Cache protection**: Cache files protected to prevent poisoning attacks
  - **OAuth authentication**: Uses `gh` CLI to verify GitHub identity securely
  - **Collaborator check**: Confirms write access via GitHub API
  - **24-hour caching**: Status cached to avoid API rate limits
  - **Fork-friendly**: Works on maintainer's own forks
  - **Threat model B protection**: Malicious prompts can't disable security features
  - Allows editing: `src/ai_guardian/*`, `tests/*`, `*.md`, `*.toml`, `.github/*`
  - Always blocks: `*ai-guardian.json`, `~/.claude/*`, `~/.cache/ai-guardian/*`
  - Comprehensive test coverage (27 new tests in test_maintainer_bypass.py)
- Enhanced TUI with ALL missing JSON schema configuration fields (Issue #53)
  - **New Global Settings tab**: Manage permissions_enabled and secret_scanning with time-based toggles
  - **New Remote Configs tab**: Manage remote policy URLs for loading enterprise/team permissions
  - **New Permissions Discovery tab**: Auto-discover permissions from local directories or GitHub repos
  - **New Directory Protection tab**: Manage directory_exclusions for .ai-read-deny blocking
  - **TimeBasedToggle widget**: Reusable component for time-based feature toggles
    - Supports three modes: Permanently Enabled, Permanently Disabled, Temporarily Disabled
    - ISO 8601 timestamp validation for disabled_until field
    - Visual status indicators and auto re-enabling after expiration
  - **Updated Secrets tab**: Pattern server enabled field now uses TimeBasedToggle
  - **Updated Prompt Injection tab**: Detection enabled field now uses TimeBasedToggle
  - **Time-based pattern support**: Skills, MCP, and Prompt Injection tabs show expiration info
    - Expiration badges with color coding: green (active), yellow (expiring soon <24h), red (expired)
    - Support for patterns with valid_until timestamp
    - Visual countdown and status display
  - All tabs support add/remove/edit operations with live configuration updates
  - Keyboard navigation and consistent UI patterns across all tabs
  - Comprehensive test coverage for new widgets and validators (387 tests passing)
- JSON Schema for configuration file validation with runtime validation (Issue #50)
  - Created formal JSON Schema at `src/ai_guardian/schemas/ai-guardian-config.schema.json`
  - **Runtime validation**: Invalid configs are rejected at load time with clear error messages
  - **Fail-fast**: Blocks operations if configuration is invalid (exit code 2)
  - **Clear errors**: Shows exact location and nature of validation errors
  - Added `jsonschema>=4.0.0` as required dependency (~2-3ms startup overhead, imperceptible)
  - Enables IDE autocomplete and real-time validation for config files
  - Covers all configuration options with descriptions and type validation
  - Validates enums (mode, detector, sensitivity), required fields, and data types
  - Supports time-based patterns and features with ISO 8601 timestamp validation
    - Time-based permission patterns (patterns with `valid_until` expiration)
    - Time-based feature toggles (permissions_enabled, secret_scanning, etc.)
    - Time-based allowlist patterns for prompt injection
  - Added `$schema` reference to ai-guardian-example.json
  - Comprehensive test coverage (29 test cases: 23 schema + 6 runtime validation)
    - Tests time-based permission patterns (Skill, Bash allow/deny)
    - Tests time-based prompt injection allowlist patterns
    - Tests permissions_directories structure
    - Tests mixed simple and time-based patterns
    - Tests invalid enums, missing fields, and type mismatches
    - Tests runtime validation with invalid configs (test_config_validation.py)
  - Clean test fixture at `tests/fixtures/valid-config.json` (without comment fields)
  - Documentation updated in README.md with IDE setup instructions
  - Benefits: faster configuration, fewer errors, inline documentation, fail-fast validation
- PowerShell tool protection for Windows users (Issue #45)
  - Added IMMUTABLE_DENY_PATTERNS for PowerShell tool to prevent Windows bypass
  - Blocks PowerShell cmdlets: Remove-Item, Move-Item, Rename-Item, Set-Content, Clear-Content, Out-File, Copy-Item
  - Blocks PowerShell aliases: del, erase, rm, mv, move, ren, copy, rmdir
  - Blocks PowerShell redirections (>, >>)
  - Protects ai-guardian config files, IDE hook files, package source code, and .ai-read-deny markers
  - Supports both Unix-style paths (/) and Windows-style paths (\) for cross-platform compatibility
  - Updated _extract_check_value() to handle PowerShell commands
  - Comprehensive test coverage (27 test cases in test_powershell_protection.py)
  - Defense in depth: prevents bypass of self-protection on Windows systems with PowerShell tool enabled
- Protection for .ai-read-deny marker files (Issue #41)
  - AI agents can no longer remove or modify `.ai-read-deny` marker files
  - Prevents bypass of directory protection by deleting marker files
  - Protected via IMMUTABLE_DENY_PATTERNS (same mechanism as ai-guardian config protection)
  - Blocks all manipulation attempts: Write, Edit, rm, mv, sed, awk, chmod, vim, nano
  - Works for absolute, relative, and nested directory paths
  - Marker file protection is always active and cannot be disabled via configuration
  - Error messages clearly indicate when marker file protection triggers
  - Comprehensive test coverage (20+ test cases)
  - Updated documentation:
    - README.md self-protection section updated with .ai-read-deny examples
    - DIRECTORY_BLOCKING.md now includes marker file protection section
    - ai-guardian-example.json updated with protection documentation
  - Defense in depth: directory protection cannot be bypassed by AI agents
- Time-based disabling for security features (Issue #35)
  - Support for temporarily disabling entire security features for time-boxed periods
  - Works for all four major features: prompt injection, tool permissions, secret scanning, and pattern server
  - Extended format: `{"enabled": {"value": false, "disabled_until": "2026-04-13T18:00:00Z", "reason": "Debugging session"}}`
  - Backward compatible: existing boolean `enabled` flags work unchanged
  - Auto-re-enabling: features automatically re-enable when disable period expires
  - Fail-safe: invalid timestamps default to permanent disable (security-first)
  - ISO 8601 timestamp format with UTC timezone required
  - Use cases: emergency debugging access, testing with false positives, maintenance windows
  - Configuration fields:
    - `prompt_injection.enabled`: Supports time-based disabling for prompt injection detection
    - `permissions_enabled.enabled`: Supports time-based disabling for tool permissions enforcement
    - `secret_scanning.enabled`: Supports time-based disabling for Gitleaks secret scanning
    - `pattern_server.enabled`: Supports time-based disabling for pattern server integration
  - Added `is_feature_enabled()` utility function to config_utils module
  - Comprehensive test coverage for time-based feature disabling logic
  - Logging records when features are temporarily disabled and when they auto-re-enable
  - Security warning: disabling features reduces protection - use sparingly and only for short periods
- Time-based expiration for permission and prompt injection allow lists (Issue #34)
  - Support both simple string patterns (permanent) and extended dict format with `valid_until` field
  - Extended format: `{"pattern": "debug-*", "valid_until": "2026-04-13T12:00:00Z"}`
  - Expired patterns are automatically filtered during permission checks
  - ISO 8601 timestamp format with UTC timezone required
  - Fail-safe: invalid timestamps default to non-expiring (permanent)
  - Works for both tool permissions and prompt injection allowlist patterns
  - Backward compatible: existing string patterns work unchanged
  - Use cases: temporary debug access, time-boxed testing, automatic permission cleanup
  - Added `parse_iso8601()` and `is_expired()` utilities to config_utils module
  - Comprehensive test coverage for expiration logic and edge cases
- Violation/audit logging for blocked operations
  - Tracks all blocked operations to `~/.config/ai-guardian/violations.jsonl`
  - Logs tool permission blocks, directory access denials, secret detections, and prompt injections
  - JSONL format for easy parsing and analysis
  - Includes violation type, severity, blocked details, context, and suggestions
  - Configurable log rotation (max_entries, retention_days)
  - CLI command `ai-guardian violations` to view recent violations
  - Filter violations by type with `--type` flag
  - Export violations with `--export` flag
  - Clear violation log with `--clear` flag
  - Privacy-safe: no full secrets or prompts logged
  - Foundation for future TUI integration (issue #22)
- Security disclaimer and expanded documentation
  - Prominent security disclaimer banner in README.md after badges section
  - Clear statement that "AI Guardian is not a silver bullet"
  - Explicit list of known limitations (prompt injection, secret scanning, fail-open design)
  - Guidance to use AI Guardian as part of defense-in-depth strategy
  - Expanded Security Design section with Architecture Principles, Known Limitations, and threat coverage
  - Lists of what AI Guardian protects against vs. threats it may miss
  - Defense-in-depth recommendations (code review, security testing, runtime monitoring)
  - Prominent "No warranty" statement referencing Apache 2.0 License
- Removed dangerous prompt injection examples from documentation for security
  - Removed specific attack pattern examples from README.md (instruction override, mode manipulation, etc.)
  - Removed attack examples from ai-guardian-example.json configuration file
  - Removed attack examples from docs/GITHUB_COPILOT.md
  - Replaced examples with general attack categories and security guidance
  - Added FAQ explaining why we don't publish specific attack patterns
  - Added guidance to research prompt injection via academic papers and OWASP (not AI agents)
  - Maintains security by not training AI agents on attack techniques
  - Developer warning in CONTRIBUTING.md for contributors working with test files
- GitHub Copilot support: Full integration with GitHub Copilot hooks
  - userPromptSubmitted hook for prompt scanning
  - preToolUse hook for tool permission checking
  - Automatic IDE detection for GitHub Copilot format
  - JSON response format for permission decisions
- Aider integration via git pre-commit hooks
  - Example pre-commit hook script for secret scanning
  - Example .aider.conf.yml configuration
  - Support for pre-commit framework integration
  - Documentation in docs/AIDER.md
- Enhanced setup command:
  - Added `--ide copilot` option for GitHub Copilot setup
  - Auto-detection now includes GitHub Copilot
- Documentation:
  - docs/GITHUB_COPILOT.md: Complete GitHub Copilot integration guide
  - docs/AIDER.md: Complete Aider git hook integration guide
  - Updated README.md with GitHub Copilot and Aider in Multi-IDE Support table
  - Added setup examples for Copilot and Aider

### Changed
- Updated Multi-IDE Support table in README.md
- Enhanced detect_ide_type() to recognize GitHub Copilot JSON format
- Enhanced detect_hook_event() to detect GitHub Copilot's toolName field
- Enhanced format_response() to output GitHub Copilot JSON format
- Enhanced extract_file_content_from_tool() to parse GitHub Copilot toolArgs JSON string


## [1.2.0] - 2026-04-10

### Added
- Workaround suggestion in error messages for documentation files (Issue #65)
  - **Smart detection**: Identifies when users try to write ABOUT ai - guardian (not modify it)
  - **Helpful tip**: Suggests using "ai - guardian" (with spaces) to avoid triggering protection patterns
  - **Context-aware**: Only shown for documentation files (.md, .txt, /docs/, README) mentioning the tool
  - **Pattern explanation**: Explains why the workaround works (literal string matching)
  - **No security impact**: Workaround only affects text content, not actual protected file paths
  - Applies to Write and Edit tools on protected documentation files
- TestPyPI workflow for safe release testing before production
- GitHub Actions workflow `.github/workflows/publish-test.yml` for TestPyPI publishing
- Comprehensive TestPyPI testing documentation in RELEASING.md
- Support for test release tags (v*-test*) to publish to TestPyPI
- Manual workflow dispatch for testing workflow changes
- Prompt injection detection as a new security layer in the hook flow
- Heuristic-based pattern detection for common injection attacks (<1ms, local, privacy-preserving)
- Configurable sensitivity levels (low, medium, high) for detection thresholds
- Custom pattern support for organization-specific injection patterns
- Allowlist patterns to handle false positives
- Comprehensive test suite with 23 tests covering various attack patterns
- Support for future ML-based detectors (Rebuff, LLM Guard)

### Changed
- Hook flow now includes prompt injection detection between directory check and secret scanning
- Updated security architecture diagram in README.md

### Security
- **CRITICAL**: Added prompt injection detection to protect against manipulation attacks
- Detects instruction override, system mode changes, prompt exfiltration, safety bypasses
- Patterns include: "ignore previous instructions", "developer mode", "reveal prompt", etc.
- Fail-open design maintains availability if detection encounters errors
- Detection runs before AI receives prompts, providing proactive protection

## [1.1.1] - 2026-03-27

### Fixed
- Logo display on PyPI package page (use absolute URL instead of relative path)

## [1.1.0] - 2026-03-27

### Added
- Workaround suggestion in error messages for documentation files (Issue #65)
  - **Smart detection**: Identifies when users try to write ABOUT ai - guardian (not modify it)
  - **Helpful tip**: Suggests using "ai - guardian" (with spaces) to avoid triggering protection patterns
  - **Context-aware**: Only shown for documentation files (.md, .txt, /docs/, README) mentioning the tool
  - **Pattern explanation**: Explains why the workaround works (literal string matching)
  - **No security impact**: Workaround only affects text content, not actual protected file paths
  - Applies to Write and Edit tools on protected documentation files
- Automated IDE hook setup command (`ai-guardian setup`) with interactive configuration
- Support for `AI_GUARDIAN_CONFIG_DIR` environment variable for custom config directory location
- Professional logo images to README and package
- AI Guardian branding assets in `images/` directory
- Multi-IDE support research documentation (Phase 0)
- Enhanced test suite with improved secret detection tests

### Changed
- Improved README with expanded installation and usage instructions
- Updated CI workflow to install gitleaks for secret detection tests
- Enhanced IDE config structure in test fixtures

### Fixed
- Cursor hook exit code handling for correct block/allow behavior
- Hatchling configuration for proper src-layout packaging
- Import paths in directory blocking tests

## [1.0.1] - 2025-03-23

### Changed
- Update README to reflect public PyPI availability
- Change installation instructions to use PyPI instead of git clone
- Add PyPI version badge

## [1.0.0] - 2025-03-23

### Added
- Workaround suggestion in error messages for documentation files (Issue #65)
  - **Smart detection**: Identifies when users try to write ABOUT ai - guardian (not modify it)
  - **Helpful tip**: Suggests using "ai - guardian" (with spaces) to avoid triggering protection patterns
  - **Context-aware**: Only shown for documentation files (.md, .txt, /docs/, README) mentioning the tool
  - **Pattern explanation**: Explains why the workaround works (literal string matching)
  - **No security impact**: Workaround only affects text content, not actual protected file paths
  - Applies to Write and Edit tools on protected documentation files
- Initial stable release
- AI IDE security hook for blocking directories
- Secret scanning integration with gitleaks
- MCP server and skill permission control system
- Matcher-based permissions with defense-in-depth model
- JSON-only configuration (removed TOML support)

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.3.0
[1.2.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.2.0
[1.1.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.1
[1.1.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.0
[1.0.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.1
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
