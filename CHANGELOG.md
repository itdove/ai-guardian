# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- Initial stable release
- AI IDE security hook for blocking directories
- Secret scanning integration with gitleaks
- MCP server and skill permission control system
- Matcher-based permissions with defense-in-depth model
- JSON-only configuration (removed TOML support)

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.2.0
[1.1.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.1
[1.1.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.0
[1.0.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.1
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
