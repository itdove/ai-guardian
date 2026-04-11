# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Security disclaimer and expanded documentation
  - Prominent security disclaimer banner in README.md after badges section
  - Clear statement that "AI Guardian is not a silver bullet"
  - Explicit list of known limitations (prompt injection, secret scanning, fail-open design)
  - Guidance to use AI Guardian as part of defense-in-depth strategy
  - Expanded Security Design section with Architecture Principles, Known Limitations, and threat coverage
  - Lists of what AI Guardian protects against vs. threats it may miss
  - Defense-in-depth recommendations (code review, security testing, runtime monitoring)
  - Prominent "No warranty" statement referencing Apache 2.0 License
- Documentation disclaimers for self-blocking behavior
  - Prominent warning banner in README.md explaining why AI Guardian blocks its own documentation
  - FAQ section addressing "is this a bug?" question about blocked README
  - Developer warning in CONTRIBUTING.md with solutions for contributors
  - Warning comments in ai-guardian-example.json about prompt injection examples
  - Clear explanation that blocking documentation files is correct and expected behavior
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
