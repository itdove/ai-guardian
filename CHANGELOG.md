# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Fixed

### Deprecated

### Removed

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

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.1
[1.1.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.0
[1.0.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.1
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
