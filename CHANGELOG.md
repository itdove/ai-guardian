# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Deprecated

### Removed

### Security

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

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.0
[1.0.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.1
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
