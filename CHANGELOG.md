# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed

- **Secret Redaction Always Redacts (Removed Block Mode)** (Issue #234)
  - **Change**: `secret_redaction.action="block"` mode removed - secrets are now always redacted (never blocked)
  - **New Default**: Changed default action from "log-only" to "warn" for better UX
  - **Valid Actions**: Only "warn" (redact with notification) and "log-only" (redact silently) are now supported
  - **Breaking Change**: Configurations with `action="block"` will fail validation with a helpful error message
  - **Rationale**: 
    - Simpler UX - one behavior, no confusing modes
    - Better DX - AI can still help (sees masked secrets) instead of being completely blocked
    - Same security - real secrets never reach AI
    - Less friction - reading files with secrets doesn't stop work
    - Name matches behavior - "secret_redaction" actually redacts
  - **Migration**: For users who want old "block" behavior, add sensitive files to `.gitleaksignore` to prevent reading them entirely
  - **Impact**: 
    - Schema updated to only allow "warn" and "log-only" 
    - TUI dropdown no longer shows "block" option
    - Config validation rejects "block" with migration guidance
    - Default config templates updated to use "warn"
  - **Files Modified**:
    - `src/ai_guardian/schemas/ai-guardian-config.schema.json`: Updated enum and default
    - `src/ai_guardian/secret_redactor.py`: Updated docstring and default
    - `src/ai_guardian/__init__.py`: Simplified to always redact when enabled
    - `src/ai_guardian/config_inspector.py`: Added validation to reject "block"
    - `src/ai_guardian/setup.py`: Changed default from "log-only" to "warn"
    - `src/ai_guardian/tui/secret_redaction.py`: Removed "block" option, default "warn"
  - **Tests Updated**: All tests expecting blocking behavior updated to expect redaction

### Fixed

- **Ignore Files Patterns with Leading `**/` Don't Work** (Issue #232)
  - **Root Cause**: Three different implementations of `ignore_files` pattern matching existed with inconsistent behavior:
    - Secret Scanning (`__init__.py`) - ✅ WORKED - Used custom `_match_leading_doublestar_pattern()` helper
    - Prompt Injection (`prompt_injection.py`) - ❌ BROKEN - Only used `Path.match()` which doesn't properly handle leading `**/`
    - Config Scanner (`config_scanner.py`) - ❌ BROKEN - Used `fnmatch.fnmatch()` which doesn't support `**/`
  - **Fix**: Extracted `_match_leading_doublestar_pattern()` to `src/ai_guardian/utils/path_matching.py` module and updated all three implementations to use it consistently
  - **Impact**: All detectors now properly support leading `**/` patterns for ignoring files in subdirectories
  - **Files Modified**:
    - `src/ai_guardian/utils/path_matching.py`: Created new utility module with `match_leading_doublestar_pattern()` and `match_ignore_pattern()` functions
    - `src/ai_guardian/__init__.py`: Updated to import and use utility function
    - `src/ai_guardian/prompt_injection.py`: Updated `_is_file_ignored()` to use utility function
    - `src/ai_guardian/config_scanner.py`: Updated `_should_ignore_file()` to use utility function
  - **Tests Added**: 
    - `tests/test_unicode_attacks.py::UnicodeDetectorIgnoreFilesTest` - 2 tests for unicode detection ignore patterns
    - `tests/test_config_scanner.py::TestConfigFileScanner::test_ignore_files_leading_double_star_patterns` - 1 test for config scanner

- **Config File Scanner File Path Extraction Bug** (Issue #228)
  - **Problem**: Config File Scanner failed to extract file path from PreToolUse hook data when using the Read tool, allowing malicious config files (CLAUDE.md, AGENTS.md, etc.) to pass through unscanned and potentially exfiltrate credentials
  - **Root Cause**: `extract_file_content_from_tool()` function only checked `tool_use.parameters.file_path` format, but Claude Code actually sends `tool_use.input.file_path`, causing file path extraction to fail with "Could not extract file path from hook data" error
  - **Fix**: Added support for `tool_use.input.file_path` format in file path extraction logic to match Claude Code's actual hook data structure
  - **Impact**: Config File Scanner now properly scans config files for exfiltration patterns (`env | curl`, AWS S3 uploads, etc.) when read via PreToolUse hooks, protecting against persistent credential theft attacks
  - **Affected Versions**: v1.3.0, v1.4.0, v1.4.1, v1.5.0-dev (bug present since Config File Scanner was added in v1.3.0)
  - **Test Added**: 1 new regression test verifying file path extraction from `tool_use.input` format (`tests/test_ai_guardian.py::test_pretooluse_hook_with_tool_use_input_format`)
  - **Files Modified**:
    - `src/ai_guardian/__init__.py`: Added `tool_use.input.file_path` check in `extract_file_content_from_tool()`
    - `tests/test_ai_guardian.py`: Added regression test with actual Claude Code hook format

- **PreToolUse Hook Auto-Approve Bug** (Issue #224)
  - **Problem**: PreToolUse hook was auto-approving all Edit and Write operations when no secrets were detected, bypassing Claude Code's normal permission prompts and removing user control over file modifications
  - **Root Cause**: `format_response()` function returned `permissionDecision: allow` for clean files, which instructed Claude Code to auto-approve the operation
  - **Fix**: PreToolUse now only returns `permissionDecision` when denying operations (secrets/threats detected). For clean operations, returns empty response to allow Claude Code's normal permission system to prompt the user
  - **Impact**: Users now properly see permission prompts for Edit/Write operations, maintaining informed consent for file modifications
  - **Affected Versions**: v1.3.0, v1.4.0, v1.4.1 (bug introduced with GitHub Copilot integration in v1.3.0)
  - **Tests Added**: 
    - **Unit Tests**: 4 new PreToolUse permission tests covering Edit/Write operations for both Claude Code and GitHub Copilot IDE types (`tests/test_hook_processing.py`)
    - **Integration Tests**: 6 new end-to-end tests verifying no auto-approve behavior (`tests/test_pretooluse_no_auto_approve.py`):
      - Edit operations (Claude Code and GitHub Copilot)
      - Write operations (Claude Code and GitHub Copilot)
      - Verification that secrets still trigger deny (no regression)
      - End-to-end workflow showing user sees permission prompts
    - **User Experience Contract Tests**: 5 new tests documenting expected UX (`tests/test_user_experience_contract.py`):
      - Read with secret → Immediate denial (no prompt shown)
      - Edit without secret → Permission prompt shown
      - Comparison test showing different UX for secret vs clean operations
      - Documentation test describing expected behavior for users
      - Manual verification guide for testing in actual Claude Code IDE
    - Updated 3 existing tests to expect correct behavior (no auto-approve)
  - **Files Modified**:
    - `src/ai_guardian/__init__.py`: Updated `format_response()` for both GITHUB_COPILOT and CLAUDE_CODE paths
    - `tests/test_hook_processing.py`: Added `PreToolUsePermissionTests` class with 4 unit tests
    - `tests/test_pretooluse_no_auto_approve.py`: Added 6 integration tests (NEW FILE)
    - `tests/test_ai_guardian.py`: Updated 3 tests to expect correct behavior

### Added


### Added

- **Local File Path Support in Remote Configurations** (Issue #223)
  - **Feature**: `remote_configs` now supports local file paths in addition to HTTPS URLs
  - **Supported Formats**:
    - `file://` URLs: `file:///etc/ai-guardian/config.toml`
    - Absolute paths: `/etc/ai-guardian/config.toml`
    - Tilde expansion: `~/team-configs/allowed-tools.toml`
  - **Caching Behavior**:
    - HTTPS URLs: Cached with TTL (default: 12h refresh, 168h expiration)
    - Local files: Always read fresh (bypass cache for immediate updates)
  - **Use Cases**:
    - Development/Testing: Test configs locally without HTTPS server
    - Air-Gapped Environments: Offline systems without internet access
    - Corporate Networks: Shared network drives (NFS, SMB)
    - CI/CD Pipelines: Build environments with local config files
    - Team Configuration: Shared configs in home directories
  - **Security**:
    - Path traversal prevention with `Path.resolve(strict=True)`
    - File type validation (regular files only)
    - Permission checks before reading
    - Symlinks followed safely with warnings
  - **Implementation**:
    - New `RemoteFetcher._fetch_from_local_file()` method
    - Updated `fetch_config()` to bypass caching for local paths
    - Both JSON and TOML formats supported
  - **Tests Added**:
    - **Unit Tests** (`tests/test_remote_fetcher_local.py`): 27 passing tests
      - file:// URLs, absolute paths, tilde expansion
      - JSON/TOML format support
      - Error handling (missing files, permission denied, invalid format)
      - Symlink following and broken symlinks
      - No-caching behavior verification
      - Edge cases (spaces in paths, special characters, UTF-8)
    - **Integration Tests** (`tests/test_integration_local_remote_configs.py`): 10 passing tests
      - Multiple local sources, cache isolation
      - Mixed local and HTTPS URLs
      - File updates reflected immediately
      - Concurrent updates, error recovery
  - **Documentation**:
    - README.md updated with local file path examples and use cases
    - Security features documented
  - **Files Modified**:
    - `src/ai_guardian/remote_fetcher.py`: Added local file path support
    - `README.md`: Added "Local File Paths" section under "Remote Configs vs Directory Discovery"


- **Integration and Use-Case Tests with Mock MCP Server** (Issue #220)
  - **Comprehensive test infrastructure** for MCP tool security testing
  - **Test Fixtures**:
    - `tests/fixtures/mock_mcp_server.py`: Simulates NotebookLM and other MCP tools with controllable responses
    - `tests/fixtures/attack_constants.py`: Comprehensive attack patterns (SSRF, secrets, prompt injection, exfiltration)
    - `tests/conftest.py`: Pytest fixtures for test isolation using `AI_GUARDIAN_CONFIG_DIR`
  - **Integration Tests** (`tests/test_integration_mcp.py`): 24 passing tests
    - MCP Tool Permission Tests (6 tests): Allowlists, blocklists, wildcards, custom servers
    - Secret Scanning Tests (4 tests): Secrets in notebook titles/sources, multiple secret types, false positives
    - Prompt Injection Tests (4 tests): Injection in parameters, role-switching, delimiter escapes
    - SSRF Protection Tests (5 tests): AWS/GCP metadata, private IPs, public URLs, Bash-specific behavior
    - Config Exfiltration Tests (3 tests): Curl exfiltration, credential theft in CLAUDE.md/AGENTS.md
    - Combined Protection Tests (2 tests): Multiple protections working together, defense in depth
  - **PostToolUse Tests** (`tests/test_posttooluse_mcp.py`): 13 passing tests
    - Secret Scanning (5 tests): Bash/Read output with secrets, Write/Edit skipped, clean outputs
    - Content Scanning (3 tests): Documents that PostToolUse only scans secrets, not prompt injection
    - MCP Tool Tests (3 tests): MCP responses, notebook lists, current scanning behavior
    - Redaction Tests (1 test): Secret redaction mode behavior
    - Combined Tests (1 test): Multiple threats in output
  - **Use-Case Tests** (`tests/test_use_cases.py`): 13 passing tests covering realistic scenarios
    - Data Exfiltration Attack (3 tests): Multi-stage attack attempts via Bash, NotebookLM, SSRF
    - Prompt Injection Chain (2 tests): Attempts to disable protections, privilege escalation prevention
    - Legitimate Workflow (2 tests): Normal NotebookLM usage, security code discussion
    - Enterprise Policy (2 tests): Approved MCP servers only, paranoid mode (all MCP blocked)
    - Multi-Stage Attack (2 tests): Combined injection + exfiltration, privilege escalation
    - Real-World Scenarios (2 tests): Developer workflows, documentation discussions
  - **Test Isolation**: All tests run in isolated temporary directories via `isolated_config_dir` fixture
  - **Benefits**:
    - ✅ Validates protections work with real MCP tool calls
    - ✅ Catches integration issues between protection layers
    - ✅ Serves as usage examples for MCP security
    - ✅ Prevents regression in multi-protection scenarios
    - ✅ Documents actual implementation behavior (SSRF only on Bash, PostToolUse only scans secrets)
    - ✅ Tests realistic attack chains and defense-in-depth
    - ✅ Validates enterprise policy enforcement
    - ✅ Ensures legitimate workflows work without false positives
  - **Hook Processing Tests** (`tests/test_hook_processing.py`): 8 passing tests
    - Hook Input Parsing (4 tests): Valid JSON, UserPromptSubmit, PreToolUse, PostToolUse
    - Tool Response Extraction (4 tests): Bash output, Read content, MCP tools, Write/Edit skipped
  - **Advanced Tool Policy Tests** (`tests/test_tool_policy_advanced.py`): 11 passing tests
    - Rule Matching (2 tests): Wildcard patterns, case sensitivity
    - Rule Ordering (2 tests): First-match wins, default behavior
    - Config Variations (4 tests): Disabled permissions, empty rules, no config, invalid rules
    - Edge Cases (3 tests): Empty tool name, null tool name, missing field
  - **End-to-End Workflow Tests** (`tests/test_e2e_workflow.py`): 5 passing tests
    - Legitimate Workflows (3 tests): NotebookLM, Bash, Read→Write workflows
    - Secret Detection (1 test): Secret caught at PostToolUse stage
    - Multi-Tool Sequence (1 test): Multiple tools in realistic workflow
  - **74 new integration and use-case tests** covering all 9 protection layers with MCP tools
  - **Test Coverage**: Core protection modules at 70% (excluding TUI/setup: 4,500 statements, 1,359 missing)
  - Part of ongoing MCP security validation effort

- **Pattern Server Support for Security Features** (Issue #206, Epic #186)
  - **OPTIONAL/ADVANCED**: Enterprise pattern server integration for centralized pattern management
  - **Three-tier pattern system**: Immutable core + Pattern server/defaults + Local config additions
  - **Multiple pattern types**: SSRF, Unicode, Config Scanner, Secret Redaction
  - **Fallback chain**: Pattern server → cache → hardcoded defaults (always available)
  - **Features**:
    - `PatternServerClient` extended for multiple pattern types (ssrf, unicode, config-exfil, secrets)
    - New `PatternLoader` base class with feature-specific implementations
    - TOML pattern file format with native comment support
    - Source attribution tracking (IMMUTABLE, SERVER, DEFAULT, LOCAL_CONFIG)
    - Pattern server configuration in JSON schema for all four features
    - Maintains 100% backward compatibility (works without pattern server)
  - **Secret Redaction** (highest value): New secret formats deployed in <24h
    - Override modes: `replace` (server replaces defaults) or `extend` (adds to defaults)  
    - 35+ secret types enterprise-manageable
  - **SSRF Protection** (second priority): RFC 1918 ranges overridable via pattern server
    - Immutable: Cloud metadata endpoints, dangerous URL schemes
    - Overridable: Private IP ranges (enables Docker access for dev teams)
  - **Unicode Detection**: Homoglyph patterns updateable as new scripts emerge
    - Immutable: Zero-width chars, bidi overrides (Unicode spec-based)
    - Overridable: 80+ homoglyph pairs managed via pattern server
  - **Config Scanner**: Enterprise-specific exfiltration patterns
    - Immutable: Core patterns (env|curl, AWS S3, GCP storage)
    - Overridable: Additional pattern server patterns
  - **Implementation**: 6 new files, 4 feature integrations, schema updates
  - **Documentation**: Implementation plan, example patterns (future)
  - **Testing**: Backward compatibility verified, pattern server optional

- **Phase 5: Integration & Polish - CI/CD and Static Analysis** (Issue #198)
  - **New `scan` Command** for static repository scanning
    - Scans files statically without running as a hook
    - Integrates all Phase 1-4 security checks (SSRF, Unicode, Config Scanner, Secret Detection)
    - File discovery with glob patterns: `--include "*.md"`, `--exclude "node_modules/*"`
    - Config-only mode: `--config-only` to scan only AI configuration files
    - Multiple output formats: text (default), JSON (`--json-output`), SARIF (`--sarif-output`)
    - CI/CD ready: `--exit-code` flag exits with code 1 if issues found
    - Usage: `ai-guardian scan . --sarif-output results.sarif --exit-code`
  - **SARIF 2.1.0 Output Format** for CI/CD integration
    - Industry-standard Static Analysis Results Interchange Format
    - GitHub Code Scanning integration: findings appear in Security tab and PR reviews
    - GitLab Security Dashboard support
    - 5 rule definitions: SSRF-001, UNICODE-001, CONFIG-001, SECRET-001, PROMPT-INJECTION-001
    - Complete metadata: file locations, line numbers, code snippets, severity levels
    - Upload to GitHub: `github/codeql-action/upload-sarif@v3`
  - **Pre-commit Hook Templates** for git workflow integration
    - Git hook template: `templates/pre-commit.sh` for direct git integration
    - pre-commit framework template: `templates/.pre-commit-config.yaml`
    - **Safe, non-invasive approach**: `ai-guardian setup --pre-commit` provides templates and instructions WITHOUT auto-installing
    - Detects existing hooks and warns to prevent conflicts with company/team hooks
    - Shows manual integration steps with copy-paste commands
    - Provides snippet for adding to existing pre-commit configurations
    - Scans staged files before commit, blocks commit if issues found
    - Skip with: `git commit --no-verify` (not recommended)
  - **Performance Benchmark Suite** (tests/benchmark_phases.py)
    - Validates all Phase 1-4 features meet performance targets
    - SSRF check: <1ms per URL (measured: ~0.016ms ✅)
    - Unicode detection: <5ms per check
    - Config file scanning: <10ms per file
    - Secret redaction: <5ms per 10KB output
    - Total overhead: <20ms for all features combined
    - Run with: `pytest tests/benchmark_phases.py -v -m benchmark`
  - **Hermes Payload Validation Suite** (tests/test_hermes_payloads.py)
    - Validates 10/10 Hermes Security Framework payloads
    - Phase 1 (SSRF): 2/2 payloads - metadata endpoint, private IP
    - Phase 2 (Unicode): 3/3 payloads - zero-width, bidi override, homoglyphs
    - Phase 3 (Config): 3/3 payloads - env|curl, base64 exfil, AWS S3 upload
    - Phase 4 (Secrets): 2/2 payloads - GitHub tokens, AWS keys
    - Meta-tests: Coverage comparison showing AI Guardian exceeds Hermes framework
    - Run with: `pytest tests/test_hermes_payloads.py -v -m hermes`
  - **GitHub Actions Workflow Example**
    - Ready-to-use workflow for security scanning in CI
    - Automated SARIF upload to GitHub Code Scanning
    - Findings visible in Security tab and PR reviews
  - **Complete documentation updates**
    - Scan command examples in README
    - SARIF output integration guide
    - Pre-commit hook setup instructions
    - Performance benchmarks and targets
  - **Production-ready features**:
    - ✅ Runtime protection (hooks)
    - ✅ Static analysis (scan command)  
    - ✅ CI/CD integration (SARIF output)
    - ✅ Developer workflow (pre-commit hooks)
    - ✅ Performance validated (<20ms overhead)
    - ✅ Hermes framework validated (10/10 payloads)
  - Part of Hermes Security Patterns integration epic (Issue #186)
- **Secret Redaction for Tool Outputs** (Issue #197, Phase 4: Hermes Security Patterns)
  - Redacts secrets from tool outputs instead of blocking them entirely, enabling work to continue while protecting credentials
  - **Defense-in-depth**: Redaction provides a safety net when secrets are unavoidable, complementing existing blocking mechanisms
  - **35+ secret types detected and redacted**:
    - API keys: OpenAI (sk-proj-*), GitHub (ghp_*, gho_*, ghr_*, ghs_*), Anthropic (sk-ant-*), GitLab (glpat-*), Google (AIza*), npm, PyPI
    - Cloud provider keys: AWS (AKIA*, aws_secret_access_key), Azure client secrets, Google OAuth tokens
    - Payment/SaaS: Stripe (sk_live_*, pk_live_*), Twilio (SK*), SendGrid (SG.*), Mailgun (key-*), Slack (xox*)
    - Private keys: RSA, SSH, PGP (full redaction for maximum security)
    - Structured formats: Environment variables, JSON fields, HTTP headers, database connection strings
    - Generic patterns: Long hex strings, Base64 encoded secrets
  - **Multiple masking strategies**:
    - `preserve_prefix_suffix`: Keep first 6 + last 4 characters for debugging (e.g., "sk-pro...1vwx")
    - `full_redact`: Complete replacement with "[HIDDEN TYPE]" for high-sensitivity secrets
    - `env_assignment`: Preserve variable name (e.g., "AWS_SECRET_KEY=[HIDDEN]")
    - `json_field`: Preserve JSON structure (e.g., '{"api_key": "[HIDDEN]"}')
    - `connection_string`: Preserve endpoint info (e.g., "mongodb://user:[HIDDEN]@host:port/db")
  - **Configuration** (`secret_redaction` section):
    - `enabled`: Toggle redaction feature (default: true)
    - `action`: "log-only" (redact silently), "warn" (redact with user warning), "block" (original blocking behavior, default: log-only)
    - `preserve_format`: Enable prefix/suffix preservation (default: true)
    - `log_redactions`: Log all redaction events (default: true)
    - `additional_patterns`: Add custom secret patterns with regex
  - **Real-world scenarios enabled**:
    - ✅ Environment variable debugging: See `AWS_REGION=us-east-1` while `AWS_SECRET_KEY=[HIDDEN]`
    - ✅ Log file analysis: Review 10,000 log lines with buried secrets redacted inline
    - ✅ Config file review: See structure (`host: prod-db.example.com`) with passwords hidden
    - ✅ Git history analysis: View commits with accidentally-committed secrets redacted
  - **Integration**: Works automatically with PostToolUse hook, requires no changes to existing workflows
  - **Performance**: <5ms overhead per tool output (sub-50ms for 10KB text with 35+ patterns)
  - **Logging**: All redactions logged to violation logger with type, position, and count metadata
  - **Testing**: 28 comprehensive test cases covering all secret types, masking strategies, and edge cases
  - Part of Hermes Security Patterns integration (defense-in-depth approach)

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
- **Clarified zero-configuration installation in README** (Issue #216)
  - Quick Start section now emphasizes that ai-guardian works immediately after installing gitleaks with zero configuration required
  - Added "Default Behavior (No Configuration File)" section showing which features are enabled by default
  - Added minimal configuration example showing that only specific restrictions need to be configured
  - Reorganized Quick Start to clearly separate zero-config installation from optional advanced configuration
  - Makes it clearer that configuration is only needed for tool/skill restrictions, directory rules, custom patterns, or log-only mode
  - All core protections (secret scanning, prompt injection, SSRF, config file scanning, immutable file protection) work out-of-the-box

### Fixed
- **Setup command now generates complete configuration with violation_logging section** (Issue #214)
  - Fixed missing `violation_logging` section in `ai-guardian setup --create-config` output
  - Added `violation_logging` property to JSON schema with proper validation
  - Users can now discover and configure violation logging from generated config files
  - Includes all log types: tool_permission, directory_blocking, secret_detected, secret_redaction, prompt_injection
  - Improves discoverability of violation logging feature (available since v1.1.0)
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
