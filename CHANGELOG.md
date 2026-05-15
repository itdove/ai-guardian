# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Document deny-by-default for MCP servers and Skills** (Issue #606)
  - README: added prominent callout after Quick Start explaining MCP/Skills are blocked by default
  - README: updated Default Behavior table to distinguish built-in tools (allowed) from MCP/Skills (blocked)
  - TOOL_POLICY.md: added "Default Security Posture" section with rationale table
  - Error message for "no permission rule" now explains deny-by-default policy instead of "matches a denied pattern"

### Added

- **`init-project` command with language auto-discovery** (Issue #608)
  - New CLI command: `ai-guardian init-project` detects programming languages and generates project-level prompt injection allowlist
  - Pattern-aware: tests language identifiers against live detection patterns, only generates entries that actually trigger false positives
  - Supports 15 languages: Python, JavaScript, TypeScript, HTML, PHP, Ruby, C/C++, Go, Rust, Java, Kotlin, Swift, Scala, CSS, Shell
  - Python projects: generates allowlist for `__init__`, `__class__`, `__import__`, `__globals__`, `__builtins__`, `__mro__`, `__subclasses__`
  - HTML projects: generates `ignore_files` globs instead of allowlisting XSS-triggering patterns (safer)
  - Options: `--dry-run` (preview), `--force` (overwrite with backup), `--json` (machine-readable), `--dir` (specify project path)

- **Project-level ai-guardian.json config overlay** (Issue #594)
  - Place `.ai-guardian/ai-guardian.json` at repo root to tune scanning rules per-project
  - Deep merge: project config overlays global config (project wins for non-locked fields)
  - `immutable` in global config sections prevents project override (`true` locks entire section, array locks specific fields)
  - Global-only sections (daemon, mcp_server, support, etc.) cannot be overridden by project
  - Self-protection: agent blocked from reading project-level config (existing IMMUTABLE_DENY_PATTERNS)
  - Console: scope toggle (Global/Project) in Settings and Config Editor panels
  - Doctor: new `check_project_config` check reports active project config
  - MCP: `get_config()` reports `project_config` path when active
  - New utilities: `get_project_config_path()`, `deep_merge()`, `GLOBAL_ONLY_SECTIONS`
  - Discovery: `AI_GUARDIAN_PROJECT_CONFIG` env var → git root → CWD

- **Console MCP Security panel shows IDE config file source** (Issue #604)
  - Each MCP server now shows which IDE config file(s) it was found in
  - Multiple IDE configs shown when a server appears in more than one (e.g., Claude + Cursor)
  - IDE labels: Claude, Cursor, Windsurf, Codex
  - Added Windsurf (`~/.windsurf/mcp.json`) and Codex (`codex.json`) config discovery
  - CLI verbose mode (`ai-guardian mcp list -v`) also shows labeled sources

- **MCP server security scanning** (Issue #468)
  - `ai-guardian mcp list` — list MCP servers with trust status
  - `ai-guardian mcp audit` — config audit for credential exposure, unpinned packages, npx auto-install, suspicious URLs
  - `ai-guardian mcp scan [server]` — deep source code scan for outbound HTTP, sensitive file reads, subprocess calls, base64 exfiltration, environment variable harvesting
  - Console panel "MCP Security" under Permissions group
  - Trust derived from `permissions.rules` — no separate config needed

- **Daemon session state persistence** (Issue #592)
  - Persist security injection tracking across daemon restarts
  - Write-behind with debounced writes (2-second delay) to avoid excessive I/O
  - Atomic file writes with secure permissions (0600) for crash safety
  - Auto-prune sessions older than 24 hours on load and persist
  - State file: `~/.local/state/ai-guardian/daemon_sessions.json`
  - Flush pending state on daemon shutdown for clean exit

### Fixed

- **Bug: GNOME system tray icon not visible after AppIndicator extension install** (Issue #602)
  - pystray `setup=` callback prevents icon from appearing on newer GNOME/GTK
  - Replace with timer-based stderr restore so icon displays correctly

- **Bug: Console startup prints MCP permission check messages to terminal** (Issue #600)
  - Suppress stderr logging (INFO/DEBUG) when running `ai-guardian console` or `ai-guardian tui`
  - File logging remains at full verbosity for debugging
  - MCP permission check results still available in Console MCP panel

- **Bug: unlisted MCP servers always blocked** (Issue #595, AAP-75435)
  - Switch permission rules to last-match-wins evaluation (consistent with directory_rules)
  - Rules evaluated in order: broad allow → category deny → specific allow
  - `mode: deny` supports `action: block|warn|log-only` (default: block)
  - New unlisted MCP servers warned instead of blocked with standard profile
  - Backward compatible: old `action` on `mode: allow` rules still works (deprecated)
  - Updated @minimal, @standard, @strict profile defaults
  - Updated default config templates with layered permission rules

### Changed

- **Performance**: Cache config file reads across `_load_*_config()` calls (Issue #569)
  - Single file read per hook invocation instead of 4-6 redundant reads
  - Uses mtime-based invalidation for automatic cache refresh
  - Refactored `_load_pattern_server_config()` to use shared `_load_config_file()` cache

## [1.7.0] - 2026-05-13

### Added

- **Daemon service architecture** (Issue #367, Phases 1-3)
  - Long-running daemon process for faster hook processing (~1-5ms vs ~50-100ms per-invocation)
  - Three modes: `"auto"` (default, daemon with local fallback), `"local"` (per-process, for CI/CD), `"daemon"` (require daemon, for testing/compliance)
  - Unix domain socket IPC on macOS/Linux, TCP localhost fallback on Windows
  - In-memory cross-hook state sharing between PreToolUse and PostToolUse via `tool_use_id`
  - Config auto-reload: mtime check per-request + periodic SHA256 checksum verification
  - Compiled regex pattern caching in memory (invalidated on config change)
  - Lazy daemon start: first hook call in `auto` mode starts daemon in background
  - Idle timeout auto-stop (default 30 minutes, configurable)
  - CLI commands: `ai-guardian daemon start|stop|status|restart`
  - System tray icon with status indicator and Pause/Resume menu (pystray + Pillow included as dependencies)
  - Graceful shutdown on SIGTERM/SIGINT with socket/PID file cleanup
  - New config section: `daemon` with `mode`, `idle_timeout_minutes`, `client_timeout_seconds`, `tray.enabled`
  - Environment variable override: `AI_GUARDIAN_DAEMON_MODE=local` for CI/CD
  - Extracted `process_hook_data()` for direct dict-based hook processing (daemon and direct mode)

- **MCP security advisor server** (Issue #477)
  - MCP server with 12 read-only security tools for AI agents via stdio transport
  - Security check tools: `check_path`, `check_command`, `check_mcp_trust`, `sanitize_text`, `check_annotations`
  - Information tools: `get_violations`, `get_config`, `get_scanner_status`, `get_scanner_supported`, `get_patterns_list`, `get_metrics`, `doctor`
  - 3 MCP resources: `security-posture`, `protected-paths`, `recent-violations`
  - Security-limited responses: yes/no answers only, no rule/pattern/allowlist exposure
  - Runtime enable/disable via config flag (no IDE restart needed)
  - CLI: `ai-guardian mcp-server` (start), `ai-guardian mcp enable/disable/status` (toggle)
  - Setup: `ai-guardian setup --mcp` / `--no-mcp` (opt-in, installs MCP config + skill)
  - Tray menu MCP toggle
  - Console MCP enable/disable button
  - AI security awareness skill (`ai-guardian-security`) teaches AI when to use each tool
  - Support bundle export: `prepare_support_bundle` + `send_support_bundle` (sanitized diagnostics with user approval)
  - New dependency: `mcp>=1.8.0` (Python >=3.10 only, MIT license)

- **Security instruction injection via systemMessage** (Issue #580)
  - Injects never-bypass security rules into AI context on every UserPromptSubmit hook
  - Uses generic language — does not name specific bypass mechanisms or config files
  - Configurable via `security_instructions.inject_on_prompt` (default: enabled)
  - Supports time-based disabling for temporary development work
  - Updated SKILL.md and MCP server to remove specific bypass mechanism names

- **Self-Protection: Block Agent Read Access** (Issue #512)
  - Read tool blocked for all ai-guardian config, state, and cache files
  - Bash cat/grep/head/tail/less/more blocked for same files
  - PowerShell Get-Content/Select-String blocked for same files
  - Immutable — cannot be overridden by user config
  - MCP server remains the approved way for agent to query security data
  - Doctor check (`check_self_protection`) verifies read protection is active

- **Multi-engine execution strategies** (Issue #250, Phase 3)
  - Execution strategy support: `first-match` (default), `any-match` (block if ANY engine finds secrets), `consensus` (block only if N engines agree)
  - Parallel engine execution via ThreadPoolExecutor for `any-match` and `consensus` strategies
  - Smart deduplication across engines (prefers verified secrets, highest confidence)
  - Per-engine configuration: `ignore_files`, `pattern_server`, `file_patterns`
  - File type routing: route different file types to specialized engines (e.g., `.env` → TruffleHog, `.py` → Gitleaks)
  - Structured scan metrics logging (engine, duration, findings count)
  - New `run_single_engine()` executor for reusable single-engine subprocess execution
  - New `select_all_engines()` for multi-engine strategies
  - Console "Engine Configuration" panel with JSON editor for engines and strategy dropdown
  - 30 new tests (92% coverage for scanners module)

- **Result caching and incremental scanning** (Issue #250, Phase 3)
  - `ScanResultCache`: File-based cache for scan results keyed by content hash + engine type + config hash
  - Configurable TTL (`cache_ttl_hours`, default 24h) with automatic expiry
  - `FileStateTracker`: Track file states for incremental scanning — skip unchanged files
  - Cache integrates transparently with `run_single_engine()` and all execution strategies
  - Config: `"cache_results": true, "cache_ttl_hours": 24, "incremental": true`

- **Secretlint integration** (Issue #250, Phase 3)
  - New `secretlint` engine preset (MIT license, Node.js-based, plugin architecture)
  - `SecretlintOutputParser` for JSON output (array and newline-delimited formats)
  - Rule ID normalization (extracts short name from `@secretlint/secretlint-rule-*` chains)
  - Install: `npm install -g @secretlint/secretlint-rule-preset-recommend`

- **GitGuardian integration** (Issue #250, Phase 3)
  - New `gitguardian` engine preset (ggshield CLI, 350+ secret types)
  - `GitGuardianOutputParser` with verified secret support (`validity: "valid_data"`)
  - Consent mechanism for cloud engines: `ai-guardian engine consent gitguardian`
  - API key validation via `GITGUARDIAN_API_KEY` environment variable
  - Cloud service warning in Console and documentation
  - License: Proprietary (free tier for individuals)

- **Enterprise features** (Issue #250, Phase 3)
  - Remote engine configuration: fetch engine config from remote URL with caching
  - Merge strategies: remote engines prepended to local (or replace with `immutable: true`)
  - Audit logging: JSONL at `~/.local/state/ai-guardian/scan-audit.jsonl`
  - Compliance reporting: generate reports for HIPAA, PCI-DSS, SOC2 frameworks
  - Export audit data for external audits

- **Per-engine pattern_server config in scanning flow** (Issue #519)
  - Engines can now override the global pattern server via per-engine `pattern_server` config
  - `pattern_server: null` disables patterns for that engine (uses built-in rules)
  - `pattern_server: { url: "..." }` fetches engine-specific patterns from a dedicated server
  - No override (key absent) uses the global pattern server (backward compatible)
  - Added `resolve_engine_config_path()` helper centralizing config_path resolution logic
  - Execution strategies (first-match, any-match, consensus) now resolve config_path per-engine
  - Replaces inline engine-type filtering in `__init__.py` with centralized resolver

- **Directory Scanning MCP Tools** (Issue #544)
  - `scan_directory` tool returns violation summary (counts and types only — no file paths or secret values)
  - `scan_directory_report` tool generates detailed report in temp directory for user review
  - Two-step flow: AI sees summary only, user reviews detailed report directly
  - Path validation blocks system directories
  - Supports JSON and SARIF output formats

- **Engine Tester** (Issue #542)
  - CLI command `ai-guardian engine-test` to test strings against individual scanner engines
  - Flags: `--engine NAME`, `--all`, `--compare`, `--pattern-server`, `--json`
  - Console panel under Tools for interactive engine testing with comparison view
  - Side-by-side engine comparison shows which engines detect a secret and which miss it

- **Security profile templates** (Issue #466)
  - Built-in profiles: `@minimal` (personal, low friction), `@standard` (team, moderate), `@strict` (enterprise SOC2/compliance)
  - CLI: `ai-guardian setup --create-config --profile @strict`
  - Custom profiles: save with `--save-profile my-team`, stored in `~/.config/ai-guardian/profiles/`
  - List all profiles: `ai-guardian setup --list-profiles`
  - File path profiles: `--profile /path/to/profile.json`
  - `@standard` matches existing `--create-config` output (backward compatible)
  - `@strict`: fail-closed (`on_scan_error: block`), high sensitivity, audit logging, annotations disabled
  - `@minimal`: warn-only actions, low sensitivity, permissions disabled, reduced PII types

- **Inline and block annotation suppression** (Issue #481)
  - `ai-guardian:allow` on a line suppresses secrets and PII for that line
  - `ai-guardian:begin-allow` / `ai-guardian:end-allow` suppresses a block of lines
  - `gitleaks:allow` suppresses secrets only (default alias)
  - Configurable aliases: `inline_allow`, `inline_allow_secrets`, `block_begin`, `block_end`
  - User config extends defaults — add custom aliases without losing built-in ones
  - Pre-processing approach: suppressed lines blanked before any scanner runs
  - Suppresses secrets and PII detection (both blocking and redaction)
  - Prompt injection, jailbreak, and config exfil are always scanned (cannot be suppressed)
  - File content only (PreToolUse/beforeReadFile) — never applies to PostToolUse, prompts, or transcripts
  - Fail-safe: unmatched `begin-allow` without `end-allow` is ignored with a warning
  - Language-agnostic: searches for marker string anywhere on a line
  - Audit trail: suppressions logged via ViolationLogger (`annotation_suppressed` type)
  - Configurable: `annotations.enabled` (default: true) to disable for strict compliance
  - Detection messages include annotation hint showing available suppression markers
  - TUI: new Annotations panel under Threat Detection for managing aliases

- **Global `on_scan_error` configuration** (Issue #461)
  - New top-level `on_scan_error` config parameter: `"allow"` (default) or `"block"`
  - Controls fail-open/fail-closed behavior when scanners encounter errors
  - `"allow"`: Current behavior — log warning, allow operation (developer productivity)
  - `"block"`: Block operation if any scanner fails (strict compliance environments)
  - Applies to: tool policy, prompt injection, config scanning, secret scanning, transcript scanning
  - TUI shows new setting in Global Settings panel
  - Default is `"allow"` for backward compatibility

- **Cross-hook context passing** (Issue #366)
  - `HookContextManager` module (`hook_context.py`) for PreToolUse to PostToolUse correlation via `tool_use_id`
  - PostToolUse inherits `file_path` from PreToolUse context for violation entries
  - Skip double-scanning: PostToolUse skips secret scan when PreToolUse already scanned clean
  - `ignore_files` consistency: PostToolUse respects ignore decisions from PreToolUse
  - PII skip consistency: PostToolUse skips PII scan when PreToolUse skipped via `ignore_files`
  - Daemon mode: uses `DaemonState` in-memory store (zero I/O overhead)
  - Local mode: session-scoped temp file with secure `0600` permissions
  - TUI: correlation ID and hook event shown on violation cards
  - TUI: "Correlated" button shows the paired PreToolUse/PostToolUse violation
  - Fail-safe: if context unavailable, PostToolUse processes normally (no regression)

- **Support bundle CLI command** (Issue #511)
  - `ai-guardian support prepare` — create sanitized bundle in temp dir for review
  - `ai-guardian support send` — send prepared bundle to configured destination
  - `ai-guardian support status` — show export destination, auth, and pending bundles
  - Options: `--output PATH`, `--no-log`, `--no-violations`, `--json`, `--prepare`, `--yes`, `--bundle PATH`
  - One-shot mode: `ai-guardian support send --prepare --yes` for CI/automation
  - Shares underlying logic with MCP tools (`prepare_support_bundle`, `send_support_bundle`)
  - Cross-process support: bundle ref persisted to state dir so `prepare` and `send` work in separate terminals

- **GCS bucket support for support bundle export** (Issue #513)
  - `gs://bucket-name/prefix/` destination format supported in config
  - Auto-detects Google Application Default Credentials (Vertex AI or `gcloud auth application-default login`)
  - Falls back to `gcloud auth print-access-token` CLI
  - No additional dependencies required (uses GCS REST API directly)

- **Project-level .aiguardignore.toml** (Issue #497)
  - Per-project `ignore_files` via `.aiguardignore.toml` in project root
  - Global `[allowlist]` paths apply to all scanners
  - Per-scanner sections: `[secret_scanning]`, `[scan_pii]`, `[prompt_injection]`, `[config_file_scanning]`
  - Consistent with `.gitleaks.toml` allowlist structure
  - Merged with JSON config `ignore_files` (both sources apply)
  - Cached with mtime-based invalidation for performance

- **Project .gitleaks.toml allowlist support** (Issue #488)
  - ai-guardian reads `.gitleaks.toml` from the project root and applies its allowlist rules
  - Works with all scanner engines (gitleaks, betterleaks, leaktk, etc.)
  - Supports global allowlists: `paths`, `regexes`, `stopwords`
  - Supports per-rule allowlists via `[[rules]]` sections
  - Path-based early skip (before scanning) and finding-level post-scan filtering
  - Cached with mtime-based invalidation for performance
  - Does not conflict with ai-guardian's own `allowlist_patterns` config

- **Health Check (Doctor) panel in Console** (Issue #502)
  - New panel under Tools section displaying all `ai-guardian doctor` checks
  - Color-coded pass/warn/fail/skip indicators with expandable details
  - Auto-refresh on navigation, manual refresh button
  - Fix Issues button with confirmation dialog for auto-fixable problems
  - Reuses existing Doctor class — same checks as the CLI

- **Pattern server doctor checks** (Issue #493)
  - `ai-guardian doctor` now checks pattern server cache path writability
  - Checks auth token availability (env var or token file)
  - Checks pattern server URL reachability (with `--check-connectivity`)
  - Checks cache freshness against configured refresh/expiry thresholds
  - Each failure includes actionable fix instructions

- **Tray menu status submenu with stats** (Issue #508)
  - Main menu header shows "● AI Guardian — Running/Paused" with status submenu
  - Submenu displays: Requests, Blocked (with percentage), Warned, Logged counts
  - Violations grouped by severity: Critical (blocked) and Warning (warned)
  - Last block type and time-ago display (e.g., "secret_detected 2m ago")
  - All stats from daemon in-memory counters (fast, no file I/O)
  - Numbers formatted with commas for readability
  - No subjective labels — numbers only

- **Terminal emulator support for tray Console on Linux** (Issue #553)
  - Added `kgx` (GNOME Console, Fedora 44+ default) to the terminal fallback chain
  - `ai-guardian doctor` checks for a supported terminal emulator on Linux
  - Documentation: terminal emulator requirement listed in docs/CONSOLE.md

- **GNOME AppIndicator Detection** (Issue #552)
  - `ai-guardian doctor` detects GNOME without AppIndicator extension and shows fix command
  - Daemon logs warning when tray icon cannot start on GNOME (no longer silent)
  - Documentation: GNOME setup steps in docs/CONSOLE.md and README requirements

- **Action field dropdowns in Console Global Settings** (Issue #447)
  - Global Settings panel now shows action dropdowns (block/warn/log-only) for Prompt Injection, PII Detection, SSRF Protection, and Config File Scanning
  - Action changes auto-save to config and stay in sync between global settings and individual panels

- **Documentation: pre-commit hook** (Issue #467)
  - Added pre-commit hook entry to README features table
  - Created `docs/PRE_COMMIT.md` covering `ai-guardian setup --pre-commit`, direct git hook, and pre-commit framework installation methods
  - Updated `docs/README.md` index with new documentation link

- **Documentation: per-engine pattern server auth** (Issue #458)
  - Document that `AI_GUARDIAN_PATTERN_TOKEN` is the default env var for all pattern server sections
  - Document how to override `token_env` per section for multi-server setups
  - Document `token_file` as alternative to env var
  - Example config showing different tokens per pattern server
  - Updated `docs/PATTERN_SERVER.md`, `ai-guardian-example.json`, and `README.md`

### Changed

- **Security rules injected only on first prompt + after blocks** (Issue #584)
  - Previously injected `_SECURITY_SYSTEM_MESSAGE` via `systemMessage` on every `UserPromptSubmit`
  - Now injects only on the first prompt per session and re-injects after any block event
  - Adds `SessionStateManager` with dual-mode support: in-memory (daemon) and file-based (local)
  - Session state included in support bundle for diagnostics
  - Reduces token overhead in long conversations

- **Deprecate `secret_scanning.pattern_server` — migrate to per-engine** (Issue #530)
  - Global `secret_scanning.pattern_server` is deprecated (gitleaks-specific but implied all engines)
  - Per-engine format is now canonical: `engines[{"type": "gitleaks", "pattern_server": {...}}]`
  - Deprecation warning logged when global format detected
  - `ai-guardian doctor` warns about deprecated format (`check_global_pattern_server`)
  - `ai-guardian doctor --fix` auto-migrates to per-engine format
  - `ai-guardian setup --migrate-pattern-server` handles full migration chain (root → global → per-engine)
  - Enhanced per-engine `pattern_server` schema to match full global schema (auth, cache, immutable, etc.)
  - Example config updated to show per-engine pattern_server as the documented format
  - Legacy format still works (backward compatible); removal planned for v2.0.0

- **Quick Start updated with one-liner setup and profiles** (Issue #566)
  - Single command now includes `--create-config`, `--mcp`, and `--install-scanner`
  - Added security profile comparison table (@minimal, @standard, @strict)

- **Simplified README to ~230 lines** (Issue #454)
  - Moved detailed documentation to `docs/` folder with links
  - Created `docs/SECURITY_DESIGN.md` for self-protection architecture details
  - Created `docs/README.md` as documentation index
  - Added documentation guidelines to AGENTS.md (README ~300 line limit)
  - No information lost — all content accessible via docs/ links

- **Support bundle keeps original file names** (Issue #543)
  - `ai-guardian.json` no longer renamed to `config.json` in the bundle
  - `violations.jsonl` no longer renamed to `violations.json` in the bundle

### Removed

- **`mcp_server.enabled` config flag** (Issue #516)
  - MCP server presence is controlled by IDE config (`.claude/settings.json`), not ai-guardian config
  - Removed `enabled` property from schema, example config, setup defaults, and template profiles
  - Removed `_is_mcp_enabled`, `_disabled_check` decorator, and `DISABLED_RESPONSE` from MCP server
  - Removed `ai-guardian mcp enable/disable/status` CLI subcommands
  - Removed MCP enable/disable toggle from Console TUI and tray menu
  - `ai-guardian setup --mcp` / `--no-mcp` remains the install/uninstall mechanism

## [1.6.2] - 2026-05-11

### Fixed

- **Betterleaks JSON parse failure no longer treated as secret detected** (Issue #532)
  - When betterleaks returns malformed JSON output, the scanner now correctly reports "no secrets found" instead of treating the parse error as a secret detection
  - Prevents false-positive security blocks caused by scanner output parsing failures

## [1.6.1] - 2026-05-06

### Fixed

- **Console crashes on MCP Servers panel and Permissions Discovery panel** (Issue #446)
  - Fixed DuplicateIds crash when navigating to MCP Servers panel by removing fixed widget ID from empty-state Static and using CSS class selector instead
  - Fixed WrongType crash when navigating to Permissions Discovery panel by changing panel wrapper from VerticalScroll to Container, consistent with all other panels

- **Clipboard "Copied" notification shown incorrectly in Linux containers** (Issue #452)
  - Console no longer shows "Copied to clipboard" when the copy actually failed
  - `copy_to_clipboard()` now returns a boolean indicating success
  - `on_text_selected` checks the return value before showing the notification
  - Wrapped in try/except to handle IndexError/AttributeError from empty selections

- **Transcript scanner re-flags same content on every prompt** (Issue #462)
  - First scan of a new transcript now initializes position to current file size instead of scanning from byte 0
  - Initial transcript content (system context, tool responses) was already scanned by PreToolUse/PostToolUse hooks — rescanning caused duplicate PII/secret warnings that overshadowed real security events (e.g., jailbreak detection)
  - Truncated/compacted transcripts now skip to current end instead of rescanning from 0
  - Transcript scanning now only catches content from `!` shell commands (its intended purpose)

### Documentation

- **Simplified README to ~230 lines** (Issue #454)
  - Moved detailed documentation to `docs/` folder with links
  - Created `docs/SECURITY_DESIGN.md` for self-protection architecture details
  - Created `docs/README.md` as documentation index
  - No information lost — all content accessible via docs/ links

## [1.6.0] - 2026-05-04

### Changed

- **Renamed all TUI references to Console** (Issue #440)
  - `ai-guardian console` is now the primary documented command
  - `ai-guardian tui` remains as backward-compatible alias
  - Updated all user-facing text, help strings, error messages, and documentation
  - Renamed `docs/TUI.md` to `docs/CONSOLE.md`
  - Renamed GitHub `tui` label to `console`
  - Internal `src/ai_guardian/tui/` directory unchanged (no import breakage)

### Added

- **Sanitize Command** (Issue #443)
  - New `ai-guardian sanitize` command for redacting secrets, PII, and threats from text
  - Neutralizes: secrets, PII, prompt injection patterns, unicode attacks (zero-width chars, bidi overrides, tag chars, homoglyphs)
  - Reads from stdin or file, outputs only redacted text to stdout (pipe-safe)
  - Ignores user config — hardcoded maximum detection, no allowlists, no ignore patterns
  - Flags: `--no-secrets`, `--no-pii`, `--no-threats`, `--summary`, `--exit-code`
  - Designed for cleaning transcripts before sharing with other AI agents

- **OSC 52 terminal escape sequence as clipboard fallback** (Issue #433)
  - Added `wl-copy` support for Wayland environments
  - Added OSC 52 escape sequence as final fallback for containers/SSH/headless
  - Works in UBI 10 containers and SSH sessions without xclip/xsel
  - Fallback chain: xclip → xsel → wl-copy → OSC 52
  - Existing pbcopy (macOS) and clip (Windows) behavior unchanged
  - Extracted `_try_clipboard_command()` helper to reduce duplication

### Documentation

- **Warning about `!` shell command bypass** (Issue #431)
  - Added security note to README.md Known Limitations section
  - Added to AGENTS.md Common Issues section
  - Added top-level comment in ai-guardian-example.json
  - Added recommendation in Console Security Dashboard and help panel
  - `!` commands bypass all ai-guardian hooks; use regular commands instead
  - Transcript scanning (Issue #430) provides after-the-fact detection

### Security

- **Gitleaks exit code 1 treated as "no secrets found" — secrets bypass detection** (Issue #411)
  - Gitleaks exit code 1 (default for "secrets found") was incorrectly added to the success codes list, causing detected secrets to be silently allowed through
  - Now correctly treats exit code 1 as "secrets found" when `--exit-code 42` is specified
  - Added debug logging for scanner command and exit code to aid troubleshooting
  - Bug introduced in v1.4.0 (PR #154)

- **PostToolUse allowed secrets through when secret_redaction was disabled** (Issue #414)
  - When `secret_redaction.enabled = false`, detected secrets were allowed through as an "emergency bypass" instead of being blocked
  - PostToolUse now correctly blocks tool output containing secrets regardless of redaction settings

### Added

- **Transcript Scanning for Secrets, PII, and Prompt Injection** (Issue #430)
  - Incrementally scans conversation transcript on each `UserPromptSubmit` event
  - Detects threats that entered via `! command` shell mode (which bypasses hooks)
  - Scans for secrets (via gitleaks/engines), PII, and prompt injection patterns
  - Detection only: warns via `systemMessage` (cannot block — content already in AI context)
  - IDE-agnostic: supports Claude Code, Cursor, and GitHub Copilot transcript paths
  - New violation types: `secret_in_transcript`, `pii_in_transcript`, `prompt_injection_in_transcript`
  - Position tracking in `~/.local/state/ai-guardian/transcript_positions.json` prevents re-scanning
  - Configurable via `transcript_scanning.enabled` (default: `true`)
  - Performance: reads only new bytes since last scan via byte-offset tracking

- **Multi-Engine Scanner Support — TruffleHog and detect-secrets** (Issue #249)
  - **TruffleHog**: 700+ detectors with entropy analysis and verified secrets detection (`"engines": ["trufflehog"]`)
  - **detect-secrets**: Baseline workflow for CI/CD pipelines with plugin-based detection (`"engines": ["detect-secrets"]`)
  - **Execution Strategies**: `first-match` (default), `any-match` (maximum security), `consensus` (reduce false positives with threshold)
  - Smart deduplication when multiple engines find the same secret
  - License: TruffleHog is AGPL-3.0 (used via subprocess, no AGPL obligations); detect-secrets is Apache-2.0
  - Interactive license notice during `ai-guardian scanner install trufflehog`

- **PII Detection in Tool Outputs** (Issue #262)
  - GDPR/CCPA compliance: detect and redact PII across all three hooks (UserPromptSubmit, PreToolUse, PostToolUse)
  - 7 PII types: SSN, Credit Card (Luhn), US Phone, Email, US Passport, IBAN (mod-97), International Phone (E.164)
  - Top-level `scan_pii` config section with `enabled`, `pii_types`, `action`, `ignore_files`, and `allowlist_patterns`
  - Enabled by default; `action: "redact"` masks PII in PostToolUse, blocks in PreToolUse/UserPromptSubmit

- **Jailbreak Detection Patterns** (Issue #263)
  - 13 built-in patterns across 4 categories: role-play jailbreaks (DAN/sudo/god mode), identity manipulation, constraint removal, hypothetical framing
  - New `jailbreak_patterns` config key for user-defined patterns
  - Error messages distinguish "Jailbreak Attempt Detected" from "Prompt Injection Detected"
  - New `jailbreak_detected` violation logging type
  - Patterns only checked for user prompts (not file content) to minimize false positives

- **Enhanced Prompt Injection Detection — 24 new patterns** (Issue #285)
  - 15 CRITICAL patterns: fake completion, HTML comment injection, chain-of-thought exploitation, instruction replacement, auto-approval manipulation, and more
  - 8 DOCUMENTATION patterns: output format manipulation, workflow chaining, Base64 encoding, delimiter injection
  - Sources: PayloadsAllTheThings, Hermes Security Patterns, Open-Prompt-Injection (USENIX 2024), arXiv 2601.17548
  - All patterns maintain <1ms detection target

- **Allowlist patterns for scan_pii and secret_scanning** (Issue #357)
  - `allowlist_patterns` config option suppresses false positives for known-safe values (e.g., corporate email domains, test API key prefixes)
  - Supports simple string patterns and time-based patterns with expiration (`valid_until`)
  - ReDoS protection and dangerous catch-all pattern blocking
  - Console updated with allowlist pattern editing for both PII and secret scanning

- **Auto-Generate Directory Rules from Skill Permissions** (Issue #144)
  - Auto-generate directory access rules from skill permissions, eliminating duplicate configuration
  - Multi-IDE support: Claude Code, Cursor, VSCode/Copilot, Windsurf
  - Opt-in via `auto_directory_rules.enabled: true`
  - Rule order (last-match-wins): User rules → Generated rules → Immutable rules
  - Generated rules override broad user deny rules for specific permitted skill paths
  - `allow_symlinks` option (default: `true`) for container environments (Issue #324)
  - Plugin cache directory scanning for Claude Code plugins
  - New `ai-guardian config show` command with `--all`, `--section`, `--preview-auto-rules` flags
  - All rules visible with `[USER]`, `[GENERATED]`, `[IMMUTABLE]` labels

- **Hook Simulator panel in Console** (Issue #397)
  - Simulate UserPromptSubmit, PreToolUse, and PostToolUse hook events
  - Test detection rules without triggering real hooks
  - View BLOCKED/ALLOWED/WARNING decisions with detection details
  - IDE format selector (Claude Code, Cursor, GitHub Copilot)

- **JSON Config Editor in Console** (Issue #388, #391)
  - Raw JSON editor for `ai-guardian.json` with syntax highlighting and line numbers
  - Real-time JSON validation with schema validation warnings on save
  - Console Settings panel with theme selector (Monokai, VS Code Dark, Dracula, GitHub Light)
  - New `console` section in schema, setup defaults, and example config
  - New dependencies: `tree-sitter>=0.25.0` and `tree-sitter-json>=0.24.0` (MIT license)

- **Show default values in Console config panels from schema** (Issue #371)
  - Each config field shows its default value from the schema
  - Fields changed from default are highlighted with a yellow left-border
  - Applied to all 11 config panels

- **Copy-to-clipboard support in Console** (Issue #362)
  - Auto-copy on text selection (like Claude Code)
  - Copy button on Violation Details modal
  - Platform-native clipboard fallback for macOS Terminal.app, Linux, Windows (Issue #377)

- **Enriched violation log entries** (Issue #408)
  - `context_snippet`: redacted context around detection (for PII and secret violations)
  - `command`: Bash command that produced flagged output
  - `tool_use_id` and `session_id`: correlation IDs for matching PreToolUse/PostToolUse events

- **`ssrf_blocked` and `config_file_exfil` violation logging types** (Issue #322)
  - SSRF and config exfiltration violations now have dedicated log types instead of being misclassified as `tool_permission`
  - Console tabs and checkboxes for both new types
  - Backward compatible with existing configs

- **Scanner/Pattern-Server Discovery Commands** (Issue #320)
  - `ai-guardian scanner supported` — lists all supported scanners with versions, repos, and licenses
  - `ai-guardian pattern-servers supported` — lists all configured pattern servers
  - `--json` flag for `scanner list`, `scanner info`, `scanner supported`, and `pattern-servers supported`

- **`--json` flag for `setup --create-config`** (Issue #326)
  - Outputs raw JSON only, pipeable to `jq`
  - `$schema` field now uses `file://` URI pointing to bundled schema (works offline)

- **`ai-guardian tui` alias for `ai-guardian console`** (Issue #389)

- **`--yes`/`-y` flag for `violations --clear`** (Issue #360)
  - Skips confirmation prompt for non-interactive use (CI, Claude Code `!` prefix, piped scripts)

- **Dependabot and scanner version monitoring** (Issues #288, #289, #290, #291, #292, #293, #309)
  - Dependabot configuration for automated GitHub Actions and Python package updates (monthly, grouped PRs)
  - Daily scanner version health monitoring via CI (`scripts/check_scanner_versions.py`)
  - Scanner version existence pre-flight checks in CI (fail fast if versions missing)
  - Automated monthly prompt injection pattern research reminders
  - Comprehensive dependency management documentation in AGENTS.md

### Changed

- **Console: Replaced 'Directory Protection' panel with 'Directory Rules' panel** (Issue #426)
  - New panel manages `directory_rules` configuration (allow/deny path access control)
  - Moved from Configuration section to Permissions section in navigation

- **Console violations panel no longer auto-modifies config** (Issue #421)
  - Removed approve/deny action buttons; details modal now shows resolution instructions with copyable config snippets
  - Users must manually edit config via Console panels, JSON editor, or text editor

- **Enhanced error messages across all protection layers** (Issue #287)
  - Consistent `🛡️ [Protection Type]` format (replaced `🚨 BLOCKED BY POLICY`)
  - Shows exact regex pattern, confidence level, and sanitized matched text for prompt injection
  - Shows secret type and location for secret scanning (value NEVER shown)
  - Context-specific recommendations and config paths for all violation types

- **Remove email from default `scan_pii.pii_types` list** (Issue #370)
  - Email PII detection now opt-in (add `"email"` to `pii_types` to re-enable)
  - Existing configs with explicit `"email"` continue to work

- **Remove dev source code patterns from immutable deny rules** (Issue #369)
  - Dev source protection was redundant with git/PR workflow
  - Pip-installed package protection kept; config/cache/hooks/markers unchanged

- **XDG Base Directory compliance** (Issue #352)
  - Logs and violations now stored in `XDG_STATE_HOME/ai-guardian` (default `~/.local/state/ai-guardian`)
  - Cache paths respect `XDG_CACHE_HOME` via centralized `get_cache_dir()`
  - Environment variable overrides: `AI_GUARDIAN_STATE_DIR`, `AI_GUARDIAN_CACHE_DIR`
  - Backward-compatible migration from old config dir on first run

### Fixed

- **Console pattern server toggle no longer destroys configuration** (Issue #418)
  - Toggle modes now only write the `enabled` field; other settings (url, auth, cache) are preserved

- **gitleaks:allow guidance now correctly says "at the end of the line"** (Issue #416)
  - Fixed incorrect placement instructions in block messages and Console help text

- **Prompt injection violation logs show actual pattern details** (Issue #420)
  - Previously hardcoded "Heuristic pattern detected" with confidence 0.95 for all violations
  - Now shows actual matched pattern, matched text, and real confidence score from detector

- **Directory blocking violations report correct reason** (Issue #347)
  - Previously always reported ".ai-read-deny marker found" even for directory rule violations
  - Now correctly distinguishes between marker-based and rule-based blocking with matched pattern

- **PII violations now include line numbers** (Issue #359)
  - PII and secret redaction violation logging populates `line_number` and `column` from redaction results instead of hardcoding `None`

- **Scanner installer respects --use-pinned and --version flags** (Issue #295)
  - After package manager installation, verifies installed version matches target; falls back to direct download if mismatched

- **GitHub Workflows: scanner versions synced with pyproject.toml** (Issue #289)
  - CI now installs exact pinned versions of all three scanners (gitleaks, betterleaks, leaktk) from pyproject.toml

- **Pattern server configuration section name corrected** (PR #318)
  - Integration test workflow now uses `pattern_servers` (plural) instead of incorrect singular form

## [1.5.1] - 2026-04-28

### Security

- **Scanner Installer: SHA-256 Checksum Verification** (Issue #278)
  - **Supply Chain Security**: All scanner binaries are now verified using SHA-256 checksums from GitHub releases
  - **MITM Protection**: Prevents man-in-the-middle attacks during download by validating binary integrity
  - **Automatic Verification**: Downloads checksums file and verifies hash matches before installation
  - **Graceful Degradation**: Installation continues with warning if checksums unavailable (older releases)
  - **Multi-Scanner Support**: Handles scanner-specific naming conventions:
    - gitleaks: `gitleaks_8.30.1_checksums.txt`
    - betterleaks: `checksums.txt`
    - leaktk: `leaktk_0.2.10_checksums.txt`
  - **Security Hardening**:
    - Path traversal protection using `os.path.basename()` sanitization
    - Version format validation (regex `^\d+\.\d+\.\d+$`) prevents URL manipulation
    - Content validation ensures checksum files are not empty or malformed
    - Binary mode indicator support (`*filename` format in checksums)
  - **User Feedback**: Console messages show verification status:
    - `✓ Checksum verification passed for {scanner} {version}` (success)
    - `⚠ Checksum verification skipped - checksums file not available` (graceful degradation)
  - **Implementation**:
    - Added `_download_checksums()` method with HTTP error handling
    - Added `_verify_checksum()` method with SHA-256 computation and validation
    - Added version format validation in `install_from_download()`
    - Added explicit archive format validation (tar.gz, tar.xz, zip)
  - **Test Coverage**: Added 17 comprehensive test cases covering:
    - Scanner-specific checksums file naming conventions
    - Network failures and HTTP errors
    - Empty and malformed checksums files
    - Hash verification (success, mismatch, missing files)
    - Multi-file checksums parsing
    - Case-insensitive hash comparison
    - Binary mode indicator handling (`*filename`)
    - Path traversal sanitization
    - Version format validation (valid/invalid formats)
  - **Total Test Suite**: 49 scanner installer tests, 1,222 full suite tests (all passing)

## [1.5.0] - 2026-04-27

### Added

- **Scanner Installer: Skip Installation if Already Up-to-Date** (Issue #271)
  - **Smart Version Checking**: `ai-guardian scanner install` now checks if scanner is already installed before downloading
  - **Skip When Up-to-Date**: Automatically skips installation if the latest version is already installed
  - **Upgrade Detection**: Automatically upgrades when a newer version is available
  - **Downgrade Protection**: Does not auto-downgrade without explicit `--version` flag
  - **Explicit Control**: `--version` flag allows downgrade or reinstall of specific versions
  - **Clear Messaging**: Shows current version, target version, and action taken
  - **Version Comparison**: Proper semantic version comparison (e.g., 8.30.1 < 8.31.0)
  - **Performance**: Saves bandwidth and time by skipping unnecessary downloads
  - **Implementation**:
    - Added `_get_installed_version()` method to detect currently installed version
    - Added `_compare_versions()` method for semantic version comparison
    - Updated `install()` method with version checking logic
  - **Test Coverage**: Added 10 comprehensive test cases for version checking scenarios
  - **Benefits**: Faster installation, bandwidth-friendly, safe (no auto-downgrades), clear user feedback

- **SSRF Protection: Wildcard Domain Pattern Support** (Issue #253)
  - **New Feature**: Added wildcard pattern matching for `additional_blocked_domains` configuration
  - **Syntax**: Supports `*` (match zero or more characters) and `?` (match exactly one character)
  - **Pattern Examples**:
    - `*.internal.com` - Block all .internal.com domains (api.internal.com, db.internal.com)
    - `admin.*` - Block admin.* with any suffix (admin.example.com, admin.local)
    - `*.corp.*` - Block all .corp. domains (api.corp.internal, db.corp.example.com)
    - `metadata.*` - Block all metadata.* endpoints (metadata.aws.com, metadata.google.internal)
    - `test?.example.com` - Block test1.example.com, test2.example.com, testa.example.com
  - **Use Cases**:
    - Block entire TLDs with single pattern (`*.internal`, `*.local`)
    - Block subdomain patterns (`*.admin.example.com`)
    - Block naming patterns (`metadata.*`, `admin.*`)
    - Enterprise-wide policies with simplified configuration
  - **Backward Compatibility**: Exact domain matching and subdomain matching still work as before
  - **Pattern Validation**: Invalid patterns are rejected at config load time with warnings
  - **Performance**: Patterns stored separately from exact domains for optimal matching
  - **Files Modified**:
    - `src/ai_guardian/ssrf_protector.py`: Added `fnmatch` import, `_blocked_domain_patterns` list, `_is_valid_domain_pattern()` method, pattern matching in `_is_domain_blocked()`
    - `src/ai_guardian/schemas/ai-guardian-config.schema.json`: Updated `additional_blocked_domains` description with wildcard pattern syntax
    - `docs/SSRF_PROTECTION.md`: Comprehensive documentation with wildcard pattern examples and use cases
  - **Tests**: Added 11 comprehensive test cases in `TestWildcardDomainPatterns` class
  - **Impact**: Users can now use flexible wildcard patterns to block domains more efficiently

- **SSRF Protection: URL Allow-List Support** (Issue #252)
  - **New Configuration**: Added `allowed_domains` array to `ssrf_protection` configuration
  - **Purpose**: Allow specific trusted domains/URLs while maintaining core protections
  - **Evaluation Order (Deny-First)**: 
    1. Check immutable core protections (metadata endpoints, dangerous schemes, private IPs)
    2. Check deny-list (`additional_blocked_domains`)
    3. Check allow-list (`allowed_domains`) - can override step 2, NOT step 1
  - **Use Cases**:
    - Allow specific internal APIs while blocking other internal domains
    - Allow development/staging servers without allowing all localhost
    - Allow specific partner domains on restricted networks
    - Provide granular control to override broad domain blocks
  - **Domain Matching**: Supports exact match and subdomain matching
    - `"api.corp.internal"` allows `api.corp.internal` and `v1.api.corp.internal`
  - **Security**: Cannot override immutable core protections
    - Metadata endpoints (169.254.169.254, metadata.google.internal) remain blocked
    - Private IP ranges (RFC 1918) remain blocked
    - Dangerous schemes (file://, gopher://) remain blocked
  - **Files Modified**:
    - `src/ai_guardian/schemas/ai-guardian-config.schema.json`: Added `allowed_domains` property
    - `src/ai_guardian/ssrf_protector.py`: Implemented allow-list logic in `_check_url()`
    - `src/ai_guardian/setup.py`: Added `allowed_domains: []` to default config
    - `ai-guardian-example.json`: Added examples and security warnings
    - `docs/SSRF_PROTECTION.md`: Comprehensive documentation with examples
    - `AGENTS.md`: Enhanced schema change checklist
  - **Tests**: Added 9 comprehensive test cases in `tests/test_ssrf_protection.py`
  - **Impact**: Users can now create exceptions for specific domains while maintaining strong security boundaries

### Security

- **Cascading Priority for Remote Config URLs to Prevent Immutability Bypass** (Issue #255)
  - **Fix**: Implemented first-match-wins cascading for remote config URL sources
  - **Vulnerability**: Users could bypass `immutable: true` enterprise policies by adding their own remote config URLs in local/user configs
  - **Attack Scenario**: Enterprise deploys system config with `immutable: true` SSRF protection, user adds attacker-controlled remote URL that disables it
  - **Solution**: Remote config URLs now follow strict priority hierarchy (system config → env var → user config → local config)
    - **System config** (`/etc/ai-guardian/remote-configs.json`): Highest priority, requires root/admin, blocks all lower sources
    - **Environment variable** (`AI_GUARDIAN_REMOTE_CONFIG_URLS`): Second priority, blocks user/local sources
    - **User config** (`~/.config/ai-guardian/ai-guardian.json`): Third priority, blocks local config
    - **Local config** (`~/.ai-guardian.json`): Lowest priority fallback
  - **Implementation**:
    - Added `_get_system_config_path()`: Returns platform-specific system config path (Linux/macOS: `/etc/ai-guardian/remote-configs.json`, Windows: `C:\ProgramData\ai-guardian\remote-configs.json`)
    - Refactored `_load_remote_configs()`: Implements cascading with early return on first match
    - Added `_fetch_remote_configs()`: Helper to reduce code duplication
  - **Testing**: Added 5 new test cases in `test_immutable_configs.py`:
    - System config blocks user remote URLs
    - Environment variable takes priority over user config
    - User remote URLs work without system config
    - Local config has lowest priority
    - Legacy format (direct list) still works
  - **Backward Compatibility**: ✅ Existing users with remote_configs in user/local files continue working unchanged
  - **Enterprise Deployment**: Enterprises can now deploy one system config file to enforce policies across all users
  - **Impact**: Critical security fix - prevents users from bypassing all enterprise security policies

### Changed

- **Documentation: Clarify SSRF Protection Limitations and Scope** (Issue #256)
  - **Updated docs/SSRF_PROTECTION.md**: Added "Important Limitations" section at the top
    - Clearly explains what SSRF protection CAN and CANNOT protect against
    - Documents pattern-based filtering vs comprehensive network security
    - Added OpenShell integration guide for comprehensive SSRF protection
    - Explains hook-based architecture and why limitations exist
  - **Updated README.md**: SSRF section now includes limitation disclaimers
    - Examples of what CAN be blocked (explicit URLs in Bash/tool parameters)
    - Examples of what CANNOT be blocked (MCP server internal calls)
    - Recommendations for network-level controls and MCP sandboxing
  - **Updated ai-guardian-example.json**: Added comprehensive limitation comments
    - Explains pattern-based filtering cannot replace network security
    - Documents that it cannot detect MCP internal network calls
    - Notes about HTTP redirects and dynamic URL construction
  - **Updated src/ai_guardian/ssrf_protector.py**: Enhanced module docstring
    - Clear architecture explanation (hook-based, not proxy)
    - Defense in depth strategy documentation
    - Usage guidance and limitations
  - **Updated error messages**: SSRF block/warn messages now mention limitations
    - Changed "SSRF ATTACK DETECTED" to "SSRF PATTERN DETECTED"
    - Added note about pattern-based detection
    - Recommends firewall rules and network controls
    - References docs/SSRF_PROTECTION.md
  - **Impact**: Users now have realistic expectations about SSRF protection scope
  - **Key Message**: ai-guardian catches obvious SSRF attempts in command strings but cannot replace network-level security

### Fixed

- **Setup.py Missing permissions_directories in Default Config Template** (Issue #240)
  - **Fix**: Added `permissions_directories` field to `_get_default_config_template()` function in setup.py
  - **Problem**: Users running `ai-guardian setup --create-config` got incomplete configuration files missing the `permissions_directories` option
  - **Root Cause**: When `permissions_directories` was added to the schema, setup.py wasn't updated (violating AGENTS.md configuration consistency guidelines)
  - **Impact**: Generated configs now include `permissions_directories` with comprehensive comments and examples:
    - Local directory scanning example (`~/.claude/skills`)
    - GitHub repository scanning example with token_env
    - Documentation explaining it's OPTIONAL/ADVANCED and most users should prefer remote_configs
  - **Location**: Added to setup.py after permissions section (line 893), before directory_rules
  - **Verification**: Tested via `_get_default_config_template()` and confirmed field appears in generated config

- **JSON Schema Missing Definitions** (Issue #239)
  - **Fix**: Added missing `pattern_server_auth` and `pattern_server_cache` definitions to schema
  - **Problem**: Schema referenced definitions that didn't exist, causing validation failures for pattern_server configurations
  - **Root Cause**: When pattern_server was refactored from root-level to nested under each feature, the auth/cache structures were not extracted into reusable definitions
  - **Impact**: Schema validation now succeeds for configs using pattern_server with auth/cache in:
    - `secret_redaction.pattern_server`
    - `prompt_injection.unicode_detection.pattern_server`
    - `ssrf_protection.pattern_server`
    - `config_file_scanning.pattern_server`
  - **Tests**: Added comprehensive test suite (`test_pattern_server_definitions.py`) validating all pattern_server references

### Added

- **LeakTK Pattern Server Documentation** (Issue #156)
  - Added comprehensive documentation for using LeakTK patterns as a pattern server
  - **README.md**: Added "Using LeakTK Patterns (Recommended)" section with quick start guide
    - Benefits: Free, community-maintained, 104+ rules, no authentication required
    - Configuration example using GitHub raw content URL
    - Verification steps and expected log output
  - **docs/SECRET_SCANNING.md**: Added complete LeakTK integration guide
    - Pattern sources comparison table (LeakTK vs Gitleaks defaults)
    - Configuration options and cache settings
    - Pattern version compatibility table (8.25.0, 8.26.0, 8.27.0)
    - Troubleshooting guide and common issues
    - FAQ section covering offline usage, updates, firewall workarounds
    - Example workflows for combining LeakTK with project-specific patterns
  - **ai-guardian-example.json**: Added LeakTK example configuration
    - Documented free, community-maintained pattern source
    - Reference to LeakTK GitHub repository
  - Feature already implemented and tested - documentation completes the feature
  - LeakTK repository: https://github.com/leaktk/patterns

- **Permissions Comparison Documentation** (Issue #235)
  - Added comprehensive `docs/PERMISSIONS_COMPARISON.md` comparing ai-guardian.json vs settings.json permission systems
  - Covers: architecture diagrams, capabilities comparison, enforcement differences, when to use each
  - Explains Skills are only controllable via ai-guardian.json (not in settings.json)
  - Documents defense-in-depth best practices using both permission systems
  - Includes example configurations for different scenarios (user preferences, enterprise enforcement, defense-in-depth)
  - Cross-referenced from README.md "When to Use" section

### Changed

- **Removed Unused Maintainer Detection Code** (Issue #231)
  - **Change**: Removed ~450 lines of unused GitHub maintainer detection code from `tool_policy.py`
  - **Removed Methods**: 
    - `_get_git_repo_info()` - Extract GitHub repo info from git remote
    - `_get_authenticated_github_user()` - Get GitHub username from gh CLI
    - `_check_github_collaborator()` - Check if user has write access via GitHub API
    - `_get_maintainer_cache()` - Read maintainer status from cache
    - `_cache_maintainer_status()` - Write maintainer status to cache
    - `_is_github_maintainer_cached()` - Main maintainer check with caching
    - `_diagnose_maintainer_bypass()` - Diagnostic helper for bypass issues
  - **Rationale**: 
    - These methods were no longer called in production code since commit `0f6e456` (April 19, 2026)
    - The `_should_skip_immutable_protection()` bypass logic was simplified to allow ALL contributors to edit development source (fork + PR workflow)
    - Maintainer check was removed to enable standard open-source contribution workflow
    - Security relies on PR review process, not role-based permissions
  - **Impact**:
    - Reduced codebase complexity (~450 lines removed)
    - Removed dependency on `gh` CLI for permission checking
    - Eliminated cache file management (`~/.cache/ai-guardian/maintainer-status.json`)
    - Faster hook execution (no GitHub API calls)
  - **Tests Updated**:
    - Renamed `test_maintainer_bypass.py` → `test_development_source_bypass.py`
    - Removed tests for unused GitHub API methods (~400 lines)
    - Kept tests for core bypass logic (`_should_skip_immutable_protection`)
    - Removed `@patch('_is_github_maintainer_cached')` mocks from other test files
  - **No Breaking Changes**: The permission model remains unchanged - all contributors can edit development source, config/hooks/cache remain always protected

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
    - Console dropdown no longer shows "block" option
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
  - **Test Coverage**: Core protection modules at 70% (excluding Console/setup: 4,500 statements, 1,359 missing)
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
  - All violations logged to Console and violation log regardless of action

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

- **Interactive Console** for managing configuration
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

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.7.0...HEAD
[1.7.0]: https://github.com/itdove/ai-guardian/compare/v1.6.2...v1.7.0
[1.6.2]: https://github.com/itdove/ai-guardian/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/itdove/ai-guardian/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/itdove/ai-guardian/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/itdove/ai-guardian/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/itdove/ai-guardian/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/itdove/ai-guardian/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/itdove/ai-guardian/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/itdove/ai-guardian/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/itdove/ai-guardian/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
