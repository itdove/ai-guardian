# Contributing to AI Guardian

Thank you for your interest in contributing to AI Guardian! This document provides guidelines for contributing to the project.

## Fork-Based Workflow

All external contributions must come from forks. Direct push access is restricted to repository maintainers.

### Why Fork-Based?

- **Release Control**: Prevents unauthorized PyPI releases
- **Standard Practice**: Common workflow for open source projects
- **Code Review**: All changes reviewed via pull requests
- **Quality Assurance**: Automated tests run on all PRs

### Quick Start

```bash
# 1. Fork the repository (via GitHub UI or CLI)
gh repo fork itdove/ai-guardian --clone

# 2. Create a feature branch
cd ai-guardian
git checkout -b feature-name

# 3. Make changes and commit
git add .
git commit -m "feat: your change description"

# 4. Push to your fork
git push origin feature-name

# 5. Create pull request
gh pr create --web
```

## Working with AI Guardian Source Code

**IMPORTANT for Contributors:** If you have AI Guardian installed and active, you may experience blocked file reads when working on this repository.

**Why?** This project's test files and source code contain actual prompt injection patterns for detection testing. When AI Guardian blocks these files, **it's working correctly!**

**Files that may be blocked:**
- `tests/test_prompt_injection.py` - Contains test cases with actual attack patterns
- `src/ai_guardian/prompt_injection.py` - Contains the detection patterns in source code
- Other test files with injection test cases

**Solutions:**

1. **View documentation on GitHub web** (recommended for reading docs):
   - https://github.com/itdove/ai-guardian

2. **Temporarily disable prompt injection detection** (for local development):
   ```bash
   # Edit ~/.config/ai-guardian/ai-guardian.json
   # Set: "prompt_injection": {"enabled": false}
   ```

3. **Add personal allowlist pattern** (use with caution):
   ```json
   {
     "prompt_injection": {
       "enabled": true,
       "allowlist_patterns": [
         ".*/ai-guardian/.*"
       ]
     }
   }
   ```
   ⚠️ **Warning**: This allows ALL files in ai-guardian repos to bypass detection. Only use if you understand the security implications.

4. **Lower sensitivity** (alternative):
   ```json
   {
     "prompt_injection": {
       "sensitivity": "low"
     }
   }
   ```

See [Handling False Positives](README.md#handling-false-positives) in the README for more configuration options.

## AI-Assisted Development

**You can use Claude or other AI assistants to contribute to ai-guardian!**

### What's Allowed

✅ **Development source code** - You can use AI to edit:
- Source files: `src/ai_guardian/*.py`
- Test files: `tests/*.py`
- Documentation: `*.md`, `*.txt`
- Configuration: `pyproject.toml`, `.github/workflows/*`

These changes only affect your local development environment until merged.

### What's Always Protected

🔒 **Critical files** - AI assistance is blocked for:
- **Config files**: `~/.config/ai-guardian/ai-guardian.json`
- **IDE hooks**: `~/.claude/settings.json`, `~/.cursor/hooks.json`
- **Cache files**: `~/.cache/ai-guardian/*`
- **Directory markers**: `.ai-read-deny` files
- **Pip-installed code**: `/usr/lib/.../site-packages/ai_guardian/*`

These files remain protected even for repository owners to prevent accidental security bypasses.

### Security Model

**Standard open-source workflow:**
1. You edit code with AI assistance in your local fork
2. Submit pull request with changes
3. Maintainers review (looking for backdoors, vulnerabilities)
4. CI/CD tests run automatically
5. Community review on public PR
6. Maintainer merges after approval

**Note**: Pip-installed ai-guardian on users' systems stays protected even if malicious code is in a PR.

### Best Practices

- ⚠️ **Be cautious** when AI suggests changes to security-critical code
- ✅ **Review carefully** before committing (AI can make mistakes)
- ✅ **Run tests** before submitting PR: `pytest`
- ✅ **Small PRs** are easier to review for security issues
- ⚠️ **Never disable** config/hooks protection for "convenience"

### For Maintainers

Repository collaborators have the same permissions as contributors - config files and hooks remain protected for everyone. This defense-in-depth approach ensures even maintainers can't accidentally compromise the security model.

## Detailed Setup

### 1. Fork the Repository

**Via GitHub UI:**
1. Go to https://github.com/itdove/ai-guardian
2. Click the "Fork" button in the top right
3. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/ai-guardian.git
   cd ai-guardian
   ```

**Via GitHub CLI:**
```bash
gh repo fork itdove/ai-guardian --clone
cd ai-guardian
```

### 2. Configure Remotes

```bash
# Your fork is 'origin' (default)
git remote -v

# Add upstream (main repository)
git remote add upstream https://github.com/itdove/ai-guardian.git

# Verify remotes
git remote -v
# Should show:
# origin    https://github.com/YOUR-USERNAME/ai-guardian.git (fetch)
# origin    https://github.com/YOUR-USERNAME/ai-guardian.git (push)
# upstream  https://github.com/itdove/ai-guardian.git (fetch)
# upstream  https://github.com/itdove/ai-guardian.git (push)
```

### 3. Keep Your Fork Synced

**Before starting new work, sync with upstream:**

```bash
# Fetch latest changes from upstream
git checkout main
git fetch upstream
git merge upstream/main

# Push updates to your fork
git push origin main
```

**Automate syncing** (optional):

```bash
# Add alias to ~/.gitconfig
git config --global alias.sync '!git fetch upstream && git checkout main && git merge upstream/main && git push origin main'

# Now you can run:
git sync
```

## Making Changes

### 1. Create a Feature Branch

**Always branch from an up-to-date main:**

```bash
git checkout main
git pull upstream main
git checkout -b feature-name
```

**Branch naming conventions:**
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test additions/fixes

Examples:
- `feature/add-secret-scanning`
- `fix/prompt-injection-bug`
- `docs/update-readme`

### 2. Make Your Changes

**Follow project guidelines:**
- See [AGENTS.md](AGENTS.md) for coding standards
- Run tests: `pytest`
- Run linters (optional but recommended)
- Update CHANGELOG.md for notable changes

**Commit message format:**

```
<type>: <subject>

<body>

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

**Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

**Examples:**
```bash
git commit -m "feat: add new secret detection pattern"
git commit -m "fix: resolve timeout in permission validation"
git commit -m "docs: update installation instructions"
```

### 3. Run Tests Locally

**Before pushing, ensure all tests pass:**

```bash
# Run all tests (1,222+ tests)
pytest

# Run with coverage (excludes TUI modules automatically)
pytest --cov=ai_guardian --cov-report=term-missing

# Run specific test file
pytest tests/unit/test_specific.py -v
```

**Test Organization:**

Tests are organized into three categories:

- **Unit tests** (`tests/unit/`) - Fast, isolated tests (~1,141 tests)
- **Integration tests** (`tests/integration/`) - Cross-component tests (~82 tests)
- **UX tests** (`tests/ux/`) - User experience contract tests (~5 tests)

**Run tests by category:**

```bash
# Run only fast unit tests (recommended during development)
pytest tests/unit/

# Run integration tests (slower, verify cross-component behavior)
pytest tests/integration/

# Run UX contract tests (user-facing behavior validation)
pytest tests/ux/

# Run all tests
pytest tests/
```

**Integration Tests:**

AI Guardian includes comprehensive integration tests for MCP security:

```bash
# Run all integration tests (~82 tests)
pytest tests/integration/ -v

# Run specific integration test files
pytest tests/integration/test_integration_mcp.py -v           # MCP tool protections (24 tests)
pytest tests/integration/test_e2e_workflow.py -v             # End-to-end workflows (5 tests)
pytest tests/integration/test_pattern_server_integration.py -v  # Pattern server integration
pytest tests/integration/test_scanner_engine_integration.py -v  # Scanner engine integration
pytest tests/integration/test_contributor_workflow.py -v     # Contributor workflow tests

# Run specific test class
pytest tests/integration/test_integration_mcp.py::MCPSecretScanningTests -v
```

**What Integration Tests Cover:**
- ✅ All 9 protection layers with MCP tools
- ✅ Realistic attack scenarios (prompt injection chains, data exfiltration, SSRF)
- ✅ Legitimate workflows (ensures no false positives)
- ✅ Defense-in-depth validation
- ✅ Enterprise policy enforcement

**Adding New Tests:**

When adding new tests, place them in the appropriate category:

1. **Unit tests** (`tests/unit/`) - For testing single components in isolation:
   - Fast tests (<1s per file typically)
   - Mock external dependencies
   - No file I/O, network calls, or subprocess execution

2. **Integration tests** (`tests/integration/`) - For testing multiple components together:
   - May be slower (>1s per file)
   - Can use real files, subprocess, or external tools
   - Test end-to-end workflows

3. **UX tests** (`tests/ux/`) - For testing user-facing behavior:
   - Validate CLI output and error messages
   - Ensure backward compatibility
   - User flow validation

**Adding Integration Tests for MCP Tools:**

1. **Add attack constants** to `tests/fixtures/attack_constants.py`:
   ```python
   # Mark fake test credentials clearly
   SECRET_NEW_PATTERN = "fake-token-XXXXXXXXXXXX"  # notsecret - FAKE TEST CREDENTIAL
   ```

2. **Use the mock MCP server** in `tests/fixtures/mock_mcp_server.py`:
   ```python
   from tests.fixtures.mock_mcp_server import create_hook_data
   
   hook_data = create_hook_data(
       tool_name="mcp__notebooklm-mcp__notebook_create",
       tool_input={"title": "Test Notebook"}
   )
   ```

3. **Create test file in** `tests/integration/`:
   ```python
   # tests/integration/test_your_feature_integration.py
   @patch('ai_guardian._load_secret_redaction_config')
   @patch('ai_guardian._load_pattern_server_config')
   def test_your_scenario(self, mock_pattern_config, mock_redaction_config):
       # Tests run in isolated temporary directories
       mock_pattern_config.return_value = None
       mock_redaction_config.return_value = (None, None)
       # ... your test code
   ```

**Optional linting:**

```bash
# Check code formatting
black --check ai_guardian/ tests/

# Run pylint
pylint ai_guardian/

# Run ruff
ruff check ai_guardian/ tests/
```

### 4. Push to Your Fork

```bash
# Push your feature branch to your fork
git push origin feature-name

# If you need to force-push (after rebase)
git push origin feature-name --force-with-lease
```

## Creating a Pull Request

### 1. Open the PR

**Via GitHub CLI (recommended):**

```bash
gh pr create --title "Your PR Title" --body "$(cat <<'EOF'
## Description

Brief description of what this PR does.

## Changes

- Change 1
- Change 2
- Change 3

## Testing

### Steps to test
1. Pull down the PR
2. Run tests: `pytest`
3. Verify functionality

### Scenarios tested
- [ ] Test scenario 1
- [ ] Test scenario 2

## Related Issues

Fixes #123
Related to #456

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Via GitHub UI:**

1. Go to your fork: `https://github.com/YOUR-USERNAME/ai-guardian`
2. Click "Compare & pull request"
3. Fill in the PR template
4. Click "Create pull request"

### 2. PR Guidelines

**Your PR should:**
- ✅ Have a clear, descriptive title
- ✅ Link to related issues (use "Fixes #123")
- ✅ Include description of changes
- ✅ Add tests for new features/fixes
- ✅ Update CHANGELOG.md under `[Unreleased]`
- ✅ Pass all CI checks (tests, linting)
- ✅ Be focused (one feature/fix per PR)

**Your PR should NOT:**
- ❌ Include unrelated changes
- ❌ Have merge conflicts (rebase if needed)
- ❌ Break existing tests
- ❌ Lack tests for new functionality
- ❌ Skip CHANGELOG.md updates

### 3. Updating Your PR

**If changes are requested:**

```bash
# Make changes in your feature branch
git checkout feature-name

# Make edits
# ...

# Commit changes
git add .
git commit -m "fix: address review feedback"

# Push to update PR
git push origin feature-name
```

**If main has been updated:**

```bash
# Sync with upstream main
git checkout main
git pull upstream main

# Rebase your feature branch
git checkout feature-name
git rebase main

# Force-push to update PR
git push origin feature-name --force-with-lease
```

## Code Review Process

### What to Expect

1. **Automated Checks**: CI runs tests automatically
2. **Code Review**: Maintainer reviews your changes
3. **Feedback**: You may receive suggestions or requests
4. **Iteration**: Make changes based on feedback
5. **Approval**: Maintainer approves when ready
6. **Merge**: Maintainer merges your PR

### Review Timeline

- Initial review: Usually within 2-3 days
- Follow-up: 1-2 days for responses
- Merge: After approval and passing checks

### After Merge

```bash
# Your PR is merged! Clean up:
git checkout main
git pull upstream main
git push origin main

# Delete your feature branch
git branch -d feature-name
git push origin --delete feature-name
```

## Special Cases

### Updating CHANGELOG.md

**All notable changes should update CHANGELOG.md:**

```markdown
## [Unreleased]

### Added
- New feature X (#123)
- New pattern for secret detection (#125)

### Changed
- Improved error messages in hook validation (#124)

### Fixed
- Fixed timeout in MCP permission check (#126)
```

**Format**: Follow [Keep a Changelog](https://keepachangelog.com/)

### Working on Multiple Features

**Keep branches separate:**

```bash
# Feature 1
git checkout -b feature-1
# ... work ...
git push origin feature-1
# Create PR 1

# Feature 2 (from main, not feature-1)
git checkout main
git checkout -b feature-2
# ... work ...
git push origin feature-2
# Create PR 2
```

### Handling Merge Conflicts

**If your PR has conflicts with main:**

```bash
# Sync with upstream
git checkout main
git pull upstream main

# Rebase your feature branch
git checkout feature-name
git rebase main

# Resolve conflicts
# ... edit conflicting files ...
git add .
git rebase --continue

# Force-push
git push origin feature-name --force-with-lease
```

## Release Process

### For Contributors

**You CANNOT create releases.** Instead:

- ✅ Submit PRs with features/fixes
- ✅ Update CHANGELOG.md in your PR
- ✅ Maintainers handle releases

**DO NOT:**
- ❌ Create version tags
- ❌ Modify version numbers in pyproject.toml or __init__.py
- ❌ Push tags to origin

### For Maintainers

See [RELEASING.md](RELEASING.md) for release procedures.

## Getting Help

### Resources

- **Documentation**: See [README.md](README.md) and [AGENTS.md](AGENTS.md)
- **Release Process**: See [RELEASING.md](RELEASING.md)
- **Bug Reports**: Open an issue
- **Questions**: Open an issue with "question" label

### Opening Issues

**Before opening an issue:**
1. Search existing issues
2. Check if it's already fixed in main
3. Gather relevant information (error messages, steps to reproduce)

**Issue template:**

```markdown
## Description

Brief description of the issue.

## Steps to Reproduce

1. Step 1
2. Step 2
3. Step 3

## Expected Behavior

What should happen.

## Actual Behavior

What actually happens.

## Environment

- OS: macOS/Linux/Windows
- Python version: 3.x
- AI Guardian version: 1.x.x

## Additional Context

Any other relevant information.
```

## Code of Conduct

### Be Respectful

- ✅ Be kind and courteous
- ✅ Respect different viewpoints
- ✅ Accept constructive criticism gracefully
- ✅ Focus on what's best for the project
- ❌ No harassment or trolling
- ❌ No spam or self-promotion

### Quality Standards

- Write clean, readable code
- Test your changes thoroughly
- Document complex logic
- Follow existing code patterns
- Ask questions if unsure

## Thank You!

Your contributions make AI Guardian better for everyone. We appreciate your time and effort!

**Questions?** Open an issue or ask in your PR.

**Found a security issue?** Email the maintainers privately instead of opening a public issue.

---

*Happy contributing!* 🚀
